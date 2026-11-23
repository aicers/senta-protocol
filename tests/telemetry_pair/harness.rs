//! A run: one `SenderStream`, one `ReceiverStream` per entry, the
//! connections between them, the clocks, and the faults the operations
//! inject. Everything observed goes into the trace, beside what the model
//! expected.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use senta_protocol::connection::{AcceptedKind, TelemetryEntry};
use senta_protocol::telemetry::{
    MemorySenderStore, ReceiverChange, ReceiverConnection, ReceiverFlowKey, ReceiverLossReason,
    ReceiverOutput, ReceiverStream, Record, SenderAction, SenderConfig, SenderConnection,
    SenderError, SenderRecovered, SenderStream, TelemetryMessage,
};
use uuid::Uuid;

use crate::fixture::{
    ENDPOINT, ENTRIES, Kinds, List, Mark, Ranges, Template, base_time, expected_hash, make_record,
    mark_of, wire,
};
use crate::ingress::{Contents, TestStore};
use crate::model::{Ctx, Model, Observed, ctl_of};
use crate::ops::{Op, Setup, Step};
use crate::trace::{
    AckFact, AssignId, Commit, CommitItem, Ev, LinkId, Lt, Reset, ResumeFact, Trace,
};

/// How many snapshots of a store a run keeps.
const SNAPSHOTS: usize = 4;
/// How many of the last records sent a `Recover` picks from.
const RECOVER_FROM: usize = 16;
/// How many rounds the drain may take.
const DRAIN_ROUNDS: usize = 60;
/// How many rounds the drain may go without `A` rising while there is
/// something to send.
const STALL_ROUNDS: usize = 4;

/// One connection, both ends.
#[derive(Debug)]
pub struct Link {
    pub id: LinkId,
    pub conn: SenderConnection,
    /// The model's number for the connection.
    pub model_id: u64,
    pub entry: Uuid,
    pub recv: Option<ReceiverConnection>,
    /// The endpoint's messages on their way, each with its `Emit` event.
    pub to_entry: VecDeque<(TelemetryMessage, usize)>,
    pub to_endpoint: VecDeque<TelemetryMessage>,
    /// The last message the entry got, to deliver again.
    last: Option<(TelemetryMessage, usize)>,
}

/// A snapshot of an entry's store, with the coverage of each stream's
/// lifetime then.
#[derive(Debug, Clone)]
struct EntrySnapshot {
    contents: Contents,
    open: BTreeMap<ReceiverFlowKey, bool>,
    coverage: BTreeMap<ReceiverFlowKey, Coverage>,
}

/// One lifetime of a stream's state at an entry: the sequence numbers its
/// content holds, and the records it stored.
#[derive(Debug, Clone, Default)]
struct Coverage {
    seqs: Ranges,
    records: BTreeMap<u64, (Vec<u8>, Option<AssignId>)>,
}

/// One entry.
pub struct Ingress {
    pub store: TestStore,
    pub machine: ReceiverStream<TestStore>,
    lifetimes: BTreeMap<ReceiverFlowKey, Lt>,
    /// Whether each stream the store holds is open.
    open: BTreeMap<ReceiverFlowKey, bool>,
    coverage: BTreeMap<Lt, Coverage>,
    snapshots: Vec<EntrySnapshot>,
    /// Its state was lost since its last recovery.
    loss_pending: bool,
}

/// Misbehaviour a mutation test makes the delivery do.
#[derive(Debug, Clone, Default)]
pub struct Tamper {
    /// Changes the last byte of every record sent again for the same
    /// assignment, in the message and in its observation.
    pub alter_resent: bool,
    /// Adds an `ack` of this `A` to the entry's answer to the next
    /// `open_stream`.
    pub forge_ack: Option<u64>,
}

/// A call to the endpoint.
enum Call {
    Collect(Mark),
    Register,
    SetEntries(Vec<Uuid>),
    Connect,
    Disconnected(SenderConnection, u64),
    Hello(SenderConnection, u64, TelemetryEntry),
    Receive(SenderConnection, u64, TelemetryMessage),
    Tick,
}

pub struct World {
    pub setup: Setup,
    config: SenderConfig,
    pub sender: SenderStream<MemorySenderStore>,
    pub model: Model,
    pub trace: Trace,
    templates: BTreeMap<Mark, Template>,
    collected_at: BTreeMap<Mark, Timestamp>,
    next_mark: Mark,
    next_stream: u128,
    next_link: LinkId,
    next_lt: Lt,
    pub wall: Timestamp,
    pub mono: Duration,
    pub list: Vec<Uuid>,
    pub ingresses: BTreeMap<Uuid, Ingress>,
    pub link: Option<Link>,
    snapshots: Vec<(MemorySenderStore, Model)>,
    endpoint_loss_pending: bool,
    /// Commits of the endpoint's store to fail, carried over to the store
    /// of a `Recover`.
    endpoint_failures: u32,
    pub tamper: Tamper,
    pub last_kinds: Kinds,
    /// The bytes each record was last sent with.
    sent: BTreeMap<Mark, Vec<u8>>,
    /// The bytes each assignment was first sent with, and the event.
    first_bytes: BTreeMap<AssignId, Vec<u8>>,
    first_emit: BTreeMap<AssignId, usize>,
    /// The operation being run, for the violations.
    step: usize,
}

fn stream_of(message: &TelemetryMessage) -> Option<Uuid> {
    match message {
        TelemetryMessage::OpenStream(m) => Some(m.stream),
        TelemetryMessage::RecordBatch(m) => Some(m.stream()),
        TelemetryMessage::DroppedRange(m) => Some(m.stream),
        TelemetryMessage::LostOnReset(m) => Some(m.old_stream),
        TelemetryMessage::CloseStream(m) => Some(m.stream),
        TelemetryMessage::ResumeInfo(m) => Some(m.stream),
        TelemetryMessage::Ack(m) => Some(m.stream),
        TelemetryMessage::ErrorMessage(m) => m.stream,
    }
}

fn key(stream: Uuid) -> ReceiverFlowKey {
    ReceiverFlowKey {
        endpoint_id: ENDPOINT,
        stream,
    }
}

impl World {
    pub fn new(setup: Setup) -> Self {
        let config = SenderConfig::new(setup.collect_limit, setup.queue_limit)
            .with_retention(setup.retention());
        let sender = SenderStream::open(MemorySenderStore::new(), config, Duration::ZERO).unwrap();
        let ingresses = ENTRIES
            .iter()
            .map(|id| {
                let store = TestStore::new(*id);
                let machine = ReceiverStream::restore(*id, store.clone()).unwrap();
                (
                    *id,
                    Ingress {
                        store,
                        machine,
                        lifetimes: BTreeMap::new(),
                        open: BTreeMap::new(),
                        coverage: BTreeMap::new(),
                        snapshots: Vec::new(),
                        loss_pending: false,
                    },
                )
            })
            .collect();
        let mut world = Self {
            setup,
            config,
            sender,
            model: Model::new(config, Duration::ZERO),
            trace: Trace::default(),
            templates: BTreeMap::new(),
            collected_at: BTreeMap::new(),
            next_mark: 1,
            next_stream: 0x5000,
            next_link: 0,
            next_lt: 0,
            wall: base_time(),
            mono: Duration::ZERO,
            list: setup.list.entries(),
            ingresses,
            link: None,
            snapshots: Vec::new(),
            endpoint_loss_pending: false,
            endpoint_failures: 0,
            tamper: Tamper::default(),
            last_kinds: Kinds::All,
            sent: BTreeMap::new(),
            first_bytes: BTreeMap::new(),
            first_emit: BTreeMap::new(),
            step: 0,
        };
        world.call(Call::Register);
        let list = world.list.clone();
        world.call(Call::SetEntries(list));
        world
    }

    fn violation(&mut self, text: impl Into<String>) {
        let text = format!("op {}: {}", self.step, text.into());
        self.trace.violation(text);
    }

    // ----- The endpoint -----

    fn fresh_stream(&mut self) -> Uuid {
        self.next_stream += 1;
        Uuid::from_u128(self.next_stream)
    }

    /// Calls the endpoint and the model alike, retrying a call whose
    /// commit failed with the same inputs, then checks the two agree and
    /// sends what the endpoint asked to send.
    #[allow(clippy::too_many_lines)] // One arm per call, each mirrored on the model.
    fn call(&mut self, call: Call) {
        let new_stream = self.fresh_stream();
        let (wall, mono) = (self.wall, self.mono);
        let status_before = self.sender.status().unsupported;
        let model_before = self.model.unsupported;
        let recoveries_before = self.trace.recoveries.len();
        let events_before = self.trace.events.len();
        let mut attempts = 0;
        let (actions, connected) = loop {
            let result = match &call {
                Call::Collect(mark) => {
                    let record = self.templates[mark].record.clone();
                    self.sender.collect(record, wall, mono).map(|a| (a, None))
                }
                Call::Register => self.sender.register(ENDPOINT).map(|a| (a, None)),
                Call::SetEntries(list) => self
                    .sender
                    .set_entries(list.clone(), wall, mono)
                    .map(|a| (a, None)),
                Call::Connect => self
                    .sender
                    .connect(wall, mono)
                    .map(|c| (c.actions, Some(c.connection))),
                Call::Disconnected(conn, _) => self
                    .sender
                    .disconnected(*conn, wall, mono)
                    .map(|a| (a, None)),
                Call::Hello(conn, _, entry) => self
                    .sender
                    .hello_ack(*conn, entry, new_stream, wall, mono)
                    .map(|a| (a, None)),
                Call::Receive(conn, _, message) => self
                    .sender
                    .receive(*conn, message, new_stream, wall, mono)
                    .map(|a| (a, None)),
                Call::Tick => self.sender.tick(wall, mono).map(|a| (a, None)),
            };
            match result {
                Ok(done) => break done,
                Err(SenderError::Store(_)) => {
                    attempts += 1;
                    assert!(attempts < 8, "a commit keeps failing");
                    self.endpoint_failures = self.endpoint_failures.saturating_sub(1);
                }
                Err(error) => panic!("the endpoint refused a call: {error}"),
            }
        };

        let link_id = self.link.as_ref().map(|l| l.id);
        let mut ctx = Ctx {
            trace: &mut self.trace,
            templates: &self.templates,
            link: link_id,
        };
        let expected = match call {
            Call::Collect(mark) => self.model.collect(&mut ctx, mark, wall, mono),
            Call::Register => {
                self.model.register(&mut ctx, ENDPOINT);
                Vec::new()
            }
            Call::SetEntries(list) => self.model.set_entries(&mut ctx, list, wall, mono),
            Call::Connect => {
                let (opened, out) = self.model.connect(&mut ctx, wall, mono);
                let connection = connected.flatten();
                match (opened, connection) {
                    (Some((model_id, entry)), Some(conn)) => {
                        if conn.entry_id() != entry {
                            self.violation(format!(
                                "connected to {} where the model expects {entry}",
                                conn.entry_id()
                            ));
                        }
                        self.next_link += 1;
                        self.link = Some(Link {
                            id: self.next_link,
                            conn,
                            model_id,
                            entry: conn.entry_id(),
                            recv: None,
                            to_entry: VecDeque::new(),
                            to_endpoint: VecDeque::new(),
                            last: None,
                        });
                    }
                    (None, None) => self.link = None,
                    (opened, connection) => {
                        self.link = None;
                        self.violation(format!(
                            "connect gave {connection:?} where the model expects {opened:?}"
                        ));
                    }
                }
                out
            }
            Call::Disconnected(_, model_id) => {
                self.model.disconnected(&mut ctx, model_id, wall, mono)
            }
            Call::Hello(_, model_id, entry) => self.model.hello_ack(
                &mut ctx,
                model_id,
                entry.entry_id,
                entry.accepted_kinds,
                new_stream,
                wall,
                mono,
            ),
            Call::Receive(_, model_id, message) => self
                .model
                .receive(&mut ctx, model_id, &message, new_stream, wall, mono),
            Call::Tick => self.model.tick(&mut ctx, wall, mono),
        };
        let actual = ctl_of(&actions);
        if actual != expected {
            self.violation(format!(
                "the endpoint did {actual:?} where the model expects {expected:?}"
            ));
        }

        // The recoveries of this call.
        let status_after = self.sender.status().unsupported;
        for id in recoveries_before..self.trace.recoveries.len() {
            let recovery = &mut self.trace.recoveries[id];
            let entry_loss = self
                .ingresses
                .get_mut(&recovery.entry)
                .map(|i| std::mem::take(&mut i.loss_pending))
                .unwrap_or_default();
            // The first reconnection after a loss of the endpoint's state
            // is the one it allows, whatever else allows it too.
            let endpoint_loss = std::mem::take(&mut self.endpoint_loss_pending);
            recovery.allowed =
                recovery.reset == Some(Reset::EntryChanged) || endpoint_loss || entry_loss;
            recovery.unsupported_expected = self.model.unsupported - model_before;
            recovery.unsupported_observed = status_after.saturating_sub(status_before);
            if let (Some(Reset::Lost { .. }), Some(old)) = (recovery.reset, recovery.old_stream) {
                let ranges = self
                    .ingresses
                    .get(&recovery.entry)
                    .unwrap()
                    .store
                    .lost_on_reset(ENDPOINT, old);
                self.trace.push(Ev::Baseline {
                    recovery: id,
                    ranges,
                });
            }
        }
        let done: Vec<usize> = self.trace.events[events_before..]
            .iter()
            .filter_map(|ev| match ev {
                Ev::NoticesDone { recovery } => Some(*recovery),
                _ => None,
            })
            .collect();
        for recovery in done {
            let r = &self.trace.recoveries[recovery];
            if let Some(old) = r.old_stream {
                let ranges = self
                    .ingresses
                    .get(&r.entry)
                    .unwrap()
                    .store
                    .lost_on_reset(ENDPOINT, old);
                self.trace.push(Ev::Held { recovery, ranges });
            }
        }

        // What the endpoint asked for.
        for action in actions {
            match action {
                SenderAction::Send(message) => self.emitted(&message),
                SenderAction::Disconnect => {
                    self.link = None;
                }
                SenderAction::Connect { .. } => {}
            }
        }
        self.cross_check();
    }

    /// Records a message the endpoint sent and puts it on its way.
    fn emitted(&mut self, message: &TelemetryMessage) {
        let Observed {
            records,
            assigns,
            items: model,
        } = self.model.observe(message);
        for record in &records {
            if let Some(mark) = record.mark {
                self.sent.insert(mark, record.bytes.clone());
            }
            if let Some(assign) = record.assign {
                self.first_bytes
                    .entry(assign)
                    .or_insert_with(|| record.bytes.clone());
            }
        }
        if let TelemetryMessage::RecordBatch(batch) = message {
            for record in &records {
                let fine = record
                    .mark
                    .and_then(|mark| self.templates.get(&mark))
                    .is_some_and(|template| {
                        let mut expected = template.record.clone();
                        expected.header.endpoint_id = ENDPOINT;
                        expected.header.stream = batch.stream();
                        expected.header.seq = record.seq;
                        Record::from_bytes(&record.bytes).ok() == Some(expected)
                    });
                if !fine {
                    self.violation(format!(
                        "the endpoint sent record {:?} at {} otherwise than collected, with its \
                         endpoint, stream and sequence number",
                        record.mark, record.seq
                    ));
                }
            }
        }
        let (wired, payload_len) = wire(message);
        let Some(link) = self.link.as_ref() else {
            self.violation(format!("the endpoint sent {message:?} with no connection"));
            return;
        };
        let (link_id, entry) = (link.id, link.entry);
        let ev = self.trace.events.len();
        for record in &records {
            if let Some(assign) = record.assign {
                self.first_emit.entry(assign).or_insert(ev);
            }
        }
        self.trace.push(Ev::Emit {
            link: link_id,
            entry,
            msg: message.clone(),
            payload_len,
            records,
            assigns,
            model,
        });
        if let Some(link) = self.link.as_mut() {
            link.to_entry.push_back((wired, ev));
        }
    }

    fn cross_check(&mut self) {
        let position = self.sender.position();
        let expected = self.model.flow.map(|flow| {
            (
                flow.stream,
                flow.entry,
                self.model.k,
                self.model.m,
                self.model.s,
            )
        });
        let actual = position.map(|p| (p.stream, p.entry_id, p.acknowledged, p.assigned, p.sent));
        if actual != expected {
            self.violation(format!(
                "the endpoint stands at {actual:?} where the model expects {expected:?}"
            ));
        }
        let status = self.sender.status();
        let actual = (
            status.collected_records,
            status.queued_records,
            status.queued_bytes,
            status.dropped_ranges,
            status.unsupported,
        );
        let expected = (
            u64::try_from(self.model.collected_len()).unwrap(),
            u64::try_from(self.model.queued_len()).unwrap(),
            self.model.queue_bytes,
            self.model.dropped_ranges,
            self.model.unsupported,
        );
        if actual != expected {
            self.violation(format!(
                "the endpoint reports (collected, queued, bytes, dropped ranges, unsupported) \
                 {actual:?} where the model expects {expected:?}"
            ));
        }
        if self.sender.target() != self.model.target {
            self.violation(format!(
                "the endpoint targets {:?} where the model expects {:?}",
                self.sender.target(),
                self.model.target
            ));
        }
    }

    // ----- Operations -----

    pub fn collect(&mut self, kind: crate::fixture::Kind, size: crate::fixture::Size) -> Mark {
        let mark = self.next_mark;
        self.next_mark += 1;
        self.templates
            .insert(mark, Template::new(make_record(mark, kind, size)));
        self.collected_at.insert(mark, self.wall);
        self.trace.marks.insert(mark);
        self.call(Call::Collect(mark));
        mark
    }

    pub fn connect(&mut self) {
        self.drop_link();
        self.call(Call::Connect);
    }

    pub fn hello(&mut self, kinds: Kinds) {
        let Some(link) = self.link.as_mut() else {
            return;
        };
        if link.recv.is_some() {
            return;
        }
        let list: Vec<AcceptedKind> = kinds.list();
        link.recv = Some(ReceiverConnection::new(ENDPOINT, list.clone()));
        let (conn, model_id, entry) = (link.conn, link.model_id, link.entry);
        self.last_kinds = kinds;
        self.call(Call::Hello(
            conn,
            model_id,
            TelemetryEntry {
                entry_id: entry,
                accepted_kinds: list,
            },
        ));
    }

    /// Ends the connection on the entry's side alone: the endpoint either
    /// already ended it or is gone.
    fn drop_link(&mut self) {
        self.link = None;
    }

    /// The connection breaks and the endpoint learns it.
    pub fn disconnect(&mut self) {
        if let Some(link) = self.link.take() {
            self.call(Call::Disconnected(link.conn, link.model_id));
        }
    }

    pub fn set_entries(&mut self, list: List) {
        self.list = list.entries();
        let entries = self.list.clone();
        self.call(Call::SetEntries(entries));
    }

    pub fn tick(&mut self) {
        self.call(Call::Tick);
    }

    pub fn advance(&mut self, by: SignedDuration) {
        self.wall = self.wall.checked_add(by).unwrap();
        self.mono += by.unsigned_abs();
    }

    pub fn advance_step(&mut self, step: Step) {
        let by = match step {
            Step::Minute => SignedDuration::from_mins(1),
            Step::Hour => SignedDuration::from_hours(1),
            Step::Retention => self.setup.retention(),
            Step::AlmostDay => SignedDuration::from_hours(24) - SignedDuration::from_mins(1),
            Step::Day => SignedDuration::from_hours(24) + SignedDuration::from_mins(1),
            Step::Month => SignedDuration::from_hours(31 * 24),
        };
        self.advance(by);
    }

    pub fn unreachable(&mut self) {
        if self.link.as_ref().is_some_and(|l| l.recv.is_some()) {
            return;
        }
        self.connect();
        self.disconnect();
        self.advance(SignedDuration::from_mins(31));
        self.tick();
    }

    /// Delivers the endpoint's next message to the entry.
    pub fn deliver_to_entry(&mut self) -> bool {
        let Some(link) = self.link.as_mut() else {
            return false;
        };
        if link.recv.is_none() {
            return false;
        }
        let Some((message, emit)) = link.to_entry.pop_front() else {
            return false;
        };
        let (mut message, _) = wire(&message);
        if self.tamper.alter_resent {
            self.alter_resent(&mut message, emit);
        }
        if let Some(link) = self.link.as_mut() {
            link.last = Some((message.clone(), emit));
        }
        self.deliver(message, Some(emit));
        true
    }

    /// Delivers the entry's last message again on the same connection, as
    /// a network that duplicates one would.
    pub fn deliver_again(&mut self) {
        let Some((message, emit)) = self.link.as_ref().and_then(|l| l.last.clone()) else {
            return;
        };
        let (message, _) = wire(&message);
        self.deliver(message, Some(emit));
    }

    fn alter_resent(&mut self, message: &mut TelemetryMessage, emit: usize) {
        let TelemetryMessage::RecordBatch(batch) = message else {
            return;
        };
        let first_emit = &self.first_emit;
        let Ev::Emit { records, .. } = &mut self.trace.events[emit] else {
            return;
        };
        let mut altered = Vec::new();
        for record in records.iter_mut() {
            let resent = record
                .assign
                .and_then(|a| first_emit.get(&a))
                .is_some_and(|first| *first < emit);
            if resent && let Some(last) = record.bytes.last_mut() {
                *last ^= 1;
            }
            altered.push(record.bytes.clone());
        }
        *batch = senta_protocol::telemetry::RecordBatch::new(batch.stream(), altered).unwrap();
    }

    /// Hands a message to the entry of the connection and records what
    /// happened.
    #[allow(clippy::too_many_lines)] // Delivery, then the facts the judges read.
    fn deliver(&mut self, message: TelemetryMessage, emit: Option<usize>) {
        let Some(link) = self.link.as_mut() else {
            return;
        };
        let (link_id, entry) = (link.id, link.entry);
        let Some(recv) = link.recv.as_mut() else {
            return;
        };
        let ingress = self.ingresses.get_mut(&entry).unwrap();
        let stream = stream_of(&message);
        let before = stream.and_then(|s| {
            ingress
                .machine
                .flow(ENDPOINT, s)
                .map(|state| (ingress.lifetimes.get(&key(s)).copied(), *state))
        });
        let armed = ingress.store.armed();
        let halted = recv.is_halted();
        let output = ingress.machine.receive(recv, message.clone(), self.wall);
        let injected = armed && !ingress.store.armed();
        let output = match (output, &message, self.tamper.forge_ack) {
            (ReceiverOutput::Reply(mut replies), TelemetryMessage::OpenStream(open), Some(a)) => {
                self.tamper.forge_ack = None;
                replies.push(TelemetryMessage::Ack(senta_protocol::telemetry::Ack {
                    stream: open.stream,
                    a,
                }));
                ReceiverOutput::Reply(replies)
            }
            (output, _, _) => output,
        };
        self.absorb(entry, emit);

        let ingress = self.ingresses.get(&entry).unwrap();
        let mut acks = Vec::new();
        let mut resume = None;
        if let ReceiverOutput::Reply(messages) = &output {
            for reply in messages {
                match reply {
                    TelemetryMessage::Ack(ack) => {
                        let lt = ingress.lifetimes.get(&key(ack.stream)).copied();
                        let covered = lt
                            .and_then(|lt| ingress.coverage.get(&lt))
                            .map_or(0, |c| c.seqs.prefix());
                        acks.push(AckFact {
                            lt,
                            a: ack.a,
                            covered,
                        });
                    }
                    TelemetryMessage::ResumeInfo(info) => {
                        let lt = ingress.lifetimes.get(&key(info.stream)).copied();
                        let last = info.last_stored.map(|l| (l.seq, l.hash));
                        let expected_hash = last.and_then(|(seq, _)| {
                            let coverage = ingress.coverage.get(&lt?)?;
                            let (bytes, assign) = coverage.records.get(&seq)?;
                            let first = assign
                                .and_then(|a| self.first_bytes.get(&a))
                                .unwrap_or(bytes);
                            Some(expected_hash(first))
                        });
                        resume = Some(ResumeFact {
                            lt,
                            a: info.a,
                            last,
                            expected_hash,
                        });
                    }
                    _ => {}
                }
            }
        }
        self.trace.push(Ev::Deliver {
            entry,
            link: link_id,
            msg: message,
            before,
            injected,
            halted,
            output: output.clone(),
            acks,
            resume,
        });
        match output {
            ReceiverOutput::Reply(messages) => {
                if let Some(link) = self.link.as_mut() {
                    link.to_endpoint.extend(messages);
                }
            }
            ReceiverOutput::Disconnect => {
                if !halted {
                    self.halt();
                }
            }
        }
    }

    /// The entry told the caller to close the connection: what the
    /// endpoint sent after reaches it, and gets no answer, before the
    /// connection closes.
    fn halt(&mut self) {
        loop {
            let Some(link) = self.link.as_mut() else {
                return;
            };
            let Some((message, emit)) = link.to_entry.pop_front() else {
                break;
            };
            let (message, _) = wire(&message);
            self.deliver(message, Some(emit));
        }
        self.disconnect();
    }

    /// Reads the writes an entry's store took, and records them as commits
    /// with the lifetime each belongs to.
    fn absorb(&mut self, entry: Uuid, emit: Option<usize>) {
        let ingress = self.ingresses.get_mut(&entry).unwrap();
        let log = ingress.store.take_log();
        let ev = self.trace.events.len();
        for changes in log {
            for change in changes {
                let (lt, item) = match change {
                    ReceiverChange::SetFlow { key, state } => {
                        // The state before this change: what the store held,
                        // as the lifetimes follow it.
                        // A stream the entry did not have, or had closed, that
                        // opens starts a new lifetime.
                        if state.is_open() && ingress.open.get(&key) != Some(&true) {
                            self.next_lt += 1;
                            ingress.lifetimes.insert(key, self.next_lt);
                            ingress.coverage.insert(self.next_lt, Coverage::default());
                        }
                        ingress.open.insert(key, state.is_open());
                        (
                            ingress.lifetimes.get(&key).copied(),
                            CommitItem::Flow { key, state },
                        )
                    }
                    ReceiverChange::RemoveFlow(key) => {
                        let lt = ingress.lifetimes.remove(&key);
                        ingress.open.remove(&key);
                        (lt, CommitItem::Remove)
                    }
                    ReceiverChange::AppendRecord(record) => {
                        let key = key_of(record.endpoint_id, record.stream);
                        let lt = ingress.lifetimes.get(&key).copied();
                        let assign = emit.and_then(|e| emitted_assign(&self.trace, e, record.seq));
                        if let Some(coverage) = lt.and_then(|lt| ingress.coverage.get_mut(&lt)) {
                            coverage.seqs.insert(record.seq, record.seq);
                            coverage
                                .records
                                .insert(record.seq, (record.bytes.clone(), assign));
                        }
                        (
                            lt,
                            CommitItem::Record {
                                key,
                                seq: record.seq,
                                mark: mark_of(&record.bytes),
                                bytes: record.bytes,
                                assign,
                            },
                        )
                    }
                    ReceiverChange::AppendLoss(loss) => {
                        let key = key_of(loss.endpoint_id, loss.stream);
                        let lt = ingress.lifetimes.get(&key).copied();
                        let assigns = emit.map_or_else(Vec::new, |e| {
                            emitted_assigns(&self.trace, e, loss.range.from, loss.range.to)
                        });
                        match loss.reason {
                            ReceiverLossReason::Dropped(reason) => {
                                if let Some(coverage) =
                                    lt.and_then(|lt| ingress.coverage.get_mut(&lt))
                                {
                                    coverage.seqs.insert(loss.range.from, loss.range.to);
                                }
                                (
                                    lt,
                                    CommitItem::Dropped {
                                        key,
                                        range: loss.range,
                                        reason,
                                        assigns,
                                    },
                                )
                            }
                            ReceiverLossReason::LostOnReset => (
                                lt,
                                CommitItem::Lor {
                                    key,
                                    range: loss.range,
                                    assigns,
                                },
                            ),
                        }
                    }
                };
                self.trace.commits.push(Commit {
                    ev,
                    entry,
                    lt,
                    item,
                });
            }
        }
    }
}

fn key_of(endpoint_id: Uuid, stream: Uuid) -> ReceiverFlowKey {
    ReceiverFlowKey {
        endpoint_id,
        stream,
    }
}

/// The assignment the record of `seq` was sent with in the `Emit` event
/// `emit`.
fn emitted_assign(trace: &Trace, emit: usize, seq: u64) -> Option<AssignId> {
    match &trace.events[emit] {
        Ev::Emit { records, .. } => records.iter().find(|r| r.seq == seq)?.assign,
        _ => None,
    }
}

/// The assignments the `Emit` event `emit` carried for `from..=to`.
fn emitted_assigns(trace: &Trace, emit: usize, from: u64, to: u64) -> Vec<AssignId> {
    match &trace.events[emit] {
        Ev::Emit { assigns, .. } => assigns
            .iter()
            .filter(|(seq, _)| (from..=to).contains(seq))
            .map(|(_, a)| *a)
            .collect(),
        _ => Vec::new(),
    }
}

impl World {
    /// Runs one operation; one that does not apply is skipped.
    pub fn run(&mut self, op: Op) {
        self.step += 1;
        match op {
            Op::Collect(kind, size) => {
                self.collect(kind, size);
            }
            Op::Connect => self.connect(),
            Op::Hello(kinds) => self.hello(kinds),
            Op::ToEntry(n) => {
                for _ in 0..n {
                    if !self.deliver_to_entry() {
                        break;
                    }
                }
            }
            Op::ToEndpoint(n) => {
                for _ in 0..n {
                    if !self.deliver_to_endpoint() {
                        break;
                    }
                }
            }
            Op::LoseReply => self.lose_reply(),
            Op::Disconnect => self.disconnect(),
            Op::Exchange => self.exchange(),
            Op::Session(kinds) => {
                self.connect();
                self.hello(kinds);
                self.exchange();
            }
            Op::Advance(step) => self.advance_step(step),
            Op::Tick => self.tick(),
            Op::SetEntries(list) => self.set_entries(list),
            Op::Unreachable => self.unreachable(),
            Op::Snapshot => self.snapshot(),
            Op::Rollback(index) => self.rollback(index),
            Op::LoseState => self.lose_state(),
            Op::Recover(mask) => self.recover(mask),
            Op::FailEndpoint(n) => {
                self.endpoint_failures = u32::from(n);
                self.sender.store_mut().fail_next_commits(u32::from(n));
            }
            Op::EntrySnapshot(entry) => self.entry_snapshot(entry.id()),
            Op::EntryRestore(entry, index) => self.entry_restore(entry.id(), Some(index)),
            Op::EntryClear(entry) => self.entry_restore(entry.id(), None),
            Op::FailEntryWrite(entry) => self
                .ingresses
                .get(&entry.id())
                .unwrap()
                .store
                .fail_next_write(true),
            Op::Prune(entry) => self.prune(entry.id()),
        }
    }

    /// Delivers the entry's next message to the endpoint.
    pub fn deliver_to_endpoint(&mut self) -> bool {
        let Some(link) = self.link.as_mut() else {
            return false;
        };
        let Some(message) = link.to_endpoint.pop_front() else {
            return false;
        };
        let (conn, model_id) = (link.conn, link.model_id);
        let (message, _) = wire(&message);
        self.call(Call::Receive(conn, model_id, message));
        true
    }

    /// Loses the entry's next `ack` or `resume_info`.
    pub fn lose_reply(&mut self) {
        if let Some(link) = self.link.as_mut()
            && matches!(
                link.to_endpoint.front(),
                Some(TelemetryMessage::Ack(_) | TelemetryMessage::ResumeInfo(_))
            )
        {
            link.to_endpoint.pop_front();
        }
    }

    /// Delivers everything both ways until nothing moves.
    pub fn exchange(&mut self) {
        for _ in 0..100_000 {
            let mut moved = false;
            while self.deliver_to_entry() {
                moved = true;
            }
            while self.deliver_to_endpoint() {
                moved = true;
            }
            if !moved {
                return;
            }
        }
        self.violation("the exchange does not end");
    }

    pub fn snapshot(&mut self) {
        let mut store = self.sender.store().clone();
        store.fail_next_commits(0);
        self.snapshots.push((store, self.model.clone()));
        if self.snapshots.len() > SNAPSHOTS {
            self.snapshots.remove(0);
        }
    }

    /// Replaces the endpoint, recording what it held before and after.
    /// `carries_on` says the new state carries on the old one's history (a
    /// state lost, or kept without its sequence state), rather than going
    /// back to a snapshot's.
    fn replace_endpoint(
        &mut self,
        sender: SenderStream<MemorySenderStore>,
        mut model: Model,
        carries_on: bool,
    ) {
        self.drop_link();
        let before = self.model.present(&self.trace);
        let old_pending = self.model.pending.as_ref().map(|p| p.recovery);
        let after = model.present(&self.trace);
        if carries_on {
            model.erased.extend(before.difference(&after).copied());
        }
        model.erased.retain(|mark| !after.contains(mark));
        self.sender = sender;
        self.model = model;
        self.trace.push(Ev::EndpointLoss);
        self.endpoint_loss_pending = true;
        let new_pending = self.model.pending.as_ref().map(|p| p.recovery);
        if let Some(recovery) = old_pending
            && new_pending != Some(recovery)
        {
            self.trace.push(Ev::NoticesDropped {
                recovery,
                entry_changed: false,
            });
        }
        if let Some(recovery) = new_pending {
            // Notices the snapshot held go out again from now on.
            self.trace.push(Ev::Revived { recovery });
            self.baseline(recovery);
        }
    }

    fn baseline(&mut self, recovery: usize) {
        let r = &self.trace.recoveries[recovery];
        if let (Some(Reset::Lost { .. }), Some(old)) = (r.reset, r.old_stream) {
            let ranges = self
                .ingresses
                .get(&r.entry)
                .unwrap()
                .store
                .lost_on_reset(ENDPOINT, old);
            self.trace.push(Ev::Baseline { recovery, ranges });
        }
    }

    pub fn rollback(&mut self, index: u8) {
        if self.snapshots.is_empty() {
            return;
        }
        let (store, model) = self.snapshots[usize::from(index) % self.snapshots.len()].clone();
        let sender = SenderStream::open(store, self.config, self.mono).unwrap();
        let model = model.reopened(self.mono);
        self.list.clone_from(&model.entries);
        self.replace_endpoint(sender, model, false);
        self.endpoint_failures = 0;
    }

    pub fn lose_state(&mut self) {
        let sender = SenderStream::open(MemorySenderStore::new(), self.config, self.mono).unwrap();
        let model = self.model.emptied(self.mono);
        self.replace_endpoint(sender, model, true);
        self.endpoint_failures = 0;
        self.call(Call::Register);
        let list = self.list.clone();
        self.call(Call::SetEntries(list));
    }

    /// Starts the endpoint again from records left over: those of the
    /// last sent that `mask` picks, in the order they were collected. A
    /// record still waiting in the collection buffer, which the endpoint
    /// keeps, is not left over from the send queue as well.
    pub fn recover(&mut self, mask: u16) {
        let waiting = self.model.collected_marks();
        let candidates: Vec<Mark> = self
            .sent
            .keys()
            .rev()
            .filter(|mark| !waiting.contains(mark))
            .take(RECOVER_FROM)
            .copied()
            .collect();
        let mut picked: Vec<Mark> = candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, mark)| *mark)
            .collect();
        picked.sort_unstable();
        self.recover_marks(&picked);
    }

    pub fn recover_marks(&mut self, marks: &[Mark]) {
        let records: Vec<SenderRecovered> = marks
            .iter()
            .map(|mark| SenderRecovered {
                bytes: self.sent[mark].clone(),
                retained_since: self.collected_at[mark],
            })
            .collect();
        let mut failures = self.endpoint_failures;
        let sender = loop {
            let mut store = self.sender.store().clone();
            store.fail_next_commits(failures);
            match SenderStream::recover(store, self.config, records.clone(), self.mono) {
                Ok(sender) => break sender,
                Err(SenderError::Store(_)) => failures = 0,
                Err(error) => panic!("recover refused the records: {error}"),
            }
        };
        self.endpoint_failures = 0;
        let mut model = self.model.reopened(self.mono);
        let left: Vec<(Mark, u64, Timestamp)> = marks
            .iter()
            .map(|mark| {
                (
                    *mark,
                    u64::try_from(self.sent[mark].len()).unwrap(),
                    self.collected_at[mark],
                )
            })
            .collect();
        let mut ctx = Ctx {
            trace: &mut self.trace,
            templates: &self.templates,
            link: None,
        };
        model.recover(&mut ctx, &left);
        self.replace_endpoint(sender, model, true);
        self.cross_check();
    }

    fn linked_to(&self, entry: Uuid) -> bool {
        self.link.as_ref().is_some_and(|l| l.entry == entry)
    }

    pub fn entry_snapshot(&mut self, entry: Uuid) {
        let ingress = self.ingresses.get_mut(&entry).unwrap();
        let coverage = ingress
            .lifetimes
            .iter()
            .map(|(key, lt)| (*key, ingress.coverage[lt].clone()))
            .collect();
        ingress.snapshots.push(EntrySnapshot {
            contents: ingress.store.contents(),
            open: ingress.open.clone(),
            coverage,
        });
        if ingress.snapshots.len() > SNAPSHOTS {
            ingress.snapshots.remove(0);
        }
    }

    /// Puts an entry's store back to a snapshot, or empties it with
    /// `None`, with no connection open to it: one open is broken first.
    /// Every stream state it gets back starts a new lifetime whose content
    /// is what the snapshot held of the old one.
    pub fn entry_restore(&mut self, entry: Uuid, index: Option<u8>) {
        if self.linked_to(entry) {
            self.disconnect();
        }
        let ingress = self.ingresses.get_mut(&entry).unwrap();
        let snapshot = match index {
            Some(_) if ingress.snapshots.is_empty() => return,
            Some(index) => ingress.snapshots[usize::from(index) % ingress.snapshots.len()].clone(),
            None => EntrySnapshot {
                contents: Contents::default(),
                open: BTreeMap::new(),
                coverage: BTreeMap::new(),
            },
        };
        let starts: BTreeMap<ReceiverFlowKey, u64> = snapshot
            .contents
            .flows
            .iter()
            .map(|(key, state)| (*key, state.a))
            .collect();
        ingress.store.set_contents(snapshot.contents);
        ingress.store.take_log();
        ingress.open = snapshot.open;
        ingress.lifetimes.clear();
        for (key, coverage) in snapshot.coverage {
            self.next_lt += 1;
            ingress.lifetimes.insert(key, self.next_lt);
            ingress.coverage.insert(self.next_lt, coverage);
            if let Some(a) = starts.get(&key) {
                self.trace.starts.insert(self.next_lt, *a);
            }
        }
        ingress.machine = ReceiverStream::restore(entry, ingress.store.clone()).unwrap();
        ingress.loss_pending = true;
        self.trace.push(Ev::IngressLoss);
        if let Some(pending) = &self.model.pending
            && self.trace.recoveries[pending.recovery].entry == entry
        {
            let recovery = pending.recovery;
            self.baseline(recovery);
        }
    }

    /// Restarts the endpoint on its own store with a smaller send queue.
    /// The one exception to a run keeping its configuration: no other way
    /// through the public API makes an `A < K` transition renumber more
    /// than the queue holds (see the pull request's deviations). With a
    /// fixed configuration, the same entry's `hello_ack` already moves
    /// every collected record its list accepts, under the limit, before
    /// the `resume_info` that starts the transition; renumbering only
    /// shortens a copy's sequence number; so the move of step 2 has
    /// nothing left to push past the limit. A smaller limit does not
    /// change that either, since the `hello_ack` moves under it too: what
    /// it makes is a renumbering that overflows at step 1.
    pub fn restart_with_queue_limit(&mut self, queue_limit: u64) {
        self.config.queue_limit = queue_limit;
        self.setup.queue_limit = queue_limit;
        let sender =
            SenderStream::open(self.sender.store().clone(), self.config, self.mono).unwrap();
        self.drop_link();
        self.sender = sender;
        self.model = self.model.reconfigured(self.config, self.mono);
    }

    /// Hands the entry of the connection a message the test made, outside
    /// the trace, and returns its answer.
    pub fn poke(&mut self, message: TelemetryMessage) -> ReceiverOutput {
        let link = self.link.as_mut().expect("a connection");
        let recv = link.recv.as_mut().expect("a connection past its hello");
        let ingress = self.ingresses.get_mut(&link.entry).unwrap();
        let (message, _) = wire(&message);
        let output = ingress.machine.receive(recv, message, self.wall);
        assert!(
            ingress.store.take_log().is_empty(),
            "a message the test made changed the entry"
        );
        output
    }

    /// The bytes the endpoint last sent `mark` with.
    pub fn sent_bytes(&self, mark: Mark) -> &[u8] {
        self.sent.get(&mark).unwrap()
    }

    /// Makes the entry's store drop the records of every write.
    pub fn drop_records_at(&self, entry: Uuid) {
        self.ingresses.get(&entry).unwrap().store.drop_records(true);
    }

    pub fn prune(&mut self, entry: Uuid) {
        let ingress = self.ingresses.get_mut(&entry).unwrap();
        let _ = ingress.machine.prune(self.wall);
        self.absorb(entry, None);
        self.trace.push(Ev::Pruned);
    }

    // ----- The end of a run -----

    /// Stops the faults and exchanges normally with the current target,
    /// without moving the clocks, until there is nothing more to send.
    pub fn drain(&mut self, kinds: Kinds) {
        for ingress in self.ingresses.values() {
            ingress.store.fail_next_write(false);
        }
        self.sender.store_mut().fail_next_commits(0);
        self.endpoint_failures = 0;
        if self.model.target.is_none() {
            self.set_entries(List::E123);
        }
        let mut stall = 0;
        let mut last = None;
        for _ in 0..DRAIN_ROUNDS {
            if self.link.is_none() {
                self.connect();
            }
            if self.link.as_ref().is_some_and(|l| l.recv.is_none()) {
                self.hello(kinds);
            }
            self.exchange();
            if self.link.is_some() && self.model.awaiting() {
                // The answer to the open_stream was lost.
                self.disconnect();
                continue;
            }
            let quiet = self.link.as_ref().is_some_and(|l| {
                l.recv.is_some()
                    && l.to_entry.is_empty()
                    && l.to_endpoint.is_empty()
                    && Some(l.entry) == self.model.target
            });
            if quiet && !self.model.has_unsent() {
                return;
            }
            // Progress: while something is to send, A rises at the entry
            // (or K at the endpoint, when only the acknowledgement was
            // lost) within a few normal exchanges.
            let a = self.model.flow.and_then(|flow| {
                self.ingresses
                    .get(&flow.entry)
                    .unwrap()
                    .machine
                    .flow(ENDPOINT, flow.stream)
                    .map(|state| (flow.stream, state.a, self.model.k))
            });
            if self.model.has_unsent() {
                if a.is_some() && a == last {
                    stall += 1;
                } else {
                    stall = 0;
                }
                if stall >= STALL_ROUNDS {
                    self.violation(format!("A does not rise while records wait: {a:?}"));
                    return;
                }
                if quiet {
                    // Nothing more goes out on this connection: what is
                    // unacknowledged goes again on the next.
                    self.disconnect();
                }
            }
            last = a;
        }
        self.violation("the drain does not end");
    }

    /// Ends the run: drains, then records where the model leaves each
    /// record.
    pub fn finish(mut self, kinds: Kinds) -> Trace {
        self.drain(kinds);
        self.trace.final_state = self.model.final_state();
        self.trace
    }
}
