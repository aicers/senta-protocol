//! The test's own model of the endpoint, from the rules the issue states.
//!
//! It holds what the endpoint should hold, sequence number by sequence
//! number and record by record, and from it the test computes what it
//! expects: the decision on each reconnection, the list of what is to be
//! sent again, the losses to report, and the counts of a status report. It
//! takes the same inputs as the `SenderStream` and learns only one thing
//! from its outputs: what was actually sent (the highest sequence number
//! sent, the hashes of what was sent, and the losses announced), which the
//! rules define by what went out.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use senta_protocol::connection::AcceptedKind;
use senta_protocol::telemetry::SenderConfig;
use senta_protocol::telemetry::{Record, ResumeInfo, TelemetryMessage, kind};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use uuid::Uuid;

use crate::fixture::{MAX_RECORD, Mark, Ranges, Template, expected_hash, mark_of};
use crate::trace::{
    AssignId, Ev, Fate, Item, LinkId, Notices, Recovery, RecoveryId, Reset, SentRecord, Trace,
};

const ACK_HOLD: SignedDuration = SignedDuration::from_hours(24);
const NODE_MOVE: Duration = Duration::from_secs(30 * 60);

/// What the endpoint should do, less the data it sends: data is judged
/// against the expected list instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctl {
    /// Every `lost_on_reset` of one sending, its ranges joined.
    Lost(Vec<(u64, u64)>),
    Close(Uuid),
    Open(Uuid),
    Disconnect,
    Connect(Uuid),
}

/// Turns the endpoint's actions into the same form.
pub fn ctl_of(actions: &[senta_protocol::telemetry::SenderAction]) -> Vec<Ctl> {
    use senta_protocol::telemetry::SenderAction;
    let mut out: Vec<Ctl> = Vec::new();
    for action in actions {
        match action {
            SenderAction::Disconnect => out.push(Ctl::Disconnect),
            SenderAction::Connect { entry_id } => out.push(Ctl::Connect(*entry_id)),
            SenderAction::Send(message) => match message {
                TelemetryMessage::LostOnReset(lost) => {
                    let ranges = lost.ranges.iter().map(|range| (range.from, range.to));
                    if let Some(Ctl::Lost(previous)) = out.last_mut() {
                        previous.extend(ranges);
                    } else {
                        out.push(Ctl::Lost(ranges.collect()));
                    }
                }
                TelemetryMessage::CloseStream(close) => out.push(Ctl::Close(close.stream)),
                TelemetryMessage::OpenStream(open) => out.push(Ctl::Open(open.stream)),
                TelemetryMessage::RecordBatch(_) | TelemetryMessage::DroppedRange(_) => {}
                other => panic!("the endpoint sent {other:?}"),
            },
        }
    }
    out
}

/// What one message the endpoint sent carried, as the model sees it.
pub struct Observed {
    /// For a `record_batch`, its records with their assignments.
    pub records: Vec<SentRecord>,
    /// For a `dropped_range` or a `lost_on_reset`, the assignment of each
    /// sequence number.
    pub assigns: Vec<(u64, AssignId)>,
    /// What the model holds at each sequence number sent.
    pub items: Vec<Option<Item>>,
}

/// What the model's calls need beside the model.
pub struct Ctx<'a> {
    pub trace: &'a mut Trace,
    pub templates: &'a BTreeMap<Mark, Template>,
    pub link: Option<LinkId>,
}

#[derive(Debug, Clone)]
struct Collected {
    mark: Mark,
    kind: u16,
    schema: u16,
    since: Timestamp,
}

#[derive(Debug, Clone)]
struct Queued {
    mark: Mark,
    kind: u16,
    schema: u16,
    order: u64,
    since: Timestamp,
    len: u64,
    acked_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
struct Conn {
    id: u64,
    entry: Uuid,
    hello: bool,
    awaiting: Option<Uuid>,
    cap: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub recovery: RecoveryId,
    pub notices: Notices,
    pub old_stream: Uuid,
}

#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub stream: Uuid,
    pub entry: Uuid,
}

/// The endpoint as the rules say it should be.
#[derive(Debug, Clone)]
pub struct Model {
    config: SenderConfig,
    pub endpoint: Option<Uuid>,
    pub entries: Vec<Uuid>,
    pub target: Option<Uuid>,
    accepted: Vec<(Uuid, Vec<AcceptedKind>)>,
    pub flow: Option<Flow>,
    pub k: u64,
    pub m: u64,
    pub s: u64,
    next_order: u64,
    collect: BTreeMap<u64, Collected>,
    queue: BTreeMap<u64, Queued>,
    pub queue_bytes: u64,
    dropped: BTreeMap<u64, DropReason>,
    /// The assignment of every sequence number of the current stream.
    assigns: BTreeMap<u64, AssignId>,
    ledger: BTreeMap<u64, [u8; 16]>,
    announced: Ranges,
    pub pending: Option<Pending>,
    pub unsupported: u64,
    pub dropped_ranges: u64,
    conn: Option<Conn>,
    next_conn: u64,
    timer_start: Duration,
    /// The recoveries this state went through: a recovery the endpoint
    /// lost by going back to an older snapshot is not among them.
    lineage: Vec<RecoveryId>,
    /// How the endpoint let records go, in this state's history.
    fates: Vec<(Mark, Fate)>,
    /// Every record collected in this state's history.
    known: BTreeSet<Mark>,
    /// No deadline falls before this: until then the deadlines need no
    /// look at the buffers.
    soonest: Option<Timestamp>,
    /// Records a loss of state took away in this state's history, with
    /// every copy and everything that could report them.
    pub erased: BTreeSet<Mark>,
}

fn expired(since: Timestamp, wall: Timestamp, period: SignedDuration) -> bool {
    wall.duration_since(since) >= period
}

impl Model {
    pub fn new(config: SenderConfig, now: Duration) -> Self {
        Self {
            config,
            endpoint: None,
            entries: Vec::new(),
            target: None,
            accepted: Vec::new(),
            flow: None,
            k: 0,
            m: 0,
            s: 0,
            next_order: 0,
            collect: BTreeMap::new(),
            queue: BTreeMap::new(),
            queue_bytes: 0,
            dropped: BTreeMap::new(),
            assigns: BTreeMap::new(),
            ledger: BTreeMap::new(),
            announced: Ranges::new(),
            pending: None,
            unsupported: 0,
            dropped_ranges: 0,
            conn: None,
            next_conn: 0,
            timer_start: now,
            lineage: Vec::new(),
            fates: Vec::new(),
            known: BTreeSet::new(),
            erased: BTreeSet::new(),
            soonest: None,
        }
    }

    /// An empty state that carries on this one's history: what the
    /// endpoint had let go, and the recoveries it went through.
    pub fn emptied(&self, now: Duration) -> Self {
        let mut model = Self::new(self.config, now);
        model.lineage.clone_from(&self.lineage);
        model.fates.clone_from(&self.fates);
        model.known.clone_from(&self.known);
        model.erased.clone_from(&self.erased);
        model
    }

    /// Notes a deadline at `since + period`.
    fn due(&mut self, since: Timestamp, period: SignedDuration) {
        let at = since.checked_add(period).unwrap_or(since);
        self.soonest = Some(self.soonest.map_or(at, |soonest| soonest.min(at)));
    }

    /// The earliest deadline of everything held.
    fn recompute_soonest(&mut self) {
        let retention = self.config.retention;
        let k = self.k;
        let mut soonest: Option<Timestamp> = None;
        let mut note = |at: Option<Timestamp>| {
            if let Some(at) = at {
                soonest = Some(soonest.map_or(at, |s| s.min(at)));
            }
        };
        for c in self.collect.values() {
            note(c.since.checked_add(retention).ok());
        }
        for (seq, q) in &self.queue {
            match q.acked_at {
                Some(at) => note(at.checked_add(ACK_HOLD).ok()),
                None if *seq > k => note(q.since.checked_add(retention).ok()),
                None => {}
            }
        }
        self.soonest = soonest;
    }

    fn fate(&mut self, mark: Mark, fate: Fate) {
        self.fates.push((mark, fate));
    }

    /// The model of the same state opened with another configuration.
    pub fn reconfigured(&self, config: SenderConfig, now: Duration) -> Self {
        let mut model = self.reopened(now);
        model.config = config;
        model.recompute_soonest();
        model
    }

    /// The model of a stream opened on this state: no connection, and the
    /// 30 minutes start again.
    pub fn reopened(&self, now: Duration) -> Self {
        let mut model = self.clone();
        model.conn = None;
        model.next_conn = 0;
        model.timer_start = now;
        model
    }

    pub fn collected_marks(&self) -> BTreeSet<Mark> {
        self.collect.values().map(|c| c.mark).collect()
    }

    pub fn collected_len(&self) -> usize {
        self.collect.len()
    }

    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    pub fn awaiting(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|conn| conn.awaiting.is_some())
    }

    /// Whether the endpoint holds something it can still send on the
    /// current stream.
    pub fn has_unsent(&self) -> bool {
        self.m > self.k
    }

    /// Every record the endpoint holds in any form: a body, a sequence
    /// number of the current stream, or a notice that reports it.
    pub fn present(&self, trace: &Trace) -> BTreeSet<Mark> {
        let mut marks: BTreeSet<Mark> = self.collect.values().map(|c| c.mark).collect();
        marks.extend(self.queue.values().map(|q| q.mark));
        marks.extend(self.assigns.values().map(|a| trace.assign_of(*a).mark));
        if let Some(pending) = &self.pending {
            marks.extend(
                pending
                    .notices
                    .links
                    .values()
                    .map(|a| trace.assign_of(*a).mark),
            );
        }
        marks
    }

    pub fn final_state(&self) -> crate::trace::Final {
        crate::trace::Final {
            collected: self.collect.values().map(|c| c.mark).collect(),
            lineage: self.lineage.iter().copied().collect(),
            fates: self.fates.clone(),
            known: self.known.clone(),
            erased: self.erased.clone(),
        }
    }

    fn accepted_of(&self, entry: Uuid) -> Option<Vec<AcceptedKind>> {
        self.accepted
            .iter()
            .find(|(id, _)| *id == entry)
            .map(|(_, kinds)| kinds.clone())
    }

    fn queue_marks(&self) -> BTreeSet<Mark> {
        self.queue.values().map(|q| q.mark).collect()
    }

    fn item_at(&self, seq: u64) -> Option<Item> {
        let assign = *self.assigns.get(&seq)?;
        if let Some(reason) = self.dropped.get(&seq) {
            return Some(Item::Dropped {
                reason: reason.clone(),
                assign,
            });
        }
        self.queue.get(&seq).map(|q| Item::Record {
            mark: q.mark,
            assign,
        })
    }

    fn items(&self, from: u64, to: u64) -> Vec<Item> {
        (from..=to)
            .map(|seq| {
                self.item_at(seq)
                    .unwrap_or_else(|| panic!("the model holds nothing at {seq} past K"))
            })
            .collect()
    }

    // ----- Buffers -----

    fn add_dropped(&mut self, seq: u64, reason: DropReason, count: bool) {
        let merged = seq
            .checked_sub(1)
            .and_then(|left| self.dropped.get(&left))
            .is_some_and(|r| *r == reason)
            || self.dropped.get(&(seq + 1)).is_some_and(|r| *r == reason);
        self.dropped.insert(seq, reason);
        if count && !merged {
            self.dropped_ranges += 1;
        }
    }

    fn drop_queued(&mut self, ctx: &mut Ctx, seq: u64, reason: DropReason) {
        let Some(q) = self.queue.remove(&seq) else {
            return;
        };
        self.queue_bytes -= q.len;
        if seq > self.s {
            self.ledger.remove(&seq);
        }
        self.add_dropped(seq, reason.clone(), true);
        ctx.trace.push(Ev::Erase {
            stream: self.flow.map_or(Uuid::nil(), |f| f.stream),
            seq,
            reason,
        });
    }

    fn enforce_queue_limit(&mut self, ctx: &mut Ctx) {
        while self.queue_bytes > self.config.queue_limit {
            let Some((&seq, _)) = self.queue.first_key_value() else {
                return;
            };
            if seq <= self.k {
                if let Some(q) = self.queue.remove(&seq) {
                    self.queue_bytes -= q.len;
                }
            } else {
                self.drop_queued(ctx, seq, DropReason::BufferOverflow);
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // One record's fields, as the rules place it.
    fn place(
        &mut self,
        ctx: &mut Ctx,
        seq: u64,
        mark: Mark,
        kind: u16,
        schema: u16,
        order: u64,
        since: Timestamp,
        len: u64,
    ) {
        if len > u64::try_from(MAX_RECORD).unwrap() {
            self.add_dropped(seq, DropReason::TooLarge, true);
            return;
        }
        self.queue.insert(
            seq,
            Queued {
                mark,
                kind,
                schema,
                order,
                since,
                len,
                acked_at: None,
            },
        );
        self.queue_bytes += len;
        self.due(since, self.config.retention);
        self.enforce_queue_limit(ctx);
    }

    /// Deletes the oldest collected records past the limit, and returns
    /// the marks of those in `copies`, which are not counted.
    fn enforce_collect_limit(&mut self, copies: &BTreeMap<u64, u64>) -> Vec<Mark> {
        let mut deleted = Vec::new();
        while self.collect.len() > self.config.collect_limit {
            let Some((order, c)) = self.collect.pop_first() else {
                break;
            };
            if copies.contains_key(&order) {
                deleted.push(c.mark);
            } else {
                self.unsupported += 1;
                self.fate(c.mark, Fate::Unsupported);
            }
        }
        deleted
    }

    fn mover(&self) -> Option<(Flow, Vec<AcceptedKind>)> {
        self.endpoint?;
        let flow = self.flow?;
        if self.target != Some(flow.entry) {
            return None;
        }
        Some((flow, self.accepted_of(flow.entry)?))
    }

    fn move_one(&mut self, ctx: &mut Ctx, order: u64, flow: Flow) {
        let Some(c) = self.collect.remove(&order) else {
            return;
        };
        let seq = self.m + 1;
        self.m = seq;
        let len = ctx.templates.get(&c.mark).unwrap().len_at(seq);
        let assign = ctx.trace.assign(c.mark, flow.stream, seq);
        self.assigns.insert(seq, assign);
        self.place(ctx, seq, c.mark, c.kind, c.schema, order, c.since, len);
    }

    fn fill(&mut self, ctx: &mut Ctx) {
        let Some((flow, kinds)) = self.mover() else {
            return;
        };
        let orders: Vec<u64> = self
            .collect
            .iter()
            .filter(|(_, c)| kind::accepts(&kinds, c.kind, c.schema))
            .map(|(order, _)| *order)
            .collect();
        for order in orders {
            self.move_one(ctx, order, flow);
        }
    }

    // ----- Deadlines -----

    fn deadlines(&mut self, ctx: &mut Ctx, wall: Timestamp, now: Duration, out: &mut Vec<Ctl>) {
        if self.soonest.is_none_or(|soonest| wall < soonest) {
            self.move_node(ctx, now, out);
            return;
        }
        self.expire(ctx, wall);
        self.recompute_soonest();
        self.move_node(ctx, now, out);
    }

    fn expire(&mut self, ctx: &mut Ctx, wall: Timestamp) {
        let retention = self.config.retention;
        let gone: Vec<u64> = self
            .collect
            .iter()
            .filter(|(_, c)| expired(c.since, wall, retention))
            .map(|(order, _)| *order)
            .collect();
        for order in gone {
            if let Some(c) = self.collect.remove(&order) {
                self.unsupported += 1;
                self.fate(c.mark, Fate::Unsupported);
            }
        }
        let k = self.k;
        let mut pending: Vec<(Timestamp, u64)> = self
            .queue
            .iter()
            .filter(|(seq, q)| **seq > k && expired(q.since, wall, retention))
            .map(|(seq, q)| (q.since, *seq))
            .collect();
        pending.sort_unstable();
        for (_, seq) in pending {
            self.drop_queued(ctx, seq, DropReason::RetentionExpired);
        }
        let copies: Vec<u64> = self
            .queue
            .iter()
            .filter(|(_, q)| q.acked_at.is_some_and(|at| expired(at, wall, ACK_HOLD)))
            .map(|(seq, _)| *seq)
            .collect();
        for seq in copies {
            if let Some(q) = self.queue.remove(&seq) {
                self.queue_bytes -= q.len;
            }
        }
    }

    fn set_target(&mut self, target: Option<Uuid>, now: Duration, out: &mut Vec<Ctl>) {
        self.target = target;
        self.timer_start = self.timer_start.max(now);
        if self.conn.take().is_some() {
            out.push(Ctl::Disconnect);
        }
        if let Some(entry) = target {
            out.push(Ctl::Connect(entry));
        }
    }

    fn move_node(&mut self, ctx: &mut Ctx, now: Duration, out: &mut Vec<Ctl>) {
        let Some(target) = self.target else {
            return;
        };
        if self.conn.as_ref().is_some_and(|c| c.hello)
            || now.saturating_sub(self.timer_start) < NODE_MOVE
        {
            return;
        }
        let next = self
            .entries
            .iter()
            .position(|e| *e == target)
            .and_then(|i| self.entries.get(i + 1))
            .or_else(|| self.entries.first())
            .copied();
        self.set_target(next, now, out);
        self.fill(ctx);
    }

    fn end_connection(&mut self, now: Duration) {
        if let Some(conn) = self.conn.take()
            && conn.hello
        {
            self.timer_start = self.timer_start.max(now);
        }
    }

    fn prune_entries(&mut self) {
        let flow_entry = self.flow.map(|f| f.entry);
        let entries = &self.entries;
        self.accepted
            .retain(|(e, _)| entries.contains(e) || Some(*e) == flow_entry);
    }

    // ----- Calls -----

    pub fn collect(
        &mut self,
        ctx: &mut Ctx,
        mark: Mark,
        wall: Timestamp,
        now: Duration,
    ) -> Vec<Ctl> {
        let mut out = Vec::new();
        self.deadlines(ctx, wall, now, &mut out);
        self.known.insert(mark);
        let order = self.next_order;
        self.next_order += 1;
        let template = ctx.templates.get(&mark).unwrap();
        let (kind, schema) = (template.kind, template.schema);
        let movable = self
            .mover()
            .filter(|(_, kinds)| kind::accepts(kinds, kind, schema))
            .map(|(flow, _)| flow);
        self.collect.insert(
            order,
            Collected {
                mark,
                kind,
                schema,
                since: wall,
            },
        );
        self.due(wall, self.config.retention);
        if let Some(flow) = movable {
            self.move_one(ctx, order, flow);
        }
        self.enforce_collect_limit(&BTreeMap::new());
        out
    }

    pub fn register(&mut self, ctx: &mut Ctx, endpoint: Uuid) {
        if self.endpoint.is_some() {
            return;
        }
        self.endpoint = Some(endpoint);
        self.fill(ctx);
    }

    pub fn set_entries(
        &mut self,
        ctx: &mut Ctx,
        entries: Vec<Uuid>,
        wall: Timestamp,
        now: Duration,
    ) -> Vec<Ctl> {
        let mut out = Vec::new();
        self.deadlines(ctx, wall, now, &mut out);
        let first = entries.first().copied();
        let keep = self.target.is_some_and(|t| entries.contains(&t));
        self.entries = entries;
        self.prune_entries();
        if !keep {
            self.set_target(first, now, &mut out);
        }
        self.fill(ctx);
        out
    }

    pub fn connect(
        &mut self,
        ctx: &mut Ctx,
        wall: Timestamp,
        now: Duration,
    ) -> (Option<(u64, Uuid)>, Vec<Ctl>) {
        let mut out = Vec::new();
        self.deadlines(ctx, wall, now, &mut out);
        self.end_connection(now);
        let Some(entry) = self.target else {
            return (None, out);
        };
        let id = self.next_conn;
        self.next_conn += 1;
        self.conn = Some(Conn {
            id,
            entry,
            hello: false,
            awaiting: None,
            cap: None,
        });
        (Some((id, entry)), out)
    }

    fn is_current(&self, id: u64) -> bool {
        self.conn.as_ref().is_some_and(|c| c.id == id)
    }

    pub fn disconnected(
        &mut self,
        ctx: &mut Ctx,
        id: u64,
        wall: Timestamp,
        now: Duration,
    ) -> Vec<Ctl> {
        let mut out = Vec::new();
        if !self.is_current(id) {
            return out;
        }
        self.end_connection(now);
        self.deadlines(ctx, wall, now, &mut out);
        out
    }

    pub fn tick(&mut self, ctx: &mut Ctx, wall: Timestamp, now: Duration) -> Vec<Ctl> {
        let mut out = Vec::new();
        self.deadlines(ctx, wall, now, &mut out);
        out
    }

    #[allow(clippy::too_many_arguments)] // The inputs of a `hello_ack`.
    pub fn hello_ack(
        &mut self,
        ctx: &mut Ctx,
        id: u64,
        entry: Uuid,
        kinds: Vec<AcceptedKind>,
        new_stream: Uuid,
        wall: Timestamp,
        now: Duration,
    ) -> Vec<Ctl> {
        let mut out = Vec::new();
        let Some(conn) = self.conn.as_mut().filter(|c| c.id == id) else {
            return out;
        };
        if conn.hello || conn.entry != entry {
            self.end_connection(now);
            return vec![Ctl::Disconnect];
        }
        conn.hello = true;
        self.deadlines(ctx, wall, now, &mut out);
        match self.accepted.iter_mut().find(|(e, _)| *e == entry) {
            Some((_, known)) => *known = kinds,
            None => self.accepted.push((entry, kinds)),
        }
        match self.flow {
            None => self.transition(ctx, Reset::Fresh, entry, new_stream, wall, &mut out),
            Some(flow) if flow.entry != entry => {
                self.transition(ctx, Reset::EntryChanged, entry, new_stream, wall, &mut out);
            }
            Some(flow) => {
                self.fill(ctx);
                self.send_open(flow.stream, &mut out);
            }
        }
        self.prune_entries();
        out
    }

    pub fn receive(
        &mut self,
        ctx: &mut Ctx,
        id: u64,
        message: &TelemetryMessage,
        new_stream: Uuid,
        wall: Timestamp,
        now: Duration,
    ) -> Vec<Ctl> {
        let mut out = Vec::new();
        let Some(conn) = self.conn.as_ref().filter(|c| c.id == id) else {
            return out;
        };
        enum Verdict {
            Invalid,
            Noop,
            Resume(ResumeInfo),
            Ack(u64),
            Closed,
        }
        let verdict = match message {
            TelemetryMessage::ResumeInfo(info) => {
                let answers = conn.hello && conn.awaiting == Some(info.stream);
                let ordered = info.last_stored.is_none_or(|l| l.seq <= info.a);
                if answers && ordered {
                    Verdict::Resume(*info)
                } else {
                    Verdict::Invalid
                }
            }
            TelemetryMessage::Ack(ack) => match self.flow {
                None => Verdict::Noop,
                Some(flow) if ack.stream != flow.stream || ack.a <= self.k => Verdict::Noop,
                Some(_) if conn.cap.is_some_and(|cap| ack.a <= cap) => Verdict::Ack(ack.a),
                Some(_) => Verdict::Invalid,
            },
            TelemetryMessage::ErrorMessage(error)
                if error.error == TelemetryError::Closed
                    && error.stream.is_some()
                    && error.stream == conn.awaiting =>
            {
                Verdict::Closed
            }
            _ => Verdict::Invalid,
        };
        if matches!(verdict, Verdict::Invalid) {
            self.end_connection(now);
            return vec![Ctl::Disconnect];
        }
        self.deadlines(ctx, wall, now, &mut out);
        match verdict {
            Verdict::Resume(info) => self.resume(ctx, &info, new_stream, wall, &mut out),
            Verdict::Ack(a) => self.confirm(ctx, a, wall),
            Verdict::Closed => {
                if let Some(conn) = self.conn.as_mut() {
                    conn.awaiting = None;
                }
                self.notices_done(ctx);
                if let Some(flow) = self.flow {
                    self.transition(ctx, Reset::Closed, flow.entry, new_stream, wall, &mut out);
                }
            }
            Verdict::Invalid | Verdict::Noop => {}
        }
        out
    }

    fn notices_done(&mut self, ctx: &mut Ctx) {
        if let Some(pending) = self.pending.take() {
            ctx.trace.push(Ev::NoticesDone {
                recovery: pending.recovery,
            });
        }
    }

    fn confirm(&mut self, ctx: &mut Ctx, a: u64, wall: Timestamp) {
        if a <= self.k {
            return;
        }
        // A dropped sequence number past what this state ever sent can be
        // acknowledged only by a loss the entry recorded for another
        // state's assignment: its own loss is never reported.
        let unsent: Vec<Mark> = self
            .dropped
            .range(self.k + 1..=a)
            .filter(|(seq, _)| **seq > self.s)
            .map(|(seq, _)| ctx.trace.assign_of(self.assigns[seq]).mark)
            .collect();
        for mark in unsent {
            self.fate(mark, Fate::ConfirmedUnsent);
        }
        for (_, q) in self.queue.range_mut(self.k + 1..=a) {
            q.acked_at = Some(wall);
        }
        self.due(wall, ACK_HOLD);
        self.ledger.retain(|seq, _| *seq > a);
        self.dropped.retain(|seq, _| *seq > a);
        self.k = a;
    }

    fn resume(
        &mut self,
        ctx: &mut Ctx,
        info: &ResumeInfo,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<Ctl>,
    ) {
        if let Some(conn) = self.conn.as_mut() {
            conn.awaiting = None;
        }
        self.notices_done(ctx);
        let Some(flow) = self.flow else {
            return;
        };
        let (k, m, a) = (self.k, self.m, info.a);
        if a < k {
            return self.transition(ctx, Reset::Lost { a }, flow.entry, new_stream, wall, out);
        }
        if m < a {
            return self.transition(ctx, Reset::Same, flow.entry, new_stream, wall, out);
        }
        let low = match info.last_stored {
            Some(last) => {
                if last.seq > k && self.ledger.get(&last.seq) != Some(&last.hash) {
                    return self.transition(ctx, Reset::Same, flow.entry, new_stream, wall, out);
                }
                last.seq.max(k)
            }
            None => k,
        };
        if !(low + 1..=a).all(|seq| self.dropped.contains_key(&seq)) {
            return self.transition(ctx, Reset::Same, flow.entry, new_stream, wall, out);
        }
        let pre_queue = self.queue_marks();
        let waiting = self.collected_marks();
        self.confirm(ctx, a, wall);
        self.s = self.s.max(a);
        let kinds = self.accepted_of(flow.entry).unwrap_or_default();
        let narrowed = self
            .queue
            .range(a + 1..)
            .any(|(_, q)| !kind::accepts(&kinds, q.kind, q.schema));
        if narrowed {
            return self.transition(ctx, Reset::Same, flow.entry, new_stream, wall, out);
        }
        if let Some(conn) = self.conn.as_mut() {
            conn.cap = Some(a);
        }
        let targets = self.queue.range(a + 1..).map(|(_, q)| q.mark).collect();
        let list = self.items(a + 1, m);
        let recovery = ctx.trace.add_recovery(Recovery {
            ev: 0,
            entry: flow.entry,
            link: ctx.link,
            reset: None,
            old_stream: None,
            stream: flow.stream,
            allowed: false,
            targets,
            waiting,
            start: a + 1,
            list,
            pre_queue,
            returned: Vec::new(),
            notices: None,
            unsupported_expected: 0,
            unsupported_observed: 0,
        });
        self.lineage.push(recovery);
    }

    fn send_open(&mut self, stream: Uuid, out: &mut Vec<Ctl>) {
        if let Some(pending) = &self.pending {
            if !pending.notices.lost.is_empty() {
                out.push(Ctl::Lost(pending.notices.lost.clone()));
            }
            if pending.notices.close {
                out.push(Ctl::Close(pending.old_stream));
            }
        }
        out.push(Ctl::Open(stream));
        if let Some(conn) = self.conn.as_mut() {
            conn.awaiting = Some(stream);
            conn.cap = None;
        }
    }

    #[allow(clippy::too_many_lines)] // The steps of one transition, in their order.
    fn transition(
        &mut self,
        ctx: &mut Ctx,
        reset: Reset,
        entry: Uuid,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<Ctl>,
    ) {
        let pre_queue = self.queue_marks();
        let waiting = self.collected_marks();
        let old_stream = self.flow.map(|f| f.stream);
        let k = self.k;
        let kinds = self.accepted_of(entry).unwrap_or_default();
        let low = match reset {
            Reset::Lost { a } => a,
            _ => k,
        };
        let carry = reset != Reset::EntryChanged;
        let targets: BTreeSet<Mark> = self.queue.range(low + 1..).map(|(_, q)| q.mark).collect();

        // 1. Renumber, in the old order.
        let mut seqs: BTreeSet<u64> = self.queue.range(low + 1..).map(|(s, _)| *s).collect();
        if carry {
            seqs.extend(self.dropped.range(low + 1..).map(|(s, _)| *s));
        }
        let mut next = 0u64;
        let mut new_dropped = Vec::new();
        let mut new_records = Vec::new();
        let mut returned = Vec::new();
        let mut returned_marks = Vec::new();
        let mut returned_copies = BTreeMap::new();
        let mut renumbered = Vec::new();
        for seq in seqs {
            if let Some(q) = self.queue.get(&seq) {
                let copy = seq <= k;
                let since = if copy { wall } else { q.since };
                if kind::accepts(&kinds, q.kind, q.schema) {
                    next += 1;
                    new_records.push((next, q.mark, q.kind, q.schema, q.order, since));
                    renumbered.push(seq);
                } else {
                    returned.push((
                        q.order,
                        Collected {
                            mark: q.mark,
                            kind: q.kind,
                            schema: q.schema,
                            since,
                        },
                    ));
                    returned_marks.push(q.mark);
                    if copy {
                        returned_copies.insert(q.order, seq);
                    }
                }
            } else if let Some(reason) = self.dropped.get(&seq) {
                next += 1;
                let mark = ctx.trace.assign_of(*self.assigns.get(&seq).unwrap()).mark;
                new_dropped.push((next, reason.clone(), mark));
            }
        }
        if reset == Reset::EntryChanged {
            let abandoned: Vec<Mark> = self
                .dropped
                .keys()
                .map(|seq| ctx.trace.assign_of(self.assigns[seq]).mark)
                .collect();
            for mark in abandoned {
                self.fate(mark, Fate::Abandoned);
            }
        }
        let announced = self.announced.clone();
        let old_assigns = std::mem::take(&mut self.assigns);
        if let Some(pending) = self.pending.take() {
            ctx.trace.push(Ev::NoticesDropped {
                recovery: pending.recovery,
                entry_changed: reset == Reset::EntryChanged,
            });
        }

        // The old stream's state goes; the new one starts.
        self.queue.clear();
        self.queue_bytes = 0;
        self.ledger.clear();
        self.dropped.clear();
        self.announced = Ranges::new();
        self.flow = Some(Flow {
            stream: new_stream,
            entry,
        });
        self.k = 0;
        self.s = 0;
        self.m = next;
        for (seq, reason, mark) in new_dropped {
            let assign = ctx.trace.assign(mark, new_stream, seq);
            self.assigns.insert(seq, assign);
            self.add_dropped(seq, reason, false);
        }
        for (order, c) in returned {
            self.due(c.since, self.config.retention);
            self.collect.insert(order, c);
        }
        for (seq, mark, kind, schema, order, since) in new_records {
            let assign = ctx.trace.assign(mark, new_stream, seq);
            self.assigns.insert(seq, assign);
            let len = ctx.templates.get(&mark).unwrap().len_at(seq);
            self.place(ctx, seq, mark, kind, schema, order, since, len);
        }

        // 2. Move the collection buffer; 3. apply its limit.
        self.fill(ctx);
        let deleted_copies = self.enforce_collect_limit(&returned_copies);

        // 4. The notices.
        let mut lost = Vec::new();
        let mut links = BTreeMap::new();
        if let (Reset::Lost { a }, Some(_)) = (reset, old_stream) {
            let mut excluded = announced;
            for seq in renumbered {
                excluded.insert(seq, seq);
            }
            for (order, seq) in &returned_copies {
                if self.collect.contains_key(order) {
                    excluded.insert(*seq, *seq);
                }
            }
            let mut set = Ranges::new();
            for seq in a + 1..=k {
                if !excluded.contains(seq) {
                    set.insert(seq, seq);
                    links.insert(seq, *old_assigns.get(&seq).unwrap());
                }
            }
            lost = set.ranges();
        }
        let close = matches!(reset, Reset::Lost { .. } | Reset::Same) && old_stream.is_some();
        let notices = Notices { lost, close, links };
        let list = self.items(1, self.m);
        let recovery = ctx.trace.add_recovery(Recovery {
            ev: 0,
            entry,
            link: ctx.link,
            reset: Some(reset),
            old_stream,
            stream: new_stream,
            allowed: false,
            targets,
            waiting,
            start: 1,
            list,
            pre_queue,
            returned: returned_marks,
            notices: Some(notices.clone()),
            unsupported_expected: 0,
            unsupported_observed: 0,
        });
        self.lineage.push(recovery);
        for mark in deleted_copies {
            self.fate(mark, Fate::LostOnResetOnly(recovery));
        }
        if let Some(old_stream) = old_stream
            && (!notices.lost.is_empty() || notices.close)
        {
            self.pending = Some(Pending {
                recovery,
                notices,
                old_stream,
            });
        }
        self.send_open(new_stream, out);
    }

    // ----- Starting from records alone -----

    /// The stream after `SenderStream::recover`: the records left over, in
    /// their order, without a stream. Each is `(mark, length, retention
    /// start)`.
    pub fn recover(&mut self, ctx: &mut Ctx, records: &[(Mark, u64, Timestamp)]) {
        if let Some(pending) = self.pending.take() {
            ctx.trace.push(Ev::NoticesDropped {
                recovery: pending.recovery,
                entry_changed: false,
            });
        }
        self.queue.clear();
        self.queue_bytes = 0;
        self.ledger.clear();
        self.dropped.clear();
        self.announced = Ranges::new();
        self.assigns.clear();
        self.flow = None;
        self.k = 0;
        self.m = 0;
        self.s = 0;
        for (seq, &(mark, len, since)) in (1..).zip(records) {
            let order = self.next_order;
            self.next_order += 1;
            let template = ctx.templates.get(&mark).unwrap();
            let assign = ctx.trace.assign(mark, Uuid::nil(), seq);
            self.assigns.insert(seq, assign);
            self.queue.insert(
                seq,
                Queued {
                    mark,
                    kind: template.kind,
                    schema: template.schema,
                    order,
                    since,
                    len,
                    acked_at: None,
                },
            );
            self.queue_bytes += len;
            self.due(since, self.config.retention);
        }
        self.prune_entries();
    }

    // ----- What was sent -----

    /// Learns what the endpoint sent in one message: returns, for a
    /// `record_batch`, its records with their assignments; for a
    /// `dropped_range` or a `lost_on_reset`, the assignment of each
    /// sequence number; and what the model holds at each sequence number
    /// sent.
    pub fn observe(&mut self, message: &TelemetryMessage) -> Observed {
        let mut records = Vec::new();
        let mut assigns = Vec::new();
        let mut items = Vec::new();
        let mut last = None;
        match message {
            TelemetryMessage::RecordBatch(batch) => {
                for bytes in batch.records() {
                    let seq = Record::from_bytes(bytes).map_or(0, |r| r.header.seq);
                    records.push(SentRecord {
                        seq,
                        mark: mark_of(bytes),
                        bytes: bytes.clone(),
                        assign: self.assigns.get(&seq).copied(),
                    });
                    items.push(self.item_at(seq));
                    self.ledger.insert(seq, expected_hash(bytes));
                    last = Some(seq);
                }
            }
            TelemetryMessage::DroppedRange(range) => {
                for seq in range.from..=range.to {
                    if let Some(assign) = self.assigns.get(&seq) {
                        assigns.push((seq, *assign));
                    }
                    items.push(self.item_at(seq));
                }
                self.announced.insert(range.from, range.to);
                last = Some(range.to);
            }
            TelemetryMessage::LostOnReset(lost) => {
                if let Some(pending) = &self.pending {
                    for range in &lost.ranges {
                        for seq in range.from..=range.to {
                            if let Some(assign) = pending.notices.links.get(&seq) {
                                assigns.push((seq, *assign));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some(last) = last {
            self.s = self.s.max(last);
            if let Some(conn) = self.conn.as_mut() {
                conn.cap = Some(conn.cap.map_or(last, |cap| cap.max(last)));
            }
        }
        Observed {
            records,
            assigns,
            items,
        }
    }
}
