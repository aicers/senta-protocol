//! The sender's state, and the rules that change it.
//!
//! Nothing here writes to the store: the calls of
//! [`SenderStream`](super::SenderStream) run these rules, then write what
//! they changed as one commit, and undo it all if the commit fails.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use uuid::Uuid;

use super::store::{
    Collected, Dropped, Entry, EntryKinds, EntrySuccess, FlowId, Key, Meta, Notice, Queued,
    SenderStateChange, SenderStateEntry, SenderStateKey, Table,
};
use super::{SenderAction, SenderConfig};
use crate::connection::{AcceptedKind, TelemetryEntry};
use crate::telemetry::{
    CloseStream, DroppedRange, LostOnReset, MAX_BATCH_LEN, MAX_RECORD_LEN, OpenStream, Record,
    RecordBatch, ResumeInfo, SeqRange, TelemetryMessage, kind, record_hash,
};
use crate::telemetry_codes::{DropReason, TelemetryError};

/// The most sequence numbers past `K` that may have been sent: `S − K`
/// never exceeds it.
pub(super) const WINDOW: u64 = 10_000;

/// How long an acknowledged record is kept after its first
/// acknowledgement.
pub(super) const ACK_HOLD: SignedDuration = SignedDuration::from_hours(24);

/// How long the endpoint tries an entry without reaching it before it
/// moves to the next.
pub(super) const NODE_MOVE: Duration = Duration::from_secs(30 * 60);

/// The most ranges one `lost_on_reset` carries. A range is at most 27
/// bytes of CBOR (`{"from": u64, "to": u64}`), so 2,000 of them, with the
/// envelope and the stream id, stay well under the 64 KiB a server
/// receives in a frame.
pub(super) const LOST_RANGES_PER_MESSAGE: usize = 2_000;

/// Why the current stream is replaced by a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reset {
    /// There is no current stream: the first, or the sequence state was
    /// lost (step 1).
    Fresh,
    /// The entry identity changed (decision ③).
    EntryChanged,
    /// The entry acknowledged less than the endpoint did, `A < K` (step
    /// 2).
    Lost { a: u64 },
    /// Steps 3 to 5, or decision ②: same entry, nothing lost to report.
    Same,
    /// The entry answered the `open_stream` with `closed`.
    Closed,
}

/// What a received message is, judged before anything changes.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Not from the current connection: ignored, nothing at all happens.
    Ignore,
    /// Invalid on the current connection: disconnect, nothing else.
    Invalid,
    /// Valid, and does nothing itself; the deadlines are still handled.
    Noop,
    /// A valid `resume_info`.
    Resume(ResumeInfo),
    /// A valid `ack` raising `K` to the value.
    Ack(u64),
    /// A `closed` error for the stream awaiting its `resume_info`.
    Closed,
}

/// The connection the caller has open, if any. It is not persistent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Conn {
    pub(super) id: u64,
    /// The entry the connection was opened to: the target then.
    pub(super) entry: Uuid,
    /// Whether the entry's `hello_ack` arrived on it.
    pub(super) hello: bool,
    /// The stream of the `open_stream` awaiting its answer.
    pub(super) awaiting: Option<Uuid>,
    /// `C`, while the connection may acknowledge the current stream.
    pub(super) authority: Option<u64>,
    /// The next sequence number to send.
    pub(super) cursor: u64,
}

/// What a call puts back if its write fails, beside the tables' own logs.
pub(super) struct Snapshot {
    meta: Meta,
    conn: Option<Conn>,
    next_conn: u64,
    timer_start: Duration,
}

/// The persistent state, with indexes derived from it.
#[derive(Debug, Default)]
pub(super) struct State {
    pub(super) meta: Meta,
    pub(super) collect: Table<u64, Collected>,
    pub(super) queue: Table<u64, Queued>,
    pub(super) ledger: Table<u64, [u8; 16]>,
    pub(super) dropped: Table<u64, Dropped>,
    pub(super) announced: Table<u64, u64>,
    pub(super) acked: Table<u64, Timestamp>,
    pub(super) notices: Table<u64, Notice>,
    /// The collection buffer by retention start.
    collect_by_time: BTreeSet<(Timestamp, u64)>,
    /// The unacknowledged records of the queue by retention start.
    pending_by_time: BTreeSet<(Timestamp, u64)>,
    /// The acknowledgements of `acked` by when they came.
    acked_by_time: BTreeSet<(Timestamp, u64)>,
    /// The byte length of every record in the queue.
    pub(super) queue_bytes: u64,
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).expect("a length in memory fits in a u64 on every supported target")
}

/// Decodes a record the state holds.
fn decode(bytes: &[u8]) -> Record {
    Record::from_bytes(bytes).expect(
        "every record the state holds was encoded by Record::to_bytes, or checked to decode and \
         encode again when the state was loaded",
    )
}

/// Encodes a record decoded from the state, with its `endpoint_id`,
/// `stream` or `seq` changed.
fn encode(record: &Record) -> Vec<u8> {
    record.to_bytes().expect(
        "a record that encoded once encodes again with another endpoint_id, stream or seq, which \
         no encoding rule depends on",
    )
}

fn expired(since: Timestamp, wall: Timestamp, period: SignedDuration) -> bool {
    wall.duration_since(since) >= period
}

/// Returns the maximal ranges of `from..=to` outside every range of
/// `excluded`.
fn subtract(from: u64, to: u64, mut excluded: Vec<(u64, u64)>) -> Vec<SeqRange> {
    let mut ranges = Vec::new();
    if from > to {
        return ranges;
    }
    excluded.sort_unstable();
    let mut cursor = from;
    for (start, end) in excluded {
        if end < cursor {
            continue;
        }
        if start > to {
            break;
        }
        if start > cursor {
            ranges.push(SeqRange {
                from: cursor,
                to: start - 1,
            });
        }
        match end.checked_add(1) {
            Some(next) => cursor = cursor.max(next),
            None => return ranges,
        }
        if cursor > to {
            return ranges;
        }
    }
    ranges.push(SeqRange { from: cursor, to });
    ranges
}

impl State {
    /// Builds the state from the entries a store read back.
    pub(super) fn load(entries: Vec<(SenderStateKey, SenderStateEntry)>) -> Result<Self, String> {
        let mut meta = None;
        let mut collect = BTreeMap::new();
        let mut queue = BTreeMap::new();
        let mut ledger = BTreeMap::new();
        let mut dropped = BTreeMap::new();
        let mut announced = BTreeMap::new();
        let mut acked = BTreeMap::new();
        let mut notices = BTreeMap::new();
        let mut any = false;
        for (SenderStateKey(key), SenderStateEntry(entry)) in entries {
            any = true;
            match (key, entry) {
                (Key::Meta, Entry::Meta(value)) => meta = Some(value),
                (Key::Collected(order), Entry::Collected(value)) => {
                    collect.insert(order, value);
                }
                (Key::Queued(seq), Entry::Queued(value)) => {
                    queue.insert(seq, value);
                }
                (Key::Ledger(seq), Entry::Ledger(value)) => {
                    ledger.insert(seq, value);
                }
                (Key::Dropped(seq), Entry::Dropped(value)) => {
                    dropped.insert(seq, value);
                }
                (Key::Announced(seq), Entry::Announced(value)) => {
                    announced.insert(seq, value);
                }
                (Key::Acked(seq), Entry::Acked(value)) => {
                    acked.insert(seq, value);
                }
                (Key::Notice(index), Entry::Notice(value)) => {
                    notices.insert(index, value);
                }
                (key, _) => return Err(format!("the entry under {key:?} is of another kind")),
            }
        }
        let meta = match meta {
            Some(meta) => meta,
            None if !any => Meta::default(),
            None => return Err("entries are stored without the stream's scalar state".to_owned()),
        };
        for (order, collected) in &collect {
            Record::from_bytes(&collected.bytes)
                .map_err(|error| format!("collected record {order}: {error}"))?
                .to_bytes()
                .map_err(|error| format!("collected record {order}: {error}"))?;
        }
        for (seq, queued) in &queue {
            Record::from_bytes(&queued.bytes)
                .map_err(|error| format!("queued record {seq}: {error}"))?
                .to_bytes()
                .map_err(|error| format!("queued record {seq}: {error}"))?;
            if record_hash(&queued.bytes) != queued.hash {
                return Err(format!(
                    "queued record {seq}: the hash is not the bytes' hash"
                ));
            }
            if meta.flow.is_some() && queued.bytes.len() > MAX_RECORD_LEN {
                return Err(format!(
                    "queued record {seq} is longer than a record may be"
                ));
            }
        }
        let mut state = Self {
            meta,
            collect: Table::from_map(collect),
            queue: Table::from_map(queue),
            ledger: Table::from_map(ledger),
            dropped: Table::from_map(dropped),
            announced: Table::from_map(announced),
            acked: Table::from_map(acked),
            notices: Table::from_map(notices),
            ..Self::default()
        };
        state.rebuild();
        Ok(state)
    }

    /// Rebuilds the indexes from the tables.
    fn rebuild(&mut self) {
        self.collect_by_time = self
            .collect
            .map()
            .iter()
            .map(|(order, collected)| (collected.retained_since, *order))
            .collect();
        let k = self.meta.k;
        self.pending_by_time = self
            .queue
            .map()
            .iter()
            .filter(|(seq, _)| **seq > k)
            .map(|(seq, queued)| (queued.retained_since, *seq))
            .collect();
        self.acked_by_time = self
            .acked
            .map()
            .iter()
            .map(|(upto, at)| (*at, *upto))
            .collect();
        self.queue_bytes = self
            .queue
            .map()
            .values()
            .map(|queued| len_u64(queued.bytes.len()))
            .sum();
    }

    /// Returns what changed since the last commit, `old` being the scalar
    /// state then.
    pub(super) fn change(&self, old: &Meta) -> SenderStateChange {
        let mut change = SenderStateChange::default();
        if self.meta != *old {
            change.puts.push((
                SenderStateKey(Key::Meta),
                SenderStateEntry(Entry::Meta(self.meta.clone())),
            ));
        }
        self.collect
            .write_change(&mut change, Key::Collected, Entry::Collected);
        self.queue
            .write_change(&mut change, Key::Queued, Entry::Queued);
        self.ledger
            .write_change(&mut change, Key::Ledger, Entry::Ledger);
        self.dropped
            .write_change(&mut change, Key::Dropped, Entry::Dropped);
        self.announced
            .write_change(&mut change, Key::Announced, Entry::Announced);
        self.acked
            .write_change(&mut change, Key::Acked, Entry::Acked);
        self.notices
            .write_change(&mut change, Key::Notice, Entry::Notice);
        change
    }

    /// Forgets the logs once the change is written.
    pub(super) fn settle(&mut self) {
        self.collect.settle();
        self.queue.settle();
        self.ledger.settle();
        self.dropped.settle();
        self.announced.settle();
        self.acked.settle();
        self.notices.settle();
    }

    /// Puts everything back as it was at the last commit.
    fn rollback(&mut self, meta: Meta) {
        self.meta = meta;
        self.collect.rollback();
        self.queue.rollback();
        self.ledger.rollback();
        self.dropped.rollback();
        self.announced.rollback();
        self.acked.rollback();
        self.notices.rollback();
        self.rebuild();
    }

    fn collect_insert(&mut self, order: u64, collected: Collected) {
        self.collect_by_time
            .insert((collected.retained_since, order));
        self.collect.insert(order, collected);
    }

    fn collect_remove(&mut self, order: u64) {
        if let Some(collected) = self.collect.get(&order) {
            self.collect_by_time
                .remove(&(collected.retained_since, order));
            self.collect.remove(&order);
        }
    }

    fn queue_insert(&mut self, seq: u64, queued: Queued) {
        self.queue_remove(seq);
        if seq > self.meta.k {
            self.pending_by_time.insert((queued.retained_since, seq));
        }
        self.queue_bytes += len_u64(queued.bytes.len());
        self.queue.insert(seq, queued);
    }

    fn queue_remove(&mut self, seq: u64) {
        if let Some(queued) = self.queue.get(&seq) {
            self.pending_by_time.remove(&(queued.retained_since, seq));
            self.queue_bytes -= len_u64(queued.bytes.len());
            self.queue.remove(&seq);
        }
    }

    fn acked_insert(&mut self, upto: u64, at: Timestamp) {
        self.acked_remove(upto);
        self.acked_by_time.insert((at, upto));
        self.acked.insert(upto, at);
    }

    fn acked_remove(&mut self, upto: u64) {
        if let Some(&at) = self.acked.get(&upto) {
            self.acked_by_time.remove(&(at, upto));
            self.acked.remove(&upto);
        }
    }

    /// Records `from..=to` as dropped for `reason`, merging it with a
    /// neighbouring range of the same reason. A range that merges with
    /// none is a new one, and is counted when `count` says so.
    fn add_dropped(&mut self, from: u64, to: u64, reason: DropReason, count: bool) {
        let mut start = from;
        let mut end = to;
        let mut merged = false;
        if let Some((&left, range)) = self.dropped.map().range(..from).next_back()
            && range.to.checked_add(1) == Some(from)
            && range.reason == reason
        {
            start = left;
            merged = true;
        }
        if let Some(right) = to.checked_add(1)
            && let Some(range) = self.dropped.get(&right)
            && range.reason == reason
        {
            end = range.to;
            self.dropped.remove(&right);
            merged = true;
        }
        self.dropped.insert(start, Dropped { to: end, reason });
        if count && !merged {
            self.meta.dropped_ranges += 1;
        }
    }

    /// Returns the dropped range holding `seq`, if any.
    pub(super) fn dropped_at(&self, seq: u64) -> Option<(u64, &Dropped)> {
        self.dropped
            .map()
            .range(..=seq)
            .next_back()
            .filter(|(_, range)| range.to >= seq)
            .map(|(from, range)| (*from, range))
    }

    /// Returns whether every sequence number of `from..=to` is dropped.
    fn all_dropped(&self, from: u64, to: u64) -> bool {
        let mut seq = from;
        while seq <= to {
            let Some((_, range)) = self.dropped_at(seq) else {
                return false;
            };
            match range.to.checked_add(1) {
                Some(next) => seq = next,
                None => return true,
            }
        }
        true
    }

    /// Adds `from..=to` to the history of announced losses.
    fn announce(&mut self, from: u64, to: u64) {
        let mut start = from;
        let mut end = to;
        if let Some((&left, &left_to)) = self.announced.map().range(..=from).next_back() {
            if left_to >= to {
                return;
            }
            if left_to.saturating_add(1) >= from {
                start = left;
                end = end.max(left_to);
            }
        }
        let overlapping: Vec<(u64, u64)> = self
            .announced
            .map()
            .range(start..=end.saturating_add(1))
            .map(|(from, to)| (*from, *to))
            .collect();
        for (from, to) in overlapping {
            self.announced.remove(&from);
            end = end.max(to);
        }
        self.announced.insert(start, end);
    }

    /// Removes everything that belongs to the current stream.
    fn clear_flow(&mut self) {
        self.queue.clear();
        self.ledger.clear();
        self.dropped.clear();
        self.announced.clear();
        self.acked.clear();
        self.notices.clear();
        self.pending_by_time.clear();
        self.acked_by_time.clear();
        self.queue_bytes = 0;
    }

    fn accepted(&self, entry: Uuid) -> Option<&[AcceptedKind]> {
        self.meta
            .accepted
            .iter()
            .find(|kinds| kinds.entry == entry)
            .map(|kinds| kinds.kinds.as_slice())
    }

    /// Drops the per-entry state of entries no longer listed, except the
    /// current stream's entry.
    fn prune_entries(&mut self) {
        let Meta {
            entries,
            accepted,
            last_success,
            flow,
            ..
        } = &mut self.meta;
        let flow_entry = flow.map(|flow| flow.entry);
        accepted.retain(|kinds| entries.contains(&kinds.entry) || Some(kinds.entry) == flow_entry);
        last_success.retain(|success| entries.contains(&success.entry));
    }
}

/// Everything a [`SenderStream`](super::SenderStream) holds but its store.
#[derive(Debug)]
pub(super) struct Core {
    pub(super) config: SenderConfig,
    pub(super) state: State,
    pub(super) conn: Option<Conn>,
    next_conn: u64,
    /// When the 30 minutes before a node move started: the latest of when
    /// the target was chosen, when a connection that had the target's
    /// `hello_ack` ended, and when the stream was started.
    timer_start: Duration,
}

impl Core {
    pub(super) fn new(config: SenderConfig, state: State, now: Duration) -> Self {
        Self {
            config,
            state,
            conn: None,
            next_conn: 0,
            timer_start: now,
        }
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot {
            meta: self.state.meta.clone(),
            conn: self.conn.clone(),
            next_conn: self.next_conn,
            timer_start: self.timer_start,
        }
    }

    pub(super) fn snapshot_meta(snapshot: &Snapshot) -> &Meta {
        &snapshot.meta
    }

    pub(super) fn restore(&mut self, snapshot: Snapshot) {
        self.state.rollback(snapshot.meta);
        self.conn = snapshot.conn;
        self.next_conn = snapshot.next_conn;
        self.timer_start = snapshot.timer_start;
    }

    // ----- Judging inputs -----

    fn current(&self, id: u64) -> Option<&Conn> {
        self.conn.as_ref().filter(|conn| conn.id == id)
    }

    /// Judges a `hello_ack` on connection `id`: `Noop` stands for valid.
    pub(super) fn judge_hello(&self, id: u64, entry: &TelemetryEntry) -> Verdict {
        match self.current(id) {
            None => Verdict::Ignore,
            Some(conn) if conn.hello || conn.entry != entry.entry_id => Verdict::Invalid,
            Some(_) => Verdict::Noop,
        }
    }

    /// Judges a message received on connection `id`.
    pub(super) fn judge(&self, id: u64, message: &TelemetryMessage) -> Verdict {
        let Some(conn) = self.current(id) else {
            return Verdict::Ignore;
        };
        let meta = &self.state.meta;
        match message {
            TelemetryMessage::ResumeInfo(info) => {
                let answers = conn.hello && conn.awaiting == Some(info.stream);
                let ordered = info.last_stored.is_none_or(|last| last.seq <= info.a);
                if answers && ordered {
                    Verdict::Resume(*info)
                } else {
                    Verdict::Invalid
                }
            }
            TelemetryMessage::Ack(ack) => {
                let Some(flow) = meta.flow else {
                    return Verdict::Noop;
                };
                if ack.stream != flow.stream || ack.a <= meta.k {
                    Verdict::Noop
                } else if conn.authority.is_some_and(|cap| ack.a <= cap) {
                    Verdict::Ack(ack.a)
                } else {
                    Verdict::Invalid
                }
            }
            TelemetryMessage::ErrorMessage(error) => {
                if error.error == TelemetryError::Closed
                    && error.stream.is_some()
                    && error.stream == conn.awaiting
                {
                    Verdict::Closed
                } else {
                    Verdict::Invalid
                }
            }
            TelemetryMessage::OpenStream(_)
            | TelemetryMessage::RecordBatch(_)
            | TelemetryMessage::DroppedRange(_)
            | TelemetryMessage::LostOnReset(_)
            | TelemetryMessage::CloseStream(_) => Verdict::Invalid,
        }
    }

    // ----- Connections and targets -----

    /// Opens a connection to the target, ending the one open before.
    pub(super) fn open_connection(&mut self, now: Duration) -> Option<(u64, Uuid)> {
        self.end_connection(now);
        let entry = self.state.meta.target?;
        let id = self.next_conn;
        self.next_conn += 1;
        self.conn = Some(Conn {
            id,
            entry,
            hello: false,
            awaiting: None,
            authority: None,
            cursor: 0,
        });
        Some((id, entry))
    }

    /// Ends the current connection, if any.
    pub(super) fn end_connection(&mut self, now: Duration) {
        if let Some(conn) = self.conn.take()
            && conn.hello
        {
            self.timer_start = self.timer_start.max(now);
        }
    }

    pub(super) fn mark_hello(&mut self) {
        if let Some(conn) = self.conn.as_mut() {
            conn.hello = true;
        }
    }

    fn set_target(&mut self, target: Option<Uuid>, now: Duration, out: &mut Vec<SenderAction>) {
        self.state.meta.target = target;
        self.timer_start = self.timer_start.max(now);
        if self.conn.take().is_some() {
            out.push(SenderAction::Disconnect);
        }
        if let Some(entry_id) = target {
            out.push(SenderAction::Connect { entry_id });
        }
    }

    /// Takes a new list of entries.
    pub(super) fn set_entries(
        &mut self,
        entries: Vec<Uuid>,
        now: Duration,
        out: &mut Vec<SenderAction>,
    ) {
        let first = entries.first().copied();
        let keep = self
            .state
            .meta
            .target
            .is_some_and(|target| entries.contains(&target));
        self.state.meta.entries = entries;
        self.state.prune_entries();
        if !keep {
            self.set_target(first, now, out);
        }
        self.fill();
    }

    // ----- Deadlines -----

    pub(super) fn deadlines(
        &mut self,
        wall: Timestamp,
        now: Duration,
        out: &mut Vec<SenderAction>,
    ) {
        self.expire_collected(wall);
        self.expire_pending(wall);
        self.expire_copies(wall);
        self.move_node(now, out);
    }

    fn expire_collected(&mut self, wall: Timestamp) {
        let retention = self.config.retention;
        while let Some(&(since, order)) = self.state.collect_by_time.first() {
            if !expired(since, wall, retention) {
                break;
            }
            self.state.collect_remove(order);
            self.state.meta.unsupported += 1;
        }
    }

    fn expire_pending(&mut self, wall: Timestamp) {
        let retention = self.config.retention;
        while let Some(&(since, seq)) = self.state.pending_by_time.first() {
            if !expired(since, wall, retention) {
                break;
            }
            self.drop_queued(seq, DropReason::RetentionExpired);
        }
    }

    /// Deletes the acknowledged copies whose first acknowledgement is 24
    /// hours old. Each acknowledgement covers the copies past the one
    /// before it; those of an earlier acknowledgement that expired first
    /// are already gone, so the range reaching back past it removes
    /// nothing more.
    fn expire_copies(&mut self, wall: Timestamp) {
        while let Some(&(at, upto)) = self.state.acked_by_time.first() {
            if !expired(at, wall, ACK_HOLD) {
                break;
            }
            let after = self
                .state
                .acked
                .map()
                .range(..upto)
                .next_back()
                .map_or(0, |(seq, _)| *seq);
            let seqs: Vec<u64> = self
                .state
                .queue
                .map()
                .range(after.saturating_add(1)..=upto)
                .map(|(seq, _)| *seq)
                .collect();
            for seq in seqs {
                self.state.queue_remove(seq);
            }
            self.state.acked_remove(upto);
        }
    }

    fn move_node(&mut self, now: Duration, out: &mut Vec<SenderAction>) {
        let Some(target) = self.state.meta.target else {
            return;
        };
        if self.conn.as_ref().is_some_and(|conn| conn.hello)
            || now.saturating_sub(self.timer_start) < NODE_MOVE
        {
            return;
        }
        let entries = &self.state.meta.entries;
        let next = entries
            .iter()
            .position(|entry| *entry == target)
            .and_then(|index| entries.get(index + 1))
            .or_else(|| entries.first())
            .copied();
        self.set_target(next, now, out);
        self.fill();
    }

    // ----- Collecting and moving -----

    /// Returns the endpoint id, stream and accepted kinds records are
    /// moved with, when they may be.
    fn mover(&self) -> Option<(Uuid, Uuid, &[AcceptedKind])> {
        let meta = &self.state.meta;
        let endpoint_id = meta.endpoint_id?;
        let flow = meta.flow?;
        if meta.target != Some(flow.entry) {
            return None;
        }
        Some((endpoint_id, flow.stream, self.state.accepted(flow.entry)?))
    }

    /// Moves every record of the collection buffer that may be moved, in
    /// collection order.
    pub(super) fn fill(&mut self) {
        let Some((endpoint_id, stream, kinds)) = self.mover() else {
            return;
        };
        let orders: Vec<u64> = self
            .state
            .collect
            .map()
            .iter()
            .filter(|(_, collected)| kind::accepts(kinds, collected.kind, collected.schema))
            .map(|(order, _)| *order)
            .collect();
        for order in orders {
            self.move_one(order, endpoint_id, stream);
        }
    }

    /// Adds a record to the collection buffer, and moves it if it may be.
    pub(super) fn collect(&mut self, collected: Collected) {
        let order = self.state.meta.next_order;
        self.state.meta.next_order += 1;
        let movable = self.mover().and_then(|(endpoint_id, stream, kinds)| {
            kind::accepts(kinds, collected.kind, collected.schema).then_some((endpoint_id, stream))
        });
        self.state.collect_insert(order, collected);
        if let Some((endpoint_id, stream)) = movable {
            self.move_one(order, endpoint_id, stream);
        }
        self.enforce_collect_limit(&BTreeMap::new());
    }

    /// Sets the endpoint id, and moves what may now be moved.
    pub(super) fn register(&mut self, endpoint_id: Uuid) {
        self.state.meta.endpoint_id = Some(endpoint_id);
        self.fill();
    }

    fn move_one(&mut self, order: u64, endpoint_id: Uuid, stream: Uuid) {
        let Some(collected) = self.state.collect.get(&order) else {
            return;
        };
        let seq = self.state.meta.m + 1;
        let mut record = decode(&collected.bytes);
        record.header.endpoint_id = endpoint_id;
        record.header.stream = stream;
        record.header.seq = seq;
        let bytes = encode(&record);
        let (kind, schema, retained_since) =
            (collected.kind, collected.schema, collected.retained_since);
        self.state.collect_remove(order);
        self.state.meta.m = seq;
        self.place(seq, bytes, kind, schema, order, retained_since);
    }

    /// Puts a record with its bytes fixed under `seq`: in the queue, or as
    /// a dropped sequence number when it is too long.
    fn place(
        &mut self,
        seq: u64,
        bytes: Vec<u8>,
        kind: u16,
        schema: u16,
        order: u64,
        retained_since: Timestamp,
    ) {
        if bytes.len() > MAX_RECORD_LEN {
            self.state.add_dropped(seq, seq, DropReason::TooLarge, true);
            return;
        }
        let hash = record_hash(&bytes);
        self.state.queue_insert(
            seq,
            Queued {
                bytes,
                hash,
                kind,
                schema,
                order,
                retained_since,
            },
        );
        self.enforce_queue_limit();
    }

    /// Deletes records while the queue is past its limit: acknowledged
    /// copies first, then unacknowledged records, lowest first.
    fn enforce_queue_limit(&mut self) {
        while self.state.queue_bytes > self.config.queue_limit {
            let Some((&seq, _)) = self.state.queue.map().first_key_value() else {
                return;
            };
            if seq <= self.state.meta.k {
                self.state.queue_remove(seq);
            } else {
                self.drop_queued(seq, DropReason::BufferOverflow);
            }
        }
    }

    /// Deletes the oldest records while the collection buffer is past its
    /// limit. Those in `copies` are not counted as unsupported.
    fn enforce_collect_limit(&mut self, copies: &BTreeMap<u64, u64>) {
        while self.state.collect.len() > self.config.collect_limit {
            let Some((&order, _)) = self.state.collect.map().first_key_value() else {
                return;
            };
            self.state.collect_remove(order);
            if !copies.contains_key(&order) {
                self.state.meta.unsupported += 1;
            }
        }
    }

    /// Deletes an unacknowledged record's body, its sequence number
    /// becoming dropped.
    fn drop_queued(&mut self, seq: u64, reason: DropReason) {
        self.state.queue_remove(seq);
        if seq > self.state.meta.s {
            self.state.ledger.remove(&seq);
        }
        self.state.add_dropped(seq, seq, reason, true);
    }

    // ----- Sending -----

    /// Sends what the current connection may send.
    pub(super) fn pump(&mut self, out: &mut Vec<SenderAction>) {
        let Some(flow) = self.state.meta.flow else {
            return;
        };
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let Some(mut cap) = conn.authority else {
            return;
        };
        let state = &mut self.state;
        let mut cursor = conn.cursor;
        loop {
            let (m, limit) = (state.meta.m, state.meta.k.saturating_add(WINDOW));
            if cursor > m || cursor > limit {
                break;
            }
            let last = if let Some((_, range)) = state.dropped_at(cursor) {
                let to = range.to.min(limit);
                out.push(SenderAction::Send(TelemetryMessage::DroppedRange(
                    DroppedRange {
                        stream: flow.stream,
                        from: cursor,
                        to,
                        reason: range.reason.clone(),
                    },
                )));
                state.announce(cursor, to);
                to
            } else {
                let mut records = Vec::new();
                let mut total = 0;
                let mut seq = cursor;
                while seq <= m && seq <= limit {
                    let Some(queued) = state.queue.get(&seq) else {
                        break;
                    };
                    if total + queued.bytes.len() > MAX_BATCH_LEN {
                        break;
                    }
                    total += queued.bytes.len();
                    records.push(queued.bytes.clone());
                    if state.ledger.get(&seq) != Some(&queued.hash) {
                        state.ledger.insert(seq, queued.hash);
                    }
                    seq += 1;
                }
                if records.is_empty() {
                    break;
                }
                let batch = RecordBatch::new(flow.stream, records).expect(
                    "no queued record is longer than MAX_RECORD_LEN, and the batch was cut at \
                     MAX_BATCH_LEN",
                );
                out.push(SenderAction::Send(TelemetryMessage::RecordBatch(batch)));
                seq - 1
            };
            state.meta.s = state.meta.s.max(last);
            cap = cap.max(last);
            let Some(next) = last.checked_add(1) else {
                cursor = last;
                break;
            };
            cursor = next;
        }
        conn.cursor = cursor;
        conn.authority = Some(cap);
    }

    /// Sends the notices, then the `open_stream` of `stream`, and awaits
    /// its answer.
    fn send_open(&mut self, stream: Uuid, out: &mut Vec<SenderAction>) {
        for notice in self.state.notices.map().values() {
            out.push(SenderAction::Send(match notice {
                Notice::Lost(lost) => TelemetryMessage::LostOnReset(lost.clone()),
                Notice::Close(close) => TelemetryMessage::CloseStream(*close),
            }));
        }
        out.push(SenderAction::Send(TelemetryMessage::OpenStream(
            OpenStream { stream },
        )));
        if let Some(conn) = self.conn.as_mut() {
            conn.awaiting = Some(stream);
            conn.authority = None;
        }
    }

    // ----- Received messages -----

    /// Handles a valid `hello_ack`.
    pub(super) fn hello_ack(
        &mut self,
        entry: &TelemetryEntry,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<SenderAction>,
    ) {
        let id = entry.entry_id;
        let kinds = entry.accepted_kinds.clone();
        match self
            .state
            .meta
            .accepted
            .iter_mut()
            .find(|kinds| kinds.entry == id)
        {
            Some(known) => {
                if known.kinds != kinds {
                    known.kinds = kinds;
                }
            }
            None => self
                .state
                .meta
                .accepted
                .push(EntryKinds { entry: id, kinds }),
        }
        match self.state.meta.flow {
            None => self.transition(Reset::Fresh, id, new_stream, wall, out),
            Some(flow) if flow.entry != id => {
                self.transition(Reset::EntryChanged, id, new_stream, wall, out);
            }
            Some(flow) => {
                self.fill();
                self.send_open(flow.stream, out);
            }
        }
        self.state.prune_entries();
    }

    /// Handles a valid `resume_info`: the reconnection judgment, then the
    /// stream decision.
    pub(super) fn resume(
        &mut self,
        info: &ResumeInfo,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<SenderAction>,
    ) {
        if let Some(conn) = self.conn.as_mut() {
            conn.awaiting = None;
        }
        // The notices went out on this connection before the open_stream
        // this answers, and the entry stores them in order before it
        // answers.
        self.state.notices.clear();
        let Some(flow) = self.state.meta.flow else {
            return;
        };
        let (k, m, a) = (self.state.meta.k, self.state.meta.m, info.a);
        let entry = flow.entry;
        if a < k {
            return self.transition(Reset::Lost { a }, entry, new_stream, wall, out);
        }
        if m < a {
            return self.transition(Reset::Same, entry, new_stream, wall, out);
        }
        let low = match info.last_stored {
            Some(last) => {
                if last.seq > k && self.state.ledger.get(&last.seq) != Some(&last.hash) {
                    return self.transition(Reset::Same, entry, new_stream, wall, out);
                }
                last.seq.max(k)
            }
            None => k,
        };
        if !self.state.all_dropped(low.saturating_add(1), a) {
            return self.transition(Reset::Same, entry, new_stream, wall, out);
        }
        self.confirm(a, wall);
        self.state.meta.s = self.state.meta.s.max(a);
        let kinds = self.state.accepted(entry).unwrap_or_default();
        let narrowed = self
            .state
            .queue
            .map()
            .range(a.saturating_add(1)..)
            .any(|(_, queued)| !kind::accepts(kinds, queued.kind, queued.schema));
        if narrowed {
            return self.transition(Reset::Same, entry, new_stream, wall, out);
        }
        if let Some(conn) = self.conn.as_mut() {
            conn.authority = Some(a);
            conn.cursor = a.saturating_add(1);
        }
    }

    /// Handles a valid `ack`.
    pub(super) fn ack(&mut self, a: u64, wall: Timestamp) {
        let Some(flow) = self.state.meta.flow else {
            return;
        };
        self.confirm(a, wall);
        let last_success = &mut self.state.meta.last_success;
        match last_success
            .iter_mut()
            .find(|success| success.entry == flow.entry)
        {
            Some(success) => success.at = wall,
            None => last_success.push(EntrySuccess {
                entry: flow.entry,
                at: wall,
            }),
        }
    }

    /// Handles a `closed` answering the awaited `open_stream`.
    pub(super) fn closed(
        &mut self,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<SenderAction>,
    ) {
        if let Some(conn) = self.conn.as_mut() {
            conn.awaiting = None;
        }
        self.state.notices.clear();
        if let Some(flow) = self.state.meta.flow {
            self.transition(Reset::Closed, flow.entry, new_stream, wall, out);
        }
    }

    /// Acknowledges everything up to `a`.
    fn confirm(&mut self, a: u64, wall: Timestamp) {
        let k = self.state.meta.k;
        if a <= k {
            return;
        }
        let state = &mut self.state;
        let pending: Vec<(Timestamp, u64)> = state
            .queue
            .map()
            .range(k + 1..=a)
            .map(|(seq, queued)| (queued.retained_since, *seq))
            .collect();
        for key in &pending {
            state.pending_by_time.remove(key);
        }
        let hashes: Vec<u64> = state
            .ledger
            .map()
            .range(..=a)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in &hashes {
            state.ledger.remove(seq);
        }
        let ranges: Vec<(u64, Dropped)> = state
            .dropped
            .map()
            .range(..=a)
            .map(|(from, range)| (*from, range.clone()))
            .collect();
        for (from, range) in ranges {
            state.dropped.remove(&from);
            if range.to > a {
                state.dropped.insert(a + 1, range);
            }
        }
        if let Some((&last, &at)) = state.acked.map().last_key_value()
            && at == wall
        {
            state.acked_remove(last);
        }
        state.acked_insert(a, wall);
        state.meta.k = a;
    }

    // ----- Opening a new stream -----

    /// Replaces the current stream by `new_stream` at `entry`.
    #[allow(clippy::too_many_lines)] // The steps of one transition, in their order.
    fn transition(
        &mut self,
        reset: Reset,
        entry: Uuid,
        new_stream: Uuid,
        wall: Timestamp,
        out: &mut Vec<SenderAction>,
    ) {
        let state = &mut self.state;
        let old_stream = state.meta.flow.map(|flow| flow.stream);
        let k = state.meta.k;
        let kinds = state.accepted(entry).map(<[_]>::to_vec).unwrap_or_default();
        let low = match reset {
            Reset::Lost { a } => a,
            _ => k,
        };

        // 1. Renumber, in the old order: records to resend, and the dropped
        // sequence numbers carried over when the entry is the same.
        let carried: Vec<(u64, u64, DropReason)> = if reset == Reset::EntryChanged {
            Vec::new()
        } else {
            state
                .dropped
                .map()
                .range(low.saturating_add(1)..)
                .map(|(from, range)| (*from, range.to, range.reason.clone()))
                .collect()
        };
        let mut carried = carried.into_iter().peekable();
        let mut next: u64 = 0;
        let mut new_dropped = Vec::new();
        let mut new_records = Vec::new();
        let mut returned = Vec::new();
        let mut returned_copies = BTreeMap::new();
        let mut renumbered = Vec::new();
        for (&old, queued) in state.queue.map().range(low.saturating_add(1)..) {
            while let Some((from, to, reason)) = carried.next_if(|(from, _, _)| *from < old) {
                carry(&mut new_dropped, &mut next, from, to, reason);
            }
            let copy = old <= k;
            let retained_since = if copy { wall } else { queued.retained_since };
            if kind::accepts(&kinds, queued.kind, queued.schema) {
                next += 1;
                let mut record = decode(&queued.bytes);
                record.header.stream = new_stream;
                record.header.seq = next;
                new_records.push((
                    next,
                    encode(&record),
                    queued.kind,
                    queued.schema,
                    queued.order,
                    retained_since,
                ));
                renumbered.push((old, old));
            } else {
                returned.push((
                    queued.order,
                    Collected {
                        bytes: queued.bytes.clone(),
                        kind: queued.kind,
                        schema: queued.schema,
                        retained_since,
                    },
                ));
                if copy {
                    returned_copies.insert(queued.order, old);
                }
            }
        }
        for (from, to, reason) in carried {
            carry(&mut new_dropped, &mut next, from, to, reason);
        }
        let announced: Vec<(u64, u64)> = state
            .announced
            .map()
            .iter()
            .map(|(from, to)| (*from, *to))
            .collect();

        // The old stream's state goes; the new one starts.
        state.clear_flow();
        state.meta.flow = Some(FlowId {
            stream: new_stream,
            entry,
        });
        state.meta.k = 0;
        state.meta.s = 0;
        state.meta.m = next;
        for (from, to, reason) in new_dropped {
            state.add_dropped(from, to, reason, false);
        }
        for (order, collected) in returned {
            state.collect_insert(order, collected);
        }
        for (seq, bytes, kind, schema, order, retained_since) in new_records {
            self.place(seq, bytes, kind, schema, order, retained_since);
        }

        // 2. Move the collection buffer.
        self.fill();
        // 3. Apply the collection buffer's limit.
        self.enforce_collect_limit(&returned_copies);

        // 4. The notices.
        let mut notices = Vec::new();
        if let (Reset::Lost { a }, Some(old_stream)) = (reset, old_stream) {
            let mut excluded = renumbered;
            excluded.extend(
                returned_copies
                    .iter()
                    .filter(|(order, _)| self.state.collect.get(order).is_some())
                    .map(|(_, seq)| (*seq, *seq)),
            );
            excluded.extend(announced);
            let ranges = subtract(a.saturating_add(1), k, excluded);
            for chunk in ranges.chunks(LOST_RANGES_PER_MESSAGE) {
                notices.push(Notice::Lost(LostOnReset {
                    old_stream,
                    ranges: chunk.to_vec(),
                }));
            }
        }
        if matches!(reset, Reset::Lost { .. } | Reset::Same)
            && let Some(stream) = old_stream
        {
            notices.push(Notice::Close(CloseStream { stream }));
        }
        for (index, notice) in (0..).zip(notices) {
            self.state.notices.insert(index, notice);
        }
        self.send_open(new_stream, out);
    }

    // ----- Starting from records alone -----

    /// Replaces the sequence state by `records`, unacknowledged and in
    /// their original order, to be renumbered by the next stream.
    pub(super) fn install_orphans(&mut self, records: Vec<(Vec<u8>, Record, Timestamp)>) {
        let state = &mut self.state;
        state.clear_flow();
        state.meta.flow = None;
        state.meta.k = 0;
        state.meta.m = 0;
        state.meta.s = 0;
        for (seq, (bytes, record, retained_since)) in (1..).zip(records) {
            let order = state.meta.next_order;
            state.meta.next_order += 1;
            let hash = record_hash(&bytes);
            state.queue_insert(
                seq,
                Queued {
                    bytes,
                    hash,
                    kind: record.kind,
                    schema: record.schema,
                    order,
                    retained_since,
                },
            );
        }
        state.prune_entries();
    }
}

/// Gives a carried dropped range `from..=to` its new place after `next`.
fn carry(
    new_dropped: &mut Vec<(u64, u64, DropReason)>,
    next: &mut u64,
    from: u64,
    to: u64,
    reason: DropReason,
) {
    let len = to - from + 1;
    new_dropped.push((*next + 1, *next + len, reason));
    *next += len;
}
