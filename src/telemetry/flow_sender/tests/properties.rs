//! Random runs of the sender alone, the entry's answers imitated by rule:
//! collection, registration, acknowledgements, disconnections,
//! reconnections, restarts and stale snapshots, checking after every call
//! that the queue has no gap, every batch names its stream, `S − K` stays
//! within the window, and the ledger within 10,000 entries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::*;

/// A xorshift64 generator with a fixed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// What an entry remembers of one stream.
#[derive(Default, Clone, Copy)]
struct Stored {
    a: u64,
    last: Option<(u64, [u8; 16])>,
}

/// The entries, as rules: they store records in order, answer an
/// `open_stream` with where the stream stands, and acknowledge.
#[derive(Default)]
struct Entries {
    streams: BTreeMap<Uuid, Stored>,
    closed: BTreeSet<Uuid>,
}

struct Run {
    rng: Rng,
    h: H,
    entries: Entries,
    /// Messages sent on the current connection, not yet handled by the
    /// entry.
    outbox: VecDeque<TelemetryMessage>,
    snapshots: Vec<MemorySenderStore>,
}

impl Run {
    fn take(&mut self, actions: &[SenderAction]) {
        let flow = self.h.stream.position().map(|position| position.stream);
        for action in actions {
            match action {
                SenderAction::Send(message) => {
                    if let TelemetryMessage::RecordBatch(batch) = message {
                        assert_eq!(Some(batch.stream()), flow, "a batch of the current stream");
                    }
                    self.outbox.push_back(message.clone());
                }
                SenderAction::Disconnect => {
                    self.outbox.clear();
                    self.h.conn = None;
                }
                SenderAction::Connect { .. } => {}
            }
        }
        // Checks every batch's records against its stream.
        sent(actions);
        self.h.check_invariants();
    }

    fn connected(&self) -> bool {
        self.h.conn.is_some() && self.h.stream.connection() == self.h.conn
    }

    /// The entry handles the next message, and may answer.
    fn deliver(&mut self) {
        if !self.connected() {
            return;
        }
        let Some(message) = self.outbox.pop_front() else {
            return;
        };
        let answer = match message {
            TelemetryMessage::OpenStream(open) => {
                if self.entries.closed.contains(&open.stream) {
                    Some(TelemetryMessage::ErrorMessage(ErrorMessage {
                        stream: Some(open.stream),
                        error: TelemetryError::Closed,
                    }))
                } else {
                    let stored = self
                        .entries
                        .streams
                        .get(&open.stream)
                        .copied()
                        .unwrap_or_default();
                    Some(resume_info(open.stream, stored.a, stored.last))
                }
            }
            TelemetryMessage::CloseStream(close) => {
                self.entries.closed.insert(close.stream);
                None
            }
            TelemetryMessage::RecordBatch(batch) => {
                let stream = batch.stream();
                let stored = self.entries.streams.entry(stream).or_default();
                for bytes in batch.records() {
                    let record = Record::from_bytes(bytes).unwrap();
                    if record.header.seq == stored.a + 1 {
                        stored.a = record.header.seq;
                        stored.last = Some((stored.a, record_hash(bytes)));
                    }
                }
                let a = stored.a;
                self.rng
                    .chance(60)
                    .then_some(TelemetryMessage::Ack(Ack { stream, a }))
            }
            TelemetryMessage::DroppedRange(range) => {
                let stored = self.entries.streams.entry(range.stream).or_default();
                if range.from <= stored.a + 1 && range.to > stored.a {
                    stored.a = range.to;
                }
                let a = stored.a;
                self.rng.chance(60).then_some(TelemetryMessage::Ack(Ack {
                    stream: range.stream,
                    a,
                }))
            }
            _ => None,
        };
        if let Some(answer) = answer {
            let actions = self.h.recv(answer);
            self.take(&actions);
        }
    }

    fn step(&mut self) {
        match self.rng.below(100) {
            0..=29 => {
                let kind = if self.rng.chance(80) { 1 } else { 2 };
                let n = self.rng.next() % 1_000;
                let actions = self.h.collect(record(kind, n));
                self.take(&actions);
            }
            30..=59 => {
                for _ in 0..self.rng.below(8) {
                    self.deliver();
                }
            }
            60..=64 => {
                // A snapshot from before registration forgets it.
                if self.h.stream.endpoint_id().is_none() {
                    let actions = self.h.stream.register(EP).unwrap();
                    self.take(&actions);
                }
            }
            65..=72 => {
                if self.connected() {
                    let actions = self.h.close();
                    self.take(&actions);
                    self.h.conn = None;
                    self.outbox.clear();
                }
                let actions = self.h.connect();
                self.outbox.clear();
                self.take(&actions);
                if let Some(conn) = self.h.conn {
                    let list = if self.rng.chance(70) { K12 } else { K1 };
                    let actions = self.h.hello(conn.entry_id(), list);
                    self.take(&actions);
                }
            }
            73..=78 => {
                if self.connected() {
                    let actions = self.h.close();
                    self.take(&actions);
                }
                self.h.conn = None;
                self.outbox.clear();
            }
            79..=86 => {
                let secs =
                    [1, 60, 600, 3600, 6 * 3600][usize::try_from(self.rng.below(5)).unwrap()];
                self.h.advance(secs);
                let actions = self.h.stream.tick(self.h.wall, self.h.now).unwrap();
                self.take(&actions);
            }
            87..=90 => {
                self.snapshots.push(self.h.stream.store().clone());
            }
            91..=93 => {
                // A restart, from the store as it is or from an older
                // snapshot of it.
                let count = u64::try_from(self.snapshots.len()).unwrap();
                let older = if count > 0 && self.rng.chance(50) {
                    let index = usize::try_from(self.rng.below(count)).unwrap();
                    self.snapshots.get(index).cloned()
                } else {
                    None
                };
                let store = older.unwrap_or_else(|| self.h.stream.store().clone());
                self.h.stream =
                    SenderStream::open(store, self.h.stream.core.config, self.h.now).unwrap();
                self.h.conn = None;
                self.outbox.clear();
                self.h.check_invariants();
            }
            94..=96 => {
                let list: &[Uuid] = if self.rng.chance(50) {
                    &[E1, E2]
                } else {
                    &[E2, E1]
                };
                let actions = self.h.entries(list);
                self.take(&actions);
            }
            _ => {
                // A long offline burst.
                for n in 0..self.rng.below(300) {
                    let actions = self.h.collect(record(1, n));
                    self.take(&actions);
                }
            }
        }
    }
}

#[test]
fn random_runs_keep_the_queue_the_window_and_the_ledger_in_shape() {
    for seed in [
        0x9e37_79b9_7f4a_7c15,
        0xdead_beef_cafe_f00d,
        42,
        7,
        0x1234_5678,
    ] {
        let retention = SignedDuration::from_hours(12);
        let mut h = H::new(SenderConfig::new(500, 40_000).with_retention(retention));
        h.entries(&[E1, E2]);
        let mut run = Run {
            rng: Rng(seed),
            h,
            entries: Entries::default(),
            outbox: VecDeque::new(),
            snapshots: Vec::new(),
        };
        for _ in 0..3_000 {
            run.step();
        }
        // The runs went through acknowledgements and new streams.
        let acknowledged = run
            .entries
            .streams
            .values()
            .filter(|stored| stored.a > 0)
            .count();
        assert!(acknowledged > 1, "seed {seed}");
    }
}
