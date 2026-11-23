use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;
use crate::connection::{AcceptedKind, SERVER_OTHER_RECEIVE_LIMIT, cbor};
use crate::host::{CollectionMode, OsFamily, OsInfo};
use crate::telemetry::{
    Ack, CloseStream, DroppedRange, ErrorMessage, LastStored, LostOnReset, MAX_BATCH_LEN,
    MAX_RECORD_LEN, NetStateSource, OpenStream, RecordBody, RecordHeader, ResumeInfo, SeqRange,
    record_hash,
};
use crate::telemetry_codes::{DropReason, TelemetryError};

mod properties;
mod scenarios;

const EP: Uuid = Uuid::from_u128(0xe0);
const E1: Uuid = Uuid::from_u128(0xa1);
const E2: Uuid = Uuid::from_u128(0xa2);
const E3: Uuid = Uuid::from_u128(0xa3);
const BASE: i64 = 1_700_000_000;
const MIN30: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Body {
    n: u64,
    #[serde(with = "cbor::bytes")]
    pad: Vec<u8>,
}

fn wall(secs: i64) -> Timestamp {
    Timestamp::from_second(BASE + secs).unwrap()
}

fn record_padded(kind: u16, n: u64, pad: usize) -> Record {
    Record {
        header: RecordHeader {
            endpoint_id: Uuid::from_u128(0xdead),
            stream: Uuid::from_u128(0xbeef),
            seq: 77,
            event_time: wall(0),
            collected_at: wall(1),
            clock_offset: None,
            hostname: "host-1".to_owned(),
            ips: vec!["192.0.2.10".parse().unwrap()],
            default_route_ip: None,
            net_state_source: NetStateSource::Observed,
            os: OsInfo {
                family: OsFamily::Windows,
                version: "10.0.22631".to_owned(),
            },
            collection_mode: CollectionMode::Essential,
            process_key: None,
        },
        kind,
        schema: 1,
        body: RecordBody::encode(&Body {
            n,
            pad: vec![7; pad],
        })
        .unwrap(),
    }
}

fn record(kind: u16, n: u64) -> Record {
    record_padded(kind, n, 0)
}

/// A record whose bytes are exactly `len` long once sent as `seq` of
/// `stream` by `EP`.
fn record_of_len(kind: u16, n: u64, len: usize, stream: Uuid, seq: u64) -> Record {
    let mut pad = len.saturating_sub(400);
    loop {
        let mut probe = record_padded(kind, n, pad);
        probe.header.endpoint_id = EP;
        probe.header.stream = stream;
        probe.header.seq = seq;
        let actual = probe.to_bytes().unwrap().len();
        if actual == len {
            return record_padded(kind, n, pad);
        }
        assert!(actual < len, "cannot make a record of {len} bytes");
        pad += 1;
    }
}

fn kinds(list: &[(u16, u16, u16)]) -> Vec<AcceptedKind> {
    list.iter()
        .map(|&(kind, schema_min, schema_max)| AcceptedKind {
            kind,
            schema_min,
            schema_max,
        })
        .collect()
}

fn entry(entry_id: Uuid, list: &[(u16, u16, u16)]) -> TelemetryEntry {
    TelemetryEntry {
        entry_id,
        accepted_kinds: kinds(list),
    }
}

/// Kind 1 only.
const K1: &[(u16, u16, u16)] = &[(1, 1, 1)];
/// Kinds 1 and 2.
const K12: &[(u16, u16, u16)] = &[(1, 1, 1), (2, 1, 1)];

fn messages(actions: &[SenderAction]) -> Vec<TelemetryMessage> {
    actions
        .iter()
        .filter_map(|action| match action {
            SenderAction::Send(message) => Some(message.clone()),
            _ => None,
        })
        .collect()
}

fn disconnects(actions: &[SenderAction]) -> bool {
    actions.contains(&SenderAction::Disconnect)
}

/// A record as sent: its stream, sequence number, `n`, and bytes.
#[derive(Debug, Clone, PartialEq)]
struct Sent {
    stream: Uuid,
    seq: u64,
    n: u64,
    endpoint_id: Uuid,
    bytes: Vec<u8>,
}

/// The records of every batch in `actions`, checking each batch's rules.
fn sent(actions: &[SenderAction]) -> Vec<Sent> {
    let mut out = Vec::new();
    for message in messages(actions) {
        if let TelemetryMessage::RecordBatch(batch) = message {
            let total: usize = batch.records().iter().map(Vec::len).sum();
            assert!(total <= MAX_BATCH_LEN);
            let mut previous = None;
            for bytes in batch.records() {
                let record = Record::from_bytes(bytes).unwrap();
                assert_eq!(record.header.stream, batch.stream());
                if let Some(previous) = previous {
                    assert_eq!(record.header.seq, previous + 1, "a batch is consecutive");
                }
                previous = Some(record.header.seq);
                out.push(Sent {
                    stream: record.header.stream,
                    seq: record.header.seq,
                    n: record.body.decode::<Body>().unwrap().n,
                    endpoint_id: record.header.endpoint_id,
                    bytes: bytes.clone(),
                });
            }
        }
    }
    out
}

fn seqs(sent: &[Sent]) -> Vec<u64> {
    sent.iter().map(|record| record.seq).collect()
}

fn ns(sent: &[Sent]) -> Vec<u64> {
    sent.iter().map(|record| record.n).collect()
}

fn drops(actions: &[SenderAction]) -> Vec<(u64, u64, DropReason)> {
    messages(actions)
        .into_iter()
        .filter_map(|message| match message {
            TelemetryMessage::DroppedRange(range) => Some((range.from, range.to, range.reason)),
            _ => None,
        })
        .collect()
}

fn lost(actions: &[SenderAction]) -> Vec<LostOnReset> {
    messages(actions)
        .into_iter()
        .filter_map(|message| match message {
            TelemetryMessage::LostOnReset(lost) => Some(lost),
            _ => None,
        })
        .collect()
}

fn lost_ranges(actions: &[SenderAction]) -> Vec<(u64, u64)> {
    lost(actions)
        .into_iter()
        .flat_map(|lost| lost.ranges)
        .map(|range| (range.from, range.to))
        .collect()
}

/// The `t` of each message, in order.
fn kinds_sent(actions: &[SenderAction]) -> Vec<&'static str> {
    messages(actions).iter().map(TelemetryMessage::t).collect()
}

fn open_of(actions: &[SenderAction]) -> Option<Uuid> {
    messages(actions)
        .into_iter()
        .find_map(|message| match message {
            TelemetryMessage::OpenStream(open) => Some(open.stream),
            _ => None,
        })
}

/// A sender, its store, and the clocks and ids its calls use.
struct H {
    stream: SenderStream<MemorySenderStore>,
    conn: Option<SenderConnection>,
    wall: Timestamp,
    now: Duration,
    next_id: u128,
}

impl H {
    fn new(config: SenderConfig) -> Self {
        Self::on(MemorySenderStore::new(), config)
    }

    fn on(store: MemorySenderStore, config: SenderConfig) -> Self {
        Self {
            stream: SenderStream::open(store, config, Duration::ZERO).unwrap(),
            conn: None,
            wall: wall(0),
            now: Duration::ZERO,
            next_id: 0,
        }
    }

    fn big() -> Self {
        Self::new(SenderConfig::new(100_000, 1 << 40))
    }

    /// Restarts on a copy of the store, keeping the clocks.
    fn restart(&self) -> Self {
        Self {
            stream: SenderStream::open(
                self.stream.store().clone(),
                self.stream.core.config,
                self.now,
            )
            .unwrap(),
            conn: None,
            wall: self.wall,
            now: self.now,
            next_id: self.next_id,
        }
    }

    fn fresh_id(&mut self) -> Uuid {
        self.next_id += 1;
        Uuid::from_u128(0x5000 + self.next_id)
    }

    fn advance(&mut self, secs: u64) {
        self.wall = self
            .wall
            .checked_add(SignedDuration::from_secs(i64::try_from(secs).unwrap()))
            .unwrap();
        self.now += Duration::from_secs(secs);
    }

    fn flow(&self) -> SenderPosition {
        self.stream.position().unwrap()
    }

    fn collect(&mut self, record: Record) -> Vec<SenderAction> {
        self.stream.collect(record, self.wall, self.now).unwrap()
    }

    fn collect_n(&mut self, kind: u16, ns: std::ops::RangeInclusive<u64>) -> Vec<SenderAction> {
        let mut actions = Vec::new();
        for n in ns {
            actions.extend(self.collect(record(kind, n)));
        }
        actions
    }

    fn entries(&mut self, list: &[Uuid]) -> Vec<SenderAction> {
        self.stream
            .set_entries(list.to_vec(), self.wall, self.now)
            .unwrap()
    }

    fn connect(&mut self) -> Vec<SenderAction> {
        let connected = self.stream.connect(self.wall, self.now).unwrap();
        self.conn = connected.connection;
        connected.actions
    }

    fn conn(&self) -> SenderConnection {
        self.conn.unwrap()
    }

    fn hello(&mut self, entry_id: Uuid, list: &[(u16, u16, u16)]) -> Vec<SenderAction> {
        let id = self.fresh_id();
        self.stream
            .hello_ack(self.conn(), &entry(entry_id, list), id, self.wall, self.now)
            .unwrap()
    }

    fn recv(&mut self, message: TelemetryMessage) -> Vec<SenderAction> {
        let id = self.fresh_id();
        self.stream
            .receive(self.conn(), &message, id, self.wall, self.now)
            .unwrap()
    }

    fn resume(&mut self, stream: Uuid, a: u64, last: Option<(u64, [u8; 16])>) -> Vec<SenderAction> {
        self.recv(resume_info(stream, a, last))
    }

    fn ack(&mut self, stream: Uuid, a: u64) -> Vec<SenderAction> {
        self.recv(TelemetryMessage::Ack(Ack { stream, a }))
    }

    fn close(&mut self) -> Vec<SenderAction> {
        let conn = self.conn();
        self.stream.disconnected(conn, self.wall, self.now).unwrap()
    }

    /// Connects to `entry_id`, takes its `hello_ack`, and answers the
    /// `open_stream` with `a` and no `last_stored`: what a fresh stream
    /// gets. Returns the actions of the `resume_info`.
    fn establish(&mut self, entry_id: Uuid, list: &[(u16, u16, u16)]) -> Vec<SenderAction> {
        self.connect();
        let opened = self.hello(entry_id, list);
        let stream = open_of(&opened).expect("an open_stream");
        self.resume(stream, 0, None)
    }

    fn hash_of(&self, seq: u64) -> [u8; 16] {
        *self.stream.core.state.ledger.get(&seq).unwrap()
    }

    fn check_invariants(&self) {
        let state = &self.stream.core.state;
        let meta = &state.meta;
        assert!(meta.s.saturating_sub(meta.k) <= engine::WINDOW, "S - K");
        assert!(state.ledger.len() <= usize::try_from(engine::WINDOW).unwrap());
        for seq in state.ledger.map().keys() {
            assert!(
                *seq > meta.k && *seq <= meta.s,
                "ledger {seq} outside (K, S]"
            );
        }
        // Every sequence number in (K, M] is queued or dropped, once.
        if meta.flow.is_some() {
            for seq in meta.k + 1..=meta.m {
                let queued = state.queue.get(&seq).is_some();
                let dropped = state.dropped_at(seq).is_some();
                assert!(
                    queued != dropped,
                    "seq {seq}: queued {queued}, dropped {dropped}"
                );
            }
        }
    }
}

fn resume_info(stream: Uuid, a: u64, last: Option<(u64, [u8; 16])>) -> TelemetryMessage {
    TelemetryMessage::ResumeInfo(ResumeInfo {
        stream,
        a,
        last_stored: last.map(|(seq, hash)| LastStored { seq, hash }),
    })
}

/// A sender registered as `EP` with `E1` as its only entry.
fn registered() -> H {
    let mut h = H::big();
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h
}
