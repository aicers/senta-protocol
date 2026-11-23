//! Records, kinds, entries, the wire, and the small helpers every part of
//! the pair test shares.

use std::collections::BTreeMap;

use jiff::Timestamp;
use senta_protocol::connection::{AcceptedKind, Envelope, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::{
    NetStateSource, Record, RecordBody, RecordHeader, SeqRange, TelemetryMessage, kind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The endpoint every run registers.
pub const ENDPOINT: Uuid = Uuid::from_u128(0xe0e0);
/// The entries of a run, each its own `ReceiverStream`.
pub const E1: Uuid = Uuid::from_u128(0xa1);
pub const E2: Uuid = Uuid::from_u128(0xa2);
pub const E3: Uuid = Uuid::from_u128(0xa3);
pub const ENTRIES: [Uuid; 3] = [E1, E2, E3];

/// The kinds records are collected with.
pub const PROC: u16 = kind::SYSMON_PROCESS_CREATE;
pub const NET: u16 = kind::SYSMON_NETWORK_CONNECT;

/// The longest record a sender sends.
pub const MAX_RECORD: usize = 262_144;

/// A record's identity: the `mark` its body carries.
pub type Mark = u64;

/// The kind and schema of a collected record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// `PROC`, schema 1.
    Proc1,
    /// `PROC`, schema 2.
    Proc2,
    /// `NET`, schema 1.
    Net,
}

impl Kind {
    pub fn kind_schema(self) -> (u16, u16) {
        match self {
            Self::Proc1 => (PROC, 1),
            Self::Proc2 => (PROC, 2),
            Self::Net => (NET, 1),
        }
    }
}

/// How long a collected record is once fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Size {
    /// A few hundred bytes.
    Normal,
    /// Exactly 262,144 bytes while its sequence number is below 24, one
    /// byte longer from 24 on.
    Limit,
    /// Past 262,144 bytes whatever its sequence number.
    Huge,
}

/// A list of accepted kinds an entry sends in its `HelloAck`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kinds {
    /// Every kind and schema collected.
    All,
    /// `PROC` schema 1 and `NET`: `Proc2` is refused.
    NoProc2,
    /// `PROC` alone: `Net` is refused.
    NoNet,
    /// `NET` alone.
    OnlyNet,
    /// `PROC` schema 1 alone.
    Proc1Only,
}

impl Kinds {
    pub fn list(self) -> Vec<AcceptedKind> {
        let entry = |kind, schema_min, schema_max| AcceptedKind {
            kind,
            schema_min,
            schema_max,
        };
        match self {
            Self::All => vec![entry(PROC, 1, 2), entry(NET, 1, 1)],
            Self::NoProc2 => vec![entry(PROC, 1, 1), entry(NET, 1, 1)],
            Self::NoNet => vec![entry(PROC, 1, 2)],
            Self::OnlyNet => vec![entry(NET, 1, 1)],
            Self::Proc1Only => vec![entry(PROC, 1, 1)],
        }
    }
}

/// An address list the endpoint is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum List {
    /// E1, E2, E3.
    E123,
    /// E2, E1.
    E21,
    /// E1 alone.
    E1,
    /// E2 alone.
    E2,
    /// E3, E1.
    E31,
    /// No entry.
    Empty,
}

impl List {
    pub fn entries(self) -> Vec<Uuid> {
        match self {
            Self::E123 => vec![E1, E2, E3],
            Self::E21 => vec![E2, E1],
            Self::E1 => vec![E1],
            Self::E2 => vec![E2],
            Self::E31 => vec![E3, E1],
            Self::Empty => Vec::new(),
        }
    }
}

/// A field no kind's body type knows, so that every receiver keeps it
/// only in the bytes.
#[derive(Serialize)]
struct Unknown {
    vendor: &'static str,
    nested: [u32; 3],
}

#[derive(Serialize)]
struct PairBody<'a> {
    mark: u64,
    #[serde(rename = "x-not-in-any-schema")]
    unknown: Unknown,
    #[serde(with = "cbor::bytes")]
    pad: &'a [u8],
}

#[derive(Deserialize)]
struct MarkOnly {
    mark: u64,
}

pub fn base_time() -> Timestamp {
    Timestamp::from_second(1_700_000_000).unwrap()
}

fn header() -> RecordHeader {
    RecordHeader {
        endpoint_id: Uuid::nil(),
        stream: Uuid::nil(),
        seq: 0,
        event_time: base_time(),
        collected_at: base_time(),
        clock_offset: None,
        hostname: "host-pair".to_owned(),
        ips: vec!["192.0.2.10".parse().unwrap()],
        default_route_ip: None,
        net_state_source: NetStateSource::Observed,
        os: OsInfo {
            family: OsFamily::Windows,
            version: "10.0.22631".to_owned(),
        },
        collection_mode: CollectionMode::Essential,
        process_key: None,
    }
}

fn with_pad(mark: Mark, kind: Kind, pad: usize) -> Record {
    let (kind, schema) = kind.kind_schema();
    let pad = vec![0x5a; pad];
    Record {
        header: header(),
        kind,
        schema,
        body: RecordBody::encode(&PairBody {
            mark,
            unknown: Unknown {
                vendor: "pair-test",
                nested: [1, 2, 3],
            },
            pad: &pad,
        })
        .unwrap(),
    }
}

/// The length of `record`'s bytes with a non-nil endpoint and stream and
/// `seq` 0: a sequence number below 24 takes the same one byte.
fn base_len(record: &Record) -> usize {
    let mut probe = record.clone();
    probe.header.endpoint_id = ENDPOINT;
    probe.header.stream = Uuid::from_u128(u128::MAX);
    probe.to_bytes().unwrap().len()
}

/// Makes the record of `mark`.
pub fn make_record(mark: Mark, kind: Kind, size: Size) -> Record {
    match size {
        Size::Normal => with_pad(mark, kind, 16),
        Size::Huge => with_pad(mark, kind, MAX_RECORD + 64),
        Size::Limit => {
            let short = base_len(&with_pad(mark, kind, MAX_RECORD - 1024));
            let pad = MAX_RECORD - 1024 + (MAX_RECORD - short);
            let record = with_pad(mark, kind, pad);
            assert_eq!(
                base_len(&record),
                MAX_RECORD,
                "a pad changes the head width"
            );
            record
        }
    }
}

/// The width CBOR gives an unsigned integer.
pub fn uint_width(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// What the model knows of a record: its kind, and how long its bytes are
/// with any sequence number.
#[derive(Debug, Clone)]
pub struct Template {
    pub record: Record,
    pub kind: u16,
    pub schema: u16,
    /// The length with a one-byte sequence number.
    pub base_len: usize,
}

impl Template {
    pub fn new(record: Record) -> Self {
        let base_len = base_len(&record);
        Self {
            kind: record.kind,
            schema: record.schema,
            record,
            base_len,
        }
    }

    /// The length of the record's bytes once it carries `seq`.
    pub fn len_at(&self, seq: u64) -> u64 {
        u64::try_from(self.base_len - 1 + uint_width(seq)).unwrap()
    }
}

/// Reads the mark out of a record's bytes.
pub fn mark_of(bytes: &[u8]) -> Option<Mark> {
    let record = Record::from_bytes(bytes).ok()?;
    record.body.decode::<MarkOnly>().ok().map(|body| body.mark)
}

/// The first 16 bytes of the SHA-256 of `bytes`: the hash the test
/// expects, computed without the crate's own function.
pub fn expected_hash(bytes: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// Sends a message through the envelope: encodes it as a frame, parses the
/// frame's envelope and decodes the message back. Returns the message and
/// the payload's length.
pub fn wire(message: &TelemetryMessage) -> (TelemetryMessage, usize) {
    let frame = message.to_frame().unwrap();
    let payload_len = frame.payload().len();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    let (t, body) = envelope.into_parts();
    (TelemetryMessage::decode(&t, &body).unwrap(), payload_len)
}

/// A set of `u64` held as disjoint, non-adjacent closed ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ranges {
    map: BTreeMap<u64, u64>,
}

impl Ranges {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, from: u64, to: u64) {
        if from > to {
            return;
        }
        let mut start = from;
        let mut end = to;
        if let Some((&left, &left_to)) = self.map.range(..=from).next_back()
            && left_to.saturating_add(1) >= from
        {
            start = left;
            end = end.max(left_to);
        }
        let touching: Vec<u64> = self
            .map
            .range(start..=end.saturating_add(1))
            .map(|(from, _)| *from)
            .collect();
        for key in touching {
            if let Some(to) = self.map.remove(&key) {
                end = end.max(to);
            }
        }
        self.map.insert(start, end);
    }

    pub fn contains(&self, value: u64) -> bool {
        self.map
            .range(..=value)
            .next_back()
            .is_some_and(|(_, to)| *to >= value)
    }

    /// The largest `p` such that `1..=p` is held.
    pub fn prefix(&self) -> u64 {
        match self.map.first_key_value() {
            Some((1, to)) => *to,
            _ => 0,
        }
    }

    pub fn ranges(&self) -> Vec<(u64, u64)> {
        self.map.iter().map(|(from, to)| (*from, *to)).collect()
    }

    pub fn covers(&self, other: &Self) -> bool {
        other.map.iter().all(|(from, to)| {
            self.map
                .range(..=from)
                .next_back()
                .is_some_and(|(_, end)| end >= to)
        })
    }
}

pub fn seq_ranges(ranges: &[(u64, u64)]) -> Vec<SeqRange> {
    ranges
        .iter()
        .map(|&(from, to)| SeqRange { from, to })
        .collect()
}
