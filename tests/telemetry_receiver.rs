//! The telemetry entry's stream state machine, driven through the public
//! API with messages the tests make as an endpoint would.
#![cfg(feature = "telemetry")]

use std::collections::BTreeMap;

use ciborium::Value;
use jiff::{SignedDuration, Timestamp};
use proptest::prelude::*;
use senta_protocol::connection::{AcceptedKind, Envelope, Frame};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::{
    Ack, CloseStream, DroppedRange, ErrorMessage, LastStored, LostOnReset, MAX_RECORD_LEN,
    MemoryReceiverStore, MemoryReceiverStoreError, NetStateSource, OpenStream,
    RECEIVER_CLOSED_RETENTION, ReceiverConnection, ReceiverEntryState, ReceiverFlowKey,
    ReceiverFlowState, ReceiverLoss, ReceiverLossReason, ReceiverOutput, ReceiverRecord,
    ReceiverStream, Record, RecordBatch, RecordBody, RecordHeader, ResumeInfo, SeqRange,
    TelemetryDecodeError, TelemetryMessage, kind, record_hash,
};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use serde::Serialize;
use uuid::Uuid;

const ENTRY: Uuid = Uuid::from_u128(0xe1);
const OTHER_ENTRY: Uuid = Uuid::from_u128(0xe2);
const ENDPOINT: Uuid = Uuid::from_u128(0xa1);
const OTHER_ENDPOINT: Uuid = Uuid::from_u128(0xa2);
const S1: Uuid = Uuid::from_u128(0x51);
const S2: Uuid = Uuid::from_u128(0x52);
const S3: Uuid = Uuid::from_u128(0x53);
const ACCEPTED: u16 = kind::SYSMON_PROCESS_CREATE;
const NOT_ACCEPTED: u16 = kind::WINDOWS_EVENT_LOG;

type Machine = ReceiverStream<MemoryReceiverStore>;

#[derive(Serialize)]
struct Body<'a> {
    note: &'a str,
}

fn t0() -> Timestamp {
    Timestamp::from_second(1_700_000_000).unwrap()
}

fn at(offset: SignedDuration) -> Timestamp {
    t0().checked_add(offset).unwrap()
}

fn kinds() -> Vec<AcceptedKind> {
    vec![AcceptedKind {
        kind: ACCEPTED,
        schema_min: 1,
        schema_max: 2,
    }]
}

fn record_full(endpoint_id: Uuid, stream: Uuid, seq: u64, kind: u16, schema: u16) -> Vec<u8> {
    record_with(endpoint_id, stream, seq, kind, schema, "event")
}

fn record_with(
    endpoint_id: Uuid,
    stream: Uuid,
    seq: u64,
    kind: u16,
    schema: u16,
    note: &str,
) -> Vec<u8> {
    Record {
        header: RecordHeader {
            endpoint_id,
            stream,
            seq,
            event_time: t0(),
            collected_at: t0(),
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
        schema,
        body: RecordBody::encode(&Body { note }).unwrap(),
    }
    .to_bytes()
    .unwrap()
}

/// An accepted record of `ENDPOINT`.
fn rec(stream: Uuid, seq: u64) -> Vec<u8> {
    record_full(ENDPOINT, stream, seq, ACCEPTED, 1)
}

fn open(stream: Uuid) -> TelemetryMessage {
    TelemetryMessage::OpenStream(OpenStream { stream })
}

fn batch(stream: Uuid, records: Vec<Vec<u8>>) -> TelemetryMessage {
    TelemetryMessage::RecordBatch(RecordBatch::new(stream, records).unwrap())
}

fn dropped(stream: Uuid, from: u64, to: u64) -> TelemetryMessage {
    dropped_for(stream, from, to, DropReason::BufferOverflow)
}

fn dropped_for(stream: Uuid, from: u64, to: u64, reason: DropReason) -> TelemetryMessage {
    TelemetryMessage::DroppedRange(DroppedRange {
        stream,
        from,
        to,
        reason,
    })
}

fn close(stream: Uuid) -> TelemetryMessage {
    TelemetryMessage::CloseStream(CloseStream { stream })
}

fn lost(old_stream: Uuid, ranges: &[(u64, u64)]) -> TelemetryMessage {
    TelemetryMessage::LostOnReset(LostOnReset {
        old_stream,
        ranges: ranges
            .iter()
            .map(|&(from, to)| SeqRange { from, to })
            .collect(),
    })
}

fn resume(stream: Uuid, a: u64, last_stored: Option<(u64, &[u8])>) -> ReceiverOutput {
    ReceiverOutput::Reply(vec![TelemetryMessage::ResumeInfo(ResumeInfo {
        stream,
        a,
        last_stored: last_stored.map(|(seq, bytes)| LastStored {
            seq,
            hash: record_hash(bytes),
        }),
    })])
}

fn ack_msg(stream: Uuid, a: u64) -> TelemetryMessage {
    TelemetryMessage::Ack(Ack { stream, a })
}

fn err_msg(stream: Uuid, error: TelemetryError) -> TelemetryMessage {
    TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: Some(stream),
        error,
    })
}

fn acked(stream: Uuid, a: u64) -> ReceiverOutput {
    ReceiverOutput::Reply(vec![ack_msg(stream, a)])
}

fn acked_then(stream: Uuid, a: u64, error: TelemetryError) -> ReceiverOutput {
    ReceiverOutput::Reply(vec![ack_msg(stream, a), err_msg(stream, error)])
}

fn refused(stream: Uuid, error: TelemetryError) -> ReceiverOutput {
    ReceiverOutput::Reply(vec![err_msg(stream, error)])
}

fn silent() -> ReceiverOutput {
    ReceiverOutput::Reply(Vec::new())
}

fn restore(store: &MemoryReceiverStore) -> Machine {
    ReceiverStream::restore(ENTRY, store.clone()).unwrap()
}

fn connection() -> ReceiverConnection {
    ReceiverConnection::new(ENDPOINT, kinds())
}

fn flow(machine: &Machine, stream: Uuid) -> ReceiverFlowState {
    *machine.flow(ENDPOINT, stream).unwrap()
}

/// A store, a state machine and a connection that opened `S1` at `t0`.
fn opened() -> (MemoryReceiverStore, Machine, ReceiverConnection) {
    let store = MemoryReceiverStore::new();
    let mut machine = restore(&store);
    let mut conn = connection();
    assert_eq!(
        machine.receive(&mut conn, open(S1), t0()),
        resume(S1, 0, None)
    );
    (store, machine, conn)
}

/// Decodes a `record_batch` body holding `records`, as the telemetry
/// message decoder sees it on the wire.
fn decode_batch(
    stream: Uuid,
    records: Vec<Vec<u8>>,
) -> Result<TelemetryMessage, TelemetryDecodeError> {
    let body = Value::Map(vec![
        (
            Value::Text("stream".to_owned()),
            Value::Bytes(stream.as_bytes().to_vec()),
        ),
        (
            Value::Text("records".to_owned()),
            Value::Array(records.into_iter().map(Value::Bytes).collect()),
        ),
    ]);
    let frame = Frame::new("record_batch", &body).unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    let (t, body) = envelope.into_parts();
    TelemetryMessage::decode(&t, &body)
}

/// The two batches past a size limit: records within the record limit
/// that are past the batch limit together, and a record past the record
/// limit.
fn too_large_streams(stream: Uuid) -> Vec<Uuid> {
    let within = vec![vec![7; MAX_RECORD_LEN - 1]; 5];
    let one_too_long = vec![vec![1], vec![9; MAX_RECORD_LEN + 1]];
    [within, one_too_long]
        .into_iter()
        .map(|records| match decode_batch(stream, records) {
            Err(TelemetryDecodeError::BatchTooLarge { stream }) => stream,
            other => panic!("expected a batch past a size limit, got {other:?}"),
        })
        .collect()
}

// ---------------------------------------------------------------------
// open_stream
// ---------------------------------------------------------------------

#[test]
fn opening_a_new_stream_answers_a_zero_resume_info_and_writes_once() {
    let (store, machine, _) = opened();
    assert_eq!(store.writes(), 1);
    assert_eq!(flow(&machine, S1), ReceiverFlowState::opened());
    assert_eq!(machine.state().open_flow(ENDPOINT), Some(S1));
    assert_eq!(store.state(ENTRY), *machine.state());
}

#[test]
fn opening_the_open_stream_answers_its_state_and_writes_nothing() {
    let (store, mut machine, mut conn) = opened();
    let r1 = rec(S1, 1);
    let _ = machine.receive(&mut conn, batch(S1, vec![r1.clone()]), t0());
    let _ = machine.receive(&mut conn, dropped(S1, 2, 5), t0());
    let writes = store.writes();
    assert_eq!(
        machine.receive(&mut conn, open(S1), t0()),
        resume(S1, 5, Some((1, &r1)))
    );
    // On another connection too.
    let mut other = connection();
    assert_eq!(
        machine.receive(&mut other, open(S1), t0()),
        resume(S1, 5, Some((1, &r1)))
    );
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_stream_with_only_dropped_ranges_has_no_last_stored() {
    let (_, mut machine, mut conn) = opened();
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 1, 3), t0()),
        acked(S1, 3)
    );
    assert_eq!(
        machine.receive(&mut conn, open(S1), t0()),
        resume(S1, 3, None)
    );
}

#[test]
fn opening_a_new_stream_closes_the_open_one() {
    let (store, mut machine, mut conn) = opened();
    let later = at(SignedDuration::from_secs(60));
    assert_eq!(
        machine.receive(&mut conn, open(S2), later),
        resume(S2, 0, None)
    );
    assert_eq!(flow(&machine, S1).closed_at, Some(later));
    assert_eq!(machine.state().open_flow(ENDPOINT), Some(S2));
    assert_eq!(store.writes(), 2);
    // The closed stream cannot be opened again.
    let writes = store.writes();
    assert_eq!(
        machine.receive(&mut conn, open(S1), later),
        refused(S1, TelemetryError::Closed)
    );
    assert_eq!(machine.state().open_flow(ENDPOINT), Some(S2));
    assert_eq!(store.writes(), writes);
}

#[test]
fn endpoints_have_their_own_open_stream() {
    let (_, mut machine, mut conn) = opened();
    let mut other = ReceiverConnection::new(OTHER_ENDPOINT, kinds());
    assert_eq!(
        machine.receive(&mut other, open(S1), t0()),
        resume(S1, 0, None)
    );
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0()),
        acked(S1, 1)
    );
    assert_eq!(machine.flow(OTHER_ENDPOINT, S1).unwrap().a, 0);
    assert_eq!(machine.state().open_flow(OTHER_ENDPOINT), Some(S1));
}

// ---------------------------------------------------------------------
// record_batch
// ---------------------------------------------------------------------

#[test]
fn the_next_record_is_stored_bit_for_bit_and_acknowledged() {
    let (store, mut machine, mut conn) = opened();
    let r1 = rec(S1, 1);
    let r2 = record_full(ENDPOINT, S1, 2, ACCEPTED, 2);
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![r1.clone(), r2.clone()]), t0()),
        acked(S1, 2)
    );
    assert_eq!(
        store.records(ENTRY),
        vec![
            ReceiverRecord {
                endpoint_id: ENDPOINT,
                stream: S1,
                seq: 1,
                bytes: r1,
            },
            ReceiverRecord {
                endpoint_id: ENDPOINT,
                stream: S1,
                seq: 2,
                bytes: r2.clone(),
            },
        ]
    );
    assert_eq!(
        flow(&machine, S1),
        ReceiverFlowState {
            a: 2,
            last_stored: Some(LastStored {
                seq: 2,
                hash: record_hash(&r2),
            }),
            closed_at: None,
        }
    );
    // One write for the batch.
    assert_eq!(store.writes(), 2);
}

#[test]
fn records_up_to_a_are_skipped_whatever_their_kind_and_bytes() {
    let (store, mut machine, mut conn) = opened();
    let r1 = rec(S1, 1);
    let _ = machine.receive(&mut conn, batch(S1, vec![r1.clone(), rec(S1, 2)]), t0());
    let writes = store.writes();
    let state = flow(&machine, S1);
    let replays = vec![
        record_full(ENDPOINT, S1, 1, NOT_ACCEPTED, 1),
        record_with(ENDPOINT, S1, 2, ACCEPTED, 1, "other bytes"),
        record_full(ENDPOINT, S1, 0, ACCEPTED, 1),
    ];
    assert_eq!(
        machine.receive(&mut conn, batch(S1, replays), t0()),
        acked(S1, 2)
    );
    assert_eq!(flow(&machine, S1), state);
    assert_eq!(store.writes(), writes);
    assert_eq!(store.records(ENTRY).len(), 2);
}

#[test]
fn a_record_past_the_next_is_a_gap() {
    let (store, mut machine, mut conn) = opened();
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![rec(S1, 2)]), t0()),
        acked_then(S1, 0, TelemetryError::Gap { expected: 1 })
    );
    assert_eq!(store.records(ENTRY), Vec::new());
    assert_eq!(store.writes(), 1);
}

#[test]
fn a_batch_stops_at_a_gap_and_stores_what_came_before() {
    let (store, mut machine, mut conn) = opened();
    let records = vec![rec(S1, 1), rec(S1, 2), rec(S1, 4), rec(S1, 3)];
    assert_eq!(
        machine.receive(&mut conn, batch(S1, records), t0()),
        acked_then(S1, 2, TelemetryError::Gap { expected: 3 })
    );
    let seqs: Vec<u64> = store.records(ENTRY).iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![1, 2]);
    assert_eq!(flow(&machine, S1).a, 2);
}

#[test]
fn a_batch_stops_at_a_kind_not_accepted() {
    let (store, mut machine, mut conn) = opened();
    let records = vec![
        rec(S1, 1),
        record_full(ENDPOINT, S1, 2, NOT_ACCEPTED, 1),
        rec(S1, 3),
    ];
    assert_eq!(
        machine.receive(&mut conn, batch(S1, records), t0()),
        acked_then(S1, 1, TelemetryError::UnsupportedKind)
    );
    // A schema outside the accepted range is refused the same way.
    let records = vec![record_full(ENDPOINT, S1, 2, ACCEPTED, 3)];
    assert_eq!(
        machine.receive(&mut conn, batch(S1, records), t0()),
        acked_then(S1, 1, TelemetryError::UnsupportedKind)
    );
    // Nothing is accepted on a connection that accepts no kind.
    let mut none = ReceiverConnection::new(ENDPOINT, Vec::new());
    let _ = machine.receive(&mut none, open(S1), t0());
    assert_eq!(
        machine.receive(&mut none, batch(S1, vec![rec(S1, 2)]), t0()),
        acked_then(S1, 1, TelemetryError::UnsupportedKind)
    );
    assert_eq!(store.records(ENTRY).len(), 1);
}

#[test]
fn an_empty_batch_is_acknowledged_without_a_write() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    let writes = store.writes();
    assert_eq!(
        machine.receive(&mut conn, batch(S1, Vec::new()), t0()),
        acked(S1, 1)
    );
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_batch_with_a_bad_record_stores_nothing_and_disconnects() {
    let bad = [
        // Does not decode.
        vec![0xff, 0x00],
        // Another endpoint in the header.
        record_full(OTHER_ENDPOINT, S1, 2, ACCEPTED, 1),
        // Another stream in the header.
        record_full(ENDPOINT, S2, 2, ACCEPTED, 1),
    ];
    for bad in bad {
        let (store, mut machine, mut conn) = opened();
        let state = machine.state().clone();
        let records = vec![rec(S1, 1), bad, rec(S1, 3)];
        assert_eq!(
            machine.receive(&mut conn, batch(S1, records), t0()),
            ReceiverOutput::Disconnect
        );
        assert!(conn.is_halted());
        assert_eq!(*machine.state(), state);
        assert_eq!(store.records(ENTRY), Vec::new());
        assert_eq!(store.writes(), 1);
    }
}

#[test]
fn the_source_is_the_connection() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    let _ = machine.receive(&mut conn, dropped(S1, 2, 3), t0());
    let _ = machine.receive(&mut conn, lost(S3, &[(1, 2)]), t0());
    assert!(
        store
            .records(ENTRY)
            .iter()
            .all(|record| record.endpoint_id == conn.endpoint_id())
    );
    assert_eq!(store.losses(ENTRY).len(), 2);
    assert!(
        store
            .losses(ENTRY)
            .iter()
            .all(|loss| loss.endpoint_id == conn.endpoint_id())
    );
    assert!(
        store
            .state(ENTRY)
            .flows
            .keys()
            .all(|key| key.endpoint_id == ENDPOINT)
    );
}

// ---------------------------------------------------------------------
// Batches past a size limit
// ---------------------------------------------------------------------

#[test]
fn batches_past_a_size_limit_are_too_large_on_an_open_stream() {
    let (store, mut machine, mut conn) = opened();
    for stream in too_large_streams(S1) {
        let writes = store.writes();
        assert_eq!(
            machine.receive_batch_too_large(&mut conn, stream, t0()),
            refused(S1, TelemetryError::TooLarge)
        );
        assert!(!conn.is_halted());
        assert_eq!(store.writes(), writes);
        assert_eq!(flow(&machine, S1).a, 0);
    }
    // The connection is kept.
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0()),
        acked(S1, 1)
    );
}

// ---------------------------------------------------------------------
// dropped_range
// ---------------------------------------------------------------------

#[test]
fn a_dropped_range_moves_a_and_records_the_new_tail() {
    let (store, mut machine, mut conn) = opened();
    let r1 = rec(S1, 1);
    let r2 = rec(S1, 2);
    let _ = machine.receive(&mut conn, batch(S1, vec![r1, r2.clone()]), t0());
    // Overlaps what was stored: only 3..=6 is recorded.
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 1, 6), t0()),
        acked(S1, 6)
    );
    assert_eq!(
        store.losses(ENTRY),
        vec![ReceiverLoss {
            endpoint_id: ENDPOINT,
            stream: S1,
            range: SeqRange { from: 3, to: 6 },
            reason: ReceiverLossReason::Dropped(DropReason::BufferOverflow),
        }]
    );
    assert_eq!(
        flow(&machine, S1),
        ReceiverFlowState {
            a: 6,
            last_stored: Some(LastStored {
                seq: 2,
                hash: record_hash(&r2),
            }),
            closed_at: None,
        }
    );
    // Starting right after A.
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 7, 7), t0()),
        acked(S1, 7)
    );
    assert_eq!(store.losses(ENTRY).len(), 2);
}

#[test]
fn a_dropped_range_already_covered_changes_nothing() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    let _ = machine.receive(&mut conn, dropped(S1, 2, 5), t0());
    let state = flow(&machine, S1);
    let losses = store.losses(ENTRY);
    let writes = store.writes();
    for (from, to) in [(2, 5), (1, 1), (3, 4), (0, 0)] {
        assert_eq!(
            machine.receive(&mut conn, dropped(S1, from, to), t0()),
            acked(S1, 5)
        );
    }
    assert_eq!(flow(&machine, S1), state);
    assert_eq!(store.losses(ENTRY), losses);
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_dropped_range_past_the_next_is_a_gap_and_a_reversed_one_bad() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 3, 4), t0()),
        refused(S1, TelemetryError::Gap { expected: 2 })
    );
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 5, 4), t0()),
        refused(S1, TelemetryError::BadRange)
    );
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 1, 0), t0()),
        refused(S1, TelemetryError::BadRange)
    );
    assert_eq!(flow(&machine, S1).a, 1);
    assert_eq!(store.losses(ENTRY), Vec::new());
    // The connection is kept.
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 2, 2), t0()),
        acked(S1, 2)
    );
}

#[test]
fn an_unknown_drop_reason_is_recorded_as_it_is() {
    let (store, mut machine, mut conn) = opened();
    let reason = DropReason::Other("disk_full".to_owned());
    assert_eq!(
        machine.receive(&mut conn, dropped_for(S1, 1, 2, reason.clone()), t0()),
        acked(S1, 2)
    );
    let reasons: Vec<ReceiverLossReason> = store
        .losses(ENTRY)
        .into_iter()
        .map(|loss| loss.reason)
        .collect();
    assert_eq!(reasons, vec![ReceiverLossReason::Dropped(reason)]);
}

// ---------------------------------------------------------------------
// The end of u64
// ---------------------------------------------------------------------

#[test]
fn a_at_u64_max_takes_nothing_more_and_does_not_overflow() {
    let (store, mut machine, mut conn) = opened();
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 1, u64::MAX - 1), t0()),
        acked(S1, u64::MAX - 1)
    );
    let last = rec(S1, u64::MAX);
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![last.clone()]), t0()),
        acked(S1, u64::MAX)
    );
    let state = flow(&machine, S1);
    assert_eq!(
        state.last_stored,
        Some(LastStored {
            seq: u64::MAX,
            hash: record_hash(&last),
        })
    );
    let writes = store.writes();
    let inputs = [
        batch(S1, vec![rec(S1, u64::MAX)]),
        batch(
            S1,
            vec![record_full(ENDPOINT, S1, u64::MAX, NOT_ACCEPTED, 1)],
        ),
        dropped(S1, u64::MAX, u64::MAX),
        dropped(S1, 1, u64::MAX),
    ];
    for input in inputs {
        assert_eq!(machine.receive(&mut conn, input, t0()), acked(S1, u64::MAX));
    }
    assert_eq!(flow(&machine, S1), state);
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_dropped_range_can_reach_u64_max() {
    let (_, mut machine, mut conn) = opened();
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 1, u64::MAX), t0()),
        acked(S1, u64::MAX)
    );
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, u64::MAX, u64::MAX), t0()),
        acked(S1, u64::MAX)
    );
}

// ---------------------------------------------------------------------
// close_stream
// ---------------------------------------------------------------------

#[test]
fn closing_the_open_stream_remembers_when() {
    let (store, mut machine, mut conn) = opened();
    let later = at(SignedDuration::from_secs(5));
    assert_eq!(machine.receive(&mut conn, close(S1), later), silent());
    assert_eq!(flow(&machine, S1).closed_at, Some(later));
    assert_eq!(machine.state().open_flow(ENDPOINT), None);
    // Closing again, or a stream not known, changes nothing.
    let writes = store.writes();
    assert_eq!(machine.receive(&mut conn, close(S1), t0()), silent());
    assert_eq!(machine.receive(&mut conn, close(S2), t0()), silent());
    assert_eq!(flow(&machine, S1).closed_at, Some(later));
    assert_eq!(machine.flow(ENDPOINT, S2), None);
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_connection_that_did_not_open_the_stream_can_close_it() {
    let (_, mut machine, _) = opened();
    let mut other = connection();
    assert_eq!(machine.receive(&mut other, close(S1), t0()), silent());
    assert_eq!(flow(&machine, S1).closed_at, Some(t0()));
}

// ---------------------------------------------------------------------
// lost_on_reset
// ---------------------------------------------------------------------

fn lost_count(store: &MemoryReceiverStore, stream: Uuid, from: u64, to: u64) -> usize {
    store
        .losses(ENTRY)
        .iter()
        .filter(|loss| {
            loss.stream == stream
                && loss.range == SeqRange { from, to }
                && loss.reason == ReceiverLossReason::LostOnReset
        })
        .count()
}

#[test]
fn lost_on_reset_records_every_range_in_one_write() {
    let (store, mut machine, mut conn) = opened();
    let state = machine.state().clone();
    let writes = store.writes();
    // An old stream the entry does not know.
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &[(1, 4), (7, 7), (1, 4)]), t0()),
        silent()
    );
    assert_eq!(store.writes(), writes + 1);
    assert_eq!(
        store.losses(ENTRY),
        vec![
            ReceiverLoss {
                endpoint_id: ENDPOINT,
                stream: S3,
                range: SeqRange { from: 1, to: 4 },
                reason: ReceiverLossReason::LostOnReset,
            },
            ReceiverLoss {
                endpoint_id: ENDPOINT,
                stream: S3,
                range: SeqRange { from: 7, to: 7 },
                reason: ReceiverLossReason::LostOnReset,
            },
        ]
    );
    assert_eq!(*machine.state(), state);
    // An empty list does nothing.
    assert_eq!(machine.receive(&mut conn, lost(S3, &[]), t0()), silent());
    assert_eq!(store.writes(), writes + 1);
}

#[test]
fn lost_on_reset_with_a_reversed_range_records_nothing() {
    let (store, mut machine, mut conn) = opened();
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &[(1, 2), (5, 4)]), t0()),
        refused(S3, TelemetryError::BadRange)
    );
    assert_eq!(store.losses(ENTRY), Vec::new());
    assert!(!conn.is_halted());
}

#[test]
fn lost_on_reset_is_accepted_for_any_old_stream_and_changes_no_stream() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    let _ = machine.receive(&mut conn, open(S2), t0());
    let state = machine.state().clone();
    // The open stream, which another connection opened too, a closed one,
    // and one never seen.
    let mut other = connection();
    let _ = machine.receive(&mut other, open(S2), t0());
    for stream in [S2, S1, S3] {
        assert_eq!(
            machine.receive(&mut conn, lost(stream, &[(1, 1)]), t0()),
            silent()
        );
    }
    assert_eq!(*machine.state(), state);
    assert_eq!(store.losses(ENTRY).len(), 3);
}

#[test]
fn lost_on_reset_received_again_adds_no_record() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, lost(S3, &[(1, 4)]), t0());
    let writes = store.writes();
    // All committed: no write at all.
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &[(1, 4)]), t0()),
        silent()
    );
    assert_eq!(store.writes(), writes);
    // Partly committed: only the new range is written.
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &[(1, 4), (6, 9)]), t0()),
        silent()
    );
    assert_eq!(lost_count(&store, S3, 1, 4), 1);
    assert_eq!(lost_count(&store, S3, 6, 9), 1);
    // After a restart.
    let mut machine = restore(&store);
    let mut conn = connection();
    let _ = machine.receive(&mut conn, lost(S3, &[(1, 4), (6, 9)]), t0());
    assert_eq!(lost_count(&store, S3, 1, 4), 1);
    assert_eq!(lost_count(&store, S3, 6, 9), 1);
    assert_eq!(store.losses(ENTRY).len(), 2);
}

#[test]
fn lost_on_reset_with_many_ranges_is_deduplicated_without_rescanning() {
    // As many distinct ranges as a frame can carry, each sent twice. A
    // duplicate check that scans the ranges before it, or every loss
    // record kept, takes billions of comparisons here.
    const RANGES: u64 = 100_000;
    let (store, mut machine, mut conn) = opened();
    let ranges: Vec<(u64, u64)> = (0..RANGES)
        .flat_map(|i| [(2 * i + 1, 2 * i + 1), (2 * i + 1, 2 * i + 1)])
        .collect();
    let writes = store.writes();
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &ranges), t0()),
        silent()
    );
    assert_eq!(store.writes(), writes + 1);
    let losses = store.losses(ENTRY);
    assert_eq!(losses.len(), usize::try_from(RANGES).unwrap());
    assert!(losses.iter().zip(0..).all(|(loss, i)| loss.range
        == SeqRange {
            from: 2 * i + 1,
            to: 2 * i + 1
        }));
    // Received again: every range is already kept, so nothing is written.
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &ranges), t0()),
        silent()
    );
    assert_eq!(store.writes(), writes + 1);
    assert_eq!(store.losses(ENTRY).len(), usize::try_from(RANGES).unwrap());
}

#[test]
fn lost_on_reset_stays_idempotent_after_the_stream_is_pruned() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, lost(S1, &[(1, 4)]), t0());
    let _ = machine.receive(&mut conn, close(S1), t0());
    let later = at(RECEIVER_CLOSED_RETENTION);
    assert_eq!(
        machine.prune(later).unwrap(),
        vec![ReceiverFlowKey {
            endpoint_id: ENDPOINT,
            stream: S1,
        }]
    );
    let _ = machine.receive(&mut conn, lost(S1, &[(1, 4)]), later);
    assert_eq!(lost_count(&store, S1, 1, 4), 1);
}

#[test]
fn a_dropped_range_of_the_same_coordinates_does_not_count() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, dropped(S1, 1, 4), t0());
    let _ = machine.receive(&mut conn, lost(S1, &[(1, 4)]), t0());
    assert_eq!(lost_count(&store, S1, 1, 4), 1);
    assert_eq!(store.losses(ENTRY).len(), 2);
    // Nor does a lost_on_reset record stop a dropped range.
    let _ = machine.receive(&mut conn, lost(S1, &[(5, 6)]), t0());
    assert_eq!(
        machine.receive(&mut conn, dropped(S1, 5, 6), t0()),
        acked(S1, 6)
    );
    assert_eq!(store.losses(ENTRY).len(), 4);
}

// ---------------------------------------------------------------------
// Messages only an entry sends
// ---------------------------------------------------------------------

#[test]
fn messages_only_an_entry_sends_disconnect() {
    let messages = [
        TelemetryMessage::ResumeInfo(ResumeInfo {
            stream: S1,
            a: 0,
            last_stored: None,
        }),
        ack_msg(S1, 0),
        err_msg(S1, TelemetryError::Closed),
    ];
    for message in messages {
        let (store, mut machine, mut conn) = opened();
        let state = machine.state().clone();
        assert_eq!(
            machine.receive(&mut conn, message, t0()),
            ReceiverOutput::Disconnect
        );
        assert_eq!(*machine.state(), state);
        assert_eq!(store.writes(), 1);
        assert!(conn.is_halted());
    }
}

// ---------------------------------------------------------------------
// Late data
// ---------------------------------------------------------------------

/// Sends a batch, a dropped range and a batch past a size limit of `S1` on
/// `conn` at `now`, and asserts each is refused with `error` and nothing
/// is stored.
fn assert_late(
    store: &MemoryReceiverStore,
    machine: &mut Machine,
    conn: &mut ReceiverConnection,
    now: Timestamp,
    error: &TelemetryError,
) {
    let writes = store.writes();
    let state = machine.state().clone();
    assert_eq!(
        machine.receive(conn, batch(S1, vec![rec(S1, 1)]), now),
        refused(S1, error.clone())
    );
    assert_eq!(
        machine.receive(conn, dropped(S1, 1, 3), now),
        refused(S1, error.clone())
    );
    for stream in too_large_streams(S1) {
        assert_eq!(
            machine.receive_batch_too_large(conn, stream, now),
            refused(S1, error.clone())
        );
    }
    assert_eq!(store.writes(), writes);
    assert_eq!(*machine.state(), state);
    assert!(!conn.is_halted());
}

#[test]
fn late_data_of_a_stream_closed_by_close_stream_is_closed() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, close(S1), t0());
    assert_late(
        &store,
        &mut machine,
        &mut conn,
        t0(),
        &TelemetryError::Closed,
    );
}

#[test]
fn late_data_of_a_stream_closed_by_a_new_open_is_closed() {
    let (store, mut machine, mut conn) = opened();
    let mut other = connection();
    let _ = machine.receive(&mut other, open(S2), t0());
    assert_late(
        &store,
        &mut machine,
        &mut conn,
        t0(),
        &TelemetryError::Closed,
    );
}

#[test]
fn data_of_a_stream_opened_on_another_connection_is_unknown() {
    let (store, mut machine, _) = opened();
    let mut other = connection();
    assert_late(
        &store,
        &mut machine,
        &mut other,
        t0(),
        &TelemetryError::UnknownStream,
    );
    // Nor is a stream never opened anywhere taken.
    let mut conn = connection();
    let _ = machine.receive(&mut conn, open(S2), t0());
    let mut fresh = connection();
    assert_eq!(
        machine.receive(&mut fresh, batch(S3, Vec::new()), t0()),
        refused(S3, TelemetryError::UnknownStream)
    );
}

#[test]
fn late_data_after_the_closed_memory_expired_or_was_pruned_is_unknown() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, close(S1), t0());
    let expired = at(RECEIVER_CLOSED_RETENTION);
    assert_late(
        &store,
        &mut machine,
        &mut conn,
        expired,
        &TelemetryError::UnknownStream,
    );
    assert_eq!(machine.prune(expired).unwrap().len(), 1);
    assert_eq!(machine.flow(ENDPOINT, S1), None);
    assert_late(
        &store,
        &mut machine,
        &mut conn,
        expired,
        &TelemetryError::UnknownStream,
    );
}

#[test]
fn late_data_of_a_stream_opened_again_elsewhere_under_the_same_id_is_unknown() {
    for prune in [false, true] {
        let (store, mut machine, mut conn) = opened();
        let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
        let _ = machine.receive(&mut conn, close(S1), t0());
        let later = at(RECEIVER_CLOSED_RETENTION);
        if prune {
            let _ = machine.prune(later).unwrap();
        }
        let mut other = connection();
        assert_eq!(
            machine.receive(&mut other, open(S1), later),
            resume(S1, 0, None)
        );
        assert_late(
            &store,
            &mut machine,
            &mut conn,
            later,
            &TelemetryError::UnknownStream,
        );
        // The connection that opened it again sends on it.
        assert_eq!(
            machine.receive(&mut other, batch(S1, vec![rec(S1, 1)]), later),
            acked(S1, 1)
        );
    }
}

#[test]
fn a_stream_is_closed_until_thirty_days_have_passed() {
    let (_, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, close(S1), t0());
    let almost = at(RECEIVER_CLOSED_RETENTION - SignedDuration::from_nanos(1));
    assert_eq!(
        machine.receive(&mut conn, open(S1), almost),
        refused(S1, TelemetryError::Closed)
    );
    assert_eq!(machine.prune(almost).unwrap(), Vec::new());
    let exactly = at(RECEIVER_CLOSED_RETENTION);
    assert_eq!(
        machine.receive(&mut conn, open(S1), exactly),
        resume(S1, 0, None)
    );
    assert_eq!(flow(&machine, S1), ReceiverFlowState::opened());
}

#[test]
fn retention_is_thirty_days() {
    assert_eq!(RECEIVER_CLOSED_RETENTION, SignedDuration::from_hours(720));
}

// ---------------------------------------------------------------------
// Pruning and opening the same id again
// ---------------------------------------------------------------------

#[test]
fn pruning_forgets_only_expired_stream_states() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    let _ = machine.receive(&mut conn, dropped(S1, 2, 3), t0());
    let _ = machine.receive(&mut conn, lost(S1, &[(9, 9)]), t0());
    // S1 closed at t0, S2 closed a day later, S3 open.
    let _ = machine.receive(&mut conn, open(S2), t0());
    let day = at(SignedDuration::from_hours(24));
    let _ = machine.receive(&mut conn, open(S3), day);
    let records = store.records(ENTRY);
    let losses = store.losses(ENTRY);
    let now = at(RECEIVER_CLOSED_RETENTION);
    assert_eq!(
        machine.prune(now).unwrap(),
        vec![ReceiverFlowKey {
            endpoint_id: ENDPOINT,
            stream: S1,
        }]
    );
    assert_eq!(machine.flow(ENDPOINT, S1), None);
    assert!(machine.flow(ENDPOINT, S2).is_some());
    assert!(machine.flow(ENDPOINT, S3).is_some());
    assert_eq!(store.state(ENTRY), *machine.state());
    assert_eq!(store.records(ENTRY), records);
    assert_eq!(store.losses(ENTRY), losses);
    // Nothing left to prune: no write.
    let writes = store.writes();
    assert_eq!(machine.prune(now).unwrap(), Vec::new());
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_failed_prune_forgets_nothing() {
    let (store, mut machine, mut conn) = opened();
    let _ = machine.receive(&mut conn, close(S1), t0());
    let state = machine.state().clone();
    store.fail_writes(true);
    assert_eq!(
        machine.prune(at(RECEIVER_CLOSED_RETENTION)),
        Err(MemoryReceiverStoreError::Write)
    );
    assert_eq!(*machine.state(), state);
    assert_eq!(store.state(ENTRY), state);
}

/// Opens `S1`, stores `r1` as its record 1, closes it, prunes it, and
/// opens it again on a new connection, 30 days later.
fn reopened_after_prune() -> (
    MemoryReceiverStore,
    Machine,
    ReceiverConnection,
    Vec<u8>,
    Timestamp,
) {
    let (store, mut machine, mut conn) = opened();
    let old = record_with(ENDPOINT, S1, 1, ACCEPTED, 1, "old");
    let _ = machine.receive(&mut conn, batch(S1, vec![old.clone()]), t0());
    let _ = machine.receive(&mut conn, close(S1), t0());
    let later = at(RECEIVER_CLOSED_RETENTION);
    let _ = machine.prune(later).unwrap();
    let mut again = connection();
    assert_eq!(
        machine.receive(&mut again, open(S1), later),
        resume(S1, 0, None)
    );
    (store, machine, again, old, later)
}

#[test]
fn a_stream_opened_again_keeps_both_records_of_the_same_seq() {
    let (store, mut machine, mut conn, old, later) = reopened_after_prune();
    let new = record_with(ENDPOINT, S1, 1, ACCEPTED, 1, "new");
    assert_ne!(old, new);
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![new.clone()]), later),
        acked(S1, 1)
    );
    let bytes: Vec<Vec<u8>> = store
        .records(ENTRY)
        .into_iter()
        .filter(|record| record.stream == S1 && record.seq == 1)
        .map(|record| record.bytes)
        .collect();
    assert_eq!(bytes, vec![old, new.clone()]);
    assert_eq!(
        flow(&machine, S1).last_stored,
        Some(LastStored {
            seq: 1,
            hash: record_hash(&new),
        })
    );
}

#[test]
fn a_stream_opened_again_is_not_acknowledged_when_the_write_fails() {
    let (store, mut machine, mut conn, old, later) = reopened_after_prune();
    let new = record_with(ENDPOINT, S1, 1, ACCEPTED, 1, "new");
    store.fail_writes(true);
    assert_eq!(
        machine.receive(&mut conn, batch(S1, vec![new]), later),
        ReceiverOutput::Disconnect
    );
    let bytes: Vec<Vec<u8>> = store
        .records(ENTRY)
        .into_iter()
        .map(|record| record.bytes)
        .collect();
    assert_eq!(bytes, vec![old]);
    assert_eq!(flow(&machine, S1).a, 0);
}

// ---------------------------------------------------------------------
// Entries sharing a store
// ---------------------------------------------------------------------

#[test]
fn two_entries_sharing_a_store_stay_apart() {
    let store = MemoryReceiverStore::new();
    let mut first = ReceiverStream::restore(ENTRY, store.clone()).unwrap();
    let mut second = ReceiverStream::restore(OTHER_ENTRY, store.clone()).unwrap();
    assert_eq!(first.entry_id(), ENTRY);
    let mut c1 = connection();
    let mut c2 = connection();
    assert_eq!(first.receive(&mut c1, open(S1), t0()), resume(S1, 0, None));
    assert_eq!(second.receive(&mut c2, open(S1), t0()), resume(S1, 0, None));
    let _ = first.receive(&mut c1, batch(S1, vec![rec(S1, 1), rec(S1, 2)]), t0());
    let _ = second.receive(&mut c2, dropped(S1, 1, 5), t0());
    let _ = first.receive(&mut c1, lost(S3, &[(1, 1)]), t0());
    // The second entry has no lost_on_reset record of the same range yet.
    let _ = second.receive(&mut c2, lost(S3, &[(1, 1)]), t0());
    let _ = first.receive(&mut c1, close(S1), t0());

    assert_eq!(first.flow(ENDPOINT, S1).unwrap().a, 2);
    assert!(!first.flow(ENDPOINT, S1).unwrap().is_open());
    let s = *second.flow(ENDPOINT, S1).unwrap();
    assert_eq!((s.a, s.last_stored, s.is_open()), (5, None, true));
    assert_eq!(store.records(ENTRY).len(), 2);
    assert_eq!(store.records(OTHER_ENTRY), Vec::new());
    assert_eq!(store.losses(ENTRY).len(), 1);
    assert_eq!(store.losses(OTHER_ENTRY).len(), 2);
    // Each entry reads back only its own state.
    assert_eq!(
        ReceiverStream::restore(ENTRY, store.clone())
            .unwrap()
            .state(),
        first.state()
    );
    assert_eq!(
        ReceiverStream::restore(OTHER_ENTRY, store.clone())
            .unwrap()
            .state(),
        second.state()
    );
    // Data the second entry still takes, though the first closed S1.
    assert_eq!(
        second.receive(&mut c2, batch(S1, vec![rec(S1, 6)]), t0()),
        acked(S1, 6)
    );
}

// ---------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------

/// An input that writes, from the state `setup` leaves, and the answer it
/// gets when the write succeeds.
struct WritingCase {
    name: &'static str,
    setup: fn(&mut Machine, &mut ReceiverConnection),
    input: fn() -> TelemetryMessage,
    /// Whether the input needs the connection to have opened `S1`.
    needs_open: bool,
    expected: ReceiverOutput,
}

fn no_setup(_: &mut Machine, _: &mut ReceiverConnection) {}

fn writing_cases() -> Vec<WritingCase> {
    vec![
        WritingCase {
            name: "open a new stream",
            setup: no_setup,
            input: || open(S2),
            needs_open: false,
            expected: resume(S2, 0, None),
        },
        WritingCase {
            name: "store a record",
            setup: no_setup,
            input: || batch(S1, vec![rec(S1, 1), rec(S1, 3)]),
            needs_open: true,
            expected: acked_then(S1, 1, TelemetryError::Gap { expected: 2 }),
        },
        WritingCase {
            name: "move A with a dropped range",
            setup: no_setup,
            input: || dropped(S1, 1, 4),
            needs_open: true,
            expected: acked(S1, 4),
        },
        WritingCase {
            name: "close the open stream",
            setup: no_setup,
            input: || close(S1),
            needs_open: false,
            expected: silent(),
        },
        WritingCase {
            name: "record a lost range",
            setup: |machine, conn| {
                let _ = machine.receive(conn, lost(S3, &[(1, 2)]), t0());
            },
            input: || lost(S3, &[(1, 2), (4, 4)]),
            needs_open: false,
            expected: silent(),
        },
    ]
}

/// The inputs a failure halts a connection for, one of every kind.
fn every_input() -> Vec<TelemetryMessage> {
    vec![
        open(S3),
        open(S1),
        batch(S1, Vec::new()),
        dropped(S1, 1, 1),
        close(S1),
        lost(S2, &[(1, 1)]),
    ]
}

fn assert_halted(
    machine: &mut Machine,
    conn: &mut ReceiverConnection,
    store: &MemoryReceiverStore,
) {
    assert!(conn.is_halted());
    let state = machine.state().clone();
    let writes = store.writes();
    for input in every_input() {
        assert_eq!(
            machine.receive(conn, input, t0()),
            ReceiverOutput::Disconnect
        );
    }
    for stream in too_large_streams(S1) {
        assert_eq!(
            machine.receive_batch_too_large(conn, stream, t0()),
            ReceiverOutput::Disconnect
        );
    }
    assert_eq!(*machine.state(), state);
    assert_eq!(store.writes(), writes);
}

#[test]
fn a_failed_write_changes_nothing_answers_nothing_and_halts_the_connection() {
    for case in writing_cases() {
        let (store, mut machine, mut conn) = opened();
        (case.setup)(&mut machine, &mut conn);
        let state = machine.state().clone();
        let losses = store.losses(ENTRY);
        let records = store.records(ENTRY);

        store.fail_writes(true);
        assert_eq!(
            machine.receive(&mut conn, (case.input)(), t0()),
            ReceiverOutput::Disconnect,
            "{}",
            case.name
        );
        assert_eq!(*machine.state(), state, "{}", case.name);
        assert_eq!(store.state(ENTRY), state, "{}", case.name);
        assert_eq!(store.losses(ENTRY), losses, "{}", case.name);
        assert_eq!(store.records(ENTRY), records, "{}", case.name);
        store.fail_writes(false);
        assert_halted(&mut machine, &mut conn, &store);

        // A new connection gets the input handled as the first time.
        let mut fresh = connection();
        if case.needs_open {
            let _ = machine.receive(&mut fresh, open(S1), t0());
        }
        assert_eq!(
            machine.receive(&mut fresh, (case.input)(), t0()),
            case.expected,
            "{}",
            case.name
        );
        assert_eq!(store.state(ENTRY), *machine.state());
    }
}

#[test]
fn a_failed_read_changes_nothing_answers_nothing_and_halts_the_connection() {
    let (store, mut machine, mut conn) = opened();
    let state = machine.state().clone();
    store.fail_reads(true);
    assert_eq!(
        machine.receive(&mut conn, lost(S3, &[(1, 2)]), t0()),
        ReceiverOutput::Disconnect
    );
    store.fail_reads(false);
    assert_eq!(*machine.state(), state);
    assert_eq!(store.losses(ENTRY), Vec::new());
    assert_halted(&mut machine, &mut conn, &store);

    let mut fresh = connection();
    assert_eq!(
        machine.receive(&mut fresh, lost(S3, &[(1, 2)]), t0()),
        silent()
    );
    assert_eq!(lost_count(&store, S3, 1, 2), 1);
}

#[test]
fn restoring_fails_when_the_store_cannot_be_read() {
    let store = MemoryReceiverStore::new();
    store.fail_reads(true);
    assert_eq!(
        ReceiverStream::restore(ENTRY, store.clone()).err(),
        Some(MemoryReceiverStoreError::Read)
    );
}

#[test]
fn a_halted_connection_leaves_other_connections_working() {
    let (store, mut machine, mut conn) = opened();
    let mut other = connection();
    let _ = machine.receive(&mut other, open(S1), t0());
    store.fail_writes(true);
    let _ = machine.receive(&mut conn, batch(S1, vec![rec(S1, 1)]), t0());
    store.fail_writes(false);
    assert!(conn.is_halted());
    assert_eq!(
        machine.receive(&mut other, batch(S1, vec![rec(S1, 1)]), t0()),
        acked(S1, 1)
    );
}

// ---------------------------------------------------------------------
// Restarting
// ---------------------------------------------------------------------

#[test]
fn a_restored_state_machine_judges_as_the_one_before() {
    let (store, mut machine, mut conn) = opened();
    let r1 = rec(S1, 1);
    let _ = machine.receive(&mut conn, batch(S1, vec![r1.clone()]), t0());
    let _ = machine.receive(&mut conn, dropped(S1, 2, 4), t0());
    let _ = machine.receive(&mut conn, open(S2), t0());
    let _ = machine.receive(&mut conn, batch(S2, vec![rec(S2, 1)]), t0());
    let _ = machine.receive(&mut conn, close(S2), t0());
    let _ = machine.receive(&mut conn, open(S3), t0());

    let mut restored = restore(&store);
    assert_eq!(restored.state(), machine.state());
    assert_eq!(store.state(ENTRY), *machine.state());

    // A connection made after the restart must open the stream again.
    let mut conn = connection();
    let probes = [
        open(S1),
        open(S2),
        batch(S3, vec![rec(S3, 1)]),
        open(S3),
        batch(S3, vec![rec(S3, 1), rec(S3, 3)]),
        dropped(S3, 2, 2),
        batch(S3, vec![rec(S3, 3)]),
    ];
    let expected = [
        refused(S1, TelemetryError::Closed),
        refused(S2, TelemetryError::Closed),
        refused(S3, TelemetryError::UnknownStream),
        resume(S3, 0, None),
        acked_then(S3, 1, TelemetryError::Gap { expected: 2 }),
        acked(S3, 2),
        acked(S3, 3),
    ];
    for (probe, expected) in probes.into_iter().zip(expected) {
        assert_eq!(restored.receive(&mut conn, probe, t0()), expected);
    }
    // Thirty days after S1 closed, it opens as new.
    let later = at(RECEIVER_CLOSED_RETENTION);
    assert_eq!(
        restored.receive(&mut conn, open(S1), later),
        resume(S1, 0, None)
    );
    assert_eq!(
        restore(&store).state(),
        restored.state(),
        "the store holds what the state machine holds"
    );
}

// ---------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------

const STREAMS: [Uuid; 3] = [S1, S2, S3];

#[derive(Debug, Clone)]
enum Op {
    Open(usize, usize),
    Batch(usize, usize, Vec<(u64, bool)>),
    Dropped(usize, usize, u64, u64),
    Close(usize, usize),
    Lost(usize, usize, Vec<(u64, u64)>),
    TooLarge(usize, usize),
    Advance(i64),
    Reconnect(usize),
    Prune,
    Restart,
    FailNextWrite,
}

fn seq() -> impl Strategy<Value = u64> {
    prop_oneof![8 => 0..12_u64, 1 => Just(u64::MAX - 1), 1 => Just(u64::MAX)]
}

fn op() -> impl Strategy<Value = Op> {
    let conn = 0..2_usize;
    let stream = 0..STREAMS.len();
    prop_oneof![
        3 => (conn.clone(), stream.clone()).prop_map(|(c, s)| Op::Open(c, s)),
        6 => (
            conn.clone(),
            stream.clone(),
            prop::collection::vec((0..12_u64, prop::bool::weighted(0.9)), 0..5)
        )
            .prop_map(|(c, s, records)| Op::Batch(c, s, records)),
        3 => (conn.clone(), stream.clone(), seq(), seq())
            .prop_map(|(c, s, from, to)| Op::Dropped(c, s, from, to)),
        1 => (conn.clone(), stream.clone()).prop_map(|(c, s)| Op::Close(c, s)),
        1 => (
            conn.clone(),
            stream.clone(),
            prop::collection::vec((0..6_u64, 0..6_u64), 0..3)
        )
            .prop_map(|(c, s, ranges)| Op::Lost(c, s, ranges)),
        1 => (conn.clone(), stream).prop_map(|(c, s)| Op::TooLarge(c, s)),
        2 => (0..(24 * 40_i64)).prop_map(Op::Advance),
        1 => conn.prop_map(Op::Reconnect),
        1 => Just(Op::Prune),
        1 => Just(Op::Restart),
        2 => Just(Op::FailNextWrite),
    ]
}

/// What the property test tracks of the instance of a stream currently
/// in the entry's state: where its records and loss records start in the
/// store, and its `A` as last seen.
#[derive(Debug, Clone, Copy)]
struct Instance {
    records_from: usize,
    losses_from: usize,
    a: u64,
}

/// Checks that the stored seqs and dropped ranges cover `1..=a` exactly.
fn covers(mut pieces: Vec<(u64, u64)>, a: u64) -> bool {
    pieces.sort_unstable();
    let mut next: u64 = 1;
    let mut done = a == 0;
    for (from, to) in pieces {
        if done || from > next {
            return false;
        }
        if to >= next {
            if to == a {
                done = true;
            } else if to > a {
                return false;
            } else {
                next = to + 1;
            }
        }
    }
    done
}

fn check_invariants(
    store: &MemoryReceiverStore,
    machine: &Machine,
    instances: &BTreeMap<ReceiverFlowKey, Instance>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(&store.state(ENTRY), machine.state());
    let records = store.records(ENTRY);
    let losses = store.losses(ENTRY);
    for (key, state) in &machine.state().flows {
        if let Some(last) = state.last_stored {
            prop_assert!(last.seq <= state.a, "L ≤ A for {key:?}");
        }
        if !state.is_open() {
            continue;
        }
        let Some(instance) = instances.get(key) else {
            return Err(TestCaseError::fail(format!(
                "no instance tracked for {key:?}"
            )));
        };
        let mut pieces: Vec<(u64, u64)> = records[instance.records_from..]
            .iter()
            .filter(|r| r.endpoint_id == key.endpoint_id && r.stream == key.stream)
            .map(|r| (r.seq, r.seq))
            .collect();
        pieces.extend(
            losses[instance.losses_from..]
                .iter()
                .filter(|l| {
                    l.endpoint_id == key.endpoint_id
                        && l.stream == key.stream
                        && matches!(l.reason, ReceiverLossReason::Dropped(_))
                })
                .map(|l| (l.range.from, l.range.to)),
        );
        prop_assert!(
            covers(pieces.clone(), state.a),
            "1..={} not covered exactly by {pieces:?}",
            state.a
        );
    }
    Ok(())
}

fn run_ops(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let store = MemoryReceiverStore::new();
    let mut machine = restore(&store);
    let mut conns = [connection(), connection()];
    let mut now = t0();
    let mut instances: BTreeMap<ReceiverFlowKey, Instance> = BTreeMap::new();
    let mut fail_next = false;

    for op in ops {
        let before: ReceiverEntryState = machine.state().clone();
        let records_before = store.records(ENTRY).len();
        let losses_before = store.losses(ENTRY).len();
        let arms_failure = matches!(op, Op::FailNextWrite);
        store.fail_writes(fail_next);
        let mut failed = false;
        let mut output = None;
        match op {
            Op::Open(c, s) => output = Some(machine.receive(&mut conns[c], open(STREAMS[s]), now)),
            Op::Batch(c, s, records) => {
                let stream = STREAMS[s];
                let records = records
                    .into_iter()
                    .map(|(seq, ok)| {
                        let kind = if ok { ACCEPTED } else { NOT_ACCEPTED };
                        record_full(ENDPOINT, stream, seq, kind, 1)
                    })
                    .collect();
                output = Some(machine.receive(&mut conns[c], batch(stream, records), now));
            }
            Op::Dropped(c, s, from, to) => {
                output = Some(machine.receive(&mut conns[c], dropped(STREAMS[s], from, to), now));
            }
            Op::Close(c, s) => {
                output = Some(machine.receive(&mut conns[c], close(STREAMS[s]), now))
            }
            Op::Lost(c, s, ranges) => {
                output = Some(machine.receive(&mut conns[c], lost(STREAMS[s], &ranges), now));
            }
            Op::TooLarge(c, s) => {
                let out = machine.receive_batch_too_large(&mut conns[c], STREAMS[s], now);
                prop_assert!(store.records(ENTRY).len() == records_before);
                output = Some(out);
            }
            Op::Advance(hours) => {
                now = now.checked_add(SignedDuration::from_hours(hours)).unwrap();
            }
            Op::Reconnect(c) => conns[c] = connection(),
            Op::Prune => failed = machine.prune(now).is_err(),
            Op::Restart => {
                machine = restore(&store);
                conns = [connection(), connection()];
            }
            Op::FailNextWrite => {}
        }
        store.fail_writes(false);
        if let Some(ReceiverOutput::Disconnect) = output {
            failed = true;
        }
        if failed {
            // Whatever made the call fail, nothing changed.
            prop_assert_eq!(machine.state(), &before);
            prop_assert_eq!(store.records(ENTRY).len(), records_before);
            prop_assert_eq!(store.losses(ENTRY).len(), losses_before);
        }
        fail_next = arms_failure;

        // Track instances: a stream open now that was not open before is
        // a new instance; A never goes back within an instance.
        let after = machine.state().clone();
        instances.retain(|key, _| after.flows.contains_key(key));
        for (key, state) in &after.flows {
            // Opening a stream that was closed, or not there, starts it
            // anew.
            let continued = before
                .flows
                .get(key)
                .is_some_and(|b| b.is_open() || !state.is_open());
            match instances.get_mut(key) {
                Some(instance) if continued => {
                    prop_assert!(state.a >= instance.a, "A went back for {key:?}");
                    instance.a = state.a;
                }
                _ => {
                    prop_assert_eq!(state.a, 0);
                    instances.insert(
                        *key,
                        Instance {
                            records_from: records_before,
                            losses_from: losses_before,
                            a: state.a,
                        },
                    );
                }
            }
        }
        check_invariants(&store, &machine, &instances)?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn invariants_hold_under_random_inputs(ops in prop::collection::vec(op(), 1..60)) {
        run_ops(ops)?;
    }
}
