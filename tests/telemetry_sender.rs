//! The sender stream, driven through the public API: a record collected,
//! sent, acknowledged, resent after a restart, and the store written one
//! commit per call.
#![cfg(feature = "telemetry")]

use std::time::Duration;

use jiff::Timestamp;
use senta_protocol::connection::{AcceptedKind, TelemetryEntry, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::{
    Ack, LastStored, MemorySenderStore, NetStateSource, Record, RecordBody, RecordHeader,
    ResumeInfo, SenderAction, SenderConfig, SenderError, SenderStateEntry, SenderStateKey,
    SenderStream, TelemetryMessage, kind, record_hash,
};
use serde::Serialize;
use uuid::Uuid;

const ENDPOINT: Uuid = Uuid::from_u128(0xe0);
const ENTRY: Uuid = Uuid::from_u128(0xa1);
const STREAM: Uuid = Uuid::from_u128(0x51);

#[derive(Serialize)]
struct Body {
    image: String,
}

fn at(secs: i64) -> Timestamp {
    Timestamp::from_second(1_700_000_000 + secs).unwrap()
}

fn record(image: &str) -> Record {
    Record {
        header: RecordHeader {
            endpoint_id: Uuid::nil(),
            stream: Uuid::nil(),
            seq: 0,
            event_time: at(0),
            collected_at: at(0),
            clock_offset: None,
            hostname: "host-1".to_owned(),
            ips: Vec::new(),
            default_route_ip: None,
            net_state_source: NetStateSource::Unknown,
            os: OsInfo {
                family: OsFamily::Windows,
                version: "10.0.22631".to_owned(),
            },
            collection_mode: CollectionMode::Essential,
            process_key: None,
        },
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: RecordBody::encode(&Body {
            image: image.to_owned(),
        })
        .unwrap(),
    }
}

fn telemetry_entry() -> TelemetryEntry {
    TelemetryEntry {
        entry_id: ENTRY,
        accepted_kinds: vec![AcceptedKind {
            kind: kind::SYSMON_PROCESS_CREATE,
            schema_min: 1,
            schema_max: 1,
        }],
    }
}

fn batches(actions: &[SenderAction]) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|action| match action {
            SenderAction::Send(TelemetryMessage::RecordBatch(batch)) => {
                Some(batch.records().to_vec())
            }
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn a_record_is_sent_acknowledged_and_resumed_after_a_restart() {
    let config = SenderConfig::new(1_000, 1 << 20);
    let mut sender = SenderStream::open(MemorySenderStore::new(), config, Duration::ZERO).unwrap();
    let actions = sender
        .set_entries(vec![ENTRY], at(0), Duration::ZERO)
        .unwrap();
    assert_eq!(actions, [SenderAction::Connect { entry_id: ENTRY }]);
    sender.register(ENDPOINT).unwrap();
    sender
        .collect(record("cmd.exe"), at(1), Duration::ZERO)
        .unwrap();
    sender
        .collect(record("pwsh.exe"), at(1), Duration::ZERO)
        .unwrap();

    let connection = sender
        .connect(at(2), Duration::ZERO)
        .unwrap()
        .connection
        .unwrap();
    assert_eq!(connection.entry_id(), ENTRY);
    let actions = sender
        .hello_ack(
            connection,
            &telemetry_entry(),
            STREAM,
            at(2),
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(
        actions,
        [SenderAction::Send(TelemetryMessage::OpenStream(
            senta_protocol::telemetry::OpenStream { stream: STREAM }
        ))]
    );
    let resume = TelemetryMessage::ResumeInfo(ResumeInfo {
        stream: STREAM,
        a: 0,
        last_stored: None,
    });
    let actions = sender
        .receive(
            connection,
            &resume,
            Uuid::from_u128(0x52),
            at(3),
            Duration::ZERO,
        )
        .unwrap();
    let records = batches(&actions);
    assert_eq!(records.len(), 2);
    for (seq, bytes) in (1..).zip(&records) {
        let header = Record::from_bytes(bytes).unwrap().header;
        assert_eq!(
            (header.endpoint_id, header.stream, header.seq),
            (ENDPOINT, STREAM, seq)
        );
    }
    let ack = TelemetryMessage::Ack(Ack {
        stream: STREAM,
        a: 1,
    });
    assert!(
        sender
            .receive(
                connection,
                &ack,
                Uuid::from_u128(0x53),
                at(4),
                Duration::ZERO
            )
            .unwrap()
            .is_empty()
    );
    let position = sender.position().unwrap();
    assert_eq!(
        (position.acknowledged, position.assigned, position.sent),
        (1, 2, 2)
    );
    assert_eq!(sender.status().entries[0].last_success, Some(at(4)));

    // Restarted from a store that went through a serialized form.
    let mut store = MemorySenderStore::new();
    let entries: Vec<(SenderStateKey, SenderStateEntry)> = sender
        .store()
        .entries()
        .iter()
        .map(|(key, entry)| {
            (
                cbor::from_slice(&cbor::to_vec(key).unwrap()).unwrap(),
                cbor::from_slice(&cbor::to_vec(entry).unwrap()).unwrap(),
            )
        })
        .collect();
    assert_eq!(entries.len(), sender.store().entries().len());
    std::mem::swap(&mut store, sender.store_mut());
    let mut sender = SenderStream::open(store, config, Duration::from_secs(10)).unwrap();
    assert_eq!(sender.connection(), None);
    assert_eq!(sender.target(), Some(ENTRY));
    let connection = sender
        .connect(at(5), Duration::from_secs(10))
        .unwrap()
        .connection
        .unwrap();
    sender
        .hello_ack(
            connection,
            &telemetry_entry(),
            Uuid::from_u128(0x54),
            at(5),
            Duration::from_secs(10),
        )
        .unwrap();
    let resume = TelemetryMessage::ResumeInfo(ResumeInfo {
        stream: STREAM,
        a: 1,
        last_stored: Some(LastStored {
            seq: 1,
            hash: record_hash(&records[0]),
        }),
    });
    let actions = sender
        .receive(
            connection,
            &resume,
            Uuid::from_u128(0x55),
            at(6),
            Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(batches(&actions), records[1..]);
}

#[test]
fn a_failed_write_changes_nothing() {
    let config = SenderConfig::new(1_000, 1 << 20);
    let mut sender = SenderStream::open(MemorySenderStore::new(), config, Duration::ZERO).unwrap();
    sender
        .set_entries(vec![ENTRY], at(0), Duration::ZERO)
        .unwrap();
    let before = sender.store().clone();
    sender.store_mut().fail_next_commits(1);
    let error = sender
        .collect(record("cmd.exe"), at(1), Duration::ZERO)
        .unwrap_err();
    assert!(matches!(error, SenderError::Store(_)));
    assert_eq!(sender.status().collected_records, 0);
    assert_eq!(sender.store().entries(), before.entries());
    sender
        .collect(record("cmd.exe"), at(1), Duration::ZERO)
        .unwrap();
    assert_eq!(sender.status().collected_records, 1);
}
