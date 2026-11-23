//! The telemetry messages, driven through the public API, against
//! hand-made CBOR.
#![cfg(feature = "telemetry")]

use std::collections::BTreeSet;

use ciborium::Value;
use ciborium::value::Integer;
use jiff::Timestamp;
use senta_protocol::connection::{Body, DecodeErrorKind, Envelope, Frame, Message, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::{
    Ack, CloseStream, DroppedRange, ErrorMessage, LastStored, LostOnReset, MAX_BATCH_LEN,
    MAX_RECORD_LEN, NetStateSource, OpenStream, Record, RecordBatch, RecordBatchTooLarge,
    RecordBody, RecordHeader, ResumeInfo, SeqRange, TELEMETRY_MESSAGE_KINDS, TelemetryDecodeError,
    TelemetryMessage, kind, record_hash,
};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use uuid::Uuid;

const STREAM: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
const OTHER_STREAM: Uuid = Uuid::from_u128(42);

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn uuid(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

fn int(n: u64) -> Value {
    Value::from(n)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

/// Wraps `body` in an envelope under `t` and parses it back.
fn envelope(t: &str, body: &Value) -> Envelope {
    let frame = Frame::new(t, body).unwrap();
    Envelope::parse(frame.payload()).unwrap()
}

fn body(t: &str, value: &Value) -> Body {
    envelope(t, value).into_parts().1
}

fn decode(t: &str, value: &Value) -> Result<TelemetryMessage, TelemetryDecodeError> {
    TelemetryMessage::decode(t, &body(t, value))
}

fn malformed_kind(t: &str, value: &Value) -> DecodeErrorKind {
    match decode(t, value) {
        Err(TelemetryDecodeError::Malformed { t: named, error }) => {
            assert_eq!(named, t);
            error.kind()
        }
        other => panic!("expected a malformed {t} for {value:?}, got {other:?}"),
    }
}

/// The text keys of a CBOR map.
fn keys(bytes: &[u8]) -> BTreeSet<String> {
    let Value::Map(entries) = ciborium::from_reader::<Value, _>(bytes).unwrap() else {
        panic!("not a map");
    };
    entries
        .into_iter()
        .map(|(key, _)| key.into_text().unwrap())
        .collect()
}

/// Encodes `message` to a frame, parses the frame and decodes it again,
/// checking `t` and the keys of the body.
fn round_trip(message: &TelemetryMessage, expected_keys: &[&str]) -> Envelope {
    let frame = message.to_frame().unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    assert_eq!(envelope.t(), message.t());
    assert_eq!(
        &TelemetryMessage::decode(envelope.t(), envelope.body()).unwrap(),
        message
    );
    let expected: BTreeSet<String> = expected_keys.iter().map(|&key| key.to_owned()).collect();
    assert_eq!(keys(envelope.body().as_bytes()), expected, "{message:?}");
    envelope
}

fn last_stored() -> LastStored {
    LastStored {
        seq: 9,
        hash: *b"0123456789abcdef",
    }
}

fn all_messages() -> Vec<(TelemetryMessage, &'static str, Vec<&'static str>)> {
    vec![
        (
            TelemetryMessage::OpenStream(OpenStream { stream: STREAM }),
            "open_stream",
            vec!["stream"],
        ),
        (
            TelemetryMessage::ResumeInfo(ResumeInfo {
                stream: STREAM,
                a: 10,
                last_stored: Some(last_stored()),
            }),
            "resume_info",
            vec!["stream", "a", "last_stored"],
        ),
        (
            TelemetryMessage::RecordBatch(
                RecordBatch::new(STREAM, vec![vec![0xa0], vec![1, 2, 3]]).unwrap(),
            ),
            "record_batch",
            vec!["stream", "records"],
        ),
        (
            TelemetryMessage::Ack(Ack {
                stream: STREAM,
                a: u64::MAX,
            }),
            "ack",
            vec!["stream", "a"],
        ),
        (
            TelemetryMessage::DroppedRange(DroppedRange {
                stream: STREAM,
                from: 3,
                to: 8,
                reason: DropReason::BufferOverflow,
            }),
            "dropped_range",
            vec!["stream", "from", "to", "reason"],
        ),
        (
            TelemetryMessage::LostOnReset(LostOnReset {
                old_stream: STREAM,
                ranges: vec![SeqRange { from: 1, to: 2 }, SeqRange { from: 5, to: 5 }],
            }),
            "lost_on_reset",
            vec!["old_stream", "ranges"],
        ),
        (
            TelemetryMessage::CloseStream(CloseStream { stream: STREAM }),
            "close_stream",
            vec!["stream"],
        ),
        (
            TelemetryMessage::ErrorMessage(ErrorMessage {
                stream: Some(STREAM),
                error: TelemetryError::Gap { expected: 11 },
            }),
            "error",
            vec!["stream", "error"],
        ),
    ]
}

/// A valid body of each message, as hand-made CBOR map entries.
fn valid_bodies() -> Vec<(&'static str, Vec<(&'static str, Value)>)> {
    vec![
        ("open_stream", vec![("stream", uuid(STREAM))]),
        (
            "resume_info",
            vec![
                ("stream", uuid(STREAM)),
                ("a", int(10)),
                (
                    "last_stored",
                    map(vec![
                        ("seq", int(9)),
                        ("hash", Value::Bytes(b"0123456789abcdef".to_vec())),
                    ]),
                ),
            ],
        ),
        (
            "record_batch",
            vec![
                ("stream", uuid(STREAM)),
                ("records", Value::Array(vec![Value::Bytes(vec![0xa0])])),
            ],
        ),
        ("ack", vec![("stream", uuid(STREAM)), ("a", int(4))]),
        (
            "dropped_range",
            vec![
                ("stream", uuid(STREAM)),
                ("from", int(3)),
                ("to", int(8)),
                ("reason", text("retention_expired")),
            ],
        ),
        (
            "lost_on_reset",
            vec![
                ("old_stream", uuid(STREAM)),
                (
                    "ranges",
                    Value::Array(vec![map(vec![("from", int(1)), ("to", int(2))])]),
                ),
            ],
        ),
        ("close_stream", vec![("stream", uuid(STREAM))]),
        (
            "error",
            vec![
                ("stream", uuid(STREAM)),
                (
                    "error",
                    map(vec![("gap", map(vec![("expected", int(11))]))]),
                ),
            ],
        ),
    ]
}

#[test]
fn the_eight_round_trip_under_their_names() {
    for (message, t, keys) in all_messages() {
        assert_eq!(message.t(), t);
        round_trip(&message, &keys);
    }
}

#[test]
fn kinds_match_the_table() {
    assert_eq!(
        TELEMETRY_MESSAGE_KINDS,
        [
            "open_stream",
            "resume_info",
            "record_batch",
            "ack",
            "dropped_range",
            "lost_on_reset",
            "close_stream",
            "error",
        ]
    );
    assert_eq!(
        [
            OpenStream::T,
            ResumeInfo::T,
            RecordBatch::T,
            Ack::T,
            DroppedRange::T,
            LostOnReset::T,
            CloseStream::T,
            ErrorMessage::T,
        ],
        TELEMETRY_MESSAGE_KINDS
    );
    let ts: Vec<&str> = all_messages().iter().map(|(_, t, _)| *t).collect();
    assert_eq!(ts, TELEMETRY_MESSAGE_KINDS);
}

#[test]
fn unknown_kinds_and_malformed_bodies_differ() {
    for t in ["hello", "ping", "records", "open_stream2", ""] {
        assert_eq!(
            decode(t, &map(vec![("stream", uuid(STREAM))])),
            Err(TelemetryDecodeError::UnknownKind { t: t.to_owned() })
        );
    }
    for t in TELEMETRY_MESSAGE_KINDS {
        assert_eq!(
            malformed_kind(t, &text("not a map")),
            DecodeErrorKind::Invalid
        );
        assert_eq!(malformed_kind(t, &map(vec![])), DecodeErrorKind::Invalid);
    }
}

#[test]
fn valid_bodies_decode() {
    for (t, entries) in valid_bodies() {
        let message = decode(t, &map(entries)).unwrap();
        assert_eq!(message.t(), t);
    }
}

#[test]
fn unknown_fields_are_ignored_at_every_depth() {
    for (t, mut entries) in valid_bodies() {
        let plain = decode(t, &map(entries.clone())).unwrap();
        // Unknown fields in nested structures.
        for (name, value) in &mut entries {
            match (*name, value) {
                ("last_stored", Value::Map(inner)) => {
                    inner.push((text("future"), int(1)));
                }
                ("error", Value::Map(inner)) => {
                    let Some((_, Value::Map(fields))) = inner.first_mut() else {
                        panic!("gap has a field map");
                    };
                    fields.push((text("future"), Value::Array(vec![])));
                }
                ("ranges", Value::Array(ranges)) => {
                    for range in ranges {
                        let Value::Map(fields) = range else {
                            panic!("a range is a map");
                        };
                        fields.push((text("future"), text("x")));
                    }
                }
                _ => {}
            }
        }
        entries.push(("added_later", map(vec![("deep", int(7))])));
        assert_eq!(decode(t, &map(entries)).unwrap(), plain, "{t}");
    }
}

#[test]
fn missing_and_mistyped_fields_fail() {
    for (t, entries) in valid_bodies() {
        let required: Vec<&str> = entries
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| {
                !matches!(
                    (t, *name),
                    ("resume_info", "last_stored") | ("error", "stream")
                )
            })
            .collect();
        for missing in &required {
            let without: Vec<_> = entries
                .iter()
                .filter(|(name, _)| name != missing)
                .cloned()
                .collect();
            assert_eq!(
                malformed_kind(t, &map(without)),
                DecodeErrorKind::Invalid,
                "{t} without {missing}"
            );
        }
        for mistyped in &required {
            let wrong: Vec<_> = entries
                .iter()
                .map(|(name, value)| {
                    if name == mistyped {
                        (*name, Value::Bool(true))
                    } else {
                        (*name, value.clone())
                    }
                })
                .collect();
            assert_eq!(
                malformed_kind(t, &map(wrong)),
                DecodeErrorKind::Invalid,
                "{t} with a mistyped {mistyped}"
            );
        }
    }
    // A UUID of the wrong length, and text for a sequence number.
    assert_eq!(
        malformed_kind(
            "ack",
            &map(vec![("stream", Value::Bytes(vec![0; 15])), ("a", int(1))])
        ),
        DecodeErrorKind::Invalid
    );
    assert_eq!(
        malformed_kind(
            "ack",
            &map(vec![("stream", uuid(STREAM)), ("a", text("1"))])
        ),
        DecodeErrorKind::Invalid
    );
    // Nested required fields.
    assert_eq!(
        malformed_kind(
            "resume_info",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("a", int(1)),
                ("last_stored", map(vec![("seq", int(1))])),
            ])
        ),
        DecodeErrorKind::Invalid
    );
    assert_eq!(
        malformed_kind(
            "lost_on_reset",
            &map(vec![
                ("old_stream", uuid(STREAM)),
                ("ranges", Value::Array(vec![map(vec![("from", int(1))])])),
            ])
        ),
        DecodeErrorKind::Invalid
    );
}

#[test]
fn duplicate_keys_fail_at_any_depth() {
    for (t, mut entries) in valid_bodies() {
        let first = entries.first().cloned().unwrap();
        entries.push(first);
        assert_eq!(
            malformed_kind(t, &map(entries)),
            DecodeErrorKind::DuplicateKey,
            "{t}"
        );
    }
    let nested = [
        (
            "resume_info",
            map(vec![
                ("stream", uuid(STREAM)),
                ("a", int(10)),
                ("last_stored", map(vec![("seq", int(1)), ("seq", int(2))])),
            ]),
        ),
        (
            "lost_on_reset",
            map(vec![
                ("old_stream", uuid(STREAM)),
                (
                    "ranges",
                    Value::Array(vec![map(vec![
                        ("from", int(1)),
                        ("to", int(2)),
                        ("to", int(3)),
                    ])]),
                ),
            ]),
        ),
        (
            "error",
            map(vec![(
                "error",
                map(vec![(
                    "gap",
                    map(vec![("expected", int(1)), ("expected", int(1))]),
                )]),
            )]),
        ),
        (
            "dropped_range",
            map(vec![
                ("stream", uuid(STREAM)),
                ("from", int(3)),
                ("to", int(8)),
                ("reason", text("buffer_overflow")),
                ("future", map(vec![("x", int(1)), ("x", int(1))])),
            ]),
        ),
    ];
    for (t, value) in nested {
        assert_eq!(
            malformed_kind(t, &value),
            DecodeErrorKind::DuplicateKey,
            "{t}"
        );
    }
}

#[test]
fn sequence_numbers_are_u64() {
    // 2^64, as a bignum; and the most negative CBOR integer, -2^64.
    let past_u64 = Value::Tag(2, Box::new(Value::Bytes(vec![1, 0, 0, 0, 0, 0, 0, 0, 0])));
    let very_negative = Value::Integer(Integer::try_from(-(i128::from(u64::MAX)) - 1).unwrap());
    for bad in [Value::from(-1), very_negative, past_u64] {
        assert_eq!(
            malformed_kind(
                "ack",
                &map(vec![("stream", uuid(STREAM)), ("a", bad.clone())])
            ),
            DecodeErrorKind::Invalid
        );
        assert_eq!(
            malformed_kind(
                "dropped_range",
                &map(vec![
                    ("stream", uuid(STREAM)),
                    ("from", bad.clone()),
                    ("to", int(1)),
                    ("reason", text("too_large")),
                ])
            ),
            DecodeErrorKind::Invalid
        );
        assert_eq!(
            malformed_kind(
                "resume_info",
                &map(vec![
                    ("stream", uuid(STREAM)),
                    ("a", int(1)),
                    (
                        "last_stored",
                        map(vec![
                            ("seq", bad.clone()),
                            ("hash", Value::Bytes(vec![0; 16])),
                        ]),
                    ),
                ])
            ),
            DecodeErrorKind::Invalid
        );
        assert_eq!(
            malformed_kind(
                "lost_on_reset",
                &map(vec![
                    ("old_stream", uuid(STREAM)),
                    (
                        "ranges",
                        Value::Array(vec![map(vec![("from", int(0)), ("to", bad.clone())])]),
                    ),
                ])
            ),
            DecodeErrorKind::Invalid
        );
        assert_eq!(
            malformed_kind(
                "error",
                &map(vec![(
                    "error",
                    map(vec![("gap", map(vec![("expected", bad)]))])
                )])
            ),
            DecodeErrorKind::Invalid
        );
    }
    assert_eq!(
        decode(
            "ack",
            &map(vec![("stream", uuid(STREAM)), ("a", int(u64::MAX))])
        )
        .unwrap(),
        TelemetryMessage::Ack(Ack {
            stream: STREAM,
            a: u64::MAX
        })
    );
}

#[test]
fn optional_fields_are_omitted_and_read_null_as_absent() {
    let without = TelemetryMessage::ResumeInfo(ResumeInfo {
        stream: STREAM,
        a: 0,
        last_stored: None,
    });
    round_trip(&without, &["stream", "a"]);
    assert_eq!(
        decode(
            "resume_info",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("a", int(0)),
                ("last_stored", Value::Null),
            ])
        )
        .unwrap(),
        without
    );
    assert_eq!(
        decode(
            "resume_info",
            &map(vec![("stream", uuid(STREAM)), ("a", int(0))])
        )
        .unwrap(),
        without
    );

    let streamless = TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: None,
        error: TelemetryError::Closed,
    });
    round_trip(&streamless, &["error"]);
    assert_eq!(
        decode(
            "error",
            &map(vec![("stream", Value::Null), ("error", text("closed"))])
        )
        .unwrap(),
        streamless
    );
    assert_eq!(
        decode("error", &map(vec![("error", text("closed"))])).unwrap(),
        streamless
    );
}

#[test]
fn last_stored_hash_is_exactly_16_bytes() {
    for len in [0, 15, 17, 32] {
        assert_eq!(
            malformed_kind(
                "resume_info",
                &map(vec![
                    ("stream", uuid(STREAM)),
                    ("a", int(1)),
                    (
                        "last_stored",
                        map(vec![("seq", int(1)), ("hash", Value::Bytes(vec![7; len]))]),
                    ),
                ])
            ),
            DecodeErrorKind::Invalid,
            "{len} bytes"
        );
    }
    // An array of 16 integers is not a byte string.
    assert_eq!(
        malformed_kind(
            "resume_info",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("a", int(1)),
                (
                    "last_stored",
                    map(vec![
                        ("seq", int(1)),
                        ("hash", Value::Array(vec![int(0); 16])),
                    ]),
                ),
            ])
        ),
        DecodeErrorKind::Invalid
    );
    let envelope = round_trip(
        &TelemetryMessage::ResumeInfo(ResumeInfo {
            stream: STREAM,
            a: 10,
            last_stored: Some(last_stored()),
        }),
        &["stream", "a", "last_stored"],
    );
    let Value::Map(entries) =
        ciborium::from_reader::<Value, _>(envelope.body().as_bytes()).unwrap()
    else {
        panic!("not a map");
    };
    let (_, stored) = entries
        .iter()
        .find(|(key, _)| key == &text("last_stored"))
        .unwrap();
    assert_eq!(
        stored,
        &map(vec![
            ("seq", int(9)),
            ("hash", Value::Bytes(b"0123456789abcdef".to_vec())),
        ])
    );
}

#[test]
fn relations_between_values_are_not_checked() {
    round_trip(
        &TelemetryMessage::DroppedRange(DroppedRange {
            stream: STREAM,
            from: 9,
            to: 2,
            reason: DropReason::TooLarge,
        }),
        &["stream", "from", "to", "reason"],
    );
    round_trip(
        &TelemetryMessage::LostOnReset(LostOnReset {
            old_stream: STREAM,
            ranges: vec![SeqRange { from: 7, to: 3 }],
        }),
        &["old_stream", "ranges"],
    );
    round_trip(
        &TelemetryMessage::ResumeInfo(ResumeInfo {
            stream: STREAM,
            a: 3,
            last_stored: Some(LastStored {
                seq: 100,
                hash: [0; 16],
            }),
        }),
        &["stream", "a", "last_stored"],
    );
}

#[test]
fn empty_lists_round_trip() {
    let batch = RecordBatch::new(STREAM, Vec::new()).unwrap();
    assert!(batch.records().is_empty());
    round_trip(
        &TelemetryMessage::RecordBatch(batch),
        &["stream", "records"],
    );
    round_trip(
        &TelemetryMessage::LostOnReset(LostOnReset {
            old_stream: STREAM,
            ranges: Vec::new(),
        }),
        &["old_stream", "ranges"],
    );
}

fn real_record_bytes() -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Body {
        image: String,
    }
    let record = Record {
        header: RecordHeader {
            endpoint_id: Uuid::from_u128(1),
            stream: STREAM,
            seq: 0,
            event_time: Timestamp::from_second(1_700_000_000).unwrap(),
            collected_at: Timestamp::from_second(1_700_000_001).unwrap(),
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
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: RecordBody::encode(&Body {
            image: "cmd.exe".to_owned(),
        })
        .unwrap(),
    };
    record.to_bytes().unwrap()
}

#[test]
fn records_travel_bit_for_bit() {
    // A record with a field this crate does not know.
    let mut value: Value = ciborium::from_reader(real_record_bytes().as_slice()).unwrap();
    let Value::Map(entries) = &mut value else {
        panic!("a record is a map");
    };
    entries.push((text("added_later"), map(vec![("x", int(1))])));
    let with_unknown_field = cbor::to_vec(&value).unwrap();
    assert!(Record::from_bytes(&with_unknown_field).is_ok());

    let records = vec![
        real_record_bytes(),
        with_unknown_field,
        // An indefinite-length map, {"a": 1}, not in any canonical form.
        vec![0xbf, 0x61, b'a', 0x01, 0xff],
        // An integer 1 in a needlessly long encoding.
        vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        // Bytes that are not CBOR at all.
        vec![0xff, 0x1c, 0x00, 0xfe],
        Vec::new(),
    ];
    let hashes: Vec<[u8; 16]> = records.iter().map(|record| record_hash(record)).collect();
    let batch = RecordBatch::new(STREAM, records.clone()).unwrap();
    assert_eq!(batch.stream(), STREAM);
    let envelope = round_trip(
        &TelemetryMessage::RecordBatch(batch),
        &["stream", "records"],
    );
    let TelemetryMessage::RecordBatch(received) =
        TelemetryMessage::decode(envelope.t(), envelope.body()).unwrap()
    else {
        panic!("expected a record batch");
    };
    assert_eq!(received.stream(), STREAM);
    assert_eq!(received.records(), records.as_slice());
    let received_hashes: Vec<[u8; 16]> = received
        .records()
        .iter()
        .map(|record| record_hash(record))
        .collect();
    assert_eq!(received_hashes, hashes);
    assert_eq!(received.into_records(), records);

    // Each record is a CBOR byte string holding exactly those bytes.
    let Value::Map(entries) =
        ciborium::from_reader::<Value, _>(envelope.body().as_bytes()).unwrap()
    else {
        panic!("not a map");
    };
    let (_, list) = entries
        .iter()
        .find(|(key, _)| key == &text("records"))
        .unwrap();
    assert_eq!(
        list,
        &Value::Array(records.iter().cloned().map(Value::Bytes).collect())
    );
}

#[test]
fn records_must_be_byte_strings() {
    for element in [
        Value::Array(vec![int(1), int(2)]),
        text("abc"),
        int(1),
        map(vec![]),
        Value::Null,
    ] {
        assert_eq!(
            malformed_kind(
                "record_batch",
                &map(vec![
                    ("stream", uuid(STREAM)),
                    (
                        "records",
                        Value::Array(vec![Value::Bytes(vec![1]), element])
                    ),
                ])
            ),
            DecodeErrorKind::Invalid
        );
    }
    assert_eq!(
        malformed_kind(
            "record_batch",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("records", Value::Bytes(vec![1]))
            ])
        ),
        DecodeErrorKind::Invalid
    );
}

fn batch_body(stream: Option<Uuid>, records: &[Vec<u8>]) -> Value {
    let mut entries = Vec::new();
    if let Some(stream) = stream {
        entries.push(("stream", uuid(stream)));
    }
    entries.push((
        "records",
        Value::Array(records.iter().cloned().map(Value::Bytes).collect()),
    ));
    map(entries)
}

#[test]
fn batches_at_the_limits_build_and_round_trip() {
    assert_eq!(MAX_RECORD_LEN, 262_144);
    assert_eq!(MAX_BATCH_LEN, 1_048_576);
    let one = vec![vec![0x5a; MAX_RECORD_LEN]];
    let full = vec![vec![1; MAX_RECORD_LEN]; 4];
    assert_eq!(full.iter().map(Vec::len).sum::<usize>(), MAX_BATCH_LEN);
    for records in [one, full] {
        let batch = RecordBatch::new(STREAM, records.clone()).unwrap();
        let envelope = round_trip(
            &TelemetryMessage::RecordBatch(batch),
            &["stream", "records"],
        );
        let Ok(TelemetryMessage::RecordBatch(received)) =
            TelemetryMessage::decode(envelope.t(), envelope.body())
        else {
            panic!("expected a record batch");
        };
        assert_eq!(received.into_records(), records);
        assert!(matches!(
            decode("record_batch", &batch_body(Some(STREAM), &records)),
            Ok(TelemetryMessage::RecordBatch(_))
        ));
    }
}

fn oversized() -> [(Vec<Vec<u8>>, RecordBatchTooLarge); 2] {
    [
        (
            vec![vec![0], vec![9; MAX_RECORD_LEN + 1]],
            RecordBatchTooLarge::Record {
                index: 1,
                len: MAX_RECORD_LEN + 1,
            },
        ),
        (
            {
                let mut records = vec![vec![1; MAX_RECORD_LEN]; 4];
                records.push(vec![2]);
                records
            },
            RecordBatchTooLarge::Batch {
                len: MAX_BATCH_LEN + 1,
            },
        ),
    ]
}

#[test]
fn batches_past_the_limits_do_not_build() {
    for (records, expected) in oversized() {
        assert_eq!(RecordBatch::new(STREAM, records), Err(expected));
    }
}

#[test]
fn batches_past_the_limits_are_too_large_when_received() {
    for (records, _) in oversized() {
        let body = batch_body(Some(OTHER_STREAM), &records);
        let result = decode("record_batch", &body);
        assert_eq!(
            result,
            Err(TelemetryDecodeError::BatchTooLarge {
                stream: OTHER_STREAM
            })
        );
        let Err(TelemetryDecodeError::BatchTooLarge { stream }) = result else {
            unreachable!();
        };
        // The refusal that a receiver sends for it.
        round_trip(
            &TelemetryMessage::ErrorMessage(ErrorMessage {
                stream: Some(stream),
                error: TelemetryError::TooLarge,
            }),
            &["stream", "error"],
        );
        // Through the generic body decoder, the same batch is an ordinary
        // decoding error.
        let error = self::body("record_batch", &body)
            .decode::<RecordBatch>()
            .unwrap_err();
        assert_eq!(error.kind(), DecodeErrorKind::Invalid);
    }
}

#[test]
fn malformed_batches_past_the_limits_are_malformed() {
    for (records, _) in oversized() {
        assert_eq!(
            malformed_kind("record_batch", &batch_body(None, &records)),
            DecodeErrorKind::Invalid
        );
        let mut elements: Vec<Value> = records.iter().cloned().map(Value::Bytes).collect();
        elements.push(text("not bytes"));
        assert_eq!(
            malformed_kind(
                "record_batch",
                &map(vec![
                    ("stream", uuid(STREAM)),
                    ("records", Value::Array(elements)),
                ])
            ),
            DecodeErrorKind::Invalid
        );
        let mut entries = vec![("stream", uuid(STREAM))];
        entries.push((
            "records",
            Value::Array(records.iter().cloned().map(Value::Bytes).collect()),
        ));
        entries.push(("stream", uuid(STREAM)));
        assert_eq!(
            malformed_kind("record_batch", &map(entries)),
            DecodeErrorKind::DuplicateKey
        );
    }
}

#[test]
fn standing_errors_travel_without_a_stream() {
    for (error, tag) in [
        (TelemetryError::NotListed, "not_listed"),
        (TelemetryError::Suspended, "suspended"),
        (TelemetryError::LeaseExpired, "lease_expired"),
    ] {
        let message = TelemetryMessage::ErrorMessage(ErrorMessage {
            stream: None,
            error: error.clone(),
        });
        let envelope = round_trip(&message, &["error"]);
        assert_eq!(envelope.t(), "error");
        assert_eq!(
            ciborium::from_reader::<Value, _>(envelope.body().as_bytes()).unwrap(),
            map(vec![("error", text(tag))])
        );
        assert_eq!(
            TelemetryMessage::decode(envelope.t(), envelope.body()).unwrap(),
            TelemetryMessage::ErrorMessage(ErrorMessage {
                stream: None,
                error
            })
        );
    }
}

#[test]
fn enums_in_messages_tolerate_newer_peers() {
    assert_eq!(
        decode(
            "dropped_range",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("from", int(1)),
                ("to", int(2)),
                (
                    "reason",
                    map(vec![("disk_full", map(vec![("free", int(0))]))])
                ),
            ])
        )
        .unwrap(),
        TelemetryMessage::DroppedRange(DroppedRange {
            stream: STREAM,
            from: 1,
            to: 2,
            reason: DropReason::Other("disk_full".to_owned()),
        })
    );
    assert_eq!(
        decode(
            "error",
            &map(vec![
                ("stream", uuid(STREAM)),
                ("error", text("rate_limited"))
            ])
        )
        .unwrap(),
        TelemetryMessage::ErrorMessage(ErrorMessage {
            stream: Some(STREAM),
            error: TelemetryError::Other("rate_limited".to_owned()),
        })
    );
    // A registered tag never leaks into `Other`.
    for (tag, expected) in [
        ("closed", TelemetryError::Closed),
        ("unsupported_kind", TelemetryError::UnsupportedKind),
    ] {
        assert_eq!(
            decode("error", &map(vec![("error", map(vec![(tag, int(1))]))])).unwrap(),
            TelemetryMessage::ErrorMessage(ErrorMessage {
                stream: None,
                error: expected,
            })
        );
    }
    assert_eq!(
        malformed_kind("error", &map(vec![("error", text("gap"))])),
        DecodeErrorKind::Invalid
    );
}
