//! The telemetry record format, its helpers and the kind registry, driven
//! through the public API, against hand-made CBOR.
#![cfg(feature = "telemetry")]

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::net::IpAddr;

use ciborium::Value;
use jiff::{SignedDuration, Timestamp};
use senta_protocol::connection::{AcceptedKind, ClockOffset, DecodeErrorKind, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::{
    NetState, NetStateGap, NetStateSource, NetStateSpan, ProcessKey, Record, RecordBody,
    RecordEncodeError, RecordHeader, ResolvedNetState, ip, kind, record_hash, resolve_net_state,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const HEADER_KEYS: [&str; 13] = [
    "endpoint_id",
    "stream",
    "seq",
    "event_time",
    "collected_at",
    "clock_offset",
    "hostname",
    "ips",
    "default_route_ip",
    "net_state_source",
    "os",
    "collection_mode",
    "process_key",
];

const REQUIRED_HEADER_KEYS: [&str; 10] = [
    "endpoint_id",
    "stream",
    "seq",
    "event_time",
    "collected_at",
    "hostname",
    "ips",
    "net_state_source",
    "os",
    "collection_mode",
];

fn at(nanos: i64) -> Timestamp {
    Timestamp::from_nanosecond(i128::from(nanos) + 1_700_000_000_000_000_000).unwrap()
}

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: i64) -> Value {
    Value::from(n)
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn encode(value: &Value) -> Vec<u8> {
    cbor::to_vec(value).unwrap()
}

fn to_value(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

fn entries(value: &Value) -> &Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

fn entries_mut(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

fn keys(value: &Value) -> BTreeSet<String> {
    entries(value)
        .iter()
        .map(|(key, _)| key.as_text().unwrap().to_owned())
        .collect()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    entries(value)
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    entries_mut(value)
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn remove(value: &mut Value, name: &str) {
    let entries = entries_mut(value);
    let before = entries.len();
    entries.retain(|(key, _)| key.as_text() != Some(name));
    assert_eq!(entries.len(), before - 1, "no field {name}");
}

fn push(value: &mut Value, name: &str, field: Value) {
    entries_mut(value).push((text(name), field));
}

fn full_header() -> RecordHeader {
    RecordHeader {
        endpoint_id: Uuid::from_u128(0x11),
        stream: Uuid::from_u128(0x22),
        seq: 42,
        event_time: at(1),
        collected_at: at(2),
        clock_offset: Some(ClockOffset {
            offset_ms: 250,
            uncertainty_ms: 3,
            measured_at: at(-5),
        }),
        hostname: "host-1".to_owned(),
        ips: vec![addr("192.0.2.10"), addr("2001:db8::10")],
        default_route_ip: Some(addr("192.0.2.1")),
        net_state_source: NetStateSource::Observed,
        os: OsInfo {
            family: OsFamily::Windows,
            version: "10.0.22631".to_owned(),
        },
        collection_mode: CollectionMode::Extended,
        process_key: Some(ProcessKey {
            os: OsFamily::Windows,
            value: vec![1, 2, 3, 4],
        }),
    }
}

fn bare_header() -> RecordHeader {
    RecordHeader {
        clock_offset: None,
        ips: Vec::new(),
        default_route_ip: None,
        net_state_source: NetStateSource::Unknown,
        process_key: None,
        ..full_header()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SampleBody {
    image: String,
    pid: u32,
    #[serde(with = "cbor::bytes")]
    hash: Vec<u8>,
    args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
}

fn sample_body() -> SampleBody {
    SampleBody {
        image: "C:\\Windows\\System32\\cmd.exe".to_owned(),
        pid: 4242,
        hash: vec![0xde, 0xad, 0xbe, 0xef],
        args: vec!["/c".to_owned(), "dir".to_owned()],
        parent: Some("explorer.exe".to_owned()),
    }
}

fn record(header: RecordHeader) -> Record {
    Record {
        header,
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: RecordBody::encode(&sample_body()).unwrap(),
    }
}

/// A record as a CBOR value, to be changed by hand before decoding.
fn record_value(record: &Record) -> Value {
    to_value(&record.to_bytes().unwrap())
}

fn decode_kind(bytes: &[u8]) -> DecodeErrorKind {
    Record::from_bytes(bytes).unwrap_err().kind()
}

#[test]
fn full_record_round_trips_under_its_key_names() {
    let record = record(full_header());
    let bytes = record.to_bytes().unwrap();
    assert_eq!(Record::from_bytes(&bytes).unwrap(), record);

    let value = to_value(&bytes);
    assert_eq!(
        keys(&value),
        ["header", "kind", "schema", "body"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let header = field(&value, "header");
    assert_eq!(
        keys(header),
        HEADER_KEYS.into_iter().map(str::to_owned).collect()
    );
    assert_eq!(field(&value, "kind"), &int(1));
    assert_eq!(field(&value, "schema"), &int(1));
    assert_eq!(
        field(header, "endpoint_id"),
        &Value::Bytes(vec![0; 15].into_iter().chain([0x11]).collect())
    );
    assert_eq!(field(header, "seq"), &int(42));
    assert_eq!(field(header, "event_time"), &int(1_700_000_000_000_000_001));
    assert_eq!(field(header, "net_state_source"), &text("observed"));
    assert_eq!(field(header, "collection_mode"), &text("extended"));
    assert_eq!(
        field(header, "os"),
        &map(vec![
            (text("family"), text("windows")),
            (text("version"), text("10.0.22631")),
        ])
    );
    assert_eq!(
        field(header, "process_key"),
        &map(vec![
            (text("os"), text("windows")),
            (text("value"), Value::Bytes(vec![1, 2, 3, 4])),
        ])
    );
    assert_eq!(
        field(header, "default_route_ip"),
        &Value::Bytes(vec![192, 0, 2, 1])
    );
}

#[test]
fn bare_record_round_trips_without_optional_keys() {
    let record = record(bare_header());
    let bytes = record.to_bytes().unwrap();
    assert_eq!(Record::from_bytes(&bytes).unwrap(), record);

    let value = to_value(&bytes);
    let header = field(&value, "header");
    assert_eq!(
        keys(header),
        REQUIRED_HEADER_KEYS
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(field(header, "ips"), &Value::Array(Vec::new()));
}

#[test]
fn null_optional_fields_read_as_none() {
    let mut value = record_value(&record(full_header()));
    let header = field_mut(&mut value, "header");
    for name in ["clock_offset", "default_route_ip", "process_key"] {
        *field_mut(header, name) = Value::Null;
    }
    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    assert_eq!(decoded.header.clock_offset, None);
    assert_eq!(decoded.header.default_route_ip, None);
    assert_eq!(decoded.header.process_key, None);
}

#[test]
fn missing_required_fields_fail() {
    let full = record_value(&record(full_header()));
    for name in REQUIRED_HEADER_KEYS {
        let mut value = full.clone();
        remove(field_mut(&mut value, "header"), name);
        assert_eq!(
            decode_kind(&encode(&value)),
            DecodeErrorKind::Invalid,
            "without {name}"
        );
    }
    for name in ["header", "kind", "schema", "body"] {
        let mut value = full.clone();
        remove(&mut value, name);
        assert_eq!(
            decode_kind(&encode(&value)),
            DecodeErrorKind::Invalid,
            "without {name}"
        );
    }
}

#[test]
fn out_of_range_kind_and_schema_and_non_map_body_fail() {
    let full = record_value(&record(full_header()));
    for name in ["kind", "schema"] {
        let mut value = full.clone();
        *field_mut(&mut value, name) = int(65_536);
        assert_eq!(
            decode_kind(&encode(&value)),
            DecodeErrorKind::Invalid,
            "{name}"
        );
        *field_mut(&mut value, name) = int(65_535);
        assert!(Record::from_bytes(&encode(&value)).is_ok(), "{name}");
    }
    for body in [
        int(1),
        Value::Array(vec![int(1)]),
        text("body"),
        Value::Bytes(vec![1]),
        Value::Null,
    ] {
        let mut value = full.clone();
        *field_mut(&mut value, "body") = body.clone();
        assert_eq!(
            decode_kind(&encode(&value)),
            DecodeErrorKind::Invalid,
            "{body:?}"
        );
    }
}

#[test]
fn duplicate_keys_fail_at_every_depth() {
    let full = record_value(&record(full_header()));

    let mut top = full.clone();
    push(&mut top, "kind", int(2));

    let mut header = full.clone();
    push(field_mut(&mut header, "header"), "seq", int(1));

    let mut os = full.clone();
    push(
        field_mut(field_mut(&mut os, "header"), "os"),
        "version",
        text("11"),
    );

    let mut body = full.clone();
    push(field_mut(&mut body, "body"), "pid", int(1));

    let mut nested = full.clone();
    *field_mut(&mut nested, "body") = map(vec![(
        text("outer"),
        map(vec![(text("a"), int(1)), (text("a"), int(2))]),
    )]);

    for (name, value) in [
        ("top level", top),
        ("header", header),
        ("os", os),
        ("body", body),
        ("nested in body", nested),
    ] {
        assert_eq!(
            decode_kind(&encode(&value)),
            DecodeErrorKind::DuplicateKey,
            "{name}"
        );
    }
}

#[test]
fn body_is_kept_and_nested_duplicates_fail_side_by_side() {
    let full = record_value(&record(full_header()));
    let kept = map(vec![
        (
            text("outer"),
            map(vec![(text("a"), int(1)), (text("b"), int(2))]),
        ),
        (int(7), text("integer key")),
    ]);
    let duplicated = map(vec![
        (
            text("outer"),
            map(vec![(text("a"), int(1)), (text("a"), int(2))]),
        ),
        (int(7), text("integer key")),
    ]);

    let mut value = full.clone();
    *field_mut(&mut value, "body") = kept.clone();
    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    assert_eq!(decoded.body.decode::<Value>().unwrap(), kept);

    let mut value = full;
    *field_mut(&mut value, "body") = duplicated;
    assert_eq!(decode_kind(&encode(&value)), DecodeErrorKind::DuplicateKey);
}

#[test]
fn unknown_fields_are_ignored() {
    let record = record(full_header());
    let mut value = record_value(&record);
    push(&mut value, "future_top", int(1));
    let header = field_mut(&mut value, "header");
    push(header, "future_header", map(vec![(text("x"), int(1))]));
    push(field_mut(header, "os"), "build", int(22631));
    push(field_mut(header, "clock_offset"), "source", text("ntp"));
    push(
        field_mut(header, "process_key"),
        "note",
        Value::Array(vec![int(1)]),
    );
    assert_eq!(Record::from_bytes(&encode(&value)).unwrap(), record);
}

#[test]
fn body_entries_are_kept_and_written_back() {
    let body = map(vec![
        (text("int"), int(-7)),
        (text("big"), Value::from(u64::MAX)),
        (text("text"), text("value")),
        (text("bytes"), Value::Bytes(vec![0, 1, 2])),
        (
            text("array"),
            Value::Array(vec![int(1), text("two"), Value::Bytes(vec![3])]),
        ),
        (
            text("nested"),
            map(vec![
                (text("inner"), map(vec![(text("deep"), Value::Bool(true))])),
                (int(3), Value::Null),
            ]),
        ),
        (Value::Bytes(vec![9]), text("byte key")),
    ]);
    let mut value = record_value(&record(full_header()));
    *field_mut(&mut value, "body") = body.clone();

    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    assert_eq!(decoded.body.decode::<Value>().unwrap(), body);

    let again = decoded.to_bytes().unwrap();
    assert_eq!(field(&to_value(&again), "body"), &body);
    assert_eq!(Record::from_bytes(&again).unwrap(), decoded);
}

#[test]
fn body_keeps_floats_and_passes_over_tags() {
    let mut value = record_value(&record(full_header()));
    *field_mut(&mut value, "body") = map(vec![
        (text("ratio"), Value::Float(0.5)),
        (text("small"), Value::Float(-1.25e-3)),
        (
            text("tagged"),
            Value::Tag(32, Box::new(text("https://example.test/"))),
        ),
    ]);
    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    // A tag other than a bignum is passed over: its value stays, the tag
    // does not.
    assert_eq!(
        decoded.body.decode::<Value>().unwrap(),
        map(vec![
            (text("ratio"), Value::Float(0.5)),
            (text("small"), Value::Float(-1.25e-3)),
            (text("tagged"), text("https://example.test/")),
        ])
    );
}

#[test]
fn typed_body_round_trips() {
    let record = record(full_header());
    let bytes = record.to_bytes().unwrap();
    let decoded = Record::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.body.decode::<SampleBody>().unwrap(), sample_body());
    assert_eq!(
        field(&to_value(&bytes), "body"),
        &map(vec![
            (text("image"), text("C:\\Windows\\System32\\cmd.exe")),
            (text("pid"), int(4242)),
            (text("hash"), Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
            (text("args"), Value::Array(vec![text("/c"), text("dir")])),
            (text("parent"), text("explorer.exe")),
        ])
    );
}

#[test]
fn body_encode_refuses_non_maps() {
    assert!(RecordBody::encode(&5_u32).is_err());
    assert!(RecordBody::encode(&vec![1_u32, 2]).is_err());
    assert!(RecordBody::encode("text").is_err());
    assert_eq!(
        RecordBody::encode(&BTreeSet::<u32>::new()).ok(),
        None,
        "an empty set is an array, not a map"
    );
}

#[test]
fn body_decode_follows_the_strict_type_rules() {
    let mut value = record_value(&record(full_header()));
    let body = field_mut(&mut value, "body");
    *field_mut(body, "hash") = Value::Array(vec![int(0xde), int(0xad)]);
    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    assert_eq!(
        decoded.body.decode::<SampleBody>().unwrap_err().kind(),
        DecodeErrorKind::Invalid
    );

    // A field the body type does not know is ignored.
    let mut value = record_value(&record(full_header()));
    push(field_mut(&mut value, "body"), "future", int(1));
    let decoded = Record::from_bytes(&encode(&value)).unwrap();
    assert_eq!(decoded.body.decode::<SampleBody>().unwrap(), sample_body());
}

#[test]
fn clock_offset_is_a_field_map_and_negative_offsets_round_trip() {
    let mut header = full_header();
    header.clock_offset = Some(ClockOffset {
        offset_ms: -1_500,
        uncertainty_ms: 7,
        measured_at: at(9),
    });
    let record = record(header);
    let bytes = record.to_bytes().unwrap();
    let value = to_value(&bytes);
    assert_eq!(
        field(field(&value, "header"), "clock_offset"),
        &map(vec![
            (text("offset_ms"), int(-1_500)),
            (text("uncertainty_ms"), int(7)),
            (text("measured_at"), int(1_700_000_000_000_000_009)),
        ])
    );
    assert_eq!(Record::from_bytes(&bytes).unwrap(), record);
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct IpHolder {
    #[serde(with = "ip")]
    one: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "ip::option")]
    maybe: Option<IpAddr>,
    #[serde(with = "ip::list")]
    many: Vec<IpAddr>,
}

#[test]
fn ip_addresses_are_byte_strings_of_their_octets() {
    let mapped = addr("::ffff:192.0.2.7");
    assert!(matches!(mapped, IpAddr::V6(_)));
    let holder = IpHolder {
        one: addr("192.0.2.1"),
        maybe: Some(addr("2001:db8::1")),
        many: vec![mapped, addr("10.0.0.1")],
    };
    let bytes = cbor::to_vec(&holder).unwrap();
    let value = to_value(&bytes);
    assert_eq!(field(&value, "one"), &Value::Bytes(vec![192, 0, 2, 1]));
    let mut v6 = vec![0x20, 0x01, 0x0d, 0xb8];
    v6.extend([0; 11]);
    v6.push(1);
    assert_eq!(field(&value, "maybe"), &Value::Bytes(v6));
    let mut mapped_bytes = vec![0; 10];
    mapped_bytes.extend([0xff, 0xff, 192, 0, 2, 7]);
    assert_eq!(
        field(&value, "many"),
        &Value::Array(vec![
            Value::Bytes(mapped_bytes),
            Value::Bytes(vec![10, 0, 0, 1]),
        ])
    );
    let decoded = cbor::from_slice::<IpHolder>(&bytes).unwrap();
    assert_eq!(decoded, holder);
    assert!(matches!(decoded.many.first(), Some(IpAddr::V6(_))));

    // In a record header too.
    let mut header = full_header();
    header.ips = vec![mapped];
    let record = record(header);
    let decoded = Record::from_bytes(&record.to_bytes().unwrap()).unwrap();
    assert_eq!(decoded.header.ips, vec![mapped]);
}

#[test]
fn ip_addresses_of_other_lengths_fail() {
    let full = record_value(&record(full_header()));
    for len in [0, 3, 5, 15, 17] {
        let bad = Value::Bytes(vec![1; len]);
        let holder = map(vec![
            (text("one"), bad.clone()),
            (text("many"), Value::Array(Vec::new())),
        ]);
        assert_eq!(
            cbor::from_slice::<IpHolder>(&encode(&holder))
                .unwrap_err()
                .kind(),
            DecodeErrorKind::Invalid,
            "{len} bytes"
        );

        let mut value = full.clone();
        *field_mut(field_mut(&mut value, "header"), "default_route_ip") = bad.clone();
        assert_eq!(decode_kind(&encode(&value)), DecodeErrorKind::Invalid);

        let mut value = full.clone();
        *field_mut(field_mut(&mut value, "header"), "ips") = Value::Array(vec![bad]);
        assert_eq!(decode_kind(&encode(&value)), DecodeErrorKind::Invalid);
    }
    // An array of integers is not a byte string.
    let mut value = full;
    *field_mut(field_mut(&mut value, "header"), "default_route_ip") =
        Value::Array(vec![int(10), int(0), int(0), int(1)]);
    assert_eq!(decode_kind(&encode(&value)), DecodeErrorKind::Invalid);
}

fn check_tag_enum<T>(known: &[(T, &str)], unknown: &str, other: fn(String) -> T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    for (variant, tag) in known {
        let bytes = cbor::to_vec(variant).unwrap();
        assert_eq!(bytes, encode(&text(tag)));
        assert_eq!(&cbor::from_slice::<T>(&bytes).unwrap(), variant);
        // A known tag as a one-entry map is its variant.
        let mapped = encode(&map(vec![(text(tag), map(vec![(text("x"), int(1))]))]));
        assert_eq!(&cbor::from_slice::<T>(&mapped).unwrap(), variant);
    }
    assert_eq!(
        cbor::from_slice::<T>(&encode(&text(unknown))).unwrap(),
        other(unknown.to_owned())
    );
    assert_eq!(
        cbor::from_slice::<T>(&encode(&map(vec![(
            text(unknown),
            Value::Array(vec![int(1)])
        )])))
        .unwrap(),
        other(unknown.to_owned())
    );
    let value = other(unknown.to_owned());
    let bytes = cbor::to_vec(&value).unwrap();
    assert_eq!(bytes, encode(&text(unknown)));
    assert_eq!(cbor::from_slice::<T>(&bytes).unwrap(), value);

    let (_, first) = known.first().unwrap();
    for bad in [
        map(vec![
            (text(first), Value::Null),
            (text(unknown), Value::Null),
        ]),
        map(Vec::new()),
        map(vec![(int(1), Value::Null)]),
        int(1),
        Value::Bytes(first.as_bytes().to_vec()),
    ] {
        assert_eq!(
            cbor::from_slice::<T>(&encode(&bad)).unwrap_err().kind(),
            DecodeErrorKind::Invalid,
            "{bad:?}"
        );
    }
}

#[test]
fn tag_enums_follow_the_tag_rules() {
    check_tag_enum(
        &[
            (OsFamily::Windows, "windows"),
            (OsFamily::Linux, "linux"),
            (OsFamily::Macos, "macos"),
        ],
        "freebsd",
        OsFamily::Other,
    );
    check_tag_enum(
        &[
            (CollectionMode::Extended, "extended"),
            (CollectionMode::Essential, "essential"),
        ],
        "minimal",
        CollectionMode::Other,
    );
    check_tag_enum(
        &[
            (NetStateSource::Observed, "observed"),
            (NetStateSource::Inferred, "inferred"),
            (NetStateSource::Unknown, "unknown"),
        ],
        "relayed",
        NetStateSource::Other,
    );
}

#[test]
fn os_info_and_process_key_are_field_maps() {
    let info = OsInfo {
        family: OsFamily::Linux,
        version: "6.8.0".to_owned(),
    };
    let bytes = cbor::to_vec(&info).unwrap();
    assert_eq!(
        to_value(&bytes),
        map(vec![
            (text("family"), text("linux")),
            (text("version"), text("6.8.0")),
        ])
    );
    assert_eq!(cbor::from_slice::<OsInfo>(&bytes).unwrap(), info);

    let key = ProcessKey {
        os: OsFamily::Linux,
        value: vec![9, 8, 7],
    };
    let bytes = cbor::to_vec(&key).unwrap();
    assert_eq!(
        to_value(&bytes),
        map(vec![
            (text("os"), text("linux")),
            (text("value"), Value::Bytes(vec![9, 8, 7])),
        ])
    );
    assert_eq!(cbor::from_slice::<ProcessKey>(&bytes).unwrap(), key);
}

#[test]
fn unknown_network_state_must_carry_no_addresses() {
    let cases = [
        (Vec::new(), None, true),
        (vec![addr("192.0.2.10")], None, false),
        (Vec::new(), Some(addr("192.0.2.1")), false),
        (vec![addr("192.0.2.10")], Some(addr("192.0.2.1")), false),
    ];
    for (ips, default_route_ip, valid) in cases {
        let mut header = bare_header();
        header.ips = ips.clone();
        header.default_route_ip = default_route_ip;
        let record = record(header);
        if valid {
            assert_eq!(record.validate(), Ok(()));
            assert!(record.to_bytes().is_ok());
            continue;
        }
        let error = record.validate().unwrap_err();
        assert_eq!(error, RecordEncodeError::UnknownNetStateWithAddresses);
        assert_eq!(record.to_bytes().unwrap_err(), error);

        // A receiver still decodes such a record.
        let mut value = record_value(&{
            let mut fine = record.clone();
            fine.header.net_state_source = NetStateSource::Observed;
            fine
        });
        *field_mut(field_mut(&mut value, "header"), "net_state_source") = text("unknown");
        let decoded = Record::from_bytes(&encode(&value)).unwrap();
        assert_eq!(decoded, record, "{ips:?} {default_route_ip:?}");
    }
    // The rule holds only for `Unknown`.
    for source in [NetStateSource::Observed, NetStateSource::Inferred] {
        let mut header = full_header();
        header.net_state_source = source;
        assert_eq!(record(header).validate(), Ok(()));
    }
}

#[test]
fn record_hash_is_the_first_half_of_sha256() {
    let bytes = record(full_header()).to_bytes().unwrap();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(record_hash(&bytes)[..], digest[..16]);

    // Known answers, for bytes that are no CBOR value and for none at all.
    assert_eq!(
        record_hash(b""),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24,
        ]
    );
    assert!(Record::from_bytes(b"abc").is_err());
    assert_eq!(
        record_hash(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23,
        ]
    );
    assert_eq!(record_hash(&[0xff, 0x00]), record_hash(&[0xff, 0x00]));
}

/// A record from a newer sender: fields and tags this version does not
/// know, decoded, mapped to `Other`, and hashed by its bytes as they are.
#[test]
fn record_from_another_version() {
    let mut value = record_value(&record(full_header()));
    push(&mut value, "priority", int(3));
    let header = field_mut(&mut value, "header");
    push(header, "boot_id", Value::Bytes(vec![7; 16]));
    *field_mut(header, "net_state_source") = text("relayed");
    *field_mut(header, "collection_mode") =
        map(vec![(text("minimal"), map(vec![(text("level"), int(2))]))]);
    *field_mut(field_mut(header, "os"), "family") = text("freebsd");
    // A known tag as a map stays its variant, not `Other`.
    *field_mut(field_mut(header, "process_key"), "os") = map(vec![(text("windows"), int(1))]);
    let bytes = encode(&value);

    let decoded = Record::from_bytes(&bytes).unwrap();
    let header = &decoded.header;
    assert_eq!(
        header.net_state_source,
        NetStateSource::Other("relayed".to_owned())
    );
    assert_eq!(
        header.collection_mode,
        CollectionMode::Other("minimal".to_owned())
    );
    assert_eq!(header.os.family, OsFamily::Other("freebsd".to_owned()));
    assert_eq!(header.process_key.as_ref().unwrap().os, OsFamily::Windows);

    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(record_hash(&bytes)[..], digest[..16]);
    assert_eq!(record_hash(&bytes), record_hash(&bytes));
    // Encoding the decoded value again drops what was unknown, and with it
    // the hash: only the bytes as received hash as the sender's did.
    let again = decoded.to_bytes().unwrap();
    assert_ne!(again, bytes);
    assert_ne!(record_hash(&again), record_hash(&bytes));
}

fn state(ips: &[&str], default_route_ip: Option<&str>) -> NetState {
    NetState {
        ips: ips.iter().map(|s| addr(s)).collect(),
        default_route_ip: default_route_ip.map(addr),
    }
}

fn a() -> NetState {
    state(&["192.0.2.10", "2001:db8::10"], Some("192.0.2.1"))
}

fn b() -> NetState {
    state(&["198.51.100.10"], Some("198.51.100.1"))
}

const MINUTE: i64 = 60_000_000_000;
const TEN_MINUTES: i64 = 10 * MINUTE;

fn span(start: i64, end: i64, state: NetState) -> NetStateSpan {
    NetStateSpan {
        start: at(start),
        end: at(end),
        state,
    }
}

fn gap(start: i64, end: i64, before: NetState, after: NetState, suspended: bool) -> NetStateGap {
    NetStateGap {
        start: at(start),
        end: at(end),
        before,
        after,
        suspended,
    }
}

fn resolved(source: NetStateSource, state: &NetState) -> ResolvedNetState {
    ResolvedNetState {
        source,
        ips: state.ips.clone(),
        default_route_ip: state.default_route_ip,
    }
}

fn unknown() -> ResolvedNetState {
    ResolvedNetState {
        source: NetStateSource::Unknown,
        ips: Vec::new(),
        default_route_ip: None,
    }
}

#[test]
fn net_state_observed_within_a_span() {
    let s = span(0, 100, a());
    for t in [0, 50, 100] {
        assert_eq!(
            resolve_net_state(at(t), Some(&s), None),
            resolved(NetStateSource::Observed, &a())
        );
    }
    for t in [-1, 101] {
        assert_eq!(resolve_net_state(at(t), Some(&s), None), unknown());
    }
}

#[test]
fn net_state_inferred_across_a_short_unchanged_gap() {
    let g = gap(0, MINUTE, a(), a(), false);
    for t in [0, MINUTE / 2, MINUTE] {
        assert_eq!(
            resolve_net_state(at(t), None, Some(&g)),
            resolved(NetStateSource::Inferred, &a())
        );
    }
    // Just outside the gap, and outside any span.
    for t in [-1, MINUTE + 1] {
        assert_eq!(resolve_net_state(at(t), None, Some(&g)), unknown());
    }
    let s = span(-2 * MINUTE, -MINUTE, b());
    assert_eq!(resolve_net_state(at(-1), Some(&s), Some(&g)), unknown());
}

#[test]
fn net_state_gap_of_ten_minutes_is_the_limit() {
    let exact = gap(0, TEN_MINUTES, a(), a(), false);
    let over = gap(0, TEN_MINUTES + 1, a(), a(), false);
    for t in [0, TEN_MINUTES / 2, TEN_MINUTES] {
        assert_eq!(
            resolve_net_state(at(t), None, Some(&exact)),
            resolved(NetStateSource::Inferred, &a())
        );
        assert_eq!(resolve_net_state(at(t), None, Some(&over)), unknown());
    }
    assert_eq!(
        SignedDuration::from_nanos(TEN_MINUTES),
        SignedDuration::from_mins(10)
    );
}

#[test]
fn net_state_span_wins_where_it_meets_a_gap() {
    let s = span(-MINUTE, 0, b());
    let g = gap(0, MINUTE, a(), a(), false);
    assert_eq!(
        resolve_net_state(at(0), Some(&s), Some(&g)),
        resolved(NetStateSource::Observed, &b())
    );
    assert_eq!(
        resolve_net_state(at(1), Some(&s), Some(&g)),
        resolved(NetStateSource::Inferred, &a())
    );
}

#[test]
fn net_state_unknown_otherwise() {
    let t = at(MINUTE / 2);
    let cases = [
        (
            "one address differs",
            gap(
                0,
                MINUTE,
                state(&["192.0.2.10"], Some("192.0.2.1")),
                state(&["192.0.2.11"], Some("192.0.2.1")),
                false,
            ),
        ),
        (
            "only the default route differs",
            gap(
                0,
                MINUTE,
                state(&["192.0.2.10"], Some("192.0.2.1")),
                state(&["192.0.2.10"], Some("192.0.2.254")),
                false,
            ),
        ),
        (
            "one side has a default route",
            gap(
                0,
                MINUTE,
                state(&["192.0.2.10"], Some("192.0.2.1")),
                state(&["192.0.2.10"], None),
                false,
            ),
        ),
        ("suspended", gap(0, MINUTE, a(), a(), true)),
        ("ends before it starts", gap(MINUTE, 0, a(), a(), false)),
    ];
    for (name, g) in cases {
        assert_eq!(resolve_net_state(t, None, Some(&g)), unknown(), "{name}");
    }
    assert_eq!(
        resolve_net_state(t, Some(&span(MINUTE, 0, a())), None),
        unknown(),
        "a span that ends before it starts"
    );
    assert_eq!(resolve_net_state(t, None, None), unknown(), "no record");
}

#[test]
fn net_state_sameness_ignores_order_and_repetition() {
    let before = state(&["192.0.2.10", "2001:db8::10"], Some("192.0.2.1"));
    let after = state(
        &["2001:db8::10", "192.0.2.10", "2001:db8::10"],
        Some("192.0.2.1"),
    );
    assert!(before.is_same_as(&after));
    assert!(after.is_same_as(&before));
    assert!(state(&[], None).is_same_as(&state(&[], None)));
    let g = gap(0, MINUTE, before.clone(), after, false);
    assert_eq!(
        resolve_net_state(at(1), None, Some(&g)),
        resolved(NetStateSource::Inferred, &before)
    );
}

#[test]
fn kind_families_by_range() {
    use kind::KindFamily;

    for (number, family) in [
        (0, None),
        (1, Some(KindFamily::Sysmon)),
        (255, Some(KindFamily::Sysmon)),
        (256, None),
        (999, None),
        (1000, Some(KindFamily::WindowsEventLog)),
        (1099, Some(KindFamily::WindowsEventLog)),
        (1100, Some(KindFamily::LinuxLog)),
        (1199, Some(KindFamily::LinuxLog)),
        (1200, Some(KindFamily::Macos)),
        (1299, Some(KindFamily::Macos)),
        (1300, Some(KindFamily::HostState)),
        (1399, Some(KindFamily::HostState)),
        (1400, None),
        (65_535, None),
    ] {
        assert_eq!(kind::family(number), family, "{number}");
    }
}

#[test]
fn kind_registry_lists_the_e1_kinds() {
    use OsFamily::{Linux, Windows};

    let both = [Windows, Linux];
    let table: [(u16, u16, &[OsFamily]); 22] = [
        (kind::SYSMON_PROCESS_CREATE, 1, &both),
        (kind::SYSMON_FILE_CREATE_TIME, 2, &[Windows]),
        (kind::SYSMON_NETWORK_CONNECT, 3, &both),
        (kind::SYSMON_PROCESS_TERMINATE, 5, &both),
        (kind::SYSMON_DRIVER_LOAD, 6, &[Windows]),
        (kind::SYSMON_IMAGE_LOAD, 7, &[Windows]),
        (kind::SYSMON_CREATE_REMOTE_THREAD, 8, &[Windows]),
        (kind::SYSMON_RAW_ACCESS_READ, 9, &[Linux]),
        (kind::SYSMON_PROCESS_ACCESS, 10, &both),
        (kind::SYSMON_FILE_CREATE, 11, &both),
        (kind::SYSMON_REGISTRY_ADD_DELETE, 12, &[Windows]),
        (kind::SYSMON_REGISTRY_VALUE_SET, 13, &[Windows]),
        (kind::SYSMON_REGISTRY_RENAME, 14, &[Windows]),
        (kind::SYSMON_FILE_CREATE_STREAM_HASH, 15, &[Windows]),
        (kind::SYSMON_PIPE_CREATED, 17, &[Windows]),
        (kind::SYSMON_DNS_QUERY, 22, &[Windows]),
        (kind::SYSMON_FILE_DELETE, 23, &both),
        (kind::SYSMON_PROCESS_TAMPERING, 25, &[Windows]),
        (kind::SYSMON_FILE_DELETE_DETECTED, 26, &[Windows]),
        (kind::WINDOWS_EVENT_LOG, 1000, &[Windows]),
        (kind::JOURNALD, 1100, &[Linux]),
        (kind::AUDITD, 1101, &[Linux]),
    ];
    for (constant, number, os) in table {
        assert_eq!(constant, number);
        let info = kind::info(number).unwrap_or_else(|| panic!("no info for {number}"));
        let sent: BTreeSet<_> = info.os().iter().map(|os| format!("{os:?}")).collect();
        let expected: BTreeSet<_> = os.iter().map(|os| format!("{os:?}")).collect();
        assert_eq!(sent, expected, "{number}");
        assert_eq!(info.schema(), 1, "{number}");
    }
    let defined: BTreeSet<u16> = table.iter().map(|(number, _, _)| *number).collect();
    assert_eq!(defined.len(), 22);
    for number in 0..=u16::MAX {
        assert_eq!(
            kind::info(number).is_some(),
            defined.contains(&number),
            "{number}"
        );
    }
    for number in [4, 18, 255, 1001] {
        assert!(kind::info(number).is_none(), "{number}");
    }
}

#[test]
fn accepted_kinds() {
    let entry = |kind, schema_min, schema_max| AcceptedKind {
        kind,
        schema_min,
        schema_max,
    };
    let list = [entry(1, 2, 4), entry(3, 1, 1)];
    assert!(kind::accepts(&list, 1, 2));
    assert!(kind::accepts(&list, 1, 3));
    assert!(kind::accepts(&list, 1, 4));
    assert!(!kind::accepts(&list, 1, 1));
    assert!(!kind::accepts(&list, 1, 5));
    assert!(kind::accepts(&list, 3, 1));
    assert!(!kind::accepts(&list, 2, 2));
    assert!(!kind::accepts(&[], 1, 1));
    assert!(!kind::accepts(&[entry(1, 3, 2)], 1, 2));
    assert!(!kind::accepts(&[entry(1, 3, 2)], 1, 3));
    // Several elements for the same kind: one match is enough.
    let split = [entry(5, 1, 1), entry(5, 3, 2), entry(5, 4, 6)];
    assert!(kind::accepts(&split, 5, 1));
    assert!(kind::accepts(&split, 5, 5));
    assert!(!kind::accepts(&split, 5, 2));
}
