//! The log record kinds' bodies (Windows event log, journald, auditd) and
//! the header rule that keeps `process_key` off their records, driven
//! through the public API, against hand-made CBOR.
#![cfg(feature = "telemetry")]

use std::collections::BTreeSet;
use std::error::Error as _;

use ciborium::Value;
use jiff::Timestamp;
use senta_protocol::connection::{AcceptedKind, DecodeError, DecodeErrorKind, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::logs::{
    AuditRecord, AuditdBody, EventData, JournaldBody, KINDS, LogBody, LogField, LogValue,
    WindowsEventLogBody,
};
use senta_protocol::telemetry::{
    NetStateSource, ProcessKey, Record, RecordBody, RecordEncodeError, RecordHeader, kind,
};
use uuid::Uuid;

const WINDOWS_KEYS: [&str; 13] = [
    "channel",
    "provider",
    "event_id",
    "version",
    "level",
    "task",
    "opcode",
    "keywords",
    "record_id",
    "computer",
    "user_sid",
    "event_data",
    "user_data_xml",
];

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: u64) -> Value {
    Value::from(n)
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
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

fn first_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    match field_mut(value, name) {
        Value::Array(items) => items.first_mut().unwrap(),
        other => panic!("expected an array, got {other:?}"),
    }
}

/// A received body, as a record's decoder keeps it.
fn received(value: &Value) -> RecordBody {
    cbor::from_slice(&cbor::to_vec(value).unwrap()).unwrap()
}

fn decode(kind: u16, value: &Value) -> Result<LogBody, DecodeError> {
    LogBody::decode(kind, &received(value))
}

fn decode_kind(kind: u16, value: &Value) -> DecodeErrorKind {
    decode(kind, value).unwrap_err().kind()
}

/// The CBOR a body encodes as.
fn encoded(body: &LogBody) -> Value {
    body.to_body().unwrap().decode().unwrap()
}

/// Checks that `body` encodes as `expected` and that both it and
/// `expected` decode back to it.
fn assert_round_trip(body: &LogBody, expected: &Value) {
    assert_eq!(&encoded(body), expected);
    let decoded = LogBody::decode(body.kind(), &body.to_body().unwrap()).unwrap();
    assert_eq!(&decoded, body);
    assert_eq!(&decode(body.kind(), expected).unwrap(), body);
}

fn windows(value: &Value) -> WindowsEventLogBody {
    match decode(kind::WINDOWS_EVENT_LOG, value).unwrap() {
        LogBody::WindowsEventLog(body) => body,
        other => panic!("expected a Windows event log body, got {other:?}"),
    }
}

fn journald(value: &Value) -> JournaldBody {
    match decode(kind::JOURNALD, value).unwrap() {
        LogBody::Journald(body) => body,
        other => panic!("expected a journald body, got {other:?}"),
    }
}

fn auditd(value: &Value) -> AuditdBody {
    match decode(kind::AUDITD, value).unwrap() {
        LogBody::Auditd(body) => body,
        other => panic!("expected an auditd body, got {other:?}"),
    }
}

fn data(name: Option<&str>, value: &str) -> EventData {
    EventData {
        name: name.map(str::to_owned),
        value: value.to_owned(),
    }
}

fn log_text(name: &str, value: &str) -> LogField {
    LogField {
        name: name.to_owned(),
        value: LogValue::Text(value.to_owned()),
    }
}

fn log_bytes(name: &str, value: &[u8]) -> LogField {
    LogField {
        name: name.to_owned(),
        value: LogValue::Bytes(value.to_vec()),
    }
}

fn data_value(name: Option<&str>, value: &str) -> Value {
    let mut entries = Vec::new();
    if let Some(name) = name {
        entries.push(("name", text(name)));
    }
    entries.push(("value", text(value)));
    map(entries)
}

fn field_value(name: &str, value: Value) -> Value {
    map(vec![("name", text(name)), ("value", value)])
}

fn full_windows() -> WindowsEventLogBody {
    WindowsEventLogBody {
        channel: Some("Microsoft-Windows-Windows Defender/Operational".to_owned()),
        provider: Some("Microsoft-Windows-Windows Defender".to_owned()),
        event_id: Some(1116),
        version: Some(0),
        level: Some(3),
        task: Some(0),
        opcode: Some(0),
        keywords: Some(0x8000_0000_0000_0000),
        record_id: Some(4711),
        computer: Some("host-1.example.com".to_owned()),
        user_sid: Some("S-1-5-18".to_owned()),
        event_data: Some(vec![
            data(Some("Product Name"), "Microsoft Defender Antivirus"),
            data(Some("Threat Name"), "Virus:DOS/EICAR_Test_File"),
            data(Some("Path"), "file:_C:\\Users\\alice\\Downloads\\eicar.com"),
            data(Some("Remediation User"), ""),
        ]),
        user_data_xml: Some("<EventXML xmlns=\"Event_NS\"><Param>1</Param></EventXML>".to_owned()),
    }
}

fn full_windows_value() -> Value {
    map(vec![
        (
            "channel",
            text("Microsoft-Windows-Windows Defender/Operational"),
        ),
        ("provider", text("Microsoft-Windows-Windows Defender")),
        ("event_id", int(1116)),
        ("version", int(0)),
        ("level", int(3)),
        ("task", int(0)),
        ("opcode", int(0)),
        ("keywords", int(0x8000_0000_0000_0000)),
        ("record_id", int(4711)),
        ("computer", text("host-1.example.com")),
        ("user_sid", text("S-1-5-18")),
        (
            "event_data",
            Value::Array(vec![
                data_value(Some("Product Name"), "Microsoft Defender Antivirus"),
                data_value(Some("Threat Name"), "Virus:DOS/EICAR_Test_File"),
                data_value(Some("Path"), "file:_C:\\Users\\alice\\Downloads\\eicar.com"),
                data_value(Some("Remediation User"), ""),
            ]),
        ),
        (
            "user_data_xml",
            text("<EventXML xmlns=\"Event_NS\"><Param>1</Param></EventXML>"),
        ),
    ])
}

fn full_journald() -> JournaldBody {
    JournaldBody {
        fields: Some(vec![
            log_text("MESSAGE", "first line\nsecond line\n"),
            log_text("PRIORITY", "6"),
            log_text("_SYSTEMD_UNIT", "sshd.service"),
            log_bytes("BINARY", &[0xff, 0xfe, 0x00]),
            log_bytes("NUL_TEXT", &[0x61, 0x00, 0x62]),
            log_text("TAG", "one"),
            log_text("TAG", "two"),
            log_text("EMPTY", ""),
            log_bytes("EMPTY_BINARY", &[]),
            log_text("TAG", "three"),
        ]),
    }
}

fn full_journald_value() -> Value {
    map(vec![(
        "fields",
        Value::Array(vec![
            field_value("MESSAGE", text("first line\nsecond line\n")),
            field_value("PRIORITY", text("6")),
            field_value("_SYSTEMD_UNIT", text("sshd.service")),
            field_value("BINARY", bytes(&[0xff, 0xfe, 0x00])),
            field_value("NUL_TEXT", bytes(&[0x61, 0x00, 0x62])),
            field_value("TAG", text("one")),
            field_value("TAG", text("two")),
            field_value("EMPTY", text("")),
            field_value("EMPTY_BINARY", bytes(&[])),
            field_value("TAG", text("three")),
        ]),
    )])
}

/// `proctitle` as the audit line carries it in hexadecimal, decoded:
/// `/bin/sh -c id`, with NULs between the arguments.
const PROCTITLE: &[u8] = b"/bin/sh\0-c\0id";

fn full_auditd() -> AuditdBody {
    AuditdBody {
        serial: Some(u64::MAX),
        records: Some(vec![
            AuditRecord {
                record_type: "SYSCALL".to_owned(),
                fields: vec![
                    log_text("arch", "c000003e"),
                    log_text("syscall", "59"),
                    log_text("success", "yes"),
                    log_text("exe", "/usr/bin/dash"),
                    log_text("key", "exec"),
                ],
            },
            AuditRecord {
                record_type: "EXECVE".to_owned(),
                fields: vec![
                    log_text("argc", "3"),
                    log_text("a0", "/bin/sh"),
                    log_text("a1", "-c"),
                    log_text("a2", "id"),
                ],
            },
            AuditRecord {
                record_type: "PROCTITLE".to_owned(),
                fields: vec![log_bytes("proctitle", PROCTITLE)],
            },
        ]),
    }
}

fn full_auditd_value() -> Value {
    let line = |record_type: &str, fields: Vec<Value>| {
        map(vec![
            ("type", text(record_type)),
            ("fields", Value::Array(fields)),
        ])
    };
    map(vec![
        ("serial", int(u64::MAX)),
        (
            "records",
            Value::Array(vec![
                line(
                    "SYSCALL",
                    vec![
                        field_value("arch", text("c000003e")),
                        field_value("syscall", text("59")),
                        field_value("success", text("yes")),
                        field_value("exe", text("/usr/bin/dash")),
                        field_value("key", text("exec")),
                    ],
                ),
                line(
                    "EXECVE",
                    vec![
                        field_value("argc", text("3")),
                        field_value("a0", text("/bin/sh")),
                        field_value("a1", text("-c")),
                        field_value("a2", text("id")),
                    ],
                ),
                line(
                    "PROCTITLE",
                    vec![field_value("proctitle", bytes(PROCTITLE))],
                ),
            ]),
        ),
    ])
}

fn full_bodies() -> [(LogBody, Value); 3] {
    [
        (
            LogBody::WindowsEventLog(full_windows()),
            full_windows_value(),
        ),
        (LogBody::Journald(full_journald()), full_journald_value()),
        (LogBody::Auditd(full_auditd()), full_auditd_value()),
    ]
}

fn empty_bodies() -> [LogBody; 3] {
    [
        LogBody::WindowsEventLog(WindowsEventLogBody::default()),
        LogBody::Journald(JournaldBody::default()),
        LogBody::Auditd(AuditdBody::default()),
    ]
}

#[test]
fn full_bodies_round_trip_under_their_key_names() {
    for (body, value) in full_bodies() {
        assert_round_trip(&body, &value);
    }
    assert_eq!(
        keys(&full_windows_value()),
        WINDOWS_KEYS.iter().map(|key| (*key).to_owned()).collect()
    );
}

#[test]
fn empty_bodies_round_trip_as_empty_maps() {
    for body in empty_bodies() {
        assert_round_trip(&body, &map(Vec::new()));
    }
}

#[test]
fn null_optional_fields_read_as_none() {
    let nulls = |names: &[&str]| map(names.iter().map(|name| (*name, Value::Null)).collect());
    assert_eq!(
        windows(&nulls(&WINDOWS_KEYS)),
        WindowsEventLogBody::default()
    );
    assert_eq!(journald(&nulls(&["fields"])), JournaldBody::default());
    assert_eq!(
        auditd(&nulls(&["serial", "records"])),
        AuditdBody::default()
    );

    // An `EventData` element's `name` too.
    let value = map(vec![(
        "event_data",
        Value::Array(vec![map(vec![("name", Value::Null), ("value", text("x"))])]),
    )]);
    assert_eq!(windows(&value).event_data, Some(vec![data(None, "x")]));
}

#[test]
fn each_absent_field_encodes_without_its_key() {
    let full = full_windows();
    let clears: [fn(&mut WindowsEventLogBody); 13] = [
        |body| body.channel = None,
        |body| body.provider = None,
        |body| body.event_id = None,
        |body| body.version = None,
        |body| body.level = None,
        |body| body.task = None,
        |body| body.opcode = None,
        |body| body.keywords = None,
        |body| body.record_id = None,
        |body| body.computer = None,
        |body| body.user_sid = None,
        |body| body.event_data = None,
        |body| body.user_data_xml = None,
    ];
    for (name, clear) in WINDOWS_KEYS.iter().zip(clears) {
        let mut body = full.clone();
        clear(&mut body);
        let mut expected = full_windows_value();
        remove(&mut expected, name);
        assert_round_trip(&LogBody::WindowsEventLog(body), &expected);
    }

    let mut body = full_auditd();
    body.serial = None;
    let mut expected = full_auditd_value();
    remove(&mut expected, "serial");
    assert_round_trip(&LogBody::Auditd(body), &expected);
}

#[test]
fn legacy_provider_event_lacks_what_its_source_lacks() {
    // An event from a legacy provider, named by `EventSourceName`, with no
    // `Channel`, `Version`, `Level`, `Task`, `Opcode`, `Keywords` or
    // `EventRecordID` in its XML.
    let value = map(vec![
        ("provider", text("MsiInstaller")),
        ("event_id", int(11707)),
        ("computer", text("host-1")),
        (
            "event_data",
            Value::Array(vec![data_value(None, "Product: Example -- ok.")]),
        ),
    ]);
    let body = windows(&value);
    assert_eq!(
        body,
        WindowsEventLogBody {
            provider: Some("MsiInstaller".to_owned()),
            event_id: Some(11707),
            computer: Some("host-1".to_owned()),
            event_data: Some(vec![data(None, "Product: Example -- ok.")]),
            ..WindowsEventLogBody::default()
        }
    );
    assert_round_trip(&LogBody::WindowsEventLog(body), &value);
}

#[test]
fn policy_exclusions_read_as_absent() {
    let mut value = full_windows_value();
    remove(&mut value, "event_data");
    remove(&mut value, "user_sid");
    let body = windows(&value);
    assert_eq!(body.event_data, None);
    assert_eq!(body.user_sid, None);
    assert_eq!(
        body,
        WindowsEventLogBody {
            event_data: None,
            user_sid: None,
            ..full_windows()
        }
    );

    let mut value = full_journald_value();
    remove(&mut value, "fields");
    assert_eq!(journald(&value).fields, None);

    let mut value = full_auditd_value();
    remove(&mut value, "records");
    let body = auditd(&value);
    assert_eq!(body.records, None);
    assert_eq!(body.serial, Some(u64::MAX));
}

#[test]
fn source_omission_and_policy_exclusion_read_the_same() {
    // The same event, once with `Channel` missing from its XML and
    // `user_sid` left out by policy, and once with the reverse: a receiver
    // reads no value for both fields either way.
    let mut no_channel = full_windows_value();
    remove(&mut no_channel, "channel");
    remove(&mut no_channel, "user_sid");
    let body = windows(&no_channel);
    assert_eq!((body.channel, body.user_sid), (None, None));

    let mut both_null = full_windows_value();
    *field_mut(&mut both_null, "channel") = Value::Null;
    *field_mut(&mut both_null, "user_sid") = Value::Null;
    assert_eq!(windows(&both_null), windows(&no_channel));
}

#[test]
fn empty_lists_and_absent_lists_differ() {
    let windows_empty = WindowsEventLogBody {
        event_data: Some(Vec::new()),
        ..WindowsEventLogBody::default()
    };
    let journald_empty = JournaldBody {
        fields: Some(Vec::new()),
    };
    let auditd_empty = AuditdBody {
        serial: None,
        records: Some(vec![AuditRecord {
            record_type: "EOE".to_owned(),
            fields: Vec::new(),
        }]),
    };
    let auditd_no_records = AuditdBody {
        serial: None,
        records: Some(Vec::new()),
    };
    let cases = [
        (
            LogBody::WindowsEventLog(windows_empty),
            map(vec![("event_data", Value::Array(Vec::new()))]),
        ),
        (
            LogBody::Journald(journald_empty),
            map(vec![("fields", Value::Array(Vec::new()))]),
        ),
        (
            LogBody::Auditd(auditd_empty),
            map(vec![(
                "records",
                Value::Array(vec![map(vec![
                    ("type", text("EOE")),
                    ("fields", Value::Array(Vec::new())),
                ])]),
            )]),
        ),
        (
            LogBody::Auditd(auditd_no_records),
            map(vec![("records", Value::Array(Vec::new()))]),
        ),
    ];
    for (body, value) in cases {
        assert_round_trip(&body, &value);
        assert!(!empty_bodies().contains(&body), "{body:?}");
    }
}

#[test]
fn unnamed_event_data_keeps_no_name_and_its_order() {
    let body = WindowsEventLogBody {
        event_data: Some(vec![
            data(None, "first"),
            data(Some("Named"), "second"),
            data(None, ""),
            data(Some("Named"), "fourth"),
        ]),
        ..WindowsEventLogBody::default()
    };
    let value = map(vec![(
        "event_data",
        Value::Array(vec![
            map(vec![("value", text("first"))]),
            data_value(Some("Named"), "second"),
            map(vec![("value", text(""))]),
            data_value(Some("Named"), "fourth"),
        ]),
    )]);
    assert_round_trip(&LogBody::WindowsEventLog(body), &value);
}

#[test]
fn missing_required_element_fields_fail() {
    let mut value = full_windows_value();
    remove(first_mut(&mut value, "event_data"), "value");
    assert_eq!(
        decode_kind(kind::WINDOWS_EVENT_LOG, &value),
        DecodeErrorKind::Invalid
    );

    for name in ["name", "value"] {
        let mut value = full_journald_value();
        remove(first_mut(&mut value, "fields"), name);
        assert_eq!(
            decode_kind(kind::JOURNALD, &value),
            DecodeErrorKind::Invalid,
            "{name}"
        );
    }

    for name in ["type", "fields"] {
        let mut value = full_auditd_value();
        remove(first_mut(&mut value, "records"), name);
        assert_eq!(
            decode_kind(kind::AUDITD, &value),
            DecodeErrorKind::Invalid,
            "{name}"
        );
    }
    for name in ["name", "value"] {
        let mut value = full_auditd_value();
        remove(first_mut(first_mut(&mut value, "records"), "fields"), name);
        assert_eq!(
            decode_kind(kind::AUDITD, &value),
            DecodeErrorKind::Invalid,
            "{name}"
        );
    }
}

#[test]
fn integers_follow_the_widths_of_the_event_schema() {
    let cases: [(&str, u64); 5] = [
        ("event_id", u64::from(u16::MAX)),
        ("version", u64::from(u8::MAX)),
        ("level", u64::from(u8::MAX)),
        ("task", u64::from(u16::MAX)),
        ("opcode", u64::from(u8::MAX)),
    ];
    for (name, max) in cases {
        let mut value = full_windows_value();
        *field_mut(&mut value, name) = int(max);
        assert!(decode(kind::WINDOWS_EVENT_LOG, &value).is_ok(), "{name}");
        for bad in [int(max + 1), Value::from(-1), text("1"), Value::Float(1.0)] {
            *field_mut(&mut value, name) = bad.clone();
            assert_eq!(
                decode_kind(kind::WINDOWS_EVENT_LOG, &value),
                DecodeErrorKind::Invalid,
                "{name} {bad:?}"
            );
        }
    }

    let body = WindowsEventLogBody {
        keywords: Some(u64::MAX),
        record_id: Some(u64::MAX),
        ..WindowsEventLogBody::default()
    };
    assert_round_trip(
        &LogBody::WindowsEventLog(body),
        &map(vec![
            ("keywords", int(u64::MAX)),
            ("record_id", int(u64::MAX)),
        ]),
    );
    let body = AuditdBody {
        serial: Some(u64::MAX),
        records: None,
    };
    assert_round_trip(
        &LogBody::Auditd(body),
        &map(vec![("serial", int(u64::MAX))]),
    );
    for (kind, name) in [
        (kind::WINDOWS_EVENT_LOG, "keywords"),
        (kind::WINDOWS_EVENT_LOG, "record_id"),
        (kind::AUDITD, "serial"),
    ] {
        // 2^64, as a bignum.
        let past_max = Value::Tag(2, Box::new(bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0])));
        let value = map(vec![(name, past_max)]);
        assert_eq!(
            decode_kind(kind, &value),
            DecodeErrorKind::Invalid,
            "{name}"
        );
    }
}

#[test]
fn unknown_fields_are_ignored_at_every_level() {
    let unknown = || map(vec![("added_in_v2", text("x"))]);

    let mut value = full_windows_value();
    push(&mut value, "added_in_v2", unknown());
    push(first_mut(&mut value, "event_data"), "added_in_v2", int(2));
    assert_eq!(windows(&value), full_windows());

    let mut value = full_journald_value();
    push(&mut value, "added_in_v2", unknown());
    push(first_mut(&mut value, "fields"), "added_in_v2", int(2));
    assert_eq!(journald(&value), full_journald());

    let mut value = full_auditd_value();
    push(&mut value, "added_in_v2", unknown());
    let record = first_mut(&mut value, "records");
    push(record, "added_in_v2", int(2));
    push(first_mut(record, "fields"), "added_in_v2", int(3));
    assert_eq!(auditd(&value), full_auditd());
}

/// A record of `kind` whose body is the raw CBOR `body`.
fn record_bytes_with_body(kind: u16, body: &[u8]) -> Vec<u8> {
    let record = Record {
        header: header(kind, None),
        kind,
        schema: 1,
        body: RecordBody::default(),
    };
    let mut bytes = record.to_bytes().unwrap();
    // The empty body map is the record's last byte.
    assert_eq!(bytes.pop(), Some(0xa0));
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn duplicate_keys_fail_at_every_depth() {
    let mut cases = Vec::new();

    let mut value = full_windows_value();
    push(&mut value, "channel", text("again"));
    cases.push((kind::WINDOWS_EVENT_LOG, value));
    let mut value = full_windows_value();
    push(first_mut(&mut value, "event_data"), "value", text("again"));
    cases.push((kind::WINDOWS_EVENT_LOG, value));

    let mut value = full_journald_value();
    push(&mut value, "fields", Value::Array(Vec::new()));
    cases.push((kind::JOURNALD, value));
    let mut value = full_journald_value();
    push(first_mut(&mut value, "fields"), "name", text("again"));
    cases.push((kind::JOURNALD, value));

    let mut value = full_auditd_value();
    push(&mut value, "serial", int(1));
    cases.push((kind::AUDITD, value));
    let mut value = full_auditd_value();
    push(first_mut(&mut value, "records"), "type", text("again"));
    cases.push((kind::AUDITD, value));
    let mut value = full_auditd_value();
    let record = first_mut(&mut value, "records");
    push(first_mut(record, "fields"), "value", text("again"));
    cases.push((kind::AUDITD, value));

    for (kind, value) in cases {
        let body = cbor::to_vec(&value).unwrap();
        let error = Record::from_bytes(&record_bytes_with_body(kind, &body)).unwrap_err();
        assert_eq!(error.kind(), DecodeErrorKind::DuplicateKey, "{value:?}");
        let error = cbor::from_slice::<RecordBody>(&body).unwrap_err();
        assert_eq!(error.kind(), DecodeErrorKind::DuplicateKey, "{value:?}");
    }
}

#[test]
fn log_values_keep_their_cbor_type() {
    let values = [
        (LogValue::Text(String::new()), text("")),
        (LogValue::Bytes(Vec::new()), bytes(&[])),
        (
            LogValue::Text("line one\nline two\r\nline three".to_owned()),
            text("line one\nline two\r\nline three"),
        ),
        (
            LogValue::Bytes(vec![0x61, 0x00, 0x62]),
            bytes(&[0x61, 0x00, 0x62]),
        ),
        (
            LogValue::Bytes(vec![0xff, 0xfe, 0x00]),
            bytes(&[0xff, 0xfe, 0x00]),
        ),
        (
            LogValue::Bytes(b"valid utf-8".to_vec()),
            bytes(b"valid utf-8"),
        ),
    ];
    for (log_value, cbor_value) in values {
        let journald = JournaldBody {
            fields: Some(vec![LogField {
                name: "F".to_owned(),
                value: log_value.clone(),
            }]),
        };
        assert_round_trip(
            &LogBody::Journald(journald),
            &map(vec![(
                "fields",
                Value::Array(vec![field_value("F", cbor_value.clone())]),
            )]),
        );
        let auditd = AuditdBody {
            serial: None,
            records: Some(vec![AuditRecord {
                record_type: "USER".to_owned(),
                fields: vec![LogField {
                    name: "f".to_owned(),
                    value: log_value,
                }],
            }]),
        };
        assert_round_trip(
            &LogBody::Auditd(auditd),
            &map(vec![(
                "records",
                Value::Array(vec![map(vec![
                    ("type", text("USER")),
                    ("fields", Value::Array(vec![field_value("f", cbor_value)])),
                ])]),
            )]),
        );
    }
}

#[test]
fn log_values_of_other_types_fail() {
    let others = [
        int(1),
        Value::from(-1),
        Value::Float(1.5),
        Value::Array(vec![text("a")]),
        map(vec![("a", text("b"))]),
        Value::Bool(true),
        Value::Null,
    ];
    for other in others {
        let value = map(vec![(
            "fields",
            Value::Array(vec![field_value("F", other.clone())]),
        )]);
        assert_eq!(
            decode_kind(kind::JOURNALD, &value),
            DecodeErrorKind::Invalid,
            "{other:?}"
        );
        let value = map(vec![(
            "records",
            Value::Array(vec![map(vec![
                ("type", text("USER")),
                (
                    "fields",
                    Value::Array(vec![field_value("f", other.clone())]),
                ),
            ])]),
        )]);
        assert_eq!(
            decode_kind(kind::AUDITD, &value),
            DecodeErrorKind::Invalid,
            "{other:?}"
        );
    }

    // `undefined`, which `ciborium::Value` cannot hold: {"fields": [{"name":
    // "F", "value": undefined}]}.
    let mut raw = vec![0xa1, 0x66];
    raw.extend_from_slice(b"fields");
    raw.extend_from_slice(&[0x81, 0xa2, 0x64]);
    raw.extend_from_slice(b"name");
    raw.extend_from_slice(&[0x61, b'F', 0x65]);
    raw.extend_from_slice(b"value");
    raw.push(0xf7);
    let body: RecordBody = cbor::from_slice(&raw).unwrap();
    let error = LogBody::decode(kind::JOURNALD, &body).unwrap_err();
    assert_eq!(error.kind(), DecodeErrorKind::Invalid);
    let record = Record::from_bytes(&record_bytes_with_body(kind::JOURNALD, &raw)).unwrap();
    let error = LogBody::decode(record.kind, &record.body).unwrap_err();
    assert_eq!(error.kind(), DecodeErrorKind::Invalid);
}

#[test]
fn journald_keeps_repeated_fields_in_order() {
    let body = JournaldBody {
        fields: Some(vec![
            log_text("CODE_LINE", "1"),
            log_text("MESSAGE", "a"),
            log_text("CODE_LINE", "2"),
            log_bytes("MESSAGE", &[0xff]),
            log_text("CODE_LINE", "1"),
        ]),
    };
    let value = map(vec![(
        "fields",
        Value::Array(vec![
            field_value("CODE_LINE", text("1")),
            field_value("MESSAGE", text("a")),
            field_value("CODE_LINE", text("2")),
            field_value("MESSAGE", bytes(&[0xff])),
            field_value("CODE_LINE", text("1")),
        ]),
    )]);
    assert_round_trip(&LogBody::Journald(body), &value);
}

#[test]
fn journald_cursor_is_never_sent_but_is_read() {
    let mut body = full_journald();
    body.fields
        .as_mut()
        .unwrap()
        .push(log_text("__CURSOR", "s=0123;i=1"));
    assert!(LogBody::Journald(body.clone()).to_body().is_err());
    assert!(RecordBody::encode(&body).is_err());

    // Names that only resemble it are sent.
    for name in ["__cursor", "_CURSOR", "CURSOR", "__CURSOR_ID"] {
        let body = JournaldBody {
            fields: Some(vec![log_text(name, "x")]),
        };
        assert!(LogBody::Journald(body).to_body().is_ok(), "{name}");
    }

    let mut value = full_journald_value();
    match field_mut(&mut value, "fields") {
        Value::Array(items) => items.push(field_value("__CURSOR", text("s=0123;i=1"))),
        other => panic!("expected an array, got {other:?}"),
    }
    assert_eq!(journald(&value), body);
}

#[test]
fn auditd_event_keeps_its_lines_and_decoded_bytes() {
    let body = auditd(&full_auditd_value());
    let records = body.records.as_ref().unwrap();
    let types: Vec<&str> = records
        .iter()
        .map(|record| record.record_type.as_str())
        .collect();
    assert_eq!(types, ["SYSCALL", "EXECVE", "PROCTITLE"]);
    let names: Vec<&str> = records
        .iter()
        .flat_map(|record| record.fields.iter().map(|field| field.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            "arch",
            "syscall",
            "success",
            "exe",
            "key",
            "argc",
            "a0",
            "a1",
            "a2",
            "proctitle"
        ]
    );
    assert_eq!(
        records.last().unwrap().fields,
        [log_bytes("proctitle", PROCTITLE)]
    );
    assert_eq!(body, full_auditd());

    let encoded = encoded(&LogBody::Auditd(body));
    let Value::Array(lines) = field(&encoded, "records") else {
        panic!("records is not an array");
    };
    let Value::Array(fields) = field(lines.last().unwrap(), "fields") else {
        panic!("fields is not an array");
    };
    assert_eq!(field(fields.first().unwrap(), "value"), &bytes(PROCTITLE));
}

#[test]
fn windows_samples_of_real_shapes() {
    // A Defender Operational event, with named `Data` elements.
    assert_round_trip(
        &LogBody::WindowsEventLog(WindowsEventLogBody {
            user_data_xml: None,
            ..full_windows()
        }),
        &{
            let mut value = full_windows_value();
            remove(&mut value, "user_data_xml");
            value
        },
    );

    // An event whose `Data` elements have no names.
    let unnamed = WindowsEventLogBody {
        channel: Some("Application".to_owned()),
        provider: Some("Application Error".to_owned()),
        event_id: Some(1000),
        level: Some(2),
        keywords: Some(0x0080_0000_0000_0000),
        record_id: Some(99),
        computer: Some("host-1".to_owned()),
        event_data: Some(vec![
            data(None, "app.exe"),
            data(None, "1.0.0.0"),
            data(None, "c0000005"),
        ]),
        ..WindowsEventLogBody::default()
    };
    assert_round_trip(
        &LogBody::WindowsEventLog(unnamed),
        &map(vec![
            ("channel", text("Application")),
            ("provider", text("Application Error")),
            ("event_id", int(1000)),
            ("level", int(2)),
            ("keywords", int(0x0080_0000_0000_0000)),
            ("record_id", int(99)),
            ("computer", text("host-1")),
            (
                "event_data",
                Value::Array(vec![
                    map(vec![("value", text("app.exe"))]),
                    map(vec![("value", text("1.0.0.0"))]),
                    map(vec![("value", text("c0000005"))]),
                ]),
            ),
        ]),
    );

    // An event with `UserData` and no `EventData`.
    let xml = "<LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"><SubjectUserName>alice</SubjectUserName></LogFileCleared>";
    let user_data = WindowsEventLogBody {
        channel: Some("Security".to_owned()),
        provider: Some("Microsoft-Windows-Eventlog".to_owned()),
        event_id: Some(1102),
        version: Some(0),
        level: Some(4),
        task: Some(104),
        opcode: Some(0),
        keywords: Some(0x4020_0000_0000_0000),
        record_id: Some(12),
        computer: Some("host-1".to_owned()),
        user_data_xml: Some(xml.to_owned()),
        ..WindowsEventLogBody::default()
    };
    assert_round_trip(
        &LogBody::WindowsEventLog(user_data),
        &map(vec![
            ("channel", text("Security")),
            ("provider", text("Microsoft-Windows-Eventlog")),
            ("event_id", int(1102)),
            ("version", int(0)),
            ("level", int(4)),
            ("task", int(104)),
            ("opcode", int(0)),
            ("keywords", int(0x4020_0000_0000_0000)),
            ("record_id", int(12)),
            ("computer", text("host-1")),
            ("user_data_xml", text(xml)),
        ]),
    );
}

#[test]
fn bodies_decode_by_kind_number() {
    for (body, value) in full_bodies() {
        let decoded = decode(body.kind(), &value).unwrap();
        assert_eq!(decoded, body);
    }
    assert!(matches!(
        decode(kind::WINDOWS_EVENT_LOG, &full_windows_value()),
        Ok(LogBody::WindowsEventLog(_))
    ));
    assert!(matches!(
        decode(kind::JOURNALD, &full_journald_value()),
        Ok(LogBody::Journald(_))
    ));
    assert!(matches!(
        decode(kind::AUDITD, &full_auditd_value()),
        Ok(LogBody::Auditd(_))
    ));
    for other in [0, 1, 999, 1001, 1099, 1102, 1199, 1300] {
        for (_, value) in full_bodies() {
            assert_eq!(
                decode_kind(other, &value),
                DecodeErrorKind::Invalid,
                "{other}"
            );
        }
        assert_eq!(
            decode_kind(other, &map(Vec::new())),
            DecodeErrorKind::Invalid
        );
    }
}

#[test]
fn body_types_cover_the_registered_log_kinds() {
    let registered: BTreeSet<u16> = (1000..=1199)
        .filter(|&number| kind::info(number).is_some())
        .collect();
    let with_bodies: BTreeSet<u16> = KINDS.into_iter().collect();
    assert_eq!(with_bodies, registered);
    assert_eq!(
        with_bodies,
        BTreeSet::from([kind::WINDOWS_EVENT_LOG, kind::JOURNALD, kind::AUDITD])
    );
    for number in KINDS {
        assert_eq!(kind::info(number).unwrap().schema(), 1, "{number}");
    }
    let from_bodies: BTreeSet<u16> = empty_bodies().iter().map(LogBody::kind).collect();
    assert_eq!(from_bodies, with_bodies);
}

fn header(kind: u16, process_key: Option<ProcessKey>) -> RecordHeader {
    let family = if kind == self::kind::WINDOWS_EVENT_LOG || kind < 1000 {
        OsFamily::Windows
    } else {
        OsFamily::Linux
    };
    RecordHeader {
        endpoint_id: Uuid::from_u128(0x11),
        stream: Uuid::from_u128(0x22),
        seq: 7,
        event_time: Timestamp::from_second(1_700_000_000).unwrap(),
        collected_at: Timestamp::from_second(1_700_000_001).unwrap(),
        clock_offset: None,
        hostname: "host-1".to_owned(),
        ips: vec!["192.0.2.10".parse().unwrap()],
        default_route_ip: None,
        net_state_source: NetStateSource::Observed,
        os: OsInfo {
            family,
            version: "1".to_owned(),
        },
        collection_mode: CollectionMode::Essential,
        process_key,
    }
}

fn process_key() -> ProcessKey {
    ProcessKey {
        os: OsFamily::Windows,
        value: vec![1, 2, 3, 4],
    }
}

fn log_record(body: &LogBody, process_key: Option<ProcessKey>) -> Record {
    Record {
        header: header(body.kind(), process_key),
        kind: body.kind(),
        schema: 1,
        body: body.to_body().unwrap(),
    }
}

#[test]
fn log_records_carry_no_process_key() {
    for (body, _) in full_bodies() {
        // Without a process key the bytes are fixed, with no such key.
        let record = log_record(&body, None);
        assert_eq!(record.validate(), Ok(()));
        let bytes = record.to_bytes().unwrap();
        let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(!keys(field(&value, "header")).contains("process_key"));
        let received = Record::from_bytes(&bytes).unwrap();
        assert_eq!(received, record);
        assert_eq!(
            LogBody::decode(received.kind, &received.body).unwrap(),
            body
        );

        // With one, fixing the bytes fails.
        let with_key = log_record(&body, Some(process_key()));
        assert_eq!(
            with_key.validate(),
            Err(RecordEncodeError::ProcessKeyOnLogKind)
        );
        assert_eq!(
            with_key.to_bytes(),
            Err(RecordEncodeError::ProcessKeyOnLogKind)
        );

        // But a receiver decodes such bytes.
        let mut value = value;
        let key_value: Value =
            ciborium::from_reader(cbor::to_vec(&process_key()).unwrap().as_slice()).unwrap();
        push(field_mut(&mut value, "header"), "process_key", key_value);
        let received = Record::from_bytes(&cbor::to_vec(&value).unwrap()).unwrap();
        assert_eq!(received, with_key);
    }

    // A Sysmon kind may carry one.
    let sysmon = Record {
        header: header(kind::SYSMON_PROCESS_CREATE, Some(process_key())),
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: RecordBody::default(),
    };
    assert_eq!(sysmon.validate(), Ok(()));
    let bytes = sysmon.to_bytes().unwrap();
    let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert!(keys(field(&value, "header")).contains("process_key"));
    // So may every other kind outside the three.
    for other in [1001, 1099, 1102, 1199, 1200] {
        let record = Record {
            kind: other,
            ..sysmon.clone()
        };
        assert_eq!(record.validate(), Ok(()), "{other}");
    }

    let error = RecordEncodeError::ProcessKeyOnLogKind;
    assert!(!error.to_string().is_empty());
    assert!(error.source().is_none());
}

#[test]
fn net_state_rule_still_holds_on_log_kinds() {
    let body = LogBody::Journald(full_journald());
    let mut record = log_record(&body, None);
    record.header.net_state_source = NetStateSource::Unknown;
    assert_eq!(
        record.to_bytes(),
        Err(RecordEncodeError::UnknownNetStateWithAddresses)
    );
    record.header.ips.clear();
    assert!(record.to_bytes().is_ok());
}

#[test]
fn accepted_kinds_filter_log_records() {
    let accepted = [AcceptedKind {
        kind: kind::JOURNALD,
        schema_min: 1,
        schema_max: 1,
    }];
    for (body, _) in full_bodies() {
        let record = log_record(&body, None);
        assert_eq!(
            kind::accepts(&accepted, record.kind, record.schema),
            record.kind == kind::JOURNALD,
            "{}",
            record.kind
        );
    }
}
