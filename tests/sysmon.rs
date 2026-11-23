//! The Sysmon kind bodies, their conversion from the Windows notation and
//! their process keys, driven through the public API.
#![cfg(feature = "telemetry")]

use std::net::IpAddr;

use ciborium::Value;
use jiff::Timestamp;
use senta_protocol::connection::{DecodeErrorKind, cbor};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::telemetry::sysmon::{
    self, BASE_SCHEMA_VERSION, Body, BodyError, ConvertError, CreateRemoteThread, DnsQuery,
    FileCreateStreamHash, FileCreateTime, HashEntry, NetworkConnect, ProcessAccess, ProcessCreate,
    ProcessTerminate,
};
use senta_protocol::telemetry::{NetStateSource, Record, RecordBody, RecordHeader, kind};
use uuid::Uuid;

const GUID_TEXT: &str = "{01020304-0506-0708-090A-0B0C0D0E0F10}";
const GUID_BYTES: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const OTHER_GUID_TEXT: &str = "{A1B2C3D4-0000-1111-2222-333344445555}";
const OTHER_GUID_BYTES: [u8; 16] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
];
const UTC_TIME: &str = "2024-03-05 12:34:56.789";
const HASHES: &str = "SHA1=3F0D0A5A2B8F6A3C9E5F1E2D3C4B5A6978695A4B,\
                      MD5=0123456789ABCDEF0123456789ABCDEF,\
                      SHA256=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF,\
                      IMPHASH=FEDCBA9876543210FEDCBA9876543210";

const SYSMON_KINDS: [u16; 19] = [
    1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 22, 23, 25, 26,
];

fn utc(text: &str) -> Timestamp {
    text.parse().unwrap()
}

/// A realistic Windows `EventData` for each Sysmon kind.
fn sample(kind: u16) -> Vec<(&'static str, &'static str)> {
    let common = |rest: &[(&'static str, &'static str)]| {
        let mut fields = vec![("RuleName", "-"), ("UtcTime", UTC_TIME)];
        fields.extend_from_slice(rest);
        fields
    };
    match kind {
        1 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("FileVersion", "10.0.22621.1 (WinBuild.160101.0800)"),
            ("Description", "Windows Command Processor"),
            ("Product", "Microsoft® Windows® Operating System"),
            ("Company", "Microsoft Corporation"),
            ("OriginalFileName", "Cmd.Exe"),
            ("CommandLine", r#""C:\Windows\system32\cmd.exe" /c whoami"#),
            ("CurrentDirectory", r"C:\Users\alice\"),
            ("User", r"CONTOSO\alice"),
            ("LogonGuid", "{6F1C3B2A-1D4E-65E7-8D4A-0F0000000000}"),
            ("LogonId", "0x3e7"),
            ("TerminalSessionId", "1"),
            ("IntegrityLevel", "Medium"),
            ("Hashes", HASHES),
            ("ParentProcessGuid", OTHER_GUID_TEXT),
            ("ParentProcessId", "4100"),
            ("ParentImage", r"C:\Windows\explorer.exe"),
            ("ParentCommandLine", r"C:\Windows\Explorer.EXE"),
            ("ParentUser", r"CONTOSO\alice"),
        ]),
        2 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "7712"),
            ("Image", r"C:\Tools\touch.exe"),
            ("TargetFilename", r"C:\Users\alice\report.docx"),
            ("CreationUtcTime", "2020-01-01 00:00:00.000"),
            ("PreviousCreationUtcTime", "2024-03-05 12:30:00.123"),
            ("User", r"CONTOSO\alice"),
        ]),
        3 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "1234"),
            ("Image", r"C:\Program Files\Browser\browser.exe"),
            ("User", r"CONTOSO\alice"),
            ("Protocol", "tcp"),
            ("Initiated", "true"),
            ("SourceIsIpv6", "false"),
            ("SourceIp", "192.0.2.10"),
            ("SourceHostname", "host-1.contoso.local"),
            ("SourcePort", "50123"),
            ("SourcePortName", "-"),
            ("DestinationIsIpv6", "true"),
            ("DestinationIp", "2001:db8::443"),
            ("DestinationHostname", "-"),
            ("DestinationPort", "443"),
            ("DestinationPortName", "https"),
        ]),
        5 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("User", r"CONTOSO\alice"),
        ]),
        6 => common(&[
            ("ImageLoaded", r"C:\Windows\System32\drivers\example.sys"),
            (
                "Hashes",
                "SHA256=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
            ),
            ("Signed", "true"),
            ("Signature", "Microsoft Windows"),
            ("SignatureStatus", "Valid"),
        ]),
        7 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("ImageLoaded", r"C:\Windows\System32\kernel32.dll"),
            ("FileVersion", "10.0.22621.2506"),
            ("Description", "Windows NT BASE API Client DLL"),
            ("Product", "Microsoft® Windows® Operating System"),
            ("Company", "Microsoft Corporation"),
            ("OriginalFileName", "kernel32"),
            ("Hashes", "MD5=0123456789ABCDEF0123456789ABCDEF"),
            ("Signed", "true"),
            ("Signature", "Microsoft Windows"),
            ("SignatureStatus", "Valid"),
            ("User", r"CONTOSO\alice"),
        ]),
        8 => common(&[
            ("SourceProcessGuid", GUID_TEXT),
            ("SourceProcessId", "4100"),
            ("SourceImage", r"C:\Tools\inject.exe"),
            ("TargetProcessGuid", OTHER_GUID_TEXT),
            ("TargetProcessId", "6228"),
            ("TargetImage", r"C:\Windows\System32\notepad.exe"),
            ("NewThreadId", "9876"),
            ("StartAddress", "0x00007FF6A1B21000"),
            ("StartModule", r"C:\Windows\System32\notepad.exe"),
            ("StartFunction", "-"),
            ("SourceUser", r"CONTOSO\alice"),
            ("TargetUser", r"CONTOSO\alice"),
        ]),
        9 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "4"),
            ("Image", "System"),
            ("Device", r"\Device\HarddiskVolume3"),
            ("User", r"NT AUTHORITY\SYSTEM"),
        ]),
        10 => common(&[
            ("SourceProcessGUID", GUID_TEXT),
            ("SourceProcessId", "4100"),
            ("SourceThreadId", "4104"),
            ("SourceImage", r"C:\Tools\dump.exe"),
            ("TargetProcessGUID", OTHER_GUID_TEXT),
            ("TargetProcessId", "712"),
            ("TargetImage", r"C:\Windows\System32\lsass.exe"),
            ("GrantedAccess", "0x1fffff"),
            (
                "CallTrace",
                r"C:\Windows\SYSTEM32\ntdll.dll+9d204|C:\Windows\System32\KERNELBASE.dll+2c13e",
            ),
            ("SourceUser", r"CONTOSO\alice"),
            ("TargetUser", r"NT AUTHORITY\SYSTEM"),
        ]),
        11 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("TargetFilename", r"C:\Users\alice\AppData\Local\Temp\a.tmp"),
            ("CreationUtcTime", "2024-03-05 12:34:56.789"),
            ("User", r"CONTOSO\alice"),
        ]),
        12 => common(&[
            ("EventType", "CreateKey"),
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\regedit.exe"),
            ("TargetObject", r"HKU\S-1-5-21-1\Software\Example"),
            ("User", r"CONTOSO\alice"),
        ]),
        13 => common(&[
            ("EventType", "SetValue"),
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\regedit.exe"),
            ("TargetObject", r"HKU\S-1-5-21-1\Software\Example\Value"),
            ("Details", "DWORD (0x00000001)"),
            ("User", r"CONTOSO\alice"),
        ]),
        14 => common(&[
            ("EventType", "RenameKey"),
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\regedit.exe"),
            ("TargetObject", r"HKU\S-1-5-21-1\Software\Old"),
            ("NewName", r"HKU\S-1-5-21-1\Software\New"),
            ("User", r"CONTOSO\alice"),
        ]),
        15 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Program Files\Browser\browser.exe"),
            (
                "TargetFilename",
                r"C:\Users\alice\Downloads\setup.exe:Zone.Identifier",
            ),
            ("CreationUtcTime", "2024-03-05 12:34:50.000"),
            (
                "Hash",
                "SHA256=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
            ),
            ("Contents", "[ZoneTransfer]  ZoneId=3"),
            ("User", r"CONTOSO\alice"),
        ]),
        17 => common(&[
            ("EventType", "CreatePipe"),
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("PipeName", r"\example_pipe"),
            ("Image", r"C:\Tools\server.exe"),
            ("User", r"CONTOSO\alice"),
        ]),
        22 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "1234"),
            ("QueryName", "www.example.com"),
            ("QueryStatus", "0"),
            (
                "QueryResults",
                "type:  5 example.cdn.net;::ffff:192.0.2.80;192.0.2.81;",
            ),
            ("Image", r"C:\Program Files\Browser\browser.exe"),
            ("User", r"CONTOSO\alice"),
        ]),
        23 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("User", r"CONTOSO\alice"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("TargetFilename", r"C:\Users\alice\payload.exe"),
            ("Hashes", "SHA1=3F0D0A5A2B8F6A3C9E5F1E2D3C4B5A6978695A4B"),
            ("IsExecutable", "true"),
            ("Archived", "true"),
        ]),
        25 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("Image", r"C:\Windows\System32\svchost.exe"),
            ("Type", "Image is replaced"),
            ("User", r"NT AUTHORITY\SYSTEM"),
        ]),
        26 => common(&[
            ("ProcessGuid", GUID_TEXT),
            ("ProcessId", "6228"),
            ("User", r"CONTOSO\alice"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
            ("TargetFilename", r"C:\Users\alice\notes.txt"),
            ("Hashes", "MD5=0123456789ABCDEF0123456789ABCDEF"),
            ("IsExecutable", "False"),
        ]),
        _ => panic!("no sample for kind {kind}"),
    }
}

/// The body's entries, as CBOR values.
fn entries(body: &RecordBody) -> Vec<(String, Value)> {
    match body.decode::<Value>().unwrap() {
        Value::Map(entries) => entries
            .into_iter()
            .map(|(key, value)| match key {
                Value::Text(key) => (key, value),
                other => panic!("a body key is not text: {other:?}"),
            })
            .collect(),
        other => panic!("a body is not a map: {other:?}"),
    }
}

fn keys(body: &RecordBody) -> Vec<String> {
    entries(body).into_iter().map(|(key, _)| key).collect()
}

fn entry(body: &RecordBody, key: &str) -> Option<Value> {
    entries(body)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
}

fn body_bytes(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let map = Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_owned()), value))
            .collect(),
    );
    cbor::to_vec(&map).unwrap()
}

fn convert_one(kind: u16, field: &'static str, value: &'static str) -> Result<Body, ConvertError> {
    sysmon::convert(kind, &[(field, value)]).map(|converted| converted.body)
}

fn invalid(field: &str) -> impl Fn(ConvertError) -> bool + '_ {
    move |error| matches!(error, ConvertError::InvalidValue { field: f, .. } if f == field)
}

fn header(process_key: Option<senta_protocol::telemetry::ProcessKey>) -> RecordHeader {
    RecordHeader {
        endpoint_id: Uuid::from_u128(1),
        stream: Uuid::from_u128(2),
        seq: 0,
        event_time: utc("2024-03-05T12:34:56.789Z"),
        collected_at: utc("2024-03-05T12:34:57Z"),
        clock_offset: None,
        hostname: "host-1".to_owned(),
        ips: Vec::new(),
        default_route_ip: None,
        net_state_source: NetStateSource::Unknown,
        os: OsInfo {
            family: OsFamily::Windows,
            version: "10.0.22631".to_owned(),
        },
        collection_mode: CollectionMode::Extended,
        process_key,
    }
}

#[test]
fn base_schema_version() {
    assert_eq!(BASE_SCHEMA_VERSION, "4.90");
}

#[test]
fn every_kind_round_trips_with_snake_case_keys() {
    for kind in SYSMON_KINDS {
        let fields = sample(kind);
        let converted = sysmon::convert(kind, &fields).unwrap();
        assert_eq!(converted.body.kind(), kind);
        assert_eq!(converted.event_time, Some(utc("2024-03-05T12:34:56.789Z")));

        let body = converted.body.to_record_body().unwrap();
        let keys = keys(&body);
        // Every sample field has a value, so each is a key, less UtcTime.
        assert_eq!(keys.len(), fields.len() - 1, "kind {kind}");
        for key in &keys {
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "kind {kind}: key {key}"
            );
        }
        assert!(!keys.iter().any(|key| key == "utc_time"), "kind {kind}");
        assert_eq!(entry(&body, "rule_name"), Some(Value::Text("-".to_owned())));

        let received = Body::from_record_body(kind, &body).unwrap();
        assert_eq!(received, converted.body, "kind {kind}");

        // Through the record's bytes, too.
        let record = Record {
            header: header(converted.body.process_key(&OsFamily::Windows)),
            kind,
            schema: kind::info(kind).unwrap().schema(),
            body,
        };
        let decoded = Record::from_bytes(&record.to_bytes().unwrap()).unwrap();
        assert_eq!(
            Body::from_record_body(decoded.kind, &decoded.body).unwrap(),
            converted.body
        );
    }
}

#[test]
fn process_access_keys_and_values() {
    let converted = sysmon::convert(kind::SYSMON_PROCESS_ACCESS, &sample(10)).unwrap();
    let body = converted.body.to_record_body().unwrap();
    assert_eq!(
        keys(&body),
        [
            "rule_name",
            "source_process_guid",
            "source_process_id",
            "source_thread_id",
            "source_image",
            "target_process_guid",
            "target_process_id",
            "target_image",
            "granted_access",
            "call_trace",
            "source_user",
            "target_user",
        ]
    );
    assert_eq!(
        entry(&body, "source_process_guid"),
        Some(Value::Bytes(GUID_BYTES.to_vec()))
    );
    assert_eq!(
        entry(&body, "target_process_guid"),
        Some(Value::Bytes(OTHER_GUID_BYTES.to_vec()))
    );
    let Body::ProcessAccess(access) = converted.body else {
        panic!("not a ProcessAccess body");
    };
    assert_eq!(access.granted_access, Some(2_097_151));
    assert_eq!(access.source_process_id, Some(4100));
}

#[test]
fn process_create_values() {
    let converted = sysmon::convert(kind::SYSMON_PROCESS_CREATE, &sample(1)).unwrap();
    let Body::ProcessCreate(create) = converted.body else {
        panic!("not a ProcessCreate body");
    };
    assert_eq!(create.rule_name.as_deref(), Some("-"));
    assert_eq!(create.logon_id, Some(999));
    assert_eq!(create.process_guid, Some(Uuid::from_bytes(GUID_BYTES)));
    assert_eq!(
        create.parent_process_guid,
        Some(Uuid::from_bytes(OTHER_GUID_BYTES))
    );
    assert_eq!(create.terminal_session_id, Some(1));
    let hashes = create.hashes.unwrap();
    let algos: Vec<&str> = hashes.iter().map(|hash| hash.algo.as_str()).collect();
    assert_eq!(algos, ["SHA1", "MD5", "SHA256", "IMPHASH"]);
    assert_eq!(
        hashes[1],
        HashEntry {
            algo: "MD5".to_owned(),
            value: vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ],
        }
    );
    assert_eq!(hashes[0].value.len(), 20);
    assert_eq!(hashes[2].value.len(), 32);
    assert_eq!(hashes[3].value.len(), 16);

    // The hashes are an array of `{algo, value}` maps, `value` bytes.
    let body = RecordBody::encode(&ProcessCreate {
        hashes: Some(hashes),
        ..ProcessCreate::default()
    })
    .unwrap();
    let Some(Value::Array(items)) = entry(&body, "hashes") else {
        panic!("hashes is not an array");
    };
    assert_eq!(items.len(), 4);
    assert_eq!(
        items[1],
        Value::Map(vec![
            (
                Value::Text("algo".to_owned()),
                Value::Text("MD5".to_owned())
            ),
            (
                Value::Text("value".to_owned()),
                Value::Bytes(vec![
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef,
                ])
            ),
        ])
    );
}

#[test]
fn utc_time_is_the_event_time() {
    let converted = sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &sample(5)).unwrap();
    assert_eq!(
        converted.event_time.unwrap().as_nanosecond(),
        1_709_642_096_789_000_000
    );

    let without: Vec<_> = sample(5)
        .into_iter()
        .filter(|&(name, _)| name != "UtcTime")
        .collect();
    let converted_without = sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &without).unwrap();
    assert_eq!(converted_without.event_time, None);
    assert_eq!(converted_without.body, converted.body);

    let empty = sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &[("UtcTime", "")]).unwrap();
    assert_eq!(empty.event_time, None);

    for bad in [
        "2024-03-05T12:34:56Z",
        "2024-02-30 00:00:00",
        "1600-01-01 00:00:00",
    ] {
        let error =
            sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &[("UtcTime", bad)]).unwrap_err();
        assert!(invalid("UtcTime")(error), "{bad}");
    }
}

#[test]
fn missing_empty_unknown_and_duplicate_fields() {
    let converted = sysmon::convert(
        kind::SYSMON_PROCESS_TERMINATE,
        &[
            ("RuleName", ""),
            ("ProcessGuid", GUID_TEXT),
            ("Image", ""),
            ("FutureField", "a value of a newer schema"),
        ],
    )
    .unwrap();
    let body = converted.body.to_record_body().unwrap();
    assert_eq!(keys(&body), ["process_guid"]);
    assert_eq!(
        converted.body,
        Body::ProcessTerminate(ProcessTerminate {
            process_guid: Some(Uuid::from_bytes(GUID_BYTES)),
            ..ProcessTerminate::default()
        })
    );

    // An empty value of a typed field is left out, not an error.
    let empty = convert_one(kind::SYSMON_PROCESS_TERMINATE, "ProcessId", "").unwrap();
    assert_eq!(empty, Body::ProcessTerminate(ProcessTerminate::default()));

    for fields in [
        vec![("Image", "a.exe"), ("Image", "b.exe")],
        vec![("Image", "a.exe"), ("Image", "")],
        vec![("UtcTime", UTC_TIME), ("UtcTime", UTC_TIME)],
        vec![("FutureField", "1"), ("FutureField", "2")],
    ] {
        let error = sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &fields).unwrap_err();
        assert_eq!(error, ConvertError::DuplicateField(fields[0].0.to_owned()));
    }
}

#[test]
fn unsigned_integers() {
    let Body::ProcessCreate(create) =
        convert_one(kind::SYSMON_PROCESS_CREATE, "LogonId", "0xffffffffffffffff").unwrap()
    else {
        panic!("not a ProcessCreate body");
    };
    assert_eq!(create.logon_id, Some(u64::MAX));
    let Body::ProcessCreate(create) =
        convert_one(kind::SYSMON_PROCESS_CREATE, "LogonId", "999").unwrap()
    else {
        panic!("not a ProcessCreate body");
    };
    assert_eq!(create.logon_id, Some(999));

    let Body::NetworkConnect(connect) =
        convert_one(kind::SYSMON_NETWORK_CONNECT, "SourcePort", "65535").unwrap()
    else {
        panic!("not a NetworkConnect body");
    };
    assert_eq!(connect.source_port, Some(u16::MAX));

    let cases: [(u16, &str, &str); 7] = [
        (kind::SYSMON_NETWORK_CONNECT, "SourcePort", "65536"),
        (kind::SYSMON_NETWORK_CONNECT, "DestinationPort", "0x10000"),
        (kind::SYSMON_PROCESS_CREATE, "ProcessId", "4294967296"),
        (
            kind::SYSMON_PROCESS_CREATE,
            "LogonId",
            "0x10000000000000000",
        ),
        (kind::SYSMON_PROCESS_CREATE, "TerminalSessionId", "one"),
        (kind::SYSMON_PROCESS_ACCESS, "GrantedAccess", "0x"),
        (kind::SYSMON_PROCESS_CREATE, "ProcessId", "-1"),
    ];
    for (kind, field, value) in cases {
        let error = sysmon::convert(kind, &[(field, value)]).unwrap_err();
        assert!(invalid(field)(error), "{field}={value}");
    }
}

#[test]
fn guids() {
    for text in [
        "{01020304-0506-0708-090A-0B0C0D0E0F10}",
        "01020304-0506-0708-090A-0B0C0D0E0F10",
        "{01020304-0506-0708-090a-0b0c0d0e0f10}",
        "01020304-0506-0708-090a-0b0c0d0e0f10",
    ] {
        let Body::ProcessTerminate(body) =
            convert_one(kind::SYSMON_PROCESS_TERMINATE, "ProcessGuid", text).unwrap()
        else {
            panic!("not a ProcessTerminate body");
        };
        assert_eq!(body.process_guid.unwrap().as_bytes(), &GUID_BYTES);
        let record_body = Body::ProcessTerminate(body).to_record_body().unwrap();
        assert_eq!(
            entry(&record_body, "process_guid"),
            Some(Value::Bytes(GUID_BYTES.to_vec()))
        );
    }
    for bad in [
        "0102030405060708090A0B0C0D0E0F10",
        "urn:uuid:01020304-0506-0708-090A-0B0C0D0E0F10",
        "{01020304-0506-0708-090A-0B0C0D0E0F1}",
    ] {
        let error = convert_one(kind::SYSMON_PROCESS_TERMINATE, "ProcessGuid", bad).unwrap_err();
        assert!(invalid("ProcessGuid")(error), "{bad}");
    }
}

#[test]
fn hashes() {
    let Body::FileDelete(delete) = convert_one(kind::SYSMON_FILE_DELETE, "Hashes", HASHES).unwrap()
    else {
        panic!("not a FileDelete body");
    };
    let hashes = delete.hashes.unwrap();
    assert_eq!(hashes.len(), 4);
    assert_eq!(hashes[3].algo, "IMPHASH");
    assert_eq!(
        hashes[3].value,
        [
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10
        ]
    );
    for bad in [
        "SHA1",
        "SHA1=00,MD5",
        "SHA1=00,,MD5=00",
        "SHA1=0G",
        "SHA1=000",
        "SHA1=",
    ] {
        let error = convert_one(kind::SYSMON_FILE_DELETE, "Hashes", bad).unwrap_err();
        assert!(invalid("Hashes")(error), "{bad}");
    }

    // Event 15's `Hash` is text.
    let raw = "SHA256=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
    let Body::FileCreateStreamHash(stream) =
        convert_one(kind::SYSMON_FILE_CREATE_STREAM_HASH, "Hash", raw).unwrap()
    else {
        panic!("not a FileCreateStreamHash body");
    };
    assert_eq!(stream.hash.as_deref(), Some(raw));
    let body = Body::FileCreateStreamHash(FileCreateStreamHash {
        hash: Some("not=hex".to_owned()),
        ..FileCreateStreamHash::default()
    })
    .to_record_body()
    .unwrap();
    assert_eq!(
        entry(&body, "hash"),
        Some(Value::Text("not=hex".to_owned()))
    );
}

#[test]
fn times() {
    let time = |value: &'static str| match convert_one(
        kind::SYSMON_FILE_CREATE_TIME,
        "CreationUtcTime",
        value,
    )? {
        Body::FileCreateTime(FileCreateTime {
            creation_utc_time, ..
        }) => Ok(creation_utc_time.unwrap()),
        other => panic!("not a FileCreateTime body: {other:?}"),
    };
    assert_eq!(
        time("2024-03-05 12:34:56.789").unwrap(),
        utc("2024-03-05T12:34:56.789Z")
    );
    assert_eq!(
        time("2024-03-05 12:34:56").unwrap(),
        utc("2024-03-05T12:34:56Z")
    );
    assert_eq!(
        time("2024-03-05 12:34:56.123456789").unwrap(),
        utc("2024-03-05T12:34:56.123456789Z")
    );
    for bad in [
        "2024-03-05T12:34:56Z",
        "2024-03-05 12:34:56.1234567891",
        "2024-02-30 12:34:56",
        "2263-01-01 00:00:00",
    ] {
        assert!(invalid("CreationUtcTime")(time(bad).unwrap_err()), "{bad}");
    }

    // A time is integer nanoseconds since the Unix epoch.
    let converted = sysmon::convert(
        kind::SYSMON_FILE_CREATE_TIME,
        &[("PreviousCreationUtcTime", "1970-01-01 00:00:01.5")],
    )
    .unwrap();
    let body = converted.body.to_record_body().unwrap();
    assert_eq!(
        entry(&body, "previous_creation_utc_time"),
        Some(Value::Integer(1_500_000_000.into()))
    );
}

#[test]
fn ip_addresses_and_booleans() {
    let converted = sysmon::convert(kind::SYSMON_NETWORK_CONNECT, &sample(3)).unwrap();
    let Body::NetworkConnect(connect) = &converted.body else {
        panic!("not a NetworkConnect body");
    };
    assert_eq!(
        connect.source_ip,
        Some("192.0.2.10".parse::<IpAddr>().unwrap())
    );
    assert_eq!(
        connect.destination_ip,
        Some("2001:db8::443".parse::<IpAddr>().unwrap())
    );
    assert_eq!(connect.initiated, Some(true));
    assert_eq!(connect.source_is_ipv6, Some(false));
    assert_eq!(connect.destination_port, Some(443));
    let body = converted.body.to_record_body().unwrap();
    assert_eq!(
        entry(&body, "source_ip"),
        Some(Value::Bytes(vec![192, 0, 2, 10]))
    );
    let Some(Value::Bytes(destination)) = entry(&body, "destination_ip") else {
        panic!("destination_ip is not bytes");
    };
    assert_eq!(destination.len(), 16);
    assert_eq!(entry(&body, "initiated"), Some(Value::Bool(true)));

    for (field, bad) in [
        ("SourceIp", "host-1"),
        ("DestinationIp", "192.0.2.256"),
        ("DestinationIp", "fe80::1%eth0"),
        ("Initiated", "1"),
        ("SourceIsIpv6", "yes"),
    ] {
        let error = convert_one(kind::SYSMON_NETWORK_CONNECT, field, bad).unwrap_err();
        assert!(invalid(field)(error), "{field}={bad}");
    }

    for (value, expected) in [("TRUE", true), ("false", false)] {
        let Body::FileDelete(delete) =
            convert_one(kind::SYSMON_FILE_DELETE, "IsExecutable", value).unwrap()
        else {
            panic!("not a FileDelete body");
        };
        assert_eq!(delete.is_executable, Some(expected));
    }
    let error = convert_one(kind::SYSMON_FILE_DELETE_DETECTED, "IsExecutable", "-").unwrap_err();
    assert!(invalid("IsExecutable")(error));
}

#[test]
fn dns_query_results_stay_as_written() {
    let raw = "type:  5 example.cdn.net;::ffff:192.0.2.80;192.0.2.81;";
    let Body::DnsQuery(DnsQuery { query_results, .. }) =
        convert_one(kind::SYSMON_DNS_QUERY, "QueryResults", raw).unwrap()
    else {
        panic!("not a DnsQuery body");
    };
    assert_eq!(query_results.as_deref(), Some(raw));
}

#[test]
fn unsupported_kinds() {
    for kind in [4, 16, 18, 19, 20, 21, 24, 100, 255, 0, 27, 1000] {
        assert_eq!(
            sysmon::convert(kind, &[("UtcTime", UTC_TIME)]),
            Err(ConvertError::UnsupportedKind(kind))
        );
        // The kind is checked before the fields.
        assert_eq!(
            sysmon::convert(kind, &[("UtcTime", "x"), ("UtcTime", "x")]),
            Err(ConvertError::UnsupportedKind(kind))
        );
        assert_eq!(
            Body::from_record_body(kind, &RecordBody::default()),
            Err(BodyError::UnsupportedKind(kind))
        );
    }
}

#[test]
fn other_versions_of_a_body() {
    // A raw field the base version does not have is dropped.
    let mut fields = sample(5);
    fields.push(("ParentProcessGuid", OTHER_GUID_TEXT));
    let converted = sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &fields).unwrap();
    assert_eq!(
        converted.body,
        sysmon::convert(kind::SYSMON_PROCESS_TERMINATE, &sample(5))
            .unwrap()
            .body
    );

    // A key the receiver does not know is ignored.
    let bytes = body_bytes(vec![
        ("image", Value::Text("cmd.exe".to_owned())),
        ("future_field", Value::Array(vec![Value::Integer(1.into())])),
        ("process_id", Value::Integer(42.into())),
    ]);
    let body: RecordBody = cbor::from_slice(&bytes).unwrap();
    assert_eq!(
        Body::from_record_body(kind::SYSMON_PROCESS_TERMINATE, &body).unwrap(),
        Body::ProcessTerminate(ProcessTerminate {
            image: Some("cmd.exe".to_owned()),
            process_id: Some(42),
            ..ProcessTerminate::default()
        })
    );

    // A body with every field missing reads, as does one with nulls.
    for kind in SYSMON_KINDS {
        let body = Body::from_record_body(kind, &RecordBody::default()).unwrap();
        assert_eq!(body.kind(), kind);
        assert!(keys(&body.to_record_body().unwrap()).is_empty());
    }
    let nulls = body_bytes(vec![("image", Value::Null), ("process_guid", Value::Null)]);
    let body: RecordBody = cbor::from_slice(&nulls).unwrap();
    assert_eq!(
        Body::from_record_body(kind::SYSMON_PROCESS_TERMINATE, &body).unwrap(),
        Body::ProcessTerminate(ProcessTerminate::default())
    );

    // A value of the wrong CBOR type does not decode.
    let wrong = body_bytes(vec![("process_guid", Value::Text(GUID_TEXT.to_owned()))]);
    let body: RecordBody = cbor::from_slice(&wrong).unwrap();
    assert!(matches!(
        Body::from_record_body(kind::SYSMON_PROCESS_TERMINATE, &body),
        Err(BodyError::Decode(_))
    ));

    // A key held twice does not decode.
    let twice = body_bytes(vec![
        ("image", Value::Text("a.exe".to_owned())),
        ("image", Value::Text("b.exe".to_owned())),
    ]);
    assert_eq!(
        cbor::from_slice::<RecordBody>(&twice).unwrap_err().kind(),
        DecodeErrorKind::DuplicateKey
    );
}

#[test]
fn process_keys() {
    for kind in [1, 2, 3, 5, 7, 9, 11, 12, 13, 14, 15, 17, 22, 23, 25, 26] {
        let body = sysmon::convert(kind, &sample(kind)).unwrap().body;
        let key = body.process_key(&OsFamily::Windows).unwrap();
        assert_eq!(key.os, OsFamily::Windows);
        assert_eq!(key.value, GUID_BYTES, "kind {kind}");
    }
    for kind in [8, 10] {
        let body = sysmon::convert(kind, &sample(kind)).unwrap().body;
        let key = body.process_key(&OsFamily::Linux).unwrap();
        assert_eq!(key.os, OsFamily::Linux);
        assert_eq!(key.value, GUID_BYTES, "kind {kind}");
    }
    let driver = sysmon::convert(kind::SYSMON_DRIVER_LOAD, &sample(6))
        .unwrap()
        .body;
    assert_eq!(driver.process_key(&OsFamily::Windows), None);

    // A body whose GUID field has no value has no key, and the target
    // process is never the key.
    let other = OsFamily::Other("plan9".to_owned());
    assert_eq!(
        Body::ProcessTerminate(ProcessTerminate::default()).process_key(&other),
        None
    );
    let access = Body::ProcessAccess(ProcessAccess {
        target_process_guid: Some(Uuid::from_bytes(OTHER_GUID_BYTES)),
        ..ProcessAccess::default()
    });
    assert_eq!(access.process_key(&other), None);
    let thread = Body::CreateRemoteThread(CreateRemoteThread {
        source_process_guid: Some(Uuid::from_bytes(OTHER_GUID_BYTES)),
        target_process_guid: Some(Uuid::from_bytes(GUID_BYTES)),
        ..CreateRemoteThread::default()
    });
    let key = thread.process_key(&other).unwrap();
    assert_eq!(key.os, other);
    assert_eq!(key.value, OTHER_GUID_BYTES);
}

#[test]
fn process_key_outlives_field_exclusion() {
    let converted = sysmon::convert(kind::SYSMON_NETWORK_CONNECT, &sample(3)).unwrap();
    // The key is taken before the policy's field exclusions.
    let key = converted.body.process_key(&OsFamily::Windows);
    let Body::NetworkConnect(mut excluded) = converted.body else {
        panic!("not a NetworkConnect body");
    };
    excluded.process_guid = None;
    excluded.user = None;
    let excluded = Body::NetworkConnect(excluded);
    assert_eq!(excluded.process_key(&OsFamily::Windows), None);

    let record = Record {
        header: header(key.clone()),
        kind: excluded.kind(),
        schema: kind::info(excluded.kind()).unwrap().schema(),
        body: excluded.to_record_body().unwrap(),
    };
    let received = Record::from_bytes(&record.to_bytes().unwrap()).unwrap();
    assert_eq!(received.header.process_key, key);
    assert_eq!(received.header.process_key.unwrap().value, GUID_BYTES);
    let body_keys = keys(&received.body);
    assert!(!body_keys.iter().any(|k| k == "process_guid" || k == "user"));
    let NetworkConnect {
        process_guid,
        image,
        ..
    } = match Body::from_record_body(received.kind, &received.body).unwrap() {
        Body::NetworkConnect(body) => body,
        other => panic!("not a NetworkConnect body: {other:?}"),
    };
    assert_eq!(process_guid, None);
    assert!(image.is_some());
}

#[test]
fn bodies_convert_into_body() {
    let body: Body = ProcessTerminate {
        process_id: Some(1),
        ..ProcessTerminate::default()
    }
    .into();
    assert_eq!(body.kind(), ProcessTerminate::KIND);
    assert_eq!(ProcessTerminate::KIND, kind::SYSMON_PROCESS_TERMINATE);
    assert_eq!(ProcessAccess::KIND, kind::SYSMON_PROCESS_ACCESS);
}
