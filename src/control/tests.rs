//! The CBOR contract of the control messages and their enums, the hardware
//! identifier hash, and the status report send decision, checked against
//! hand-made CBOR.

use std::fmt::Debug;
use std::time::Duration;

use ciborium::Value;
use jiff::Timestamp;
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use super::*;
use crate::connection::{
    ClockOffset, DecodeErrorKind, EndpointAction, EndpointChannel, EndpointConfig,
    EndpointConnection, Envelope, Frame, Message, SERVER_ACTIVE_RECEIVE_LIMIT, ServerAction,
    ServerChannel, ServerConfig, ServerConnection, cbor,
};
use crate::host::{CollectionMode, OsFamily, OsInfo};
use crate::results::{CommandResultKind, DocumentResult};
use crate::standing::SuspendReason;

const SALT: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

/// HMAC-SHA256 keyed with the bytes 0x01..=0x10, over `clumit-endpoint`
/// followed by [`SALT`], computed apart from this crate with Python:
///
/// ```text
/// import hmac, hashlib
/// key = bytes(range(1, 17))
/// salt = bytes(range(0x20, 0x40))
/// hmac.new(key, b"clumit-endpoint" + salt, hashlib.sha256).hexdigest()
/// ```
const EXPECTED_HASH: &str = "72204bd1da374a7ec58ce7a55c3a7b70ef0f789962d9a1e520ceb8e39649b665";

/// The same for the key `8f3a2b1c4d5e6f708192a3b4c5d6e7f8` and a salt of 32
/// bytes 0xa5:
///
/// ```text
/// key = bytes.fromhex("8f3a2b1c4d5e6f708192a3b4c5d6e7f8")
/// hmac.new(key, b"clumit-endpoint" + bytes([0xa5] * 32), hashlib.sha256).hexdigest()
/// ```
const EXPECTED_HASH_2: &str = "2e46a13e6541cb667b0755a789cc583967225f3ebdad7e2b2fcb9ce9f764a76b";

const MIB: usize = 1024 * 1024;

// --- helpers -------------------------------------------------------------

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn uuid_value(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn value_of<T: Serialize + ?Sized>(value: &T) -> Value {
    ciborium::from_reader(cbor::to_vec(value).unwrap().as_slice()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes `body` as the body of an envelope named `t`.
fn decode_body(t: &str, body: &Value) -> Result<ControlMessage, ControlDecodeError> {
    let frame = Frame::new(t, body).unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    ControlMessage::decode(envelope.t(), envelope.body())
}

/// Returns the kind of the body error decoding `body` under `t` fails with.
fn body_error(t: &str, body: &Value) -> DecodeErrorKind {
    match decode_body(t, body) {
        Err(ControlDecodeError::Body { t: got, error }) => {
            assert_eq!(got, t);
            error.kind()
        }
        other => panic!("expected a body error for {t}, got {other:?}"),
    }
}

/// Returns the body a message encodes to, checking the envelope's `t`.
fn body_of(message: &ControlMessage) -> Value {
    let frame = message.to_frame().unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    assert_eq!(envelope.t(), message.t());
    ciborium::from_reader(envelope.body().as_bytes()).unwrap()
}

/// Encodes a message, decodes it back, and checks that the result encodes
/// to the same bytes. Returns the decoded message and the body.
fn round_trip(message: &ControlMessage) -> (ControlMessage, Value) {
    let frame = message.to_frame().unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    let decoded = ControlMessage::decode(envelope.t(), envelope.body()).unwrap();
    assert_eq!(decoded.t(), message.t());
    assert_eq!(decoded.to_frame().unwrap().as_bytes(), frame.as_bytes());
    (decoded, body_of(message))
}

/// Encodes a typed message, decodes it back through [`ControlMessage`],
/// and checks it equals the original. Returns the body.
fn typed_round_trip<M>(message: &M, get: fn(ControlMessage) -> Option<M>) -> Value
where
    M: Message + Clone + PartialEq + Debug + Into<ControlMessage>,
{
    let (decoded, body) = round_trip(&message.clone().into());
    assert_eq!(decoded.t(), M::T);
    assert_eq!(&get(decoded).unwrap(), message);
    body
}

fn entries(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

/// Returns the value at `path`: map keys, or indices into arrays.
fn at<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    let mut current = value;
    for step in path {
        current = match current {
            Value::Map(entries) => entries
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some(step))
                .map(|(_, value)| value)
                .unwrap_or_else(|| panic!("no key {step}")),
            Value::Array(items) => items.get_mut(step.parse::<usize>().unwrap()).unwrap(),
            other => panic!("cannot step into {other:?}"),
        };
    }
    current
}

fn keys(value: &Value) -> Vec<String> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .map(|(key, _)| key.as_text().unwrap().to_owned())
            .collect(),
        other => panic!("expected a map, got {other:?}"),
    }
}

fn has_key(value: &Value, key: &str) -> bool {
    keys(value).iter().any(|k| k == key)
}

fn remove_key(value: &mut Value, key: &str) {
    let entries = entries(value);
    let before = entries.len();
    entries.retain(|(k, _)| k.as_text() != Some(key));
    assert_eq!(entries.len() + 1, before, "no key {key} to remove");
}

fn set_key(value: &mut Value, key: &str, new: Value) {
    let entries = entries(value);
    match entries.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
        Some((_, old)) => *old = new,
        None => entries.push((text(key), new)),
    }
}

/// The tags whose one-entry maps are an enum's, not a struct's.
const CONTENT_TAGS: [&str; 14] = [
    "halted",
    "group",
    "endpoint",
    "customer",
    "install",
    "signature_rejected",
    "unknown_kid",
    "approved",
    "pending",
    "rejected",
    "keyset_gap",
    "recovery_key_gap",
    "apply_failed",
    "failed",
];

fn is_enum_map(entries: &[(Value, Value)]) -> bool {
    matches!(entries, [(key, _)] if key.as_text().is_some_and(|key| CONTENT_TAGS.contains(&key)))
}

/// Adds a field no version knows to every struct's map, at every depth,
/// and returns how many were added.
fn add_unknown_fields(value: &mut Value) -> usize {
    match value {
        Value::Map(entries) => {
            let enum_map = is_enum_map(entries);
            let mut added: usize = entries
                .iter_mut()
                .map(|(_, value)| add_unknown_fields(value))
                .sum();
            if !enum_map {
                entries.push((
                    text("zz_from_a_newer_version"),
                    map(vec![(
                        "nested",
                        Value::Array(vec![Value::from(1), Value::Null]),
                    )]),
                ));
                added += 1;
            }
            added
        }
        Value::Array(items) => items.iter_mut().map(add_unknown_fields).sum(),
        _ => 0,
    }
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, DecodeErrorKind> {
    cbor::from_slice(&cbor::to_vec(value).unwrap()).map_err(|error| error.kind())
}

// --- samples -------------------------------------------------------------

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn at_second(second: i64) -> Timestamp {
    Timestamp::from_second(second).unwrap()
}

fn hardware() -> Hardware {
    Hardware {
        machine_id_hash: [0x5a; 32],
        smbios_uuid: Some("4c4c4544-0042-3510-8058-b7c04f4e3332".to_owned()),
        smbios_serial: Some("7B5XQ32".to_owned()),
    }
}

fn os() -> OsInfo {
    OsInfo {
        family: OsFamily::Windows,
        version: "10.0.22631".to_owned(),
    }
}

fn enroll_request() -> EnrollRequest {
    EnrollRequest {
        attempt_id: id(1),
        trusted_keyset: KeysetPosition {
            recovery_epoch: 2,
            keyset_version: 5,
        },
        trusted_recovery_key_version: 3,
        enroll_token: EnrollToken::new("eyJ.enroll.token".to_owned()),
        hardware: hardware(),
        hostname: "host-1".to_owned(),
        os: os(),
        senta_version: "1.4.0".to_owned(),
        key_storage: KeyStorage::Tpm,
        vdi_mode: true,
    }
}

fn approved(chain: &[&str]) -> EnrollResult {
    EnrollResult {
        outcome: EnrollOutcome::Approved {
            enroll_result: "eyJ.enroll-result.sig".to_owned(),
            chain: chain.iter().map(|&s| s.to_owned()).collect(),
        },
    }
}

fn every_problem() -> Vec<Problem> {
    vec![
        Problem::SignatureRejected {
            typ: Some("senta-command".to_owned()),
            kid: Some("customer:install-1:3".to_owned()),
            result: DocumentResult::BadSignature,
        },
        Problem::UnknownKid {
            kid: "customer:install-1:9".to_owned(),
        },
        Problem::KeysetGap,
        Problem::UpdateFailed,
        Problem::UpdateRolledBack,
        Problem::SourceUnreachable,
        Problem::PriorEpochState,
        Problem::SysmonMissing,
        Problem::ClockSkew,
        Problem::InstallConfigInvalid,
        Problem::SysmonStopped,
        Problem::SysmonConfigChanged,
        Problem::UnexpectedRestart,
        Problem::Other("disk_full".to_owned()),
    ]
}

fn slot(state: DocumentSlotState) -> DocumentSlot {
    DocumentSlot {
        typ: "senta-policy".to_owned(),
        target: Some(DocumentTarget::Group(id(7))),
        verified_version: Some(4),
        applied_version: Some(3),
        state,
        in_use: Some(InUseDocument {
            recovery_epoch: 1,
            version: 9,
        }),
        untrusted: true,
    }
}

/// A status report with every field filled, every [`Problem`] and every
/// [`DocumentSlotState`].
fn full_report() -> StatusReport {
    StatusReport {
        endpoint: EndpointStatus {
            senta_version: "1.4.0".to_owned(),
            os: os(),
            key_storage: KeyStorage::Dpapi,
            keyset: KeysetPosition {
                recovery_epoch: 2,
                keyset_version: 6,
            },
            recovery_key_version: 3,
        },
        documents: vec![
            slot(DocumentSlotState::Halted {
                reason: "disk full".to_owned(),
            }),
            slot(DocumentSlotState::Current),
            slot(DocumentSlotState::Pending),
            slot(DocumentSlotState::PendingOffTarget),
            slot(DocumentSlotState::Other("paused".to_owned())),
        ],
        collection: CollectionStatus {
            collection_mode: CollectionMode::Extended,
            sysmon: SysmonStatus {
                state: SysmonState::Standalone,
                version: Some("15.15".to_owned()),
            },
            audit_policy: AuditPolicyState::GpoManaged,
        },
        transport: TransportStatus {
            entries: vec![
                EntryStatus {
                    entry_id: id(11),
                    last_success_at: Some(at_second(1_700_000_000)),
                },
                EntryStatus {
                    entry_id: id(12),
                    last_success_at: Some(at_second(1_700_000_100)),
                },
            ],
            buffered_records: 120,
            buffered_bytes: 65_536,
            dropped_ranges: 2,
            unsupported_dropped: 7,
        },
        clock: ClockStatus {
            offset: Some(ClockOffset {
                offset_ms: 1_250,
                uncertainty_ms: 12,
                measured_at: at_second(1_700_000_050),
            }),
            exceeds_tolerance: false,
        },
        hardware: hardware(),
        problems: every_problem(),
    }
}

/// A status report with every optional field empty.
fn empty_report() -> StatusReport {
    StatusReport {
        endpoint: EndpointStatus {
            senta_version: "1.4.0".to_owned(),
            os: OsInfo {
                family: OsFamily::Linux,
                version: "6.8".to_owned(),
            },
            key_storage: KeyStorage::File,
            keyset: KeysetPosition {
                recovery_epoch: 0,
                keyset_version: 1,
            },
            recovery_key_version: 1,
        },
        documents: vec![DocumentSlot {
            typ: "senta-addresses".to_owned(),
            target: None,
            verified_version: None,
            applied_version: None,
            state: DocumentSlotState::Current,
            in_use: None,
            untrusted: false,
        }],
        collection: CollectionStatus {
            collection_mode: CollectionMode::Essential,
            sysmon: SysmonStatus {
                state: SysmonState::Absent,
                version: None,
            },
            audit_policy: AuditPolicyState::Off,
        },
        transport: TransportStatus {
            entries: vec![EntryStatus {
                entry_id: id(11),
                last_success_at: None,
            }],
            buffered_records: 0,
            buffered_bytes: 0,
            dropped_ranges: 0,
            unsupported_dropped: 0,
        },
        clock: ClockStatus {
            offset: None,
            exceeds_tolerance: false,
        },
        hardware: Hardware {
            machine_id_hash: [1; 32],
            smbios_uuid: None,
            smbios_serial: None,
        },
        problems: vec![],
    }
}

fn full_ack() -> DocumentAck {
    DocumentAck {
        typ: Some("senta-keyset".to_owned()),
        target: Some(DocumentTarget::Customer(id(3))),
        recovery_epoch: Some(2),
        version: Some(6),
        result: DocumentResult::KeysetGap {
            have_epoch: 2,
            have_version: 4,
        },
    }
}

fn command_result(bundle: Option<Vec<u8>>) -> CommandResult {
    CommandResult {
        command_id: id(21),
        result: CommandResultKind::Failed {
            reason: "timeout".to_owned(),
        },
        bundle: bundle.map(|bytes| Bundle::try_from(bytes).unwrap()),
    }
}

/// One of each message, with every optional field filled.
fn every_message() -> Vec<ControlMessage> {
    vec![
        enroll_request().into(),
        EnrollResultPoll { attempt_id: id(1) }.into(),
        Unenroll {
            uninstall_token: UninstallToken::new("correct horse".to_owned()),
        }
        .into(),
        approved(&["eyJ.keyset.1", "eyJ.recovery.2"]).into(),
        full_report().into(),
        Documents {
            documents: vec!["eyJ.a.1".to_owned(), "eyJ.b.2".to_owned()],
        }
        .into(),
        full_ack().into(),
        Command {
            command: "eyJ.command.sig".to_owned(),
        }
        .into(),
        command_result(Some(vec![1, 2, 3])).into(),
        SuspendNotice {
            reason: SuspendReason::License,
        }
        .into(),
    ]
}

macro_rules! getter {
    ($variant:ident) => {
        |message| match message {
            ControlMessage::$variant(inner) => Some(inner),
            _ => None,
        }
    };
}

// --- message kinds and the envelope --------------------------------------

#[test]
fn message_kinds_are_the_table() {
    assert_eq!(
        MESSAGE_KINDS,
        [
            "enroll_request",
            "enroll_result_poll",
            "unenroll",
            "enroll_result",
            "status_report",
            "documents",
            "document_ack",
            "command",
            "command_result",
            "suspend_notice",
        ]
    );
    let kinds: Vec<&str> = every_message().iter().map(ControlMessage::t).collect();
    assert_eq!(kinds, MESSAGE_KINDS);
}

#[test]
fn unknown_kinds_and_broken_bodies_are_told_apart() {
    for t in ["hello", "ping", "unsupported", "status", ""] {
        assert_eq!(
            decode_body(t, &map(vec![])).unwrap_err(),
            ControlDecodeError::UnknownKind { t: t.to_owned() }
        );
    }
    for t in MESSAGE_KINDS {
        assert_eq!(body_error(t, &Value::from(1)), DecodeErrorKind::Invalid);
        assert_eq!(body_error(t, &map(vec![])), DecodeErrorKind::Invalid);
    }
    assert_eq!(
        body_error("documents", &map(vec![("documents", Value::from(1))])),
        DecodeErrorKind::Invalid
    );
}

#[test]
fn the_connection_helper_delivers_known_kinds() {
    let wall = at_second(1_700_000_000);
    let mut server = ServerConnection::new(
        ServerConfig::new(ServerChannel::Control, SERVER_ACTIVE_RECEIVE_LIMIT)
            .with_known_kinds(MESSAGE_KINDS),
        Duration::ZERO,
    );
    let (mut endpoint, hello) = EndpointConnection::new(
        EndpointConfig::new(EndpointChannel::Control, "0.1.0").with_known_kinds(MESSAGE_KINDS),
        wall,
        Duration::ZERO,
    )
    .unwrap();
    let actions = server.receive(hello.as_bytes(), wall, Duration::from_millis(5));
    let Some(ServerAction::Send(ack)) = actions.first() else {
        panic!("expected a hello_ack, got {actions:?}");
    };
    let actions = endpoint.receive(ack.as_bytes(), wall, Duration::from_millis(10));
    assert!(matches!(
        actions.first(),
        Some(EndpointAction::Handshake(_))
    ));

    let poll = EnrollResultPoll { attempt_id: id(4) };
    let frame = ControlMessage::from(poll).to_frame().unwrap();
    let actions = server.receive(frame.as_bytes(), wall, Duration::from_millis(20));
    let Some(ServerAction::Deliver(envelope)) = actions.first() else {
        panic!("expected a delivery, got {actions:?}");
    };
    let ControlMessage::EnrollResultPoll(received) =
        ControlMessage::decode(envelope.t(), envelope.body()).unwrap()
    else {
        panic!("expected an enroll_result_poll");
    };
    assert_eq!(received, poll);

    let notice = ControlMessage::from(SuspendNotice {
        reason: SuspendReason::Operator,
    })
    .to_frame()
    .unwrap();
    let actions = endpoint.receive(notice.as_bytes(), wall, Duration::from_millis(30));
    let Some(EndpointAction::Deliver(envelope)) = actions.first() else {
        panic!("expected a delivery, got {actions:?}");
    };
    assert!(matches!(
        ControlMessage::decode(envelope.t(), envelope.body()).unwrap(),
        ControlMessage::SuspendNotice(SuspendNotice {
            reason: SuspendReason::Operator
        })
    ));
}

#[test]
fn every_message_round_trips_under_its_field_names() {
    let expected: [&[&str]; 10] = [
        &[
            "attempt_id",
            "trusted_keyset",
            "trusted_recovery_key_version",
            "enroll_token",
            "hardware",
            "hostname",
            "os",
            "senta_version",
            "key_storage",
            "vdi_mode",
        ],
        &["attempt_id"],
        &["uninstall_token"],
        &["outcome"],
        &[
            "endpoint",
            "documents",
            "collection",
            "transport",
            "clock",
            "hardware",
            "problems",
        ],
        &["documents"],
        &["typ", "target", "recovery_epoch", "version", "result"],
        &["command"],
        &["command_id", "result", "bundle"],
        &["reason"],
    ];
    for (message, expected) in every_message().iter().zip(expected) {
        let (_, body) = round_trip(message);
        let mut got = keys(&body);
        let mut expected: Vec<String> = expected.iter().map(|&k| k.to_owned()).collect();
        got.sort_unstable();
        expected.sort_unstable();
        assert_eq!(got, expected, "{}", message.t());
    }

    assert_enroll_request_round_trips(&enroll_request());
    typed_round_trip(
        &EnrollResultPoll { attempt_id: id(1) },
        getter!(EnrollResultPoll),
    );
    typed_round_trip(&full_report(), getter!(StatusReport));
    typed_round_trip(&full_ack(), getter!(DocumentAck));
    typed_round_trip(&command_result(Some(vec![9; 10])), getter!(CommandResult));
    typed_round_trip(
        &SuspendNotice {
            reason: SuspendReason::Revoked,
        },
        getter!(SuspendNotice),
    );
}

#[test]
fn enroll_request_body_has_the_documented_shape() {
    let body = assert_enroll_request_round_trips(&enroll_request());
    let expected = map(vec![
        ("attempt_id", uuid_value(id(1))),
        (
            "trusted_keyset",
            map(vec![
                ("recovery_epoch", Value::from(2)),
                ("keyset_version", Value::from(5)),
            ]),
        ),
        ("trusted_recovery_key_version", Value::from(3)),
        ("enroll_token", text("eyJ.enroll.token")),
        (
            "hardware",
            map(vec![
                ("machine_id_hash", Value::Bytes(vec![0x5a; 32])),
                ("smbios_uuid", text("4c4c4544-0042-3510-8058-b7c04f4e3332")),
                ("smbios_serial", text("7B5XQ32")),
            ]),
        ),
        ("hostname", text("host-1")),
        (
            "os",
            map(vec![
                ("family", text("windows")),
                ("version", text("10.0.22631")),
            ]),
        ),
        ("senta_version", text("1.4.0")),
        ("key_storage", text("tpm")),
        ("vdi_mode", Value::Bool(true)),
    ]);
    assert_eq!(body, expected);
}

/// Round-trips an enrollment request, which has no equality, and checks
/// that each field decodes as it was. Returns the body.
fn assert_enroll_request_round_trips(request: &EnrollRequest) -> Value {
    let (decoded, body) = round_trip(&request.clone().into());
    let ControlMessage::EnrollRequest(decoded) = decoded else {
        panic!("expected an enroll_request");
    };
    assert_eq!(decoded.attempt_id, request.attempt_id);
    assert_eq!(decoded.trusted_keyset, request.trusted_keyset);
    assert_eq!(
        decoded.trusted_recovery_key_version,
        request.trusted_recovery_key_version
    );
    assert_eq!(decoded.enroll_token.expose(), request.enroll_token.expose());
    assert_eq!(decoded.hardware, request.hardware);
    assert_eq!(decoded.hostname, request.hostname);
    assert_eq!(decoded.os, request.os);
    assert_eq!(decoded.senta_version, request.senta_version);
    assert_eq!(decoded.key_storage, request.key_storage);
    assert_eq!(decoded.vdi_mode, request.vdi_mode);
    body
}

#[test]
fn enroll_request_redacts_its_token() {
    let request = enroll_request();
    for debug in [
        format!("{request:?}"),
        format!("{:?}", ControlMessage::from(request.clone())),
        format!("{:?}", request.enroll_token),
    ] {
        assert!(!debug.contains("eyJ.enroll.token"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}

#[test]
fn unenroll_round_trips_and_redacts_its_token() {
    let message = Unenroll {
        uninstall_token: UninstallToken::new("correct horse".to_owned()),
    };
    let (decoded, body) = round_trip(&message.clone().into());
    assert_eq!(body, map(vec![("uninstall_token", text("correct horse"))]));
    let ControlMessage::Unenroll(decoded) = decoded else {
        panic!("expected an unenroll");
    };
    assert_eq!(decoded.uninstall_token.expose(), "correct horse");
    for debug in [
        format!("{message:?}"),
        format!("{:?}", ControlMessage::from(message)),
    ] {
        assert!(!debug.contains("correct horse"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}

// --- compatibility -------------------------------------------------------

#[test]
fn unknown_fields_are_ignored_at_every_depth() {
    for message in every_message() {
        let mut body = body_of(&message);
        let added = add_unknown_fields(&mut body);
        assert!(added >= 1, "{}", message.t());
        let decoded = decode_body(message.t(), &body).unwrap();
        assert_eq!(
            decoded.to_frame().unwrap().as_bytes(),
            message.to_frame().unwrap().as_bytes(),
            "{}",
            message.t()
        );
    }
    // Every struct of the two largest bodies took one: in the report, the
    // body, `endpoint` with its `os` and `keyset`, five slots with their
    // `in_use` and one `halted` field map, `collection` with its `sysmon`,
    // `transport` with two entries, `clock` with its `offset`, `hardware`,
    // and the field maps of `signature_rejected` and `unknown_kid`.
    let mut body = body_of(&full_report().into());
    assert_eq!(add_unknown_fields(&mut body), 25);
    let mut body = body_of(&enroll_request().into());
    assert_eq!(add_unknown_fields(&mut body), 4);
}

#[test]
fn missing_required_fields_fail() {
    let optional: &[(&str, &[&str])] = &[
        (
            "document_ack",
            &["typ", "target", "recovery_epoch", "version"],
        ),
        ("command_result", &["bundle"]),
    ];
    for message in every_message() {
        let body = body_of(&message);
        let skip = optional
            .iter()
            .find(|(t, _)| *t == message.t())
            .map_or(&[][..], |(_, keys)| *keys);
        for key in keys(&body) {
            if skip.contains(&key.as_str()) {
                continue;
            }
            let mut broken = body.clone();
            remove_key(&mut broken, &key);
            assert_eq!(
                body_error(message.t(), &broken),
                DecodeErrorKind::Invalid,
                "{} without {key}",
                message.t()
            );
        }
    }

    let nested: &[(&str, ControlMessage, &[&str], &[&str])] = &[
        (
            "enroll_request",
            enroll_request().into(),
            &["trusted_keyset"],
            &["recovery_epoch", "keyset_version"],
        ),
        (
            "enroll_request",
            enroll_request().into(),
            &["hardware"],
            &["machine_id_hash"],
        ),
        (
            "enroll_request",
            enroll_request().into(),
            &["os"],
            &["family", "version"],
        ),
        (
            "enroll_result",
            approved(&["a"]).into(),
            &["outcome", "approved"],
            &["enroll_result", "chain"],
        ),
        (
            "document_ack",
            full_ack().into(),
            &["result", "keyset_gap"],
            &["have_epoch"],
        ),
        (
            "status_report",
            full_report().into(),
            &["endpoint"],
            &[
                "senta_version",
                "os",
                "key_storage",
                "keyset",
                "recovery_key_version",
            ],
        ),
        (
            "status_report",
            full_report().into(),
            &["endpoint", "keyset"],
            &["keyset_version"],
        ),
        (
            "status_report",
            full_report().into(),
            &["documents", "0"],
            &["typ", "state", "untrusted"],
        ),
        (
            "status_report",
            full_report().into(),
            &["documents", "0", "in_use"],
            &["recovery_epoch", "version"],
        ),
        (
            "status_report",
            full_report().into(),
            &["documents", "0", "state", "halted"],
            &["reason"],
        ),
        (
            "status_report",
            full_report().into(),
            &["collection"],
            &["collection_mode", "sysmon", "audit_policy"],
        ),
        (
            "status_report",
            full_report().into(),
            &["collection", "sysmon"],
            &["state"],
        ),
        (
            "status_report",
            full_report().into(),
            &["transport"],
            &[
                "entries",
                "buffered_records",
                "buffered_bytes",
                "dropped_ranges",
                "unsupported_dropped",
            ],
        ),
        (
            "status_report",
            full_report().into(),
            &["transport", "entries", "1"],
            &["entry_id"],
        ),
        (
            "status_report",
            full_report().into(),
            &["clock"],
            &["exceeds_tolerance"],
        ),
        (
            "status_report",
            full_report().into(),
            &["clock", "offset"],
            &["offset_ms", "uncertainty_ms", "measured_at"],
        ),
        (
            "status_report",
            full_report().into(),
            &["problems", "0", "signature_rejected"],
            &["result"],
        ),
        (
            "status_report",
            full_report().into(),
            &["problems", "1", "unknown_kid"],
            &["kid"],
        ),
    ];
    for (t, message, path, required) in nested {
        let body = body_of(message);
        for key in *required {
            let mut broken = body.clone();
            remove_key(at(&mut broken, path), key);
            assert_eq!(
                body_error(t, &broken),
                DecodeErrorKind::Invalid,
                "{t} without {path:?}.{key}"
            );
        }
    }
}

#[test]
fn mistyped_fields_fail() {
    let cases: Vec<(ControlMessage, &[&str], &str, Value)> = vec![
        (
            enroll_request().into(),
            &[],
            "attempt_id",
            text("not a uuid"),
        ),
        (
            enroll_request().into(),
            &[],
            "attempt_id",
            Value::Bytes(vec![0; 15]),
        ),
        (enroll_request().into(), &[], "vdi_mode", Value::from(1)),
        (
            enroll_request().into(),
            &[],
            "enroll_token",
            Value::Bytes(b"jws".to_vec()),
        ),
        (
            enroll_request().into(),
            &[],
            "trusted_recovery_key_version",
            Value::from(-1),
        ),
        (
            enroll_request().into(),
            &[],
            "hardware",
            Value::Array(vec![]),
        ),
        (enroll_request().into(), &[], "key_storage", Value::from(2)),
        (
            enroll_request().into(),
            &["hardware"],
            "smbios_uuid",
            Value::Bytes(vec![1; 16]),
        ),
        (
            Documents {
                documents: vec!["a".to_owned()],
            }
            .into(),
            &[],
            "documents",
            Value::Array(vec![Value::from(1)]),
        ),
        (full_ack().into(), &[], "typ", Value::from(1)),
        (full_ack().into(), &[], "version", text("6")),
        (full_ack().into(), &[], "target", text("group")),
        (command_result(None).into(), &[], "bundle", text("bytes")),
        (
            command_result(None).into(),
            &[],
            "bundle",
            Value::Array(vec![Value::from(1)]),
        ),
        (
            full_report().into(),
            &["transport"],
            "buffered_records",
            Value::from(-5),
        ),
        (
            full_report().into(),
            &["clock", "offset"],
            "offset_ms",
            text("12"),
        ),
        (
            full_report().into(),
            &["clock"],
            "exceeds_tolerance",
            Value::Null,
        ),
        (
            full_report().into(),
            &["transport", "entries", "0"],
            "last_success_at",
            text("yesterday"),
        ),
        (
            full_report().into(),
            &["documents", "0"],
            "untrusted",
            text("yes"),
        ),
        (full_report().into(), &[], "problems", map(vec![])),
    ];
    for (message, path, key, value) in cases {
        let mut body = body_of(&message);
        set_key(at(&mut body, path), key, value);
        assert_eq!(
            body_error(message.t(), &body),
            DecodeErrorKind::Invalid,
            "{} {path:?}.{key}",
            message.t()
        );
    }
}

#[test]
fn duplicate_keys_fail_at_any_depth() {
    let cases: Vec<(ControlMessage, &[&str], &str)> = vec![
        (
            Documents {
                documents: vec!["a".to_owned()],
            }
            .into(),
            &[],
            "documents",
        ),
        (enroll_request().into(), &[], "hostname"),
        (enroll_request().into(), &["os"], "family"),
        (enroll_request().into(), &["hardware"], "machine_id_hash"),
        (
            full_report().into(),
            &["endpoint", "keyset"],
            "keyset_version",
        ),
        (
            full_report().into(),
            &["documents", "0", "state", "halted"],
            "reason",
        ),
        (full_report().into(), &["clock", "offset"], "offset_ms"),
        (approved(&["x"]).into(), &["outcome", "approved"], "chain"),
    ];
    for (message, path, key) in cases {
        let mut body = body_of(&message);
        let target = at(&mut body, path);
        let value = at(target, &[key]).clone();
        entries(target).push((text(key), value));
        assert_eq!(
            body_error(message.t(), &body),
            DecodeErrorKind::DuplicateKey,
            "{} {path:?}.{key}",
            message.t()
        );
    }
}

// --- optional fields -----------------------------------------------------

#[test]
fn optional_fields_are_left_out_and_read_null_as_none() {
    let ack = DocumentAck {
        typ: None,
        target: None,
        recovery_epoch: None,
        version: None,
        result: DocumentResult::Applied,
    };
    let body = typed_round_trip(&ack, getter!(DocumentAck));
    assert_eq!(body, map(vec![("result", text("applied"))]));
    let nulls = map(vec![
        ("typ", Value::Null),
        ("target", Value::Null),
        ("recovery_epoch", Value::Null),
        ("version", Value::Null),
        ("result", text("applied")),
    ]);
    let ControlMessage::DocumentAck(decoded) = decode_body("document_ack", &nulls).unwrap() else {
        panic!("expected a document_ack");
    };
    assert_eq!(decoded, ack);

    let report = empty_report();
    let mut body = typed_round_trip(&report, getter!(StatusReport));
    for (path, key) in [
        (&["documents", "0"][..], "target"),
        (&["documents", "0"], "verified_version"),
        (&["documents", "0"], "applied_version"),
        (&["documents", "0"], "in_use"),
        (&["collection", "sysmon"], "version"),
        (&["transport", "entries", "0"], "last_success_at"),
        (&["clock"], "offset"),
        (&["hardware"], "smbios_uuid"),
        (&["hardware"], "smbios_serial"),
    ] {
        assert!(!has_key(at(&mut body, path), key), "{path:?}.{key}");
        set_key(at(&mut body, path), key, Value::Null);
    }
    let ControlMessage::StatusReport(decoded) = decode_body("status_report", &body).unwrap() else {
        panic!("expected a status_report");
    };
    assert_eq!(decoded, report);

    let result = command_result(None);
    let body = typed_round_trip(&result, getter!(CommandResult));
    assert!(!has_key(&body, "bundle"));
    let mut with_null = body;
    set_key(&mut with_null, "bundle", Value::Null);
    let ControlMessage::CommandResult(decoded) = decode_body("command_result", &with_null).unwrap()
    else {
        panic!("expected a command_result");
    };
    assert_eq!(decoded, result);
}

// --- hardware ------------------------------------------------------------

#[test]
fn hardware_hash_must_be_32_bytes() {
    let mut value = value_of(&hardware());
    for len in [0, 31, 33, 64] {
        set_key(&mut value, "machine_id_hash", Value::Bytes(vec![7; len]));
        assert_eq!(
            decode::<Hardware>(&value).unwrap_err(),
            DecodeErrorKind::Invalid,
            "{len}"
        );
        let mut body = body_of(&enroll_request().into());
        set_key(
            at(&mut body, &["hardware"]),
            "machine_id_hash",
            Value::Bytes(vec![7; len]),
        );
        assert_eq!(
            body_error("enroll_request", &body),
            DecodeErrorKind::Invalid
        );
    }
    set_key(&mut value, "machine_id_hash", Value::Bytes(vec![7; 32]));
    assert_eq!(decode::<Hardware>(&value).unwrap().machine_id_hash, [7; 32]);

    let bare = map(vec![("machine_id_hash", Value::Bytes(vec![9; 32]))]);
    assert_eq!(
        decode::<Hardware>(&bare).unwrap(),
        Hardware {
            machine_id_hash: [9; 32],
            smbios_uuid: None,
            smbios_serial: None,
        }
    );
    // The SMBIOS strings are not checked.
    let loose = map(vec![
        ("machine_id_hash", Value::Bytes(vec![9; 32])),
        ("smbios_uuid", text("NOT-A-UUID")),
        ("smbios_serial", text("  padded  ")),
    ]);
    let decoded = decode::<Hardware>(&loose).unwrap();
    assert_eq!(decoded.smbios_uuid.as_deref(), Some("NOT-A-UUID"));
    assert_eq!(decoded.smbios_serial.as_deref(), Some("  padded  "));
}

#[test]
fn machine_id_hash_matches_an_independent_hmac() {
    assert_eq!(
        machine_id_hash(MachineId::Linux("0102030405060708090a0b0c0d0e0f10"), &SALT)
            .unwrap()
            .to_vec(),
        hex(EXPECTED_HASH)
    );
    assert_eq!(
        machine_id_hash(
            MachineId::Linux("8f3a2b1c4d5e6f708192a3b4c5d6e7f8"),
            &[0xa5; 32]
        )
        .unwrap()
        .to_vec(),
        hex(EXPECTED_HASH_2)
    );
    assert_eq!(
        machine_id_hash(
            MachineId::Windows("8F3A2B1C-4D5E-6F70-8192-A3B4C5D6E7F8"),
            &[0xa5; 32]
        )
        .unwrap()
        .to_vec(),
        hex(EXPECTED_HASH_2)
    );
}

#[test]
fn spellings_of_the_same_bytes_hash_the_same() {
    let expected = hex(EXPECTED_HASH);
    for machine_id in [
        MachineId::Linux("0102030405060708090a0b0c0d0e0f10"),
        MachineId::Linux("0102030405060708090A0B0C0D0E0F10"),
        MachineId::Windows("{01020304-0506-0708-090A-0B0C0D0E0F10}"),
        MachineId::Windows("{01020304-0506-0708-090a-0b0c0d0e0f10}"),
        MachineId::Windows("01020304-0506-0708-090A-0B0C0D0E0F10"),
        MachineId::Windows("01020304-0506-0708-090a-0b0c0d0e0f10"),
    ] {
        assert_eq!(
            machine_id_hash(machine_id, &SALT).unwrap().to_vec(),
            expected,
            "{machine_id:?}"
        );
    }
    assert_ne!(
        machine_id_hash(
            MachineId::Linux("0102030405060708090a0b0c0d0e0f10"),
            &[0; 32]
        )
        .unwrap(),
        machine_id_hash(MachineId::Linux("0102030405060708090a0b0c0d0e0f10"), &SALT).unwrap()
    );
}

#[test]
fn malformed_machine_ids_are_refused() {
    for linux in [
        "0102030405060708090a0b0c0d0e0f1",
        "0102030405060708090a0b0c0d0e0f100",
        "0102030405060708090a0b0c0d0e0fzz",
        "0102030405060708090a0b0c0d0e0f+1",
        "0102030405060708090a0b0c0d0e0f10\n",
        " 0102030405060708090a0b0c0d0e0f10",
        "01020304-0506-0708-090a-0b0c0d0e0f10",
        "",
    ] {
        assert_eq!(
            machine_id_hash(MachineId::Linux(linux), &SALT).unwrap_err(),
            InvalidMachineId::Linux,
            "{linux:?}"
        );
    }
    for windows in [
        "{01020304-0506-0708-090A-0B0C0D0E0F10",
        "01020304-0506-0708-090A-0B0C0D0E0F10}",
        "0102030405060708090A0B0C0D0E0F10",
        "010203040-506-0708-090A-0B0C0D0E0F10",
        "01020304-0506-0708-090A0-B0C0D0E0F10",
        "01020304-0506-0708-090A-0B0C0D0E0F1",
        "01020304-0506-0708-090A-0B0C0D0E0F100",
        "01020304-0506-0708-090A-0B0C0D0E0F1G",
        "01020304-0506-0708-090A-0B0C-0D0E0F10",
        "{{01020304-0506-0708-090A-0B0C0D0E0F10}}",
        "(01020304-0506-0708-090A-0B0C0D0E0F10)",
        " 01020304-0506-0708-090A-0B0C0D0E0F10",
        "{}",
        "",
    ] {
        assert_eq!(
            machine_id_hash(MachineId::Windows(windows), &SALT).unwrap_err(),
            InvalidMachineId::Windows,
            "{windows:?}"
        );
    }
}

// --- enums ---------------------------------------------------------------

/// Checks that each value encodes to its expected CBOR and decodes back.
fn assert_shapes<T>(cases: Vec<(T, Value)>)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    for (value, expected) in cases {
        assert_eq!(value_of(&value), expected, "{value:?}");
        assert_eq!(decode::<T>(&expected).unwrap(), value);
    }
}

/// Checks the rules for tags `T` does not know, and for shapes no tag has.
fn assert_tag_rules<T>(other: fn(String) -> T, unit_tag: Option<(&str, T)>, content_tags: &[&str])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let unknown = other("from_a_newer_version".to_owned());
    assert_eq!(decode::<T>(&text("from_a_newer_version")).unwrap(), unknown);
    for content in [
        Value::Null,
        Value::from(1),
        map(vec![("anything", Value::Array(vec![Value::Bool(true)]))]),
        Value::Bytes(vec![1, 2]),
    ] {
        let mapped = Value::Map(vec![(text("from_a_newer_version"), content)]);
        assert_eq!(decode::<T>(&mapped).unwrap(), unknown);
    }
    assert_eq!(value_of(&unknown), text("from_a_newer_version"));

    if let Some((tag, variant)) = unit_tag {
        let mapped = Value::Map(vec![(text(tag), map(vec![("ignored", Value::from(1))]))]);
        assert_eq!(decode::<T>(&mapped).unwrap(), variant, "{tag}");
        assert_eq!(
            decode::<T>(&Value::Map(vec![(text(tag), Value::Null)])).unwrap(),
            variant
        );
        // A registered tag never leaks into `Other`.
        let decoded = decode::<T>(&text(tag)).unwrap();
        assert_ne!(decoded, other(tag.to_owned()));
        assert_eq!(
            decode::<T>(&value_of(&other(tag.to_owned()))).unwrap(),
            variant
        );
    }
    for tag in content_tags {
        assert_eq!(
            decode::<T>(&text(tag)).unwrap_err(),
            DecodeErrorKind::Invalid,
            "{tag} as text"
        );
    }
    for bad in [
        Value::Map(vec![]),
        Value::Map(vec![
            (text("from_a_newer_version"), Value::Null),
            (text("another"), Value::Null),
        ]),
        Value::Map(vec![(Value::from(1), Value::Null)]),
        Value::Map(vec![(Value::Bytes(b"tag".to_vec()), Value::Null)]),
        Value::from(1),
        Value::Bool(true),
        Value::Bytes(b"tag".to_vec()),
        Value::Array(vec![text("tag")]),
        Value::Null,
    ] {
        assert_eq!(
            decode::<T>(&bad).unwrap_err(),
            DecodeErrorKind::Invalid,
            "{bad:?}"
        );
    }
}

#[test]
fn unit_enums_round_trip_by_their_tags() {
    assert_shapes(vec![
        (SuspendReason::Revoked, text("revoked")),
        (SuspendReason::Operator, text("operator")),
        (SuspendReason::License, text("license")),
    ]);
    assert_shapes(vec![
        (EnrollRejectReason::BadToken, text("bad_token")),
        (EnrollRejectReason::TokenRevoked, text("token_revoked")),
        (EnrollRejectReason::TokenExpired, text("token_expired")),
        (EnrollRejectReason::RateLimited, text("rate_limited")),
        (EnrollRejectReason::Denied, text("denied")),
    ]);
    assert_shapes(vec![
        (PendingReason::AwaitingApproval, text("awaiting_approval")),
        (PendingReason::LicensePending, text("license_pending")),
    ]);
    assert_shapes(vec![
        (KeyStorage::File, text("file")),
        (KeyStorage::Dpapi, text("dpapi")),
        (KeyStorage::Tpm, text("tpm")),
        (KeyStorage::SecureEnclave, text("secure_enclave")),
    ]);
    assert_shapes(vec![
        (SysmonState::Builtin, text("builtin")),
        (SysmonState::Standalone, text("standalone")),
        (SysmonState::Absent, text("none")),
    ]);
    assert_shapes(vec![
        (AuditPolicyState::Applied, text("applied")),
        (AuditPolicyState::GpoManaged, text("gpo_managed")),
        (AuditPolicyState::Off, text("off")),
    ]);
}

#[test]
fn content_enums_round_trip_in_their_shapes() {
    assert_shapes(vec![
        (DocumentSlotState::Current, text("current")),
        (DocumentSlotState::Pending, text("pending")),
        (
            DocumentSlotState::PendingOffTarget,
            text("pending_off_target"),
        ),
        (
            DocumentSlotState::Halted {
                reason: "disk full".to_owned(),
            },
            map(vec![("halted", map(vec![("reason", text("disk full"))]))]),
        ),
    ]);
    assert_shapes(vec![
        (
            DocumentTarget::Group(id(5)),
            map(vec![("group", uuid_value(id(5)))]),
        ),
        (
            DocumentTarget::Endpoint(id(5)),
            map(vec![("endpoint", uuid_value(id(5)))]),
        ),
        (
            DocumentTarget::Customer(id(6)),
            map(vec![("customer", uuid_value(id(6)))]),
        ),
        (
            DocumentTarget::Install("install-1".to_owned()),
            map(vec![("install", text("install-1"))]),
        ),
    ]);
    assert_shapes(vec![
        (
            Problem::SignatureRejected {
                typ: Some("senta-command".to_owned()),
                kid: Some("customer:i:1".to_owned()),
                result: DocumentResult::ApplyFailed {
                    reason: "x".to_owned(),
                },
            },
            map(vec![(
                "signature_rejected",
                map(vec![
                    ("typ", text("senta-command")),
                    ("kid", text("customer:i:1")),
                    (
                        "result",
                        map(vec![("apply_failed", map(vec![("reason", text("x"))]))]),
                    ),
                ]),
            )]),
        ),
        (
            Problem::SignatureRejected {
                typ: Some("senta-command".to_owned()),
                kid: None,
                result: DocumentResult::SchemaError,
            },
            map(vec![(
                "signature_rejected",
                map(vec![
                    ("typ", text("senta-command")),
                    ("result", text("schema_error")),
                ]),
            )]),
        ),
        (
            Problem::SignatureRejected {
                typ: None,
                kid: None,
                result: DocumentResult::BadSignature,
            },
            map(vec![(
                "signature_rejected",
                map(vec![("result", text("bad_signature"))]),
            )]),
        ),
        (
            Problem::UnknownKid {
                kid: "customer:i:9".to_owned(),
            },
            map(vec![(
                "unknown_kid",
                map(vec![("kid", text("customer:i:9"))]),
            )]),
        ),
        (Problem::KeysetGap, text("keyset_gap")),
        (Problem::UpdateFailed, text("update_failed")),
        (Problem::UpdateRolledBack, text("update_rolled_back")),
        (Problem::SourceUnreachable, text("source_unreachable")),
        (Problem::PriorEpochState, text("prior_epoch_state")),
        (Problem::SysmonMissing, text("sysmon_missing")),
        (Problem::ClockSkew, text("clock_skew")),
        (
            Problem::InstallConfigInvalid,
            text("install_config_invalid"),
        ),
        (Problem::SysmonStopped, text("sysmon_stopped")),
        (Problem::SysmonConfigChanged, text("sysmon_config_changed")),
        (Problem::UnexpectedRestart, text("unexpected_restart")),
    ]);
    assert_shapes(vec![
        (
            EnrollOutcome::Approved {
                enroll_result: "r".to_owned(),
                chain: vec!["k".to_owned(), "rk".to_owned()],
            },
            map(vec![(
                "approved",
                map(vec![
                    ("enroll_result", text("r")),
                    ("chain", Value::Array(vec![text("k"), text("rk")])),
                ]),
            )]),
        ),
        (
            EnrollOutcome::Pending {
                reason: PendingReason::LicensePending,
            },
            map(vec![(
                "pending",
                map(vec![("reason", text("license_pending"))]),
            )]),
        ),
        (
            EnrollOutcome::Rejected {
                reason: EnrollRejectReason::RateLimited,
            },
            map(vec![(
                "rejected",
                map(vec![("reason", text("rate_limited"))]),
            )]),
        ),
    ]);
}

#[test]
fn tag_rules_hold_for_every_enum() {
    assert_tag_rules(
        SuspendReason::Other,
        Some(("operator", SuspendReason::Operator)),
        &[],
    );
    assert_tag_rules(
        EnrollRejectReason::Other,
        Some(("token_expired", EnrollRejectReason::TokenExpired)),
        &[],
    );
    assert_tag_rules(
        PendingReason::Other,
        Some(("awaiting_approval", PendingReason::AwaitingApproval)),
        &[],
    );
    assert_tag_rules(KeyStorage::Other, Some(("tpm", KeyStorage::Tpm)), &[]);
    assert_tag_rules(SysmonState::Other, Some(("none", SysmonState::Absent)), &[]);
    assert_tag_rules(
        AuditPolicyState::Other,
        Some(("gpo_managed", AuditPolicyState::GpoManaged)),
        &[],
    );
    assert_tag_rules(
        DocumentSlotState::Other,
        Some(("pending_off_target", DocumentSlotState::PendingOffTarget)),
        &["halted"],
    );
    assert_tag_rules(
        DocumentTarget::Other,
        None,
        &["group", "endpoint", "customer", "install"],
    );
    assert_tag_rules(
        Problem::Other,
        Some(("keyset_gap", Problem::KeysetGap)),
        &["signature_rejected", "unknown_kid"],
    );
    assert_tag_rules(
        EnrollOutcome::Other,
        None,
        &["approved", "pending", "rejected"],
    );
}

#[test]
fn tamper_problem_tags_are_read_as_their_variants_not_other() {
    for (tag, variant) in [
        ("sysmon_stopped", Problem::SysmonStopped),
        ("sysmon_config_changed", Problem::SysmonConfigChanged),
        ("unexpected_restart", Problem::UnexpectedRestart),
    ] {
        assert_eq!(decode::<Problem>(&text(tag)).unwrap(), variant, "{tag}");
        assert_eq!(
            decode::<Problem>(&value_of(&Problem::Other(tag.to_owned()))).unwrap(),
            variant,
            "{tag}"
        );
    }
}

#[test]
fn content_field_maps_ignore_unknown_fields_and_need_their_own() {
    let halted = map(vec![(
        "halted",
        map(vec![("reason", text("r")), ("attempts", Value::from(3))]),
    )]);
    assert_eq!(
        decode::<DocumentSlotState>(&halted).unwrap(),
        DocumentSlotState::Halted {
            reason: "r".to_owned()
        }
    );
    for bad in [
        map(vec![("halted", map(vec![]))]),
        map(vec![("halted", text("r"))]),
        map(vec![("halted", map(vec![("reason", Value::from(1))]))]),
    ] {
        assert_eq!(
            decode::<DocumentSlotState>(&bad).unwrap_err(),
            DecodeErrorKind::Invalid
        );
    }
    for bad in [
        map(vec![("group", Value::Bytes(vec![0; 15]))]),
        map(vec![(
            "group",
            text("00000000-0000-0000-0000-000000000005"),
        )]),
        map(vec![("group", map(vec![("id", uuid_value(id(5)))]))]),
        map(vec![("install", Value::from(1))]),
    ] {
        assert_eq!(
            decode::<DocumentTarget>(&bad).unwrap_err(),
            DecodeErrorKind::Invalid,
            "{bad:?}"
        );
    }
    let rejected = map(vec![(
        "signature_rejected",
        map(vec![
            ("result", text("unknown_kid")),
            ("kid", Value::Null),
            ("typ", Value::Null),
            ("detail", text("x")),
        ]),
    )]);
    assert_eq!(
        decode::<Problem>(&rejected).unwrap(),
        Problem::SignatureRejected {
            typ: None,
            kid: None,
            result: DocumentResult::UnknownKid,
        }
    );
    assert_eq!(
        decode::<Problem>(&map(vec![("signature_rejected", map(vec![]))])).unwrap_err(),
        DecodeErrorKind::Invalid
    );
    let approved = map(vec![(
        "approved",
        map(vec![
            ("enroll_result", text("r")),
            ("chain", Value::Array(vec![])),
            ("note", text("x")),
        ]),
    )]);
    assert_eq!(
        decode::<EnrollOutcome>(&approved).unwrap(),
        EnrollOutcome::Approved {
            enroll_result: "r".to_owned(),
            chain: vec![],
        }
    );
    assert_eq!(
        decode::<EnrollOutcome>(&map(vec![("pending", map(vec![]))])).unwrap_err(),
        DecodeErrorKind::Invalid
    );
}

// --- enrollment ----------------------------------------------------------

#[test]
fn enroll_results_round_trip() {
    for result in [
        approved(&[
            "eyJ.keyset.5",
            "eyJ.recovery.2",
            "eyJ.keyset.6",
            "eyJ.keyset.7",
        ]),
        approved(&["eyJ.recovery.2", "eyJ.keyset.1"]),
        approved(&[]),
        EnrollResult {
            outcome: EnrollOutcome::Pending {
                reason: PendingReason::AwaitingApproval,
            },
        },
        EnrollResult {
            outcome: EnrollOutcome::Rejected {
                reason: EnrollRejectReason::Denied,
            },
        },
    ] {
        typed_round_trip(&result, getter!(EnrollResult));
    }

    let result = approved(&["eyJ.keyset.5", "eyJ.recovery.2", "eyJ.keyset.6"]);
    let body = typed_round_trip(&result, getter!(EnrollResult));
    let ControlMessage::EnrollResult(decoded) = decode_body("enroll_result", &body).unwrap() else {
        panic!("expected an enroll_result");
    };
    let (enroll_result, chain) = decoded.approved().unwrap();
    assert_eq!(enroll_result, "eyJ.enroll-result.sig");
    assert_eq!(chain, ["eyJ.keyset.5", "eyJ.recovery.2", "eyJ.keyset.6"]);

    let empty = approved(&[]);
    let body = typed_round_trip(&empty, getter!(EnrollResult));
    assert_eq!(
        body,
        map(vec![(
            "outcome",
            map(vec![(
                "approved",
                map(vec![
                    ("enroll_result", text("eyJ.enroll-result.sig")),
                    ("chain", Value::Array(vec![])),
                ]),
            )]),
        )])
    );
    assert_eq!(empty.approved().unwrap().1, [] as [String; 0]);
    assert!(
        EnrollResult {
            outcome: EnrollOutcome::Other("deferred".to_owned()),
        }
        .approved()
        .is_none()
    );
}

#[test]
fn documents_keep_their_order() {
    let documents = Documents {
        documents: ["eyJ.z.3", "eyJ.a.1", "eyJ.m.2", "eyJ.a.1"]
            .map(str::to_owned)
            .to_vec(),
    };
    let body = typed_round_trip(&documents, getter!(Documents));
    assert_eq!(
        body,
        map(vec![(
            "documents",
            Value::Array(
                ["eyJ.z.3", "eyJ.a.1", "eyJ.m.2", "eyJ.a.1"]
                    .map(text)
                    .to_vec()
            ),
        )])
    );
    typed_round_trip(&Documents { documents: vec![] }, getter!(Documents));
}

#[test]
fn malformed_jws_passes_through_unchanged() {
    let odd = ["not-a-jws", "", "a.b", "  spaces  ", "{\"json\":1}"];
    for jws in odd {
        let command = Command {
            command: jws.to_owned(),
        };
        assert_eq!(
            typed_round_trip(&command, getter!(Command)),
            map(vec![("command", text(jws))])
        );
    }
    let documents = Documents {
        documents: odd.map(str::to_owned).to_vec(),
    };
    typed_round_trip(&documents, getter!(Documents));
    let result = EnrollResult {
        outcome: EnrollOutcome::Approved {
            enroll_result: "not-a-jws".to_owned(),
            chain: odd.map(str::to_owned).to_vec(),
        },
    };
    typed_round_trip(&result, getter!(EnrollResult));
    let body = map(vec![("command", text("not-a-jws"))]);
    let ControlMessage::Command(decoded) = decode_body("command", &body).unwrap() else {
        panic!("expected a command");
    };
    assert_eq!(decoded.command, "not-a-jws");
}

// --- acknowledgements and command results -------------------------------

#[test]
fn document_acks_round_trip() {
    let body = typed_round_trip(&full_ack(), getter!(DocumentAck));
    assert_eq!(
        body,
        map(vec![
            ("typ", text("senta-keyset")),
            ("target", map(vec![("customer", uuid_value(id(3)))])),
            ("recovery_epoch", Value::from(2)),
            ("version", Value::from(6)),
            (
                "result",
                map(vec![(
                    "keyset_gap",
                    map(vec![
                        ("have_epoch", Value::from(2)),
                        ("have_version", Value::from(4)),
                    ]),
                )]),
            ),
        ])
    );
    let bare = DocumentAck {
        typ: None,
        target: None,
        recovery_epoch: None,
        version: None,
        result: DocumentResult::Stale,
    };
    assert_eq!(
        typed_round_trip(&bare, getter!(DocumentAck)),
        map(vec![("result", text("stale"))])
    );

    let update = |target| DocumentAck {
        typ: Some("senta-update".to_owned()),
        target: Some(target),
        recovery_epoch: None,
        version: Some(3),
        result: DocumentResult::Applied,
    };
    let group = update(DocumentTarget::Group(id(42)));
    let endpoint = update(DocumentTarget::Endpoint(id(42)));
    let group_body = typed_round_trip(&group, getter!(DocumentAck));
    let endpoint_body = typed_round_trip(&endpoint, getter!(DocumentAck));
    assert_ne!(group_body, endpoint_body);
    assert_ne!(group, endpoint);
}

#[test]
fn bundles_are_capped_at_one_mib() {
    assert_eq!(BUNDLE_LIMIT, MIB);
    let exact = command_result(Some(vec![0xab; MIB]));
    let body = typed_round_trip(&exact, getter!(CommandResult));
    assert_eq!(
        *at(&mut body.clone(), &["bundle"]),
        Value::Bytes(vec![0xab; MIB])
    );
    assert_eq!(exact.bundle.as_ref().unwrap().as_bytes().len(), MIB);

    let error = Bundle::try_from(vec![0; MIB + 1]).unwrap_err();
    assert_eq!(error.size(), MIB + 1);

    let mut over = body;
    set_key(&mut over, "bundle", Value::Bytes(vec![0; MIB + 1]));
    assert_eq!(
        body_error("command_result", &over),
        DecodeErrorKind::Invalid
    );

    let none = command_result(None);
    let body = typed_round_trip(&none, getter!(CommandResult));
    assert_eq!(keys(&body), ["command_id", "result"]);
    assert_eq!(Bundle::try_from(vec![1, 2]).unwrap().into_bytes(), [1, 2]);
}

#[test]
fn command_results_round_trip_every_kind() {
    for result in [
        CommandResultKind::Done,
        CommandResultKind::AlreadyDone,
        CommandResultKind::Failed {
            reason: "exit 1".to_owned(),
        },
        CommandResultKind::Rejected(DocumentResult::Expired),
    ] {
        typed_round_trip(
            &CommandResult {
                command_id: id(9),
                result,
                bundle: None,
            },
            getter!(CommandResult),
        );
    }
}

// --- status report -------------------------------------------------------

#[test]
fn status_reports_round_trip_full_and_empty() {
    let full = typed_round_trip(&full_report(), getter!(StatusReport));
    let mut full = full;
    let problems = at(&mut full, &["problems"]).clone();
    assert_eq!(problems, value_of(&every_problem()));
    typed_round_trip(&empty_report(), getter!(StatusReport));
}

#[test]
fn a_halted_slot_reports_the_failure_and_versions() {
    let mut report = empty_report();
    report.documents = vec![DocumentSlot {
        typ: "senta-policy".to_owned(),
        target: Some(DocumentTarget::Group(id(7))),
        verified_version: Some(5),
        applied_version: Some(4),
        state: DocumentSlotState::Halted {
            reason: "collector refused the policy".to_owned(),
        },
        in_use: None,
        untrusted: false,
    }];
    let mut body = typed_round_trip(&report, getter!(StatusReport));
    let slot = at(&mut body, &["documents", "0"]).clone();
    assert_eq!(
        slot,
        map(vec![
            ("typ", text("senta-policy")),
            ("target", map(vec![("group", uuid_value(id(7)))])),
            ("verified_version", Value::from(5)),
            ("applied_version", Value::from(4)),
            (
                "state",
                map(vec![(
                    "halted",
                    map(vec![("reason", text("collector refused the policy"))]),
                )]),
            ),
            ("untrusted", Value::Bool(false)),
        ])
    );
}

#[test]
fn a_new_epoch_halting_at_its_first_document_round_trips() {
    let mut report = empty_report();
    let halted = DocumentSlot {
        typ: "senta-policy".to_owned(),
        target: Some(DocumentTarget::Group(id(7))),
        verified_version: Some(1),
        applied_version: None,
        state: DocumentSlotState::Halted {
            reason: "bad rule".to_owned(),
        },
        in_use: Some(InUseDocument {
            recovery_epoch: 1,
            version: 12,
        }),
        untrusted: true,
    };
    report.documents = vec![halted.clone()];
    let mut body = typed_round_trip(&report, getter!(StatusReport));
    let slot = at(&mut body, &["documents", "0"]);
    assert!(!has_key(slot, "applied_version"));
    assert_eq!(
        *at(slot, &["in_use"]),
        map(vec![
            ("recovery_epoch", Value::from(1)),
            ("version", Value::from(12)),
        ])
    );
    assert_eq!(*at(slot, &["untrusted"]), Value::Bool(true));
    assert_eq!(*at(slot, &["verified_version"]), Value::from(1));
    let ControlMessage::StatusReport(decoded) = decode_body("status_report", &body).unwrap() else {
        panic!("expected a status_report");
    };
    assert_eq!(decoded.documents, [halted]);
}

#[test]
fn a_negative_clock_offset_round_trips() {
    let mut report = empty_report();
    report.clock = ClockStatus {
        offset: Some(ClockOffset {
            offset_ms: -4_000_123,
            uncertainty_ms: 40,
            measured_at: at_second(1_700_000_000),
        }),
        exceeds_tolerance: true,
    };
    let mut body = typed_round_trip(&report, getter!(StatusReport));
    assert_eq!(
        *at(&mut body, &["clock", "offset", "offset_ms"]),
        Value::from(-4_000_123)
    );
}

#[test]
fn signature_rejected_round_trips_with_and_without_kid() {
    for kid in [Some("customer:install-1:3".to_owned()), None] {
        let mut report = empty_report();
        report.problems = vec![Problem::SignatureRejected {
            typ: Some("senta-command".to_owned()),
            kid: kid.clone(),
            result: DocumentResult::RevokedKid,
        }];
        let mut body = typed_round_trip(&report, getter!(StatusReport));
        let fields = at(&mut body, &["problems", "0", "signature_rejected"]);
        assert_eq!(has_key(fields, "kid"), kid.is_some());
    }
}

// --- send decision -------------------------------------------------------

#[test]
fn a_report_is_sent_first_and_then_every_five_minutes() {
    let report = full_report();
    let sent_at = Duration::from_secs(1_000);
    assert!(should_send_status_report(None, sent_at, &report));
    let last = Some((sent_at, &report));
    assert!(!should_send_status_report(last, sent_at, &report));
    assert!(!should_send_status_report(
        last,
        sent_at + STATUS_REPORT_INTERVAL - Duration::from_nanos(1),
        &report
    ));
    assert!(should_send_status_report(
        last,
        sent_at + Duration::from_secs(300),
        &report
    ));
    assert!(should_send_status_report(
        last,
        sent_at + Duration::from_secs(301),
        &report
    ));
    // The monotonic clock behind the last send counts as no time passed.
    assert!(!should_send_status_report(
        last,
        Duration::from_secs(10),
        &report
    ));
    assert!(!should_send_status_report(last, Duration::ZERO, &report));
}

#[test]
fn a_change_in_any_field_sends_at_once() {
    type Change = fn(&mut StatusReport);
    let changes: [(&str, Change); 13] = [
        ("last_success_at", |r| {
            r.transport.entries[0].last_success_at = Some(at_second(1_700_000_001));
        }),
        ("measured_at", |r| {
            r.clock.offset.as_mut().unwrap().measured_at = at_second(1_700_000_051);
        }),
        ("buffered_records", |r| r.transport.buffered_records += 1),
        ("buffered_bytes", |r| r.transport.buffered_bytes += 1),
        ("dropped_ranges", |r| r.transport.dropped_ranges += 1),
        ("unsupported_dropped", |r| {
            r.transport.unsupported_dropped += 1
        }),
        ("offset_ms", |r| {
            r.clock.offset.as_mut().unwrap().offset_ms -= 1
        }),
        ("exceeds_tolerance", |r| r.clock.exceeds_tolerance = true),
        ("problems", |r| {
            r.problems.pop();
        }),
        ("documents", |r| {
            r.documents[1].state = DocumentSlotState::Pending
        }),
        ("documents order", |r| r.documents.swap(0, 1)),
        ("hardware", |r| r.hardware.smbios_serial = None),
        ("senta_version", |r| r.endpoint.senta_version.push('1')),
    ];
    let sent = full_report();
    let sent_at = Duration::from_secs(1_000);
    for (name, change) in changes {
        let mut current = full_report();
        change(&mut current);
        assert_ne!(current, sent, "{name}");
        assert!(
            should_send_status_report(Some((sent_at, &sent)), sent_at, &current),
            "{name}"
        );
        assert!(
            should_send_status_report(
                Some((sent_at, &sent)),
                sent_at + Duration::from_secs(299),
                &current
            ),
            "{name}"
        );
        assert!(
            should_send_status_report(Some((sent_at, &sent)), Duration::ZERO, &current),
            "{name}"
        );
    }
}
