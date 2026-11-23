//! The control port: REview's ingress, without a lease, telling a
//! suspended endpoint so.

use ciborium::Value;
use senta_protocol::auth::active_list::{
    Admission, ConnectionId, EntryState, Lease, Standing, allowed,
};
use senta_protocol::auth::tls::{CONTROL_ALPN, TELEMETRY_ALPN};
use senta_protocol::connection::{
    CloseReason, ConnectionKind, EndpointChannel, Envelope, Frame, FrameTooLarge, HelloAck,
    Message, SERVER_OTHER_RECEIVE_LIMIT, ServerChannel, StandingVerdict, Unsupported,
};
use senta_protocol::control::{
    AuditPolicyState, ClockStatus, CollectionStatus, CommandResult, ControlMessage, DocumentAck,
    DocumentSlot, DocumentSlotState, EndpointStatus, EnrollRequest, EnrollResultPoll, EnrollToken,
    EntryStatus, Hardware, KeyStorage, KeysetPosition, MESSAGE_KINDS, StatusReport, SuspendNotice,
    SysmonState, SysmonStatus, TransportStatus, Unenroll, UninstallToken,
};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::results::{CommandResultKind, DocumentResult};
use senta_protocol::standing::SuspendReason;
use uuid::Uuid;

use crate::common::{
    ACTIVE, Ingress, IngressClose, LISTED_SUSPEND_REASON, NOT_LISTED, PENDING, Port, SUSPENDED,
    UNKNOWN_T, active_handshake, active_receive_limit, assert_ended_silently, assert_kept,
    assert_row, assert_unsupported, body_keys, diff, endpoint_receive_limit, framing_samples,
    no_common_version, other_ports_alpn, someone_elses_certificate, ts, unknown,
    unknown_kind_from_the_ingress, unknown_of,
};

/// The control port's composition.
struct Control;

impl Port for Control {
    const ALPN: &'static [u8] = CONTROL_ALPN;
    const KINDS: &'static [&'static str] = &MESSAGE_KINDS;

    fn lease() -> Option<Lease> {
        None
    }

    fn server_channel() -> ServerChannel {
        ServerChannel::Control
    }

    fn endpoint_channel() -> EndpointChannel {
        EndpointChannel::Control
    }

    fn verdict(standing: &Standing, t: &str) -> StandingVerdict {
        match allowed(standing, ConnectionKind::Control, t) {
            Admission::Accept => StandingVerdict::Accept,
            Admission::Unsupported => StandingVerdict::Unsupported,
            Admission::Close => StandingVerdict::Close,
            Admission::ErrorThenClose(error) => {
                panic!("control refuses with no telemetry error, yet got {error:?}")
            }
        }
    }

    fn decode(envelope: &Envelope) -> Option<Frame> {
        let message = ControlMessage::decode(envelope.t(), envelope.body()).ok()?;
        Some(message.to_frame().unwrap())
    }

    fn notice(standing: &Standing) -> Option<Frame> {
        let reason = standing.suspend_notice(ConnectionKind::Control)?;
        let notice = ControlMessage::from(SuspendNotice {
            reason: reason.clone(),
        });
        Some(notice.to_frame().unwrap())
    }

    fn lease_expired() -> Frame {
        panic!("the control ingress holds its list under no lease")
    }
}

// ---------------------------------------------------------------------------
// Samples
// ---------------------------------------------------------------------------

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn os() -> OsInfo {
    OsInfo {
        family: OsFamily::Windows,
        version: "10.0.22631".to_owned(),
    }
}

fn hardware() -> Hardware {
    Hardware {
        machine_id_hash: [0x5a; 32],
        smbios_uuid: None,
        smbios_serial: None,
    }
}

fn keyset() -> KeysetPosition {
    KeysetPosition {
        recovery_epoch: 0,
        keyset_version: 1,
    }
}

fn frame(message: impl Into<ControlMessage>) -> Frame {
    message.into().to_frame().unwrap()
}

fn document_ack() -> Frame {
    frame(DocumentAck {
        typ: Some("senta-policy".to_owned()),
        target: None,
        recovery_epoch: None,
        version: Some(3),
        result: DocumentResult::Applied,
    })
}

/// One of each control message an endpoint sends, then the framing's own,
/// then a kind nobody knows.
fn samples() -> Vec<(&'static str, Frame)> {
    let mut samples = vec![
        (
            "enroll_request",
            frame(EnrollRequest {
                attempt_id: id(1),
                trusted_keyset: keyset(),
                trusted_recovery_key_version: 1,
                enroll_token: EnrollToken::new("eyJ.enroll.token".to_owned()),
                hardware: hardware(),
                hostname: "host-1".to_owned(),
                os: os(),
                senta_version: "1.4.0".to_owned(),
                key_storage: KeyStorage::Tpm,
                vdi_mode: false,
            }),
        ),
        (
            "enroll_result_poll",
            frame(EnrollResultPoll { attempt_id: id(1) }),
        ),
        (
            "unenroll",
            frame(Unenroll {
                uninstall_token: UninstallToken::new("correct horse".to_owned()),
            }),
        ),
        (
            "status_report",
            frame(StatusReport {
                endpoint: EndpointStatus {
                    senta_version: "1.4.0".to_owned(),
                    os: os(),
                    key_storage: KeyStorage::Tpm,
                    keyset: keyset(),
                    recovery_key_version: 1,
                },
                documents: vec![DocumentSlot {
                    typ: "senta-addresses".to_owned(),
                    target: None,
                    verified_version: Some(2),
                    applied_version: Some(2),
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
                hardware: hardware(),
                problems: vec![],
            }),
        ),
        ("document_ack", document_ack()),
        (
            "command_result",
            frame(CommandResult {
                command_id: id(21),
                result: CommandResultKind::Done,
                bundle: None,
            }),
        ),
    ];
    samples.extend(framing_samples());
    samples.push((UNKNOWN_T, unknown()));
    let mut ts: Vec<&str> = samples.iter().map(|(t, _)| *t).collect();
    ts.sort_unstable();
    assert_eq!(
        ts,
        [
            "command_result",
            "document_ack",
            "enroll_request",
            "enroll_result_poll",
            "ping",
            "pong",
            "status_report",
            "unenroll",
            UNKNOWN_T,
        ],
        "the eight control kinds an endpoint sends, and one unknown"
    );
    samples
}

/// A `document_ack` whose envelope is sound and whose body is not: its
/// `result` is a number.
fn malformed_document_ack() -> Frame {
    let frame = Frame::new(
        "document_ack",
        &Value::Map(vec![(Value::Text("result".to_owned()), Value::from(5))]),
    )
    .unwrap();
    let envelope = Envelope::parse(frame.payload()).unwrap();
    assert!(ControlMessage::decode(envelope.t(), envelope.body()).is_err());
    frame
}

/// Returns the reason of the `suspend_notice` a frame holds.
fn notice_reason(payload: &[u8]) -> SuspendReason {
    let envelope = Envelope::parse(payload).unwrap();
    let ControlMessage::SuspendNotice(notice) =
        ControlMessage::decode(envelope.t(), envelope.body()).unwrap()
    else {
        panic!("expected a suspend_notice, got {:?}", envelope.t());
    };
    notice.reason
}

/// Asserts that the first `hello` was answered with a `hello_ack` and
/// nothing else, and the connection stays open.
fn assert_acked_alone(ingress: &mut Ingress<Control>, id: ConnectionId) {
    let conn = ingress.conn(id);
    assert_eq!(
        ts(conn.endpoint.frames()),
        [HelloAck::T],
        "no suspend_notice"
    );
    assert!(conn.endpoint.handshake.is_some());
    assert!(conn.ingress.handshake.is_some());
    assert_kept(ingress, id);
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

#[test]
fn an_active_endpoint_completes_the_handshake() {
    let (ingress, id) = active_handshake::<Control>();
    let conn = ingress.conn(id);
    assert_eq!(conn.alpn().0, Some(&b"senta-control/1"[..]));
    assert_eq!(conn.endpoint.handshake.as_ref().unwrap().telemetry, None);
    assert_eq!(
        body_keys(&conn.endpoint.frames()[0]),
        ["server_time", "version"],
        "no entry_id or accepted_kinds"
    );
}

#[test]
fn an_endpoint_offering_the_telemetry_alpn_is_not_taken() {
    other_ports_alpn::<Control>(TELEMETRY_ALPN);
}

#[test]
fn someone_elses_certificate_is_refused_in_the_handshake() {
    someone_elses_certificate::<Control>();
}

#[test]
fn no_common_version_is_refused_before_the_handshake() {
    no_common_version::<Control>();
}

// ---------------------------------------------------------------------------
// The first hello, by standing
// ---------------------------------------------------------------------------

#[test]
fn first_hello_not_listed() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(NOT_LISTED);
    assert_acked_alone(&mut ingress, id);
}

#[test]
fn first_hello_license_pending() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(PENDING);
    assert_acked_alone(&mut ingress, id);
}

#[test]
fn first_hello_suspended() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(SUSPENDED);
    let conn = ingress.conn(id);
    assert_eq!(ts(conn.endpoint.frames()), [HelloAck::T, SuspendNotice::T]);
    assert_eq!(
        notice_reason(&conn.endpoint.frames()[1]),
        LISTED_SUSPEND_REASON
    );
    assert!(conn.endpoint.handshake.is_some());
    assert_kept(&mut ingress, id);
}

#[test]
fn first_hello_active() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(ACTIVE);
    assert_acked_alone(&mut ingress, id);
}

#[test]
fn first_hello_unready() {
    let mut ingress = Ingress::<Control>::unready();
    let id = ingress.open(ACTIVE);
    assert_ended_silently(
        &ingress,
        id,
        0,
        &IngressClose::Helper(CloseReason::Standing {
            t: "hello".to_owned(),
        }),
    );
    assert_eq!(ingress.conn(id).endpoint.handshake, None);
}

// ---------------------------------------------------------------------------
// After the handshake, by standing
// ---------------------------------------------------------------------------

#[test]
fn after_the_handshake_not_listed() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(NOT_LISTED);
    assert_row(
        &mut ingress,
        id,
        &samples(),
        &["ping", "pong", "enroll_request", "enroll_result_poll"],
    );
}

#[test]
fn after_the_handshake_license_pending() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(PENDING);
    assert_row(
        &mut ingress,
        id,
        &samples(),
        &[
            "ping",
            "pong",
            "status_report",
            "enroll_result_poll",
            "unenroll",
        ],
    );
}

#[test]
fn after_the_handshake_suspended() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(SUSPENDED);
    assert_row(
        &mut ingress,
        id,
        &samples(),
        &["ping", "pong", "status_report", "unenroll"],
    );
}

#[test]
fn after_the_handshake_active() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(ACTIVE);
    assert_row(
        &mut ingress,
        id,
        &samples(),
        &[
            "ping",
            "pong",
            "enroll_request",
            "enroll_result_poll",
            "unenroll",
            "status_report",
            "document_ack",
            "command_result",
        ],
    );
}

#[test]
fn standing_is_judged_before_the_body_is_read() {
    let mut ingress = Ingress::<Control>::listed();
    for n in [NOT_LISTED, PENDING, SUSPENDED] {
        let id = ingress.open(n);
        let seen = ingress.conn(id).endpoint.frames().len();
        ingress.endpoint_send(id, &malformed_document_ack());
        let replies = &ingress.conn(id).endpoint.frames()[seen..];
        assert_eq!(ts(replies), [Unsupported::T], "endpoint {n}");
        assert_unsupported(&replies[0], "document_ack");
        assert_kept(&mut ingress, id);
    }

    let id = ingress.open(ACTIVE);
    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &malformed_document_ack());
    assert_ended_silently(
        &ingress,
        id,
        seen,
        &IngressClose::Helper(CloseReason::BodyRejected),
    );
    assert!(ingress.conn(id).ingress.delivered.is_empty());
}

// ---------------------------------------------------------------------------
// Standing that changes
// ---------------------------------------------------------------------------

#[test]
fn suspending_an_open_connection_sends_a_notice() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(ACTIVE);
    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.apply(diff(
        ACTIVE,
        EntryState::Suspended {
            reason: SuspendReason::License,
        },
    ));
    let conn = ingress.conn(id);
    let notices = &conn.endpoint.frames()[seen..];
    assert_eq!(ts(notices), [SuspendNotice::T]);
    assert_eq!(notice_reason(&notices[0]), SuspendReason::License);
    let delivered = conn.endpoint.delivered.last().unwrap();
    assert_eq!(delivered.t(), SuspendNotice::T, "the endpoint takes it");

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &document_ack());
    let replies = &ingress.conn(id).endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], "document_ack");
    assert_kept(&mut ingress, id);
}

#[test]
fn no_notice_outside_suspension() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(ACTIVE);
    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.apply(diff(ACTIVE, EntryState::LicensePending));
    assert_eq!(
        ts(&ingress.conn(id).endpoint.frames()[seen..]),
        Vec::<String>::new()
    );

    ingress.endpoint_send(id, &document_ack());
    let replies = &ingress.conn(id).endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T], "the standing did change");
    assert_kept(&mut ingress, id);
}

// ---------------------------------------------------------------------------
// Frame size limits
// ---------------------------------------------------------------------------

#[test]
fn a_connection_not_listed_receives_up_to_64_kib() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(NOT_LISTED);

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_OTHER_RECEIVE_LIMIT));
    let replies = &ingress.conn(id).endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], UNKNOWN_T);
    assert_kept(&mut ingress, id);

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_OTHER_RECEIVE_LIMIT + 1));
    assert_ended_silently(
        &ingress,
        id,
        seen,
        &IngressClose::Helper(CloseReason::FrameTooLarge(FrameTooLarge {
            length: SERVER_OTHER_RECEIVE_LIMIT + 1,
            limit: SERVER_OTHER_RECEIVE_LIMIT,
        })),
    );
}

#[test]
fn an_active_connection_receives_up_to_4_mib() {
    active_receive_limit::<Control>();
}

#[test]
fn the_receive_limit_follows_the_standing() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(ACTIVE);

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_OTHER_RECEIVE_LIMIT + 1));
    let replies = &ingress.conn(id).endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], UNKNOWN_T);

    ingress.apply(diff(
        ACTIVE,
        EntryState::Suspended {
            reason: SuspendReason::Operator,
        },
    ));
    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_OTHER_RECEIVE_LIMIT + 1));
    assert_ended_silently(
        &ingress,
        id,
        seen,
        &IngressClose::Helper(CloseReason::FrameTooLarge(FrameTooLarge {
            length: SERVER_OTHER_RECEIVE_LIMIT + 1,
            limit: SERVER_OTHER_RECEIVE_LIMIT,
        })),
    );
}

#[test]
fn the_endpoint_receives_up_to_4_mib() {
    let mut ingress = Ingress::<Control>::listed();
    let id = ingress.open(NOT_LISTED);
    endpoint_receive_limit(&mut ingress, id);
}

// ---------------------------------------------------------------------------
// Unknown kinds
// ---------------------------------------------------------------------------

#[test]
fn the_endpoint_refuses_a_kind_it_does_not_know() {
    unknown_kind_from_the_ingress::<Control>();
}
