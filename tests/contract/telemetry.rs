//! The telemetry port: an event store entry's ingress, holding its list
//! under a lease, refusing with telemetry errors.

use ciborium::Value;
use senta_protocol::auth::active_list::{
    ConnectionId, DEFAULT_LEASE_LENGTH, EntryState, Lease, Standing, allowed,
};
use senta_protocol::auth::tls::{CONTROL_ALPN, TELEMETRY_ALPN};
use senta_protocol::connection::{
    AcceptedKind, CloseReason, ConnectionKind, EndpointChannel, EndpointConfig, Envelope, Frame,
    FrameTooLarge, Hello, HelloAck, Message, SERVER_OTHER_RECEIVE_LIMIT, ServerChannel,
    StandingVerdict, TelemetryEntry,
};
use senta_protocol::standing::SuspendReason;
use senta_protocol::telemetry::{
    CloseStream, DroppedRange, ErrorMessage, LostOnReset, OpenStream, RecordBatch, SeqRange,
    TELEMETRY_MESSAGE_KINDS, TelemetryMessage,
};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use uuid::Uuid;

use crate::common::{
    ACTIVE, CRATE_VERSION, Ingress, IngressClose, LIST_VERSION, NOT_LISTED, OTHER_ACTIVE, PENDING,
    Port, SUSPENDED, UNKNOWN_T, active_handshake, active_receive_limit, assert_ended_silently,
    assert_kept, assert_row, body_keys, diff, endpoint_config, endpoint_receive_limit,
    endpoint_wall, framing_samples, no_common_version, open_speaking_version_2, other_ports_alpn,
    padded, someone_elses_certificate, ts, unknown, unknown_kind_from_the_ingress,
};

/// The entry this ingress is.
const ENTRY_ID: Uuid = Uuid::from_u128(0xe17);

/// The record kinds this entry accepts.
fn accepted_kinds() -> Vec<AcceptedKind> {
    vec![AcceptedKind {
        kind: 1,
        schema_min: 1,
        schema_max: 2,
    }]
}

/// The telemetry port's composition.
struct Telemetry;

impl Port for Telemetry {
    const ALPN: &'static [u8] = TELEMETRY_ALPN;
    const KINDS: &'static [&'static str] = &TELEMETRY_MESSAGE_KINDS;

    fn lease() -> Option<Lease> {
        Some(Lease::new(DEFAULT_LEASE_LENGTH))
    }

    fn server_channel() -> ServerChannel {
        ServerChannel::Telemetry {
            entry_id: ENTRY_ID,
            accepted_kinds: accepted_kinds(),
        }
    }

    fn endpoint_channel() -> EndpointChannel {
        EndpointChannel::Telemetry {
            expected_entry_id: ENTRY_ID,
        }
    }

    fn verdict(standing: &Standing, t: &str) -> StandingVerdict {
        allowed(standing, ConnectionKind::Telemetry, t).to_standing_verdict()
    }

    fn decode(envelope: &Envelope) -> Option<Frame> {
        let message = TelemetryMessage::decode(envelope.t(), envelope.body()).ok()?;
        Some(message.to_frame().unwrap())
    }

    fn notice(standing: &Standing) -> Option<Frame> {
        assert_eq!(standing.suspend_notice(ConnectionKind::Telemetry), None);
        None
    }

    fn lease_expired() -> Frame {
        Frame::from_message(&ErrorMessage {
            stream: None,
            error: TelemetryError::LeaseExpired,
        })
        .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Samples
// ---------------------------------------------------------------------------

const STREAM: Uuid = Uuid::from_u128(0x5e);

fn frame(message: TelemetryMessage) -> Frame {
    message.to_frame().unwrap()
}

fn record_batch() -> Frame {
    frame(TelemetryMessage::RecordBatch(
        RecordBatch::new(STREAM, vec![vec![0xa1, 0x61, 0x6b, 0x01]]).unwrap(),
    ))
}

/// One of each telemetry message an endpoint sends, then the framing's
/// own, then a kind nobody knows.
fn samples() -> Vec<(&'static str, Frame)> {
    let mut samples = vec![
        (
            "open_stream",
            frame(TelemetryMessage::OpenStream(OpenStream { stream: STREAM })),
        ),
        ("record_batch", record_batch()),
        (
            "dropped_range",
            frame(TelemetryMessage::DroppedRange(DroppedRange {
                stream: STREAM,
                from: 3,
                to: 5,
                reason: DropReason::BufferOverflow,
            })),
        ),
        (
            "lost_on_reset",
            frame(TelemetryMessage::LostOnReset(LostOnReset {
                old_stream: Uuid::from_u128(0x5d),
                ranges: vec![SeqRange { from: 0, to: 9 }],
            })),
        ),
        (
            "close_stream",
            frame(TelemetryMessage::CloseStream(CloseStream {
                stream: STREAM,
            })),
        ),
    ];
    samples.extend(framing_samples());
    samples.push((UNKNOWN_T, unknown()));
    let mut ts: Vec<&str> = samples.iter().map(|(t, _)| *t).collect();
    ts.sort_unstable();
    assert_eq!(
        ts,
        [
            "close_stream",
            "dropped_range",
            "lost_on_reset",
            "open_stream",
            "ping",
            "pong",
            "record_batch",
            UNKNOWN_T,
        ],
        "the five telemetry kinds an endpoint sends, the framing's two, and one unknown"
    );
    samples
}

/// Asserts that `payload` is the telemetry `error { error }`, with no
/// `stream` key.
fn assert_error_frame(payload: &[u8], error: &TelemetryError) {
    let envelope = Envelope::parse(payload).unwrap();
    assert_eq!(envelope.t(), ErrorMessage::T);
    assert_eq!(body_keys(payload), ["error"], "no stream");
    assert_eq!(
        TelemetryMessage::decode(envelope.t(), envelope.body()).unwrap(),
        TelemetryMessage::ErrorMessage(ErrorMessage {
            stream: None,
            error: error.clone(),
        })
    );
}

/// Asserts that the first `hello` was refused with `error { error }` and
/// no `hello_ack`: the endpoint's helper hands the error over as it came
/// and ends the connection, and so does the ingress.
fn assert_hello_refused(ingress: &Ingress<Telemetry>, id: ConnectionId, error: &TelemetryError) {
    let conn = ingress.conn(id);
    let frames = conn.endpoint.frames();
    assert_eq!(ts(frames), [ErrorMessage::T], "no hello_ack");
    assert_error_frame(&frames[0], error);

    assert_eq!(conn.endpoint.handshake, None);
    let [delivered] = conn.endpoint.delivered.as_slice() else {
        panic!(
            "expected the error delivered, got {:?}",
            conn.endpoint.delivered
        );
    };
    assert_eq!(delivered.t(), ErrorMessage::T);
    let sent = Envelope::parse(&frames[0]).unwrap();
    assert_eq!(delivered.body().as_bytes(), sent.body().as_bytes());
    assert_eq!(
        conn.endpoint.closed,
        Some(CloseReason::ExpectedHelloAck {
            t: ErrorMessage::T.to_owned(),
        })
    );

    assert_eq!(conn.ingress.handshake, None);
    assert_eq!(
        conn.ingress.closed,
        Some(IngressClose::Helper(CloseReason::Standing {
            t: Hello::T.to_owned(),
        }))
    );
    assert!(conn.endpoint.peer_closed);
}

/// Asserts that the ingress sent `error { error }` after the first `seen`
/// frames, and ended the connection, for `why`.
fn assert_error_then_end(
    ingress: &Ingress<Telemetry>,
    id: ConnectionId,
    seen: usize,
    error: &TelemetryError,
    why: &IngressClose,
) {
    let conn = ingress.conn(id);
    let frames = &conn.endpoint.frames()[seen..];
    assert_eq!(ts(frames), [ErrorMessage::T]);
    assert_error_frame(&frames[0], error);
    let delivered = conn.endpoint.delivered.last().unwrap();
    assert_eq!(delivered.t(), ErrorMessage::T, "the endpoint takes it");
    assert_eq!(conn.ingress.closed.as_ref(), Some(why));
    assert!(conn.endpoint.peer_closed);
}

/// The fields of a valid `hello` body.
fn hello_fields() -> Vec<(&'static str, Value)> {
    let sent_at = i64::try_from(endpoint_wall().as_nanosecond()).unwrap();
    vec![
        ("crate_version", Value::Text(CRATE_VERSION.to_owned())),
        (
            "versions",
            Value::Map(vec![
                (Value::Text("min".to_owned()), Value::from(1)),
                (Value::Text("max".to_owned()), Value::from(1)),
            ]),
        ),
        ("sent_at", Value::from(sent_at)),
    ]
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

#[test]
fn an_active_endpoint_completes_the_handshake() {
    let (ingress, id) = active_handshake::<Telemetry>();
    let conn = ingress.conn(id);
    assert_eq!(conn.alpn().0, Some(&b"senta-telemetry/1"[..]));
    assert_eq!(
        conn.endpoint.handshake.as_ref().unwrap().telemetry,
        Some(TelemetryEntry {
            entry_id: ENTRY_ID,
            accepted_kinds: accepted_kinds(),
        })
    );
}

#[test]
fn another_entry_is_left_after_its_hello_ack() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let other = Uuid::from_u128(0xe18);
    let client = ingress.pki().endpoint_client(ACTIVE, TELEMETRY_ALPN);
    let endpoint = EndpointConfig::new(
        EndpointChannel::Telemetry {
            expected_entry_id: other,
        },
        CRATE_VERSION,
    )
    .with_known_kinds(TELEMETRY_MESSAGE_KINDS);
    let id = ingress.connect(client, endpoint);
    ingress.hello(id);

    let conn = ingress.conn(id);
    assert_eq!(ts(conn.endpoint.frames()), [HelloAck::T]);
    assert_eq!(conn.endpoint.handshake, None);
    assert_eq!(
        conn.endpoint.closed,
        Some(CloseReason::EntryIdMismatch {
            expected: other,
            received: Some(ENTRY_ID),
        })
    );
    assert!(conn.ingress.peer_closed, "the ingress saw the end");
}

#[test]
fn an_endpoint_offering_the_control_alpn_is_not_taken() {
    other_ports_alpn::<Telemetry>(CONTROL_ALPN);
}

#[test]
fn someone_elses_certificate_is_refused_in_the_handshake() {
    someone_elses_certificate::<Telemetry>();
}

#[test]
fn no_common_version_is_refused_before_the_handshake() {
    no_common_version::<Telemetry>();
}

#[test]
fn standing_is_judged_before_the_version() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = open_speaking_version_2(&mut ingress, NOT_LISTED);
    assert_hello_refused(&ingress, id, &TelemetryError::NotListed);
}

// ---------------------------------------------------------------------------
// The first hello, by standing
// ---------------------------------------------------------------------------

#[test]
fn first_hello_not_listed() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(NOT_LISTED);
    assert_hello_refused(&ingress, id, &TelemetryError::NotListed);
}

#[test]
fn first_hello_license_pending() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(PENDING);
    assert_hello_refused(&ingress, id, &TelemetryError::NotListed);
}

#[test]
fn first_hello_suspended() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(SUSPENDED);
    assert_hello_refused(&ingress, id, &TelemetryError::Suspended);
}

#[test]
fn first_hello_lease_expired() {
    let mut ingress = Ingress::<Telemetry>::listed();
    ingress.now = DEFAULT_LEASE_LENGTH;
    let id = ingress.open(ACTIVE);
    assert_hello_refused(&ingress, id, &TelemetryError::LeaseExpired);
}

#[test]
fn first_hello_unready() {
    let mut ingress = Ingress::<Telemetry>::unready();
    let id = ingress.open(ACTIVE);
    assert_ended_silently(
        &ingress,
        id,
        0,
        &IngressClose::Helper(CloseReason::Standing {
            t: Hello::T.to_owned(),
        }),
    );
    assert_eq!(ingress.conn(id).endpoint.handshake, None);
}

#[test]
fn first_hello_active() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(ACTIVE);
    let conn = ingress.conn(id);
    assert_eq!(ts(conn.endpoint.frames()), [HelloAck::T]);
    assert!(conn.endpoint.handshake.is_some());
    assert_kept(&mut ingress, id);
}

#[test]
fn a_first_message_other_than_hello_ends_the_connection_silently() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let client = ingress.pki().endpoint_client(NOT_LISTED, TELEMETRY_ALPN);
    let id = ingress.connect(client, endpoint_config::<Telemetry>());
    ingress.endpoint_send(
        id,
        &frame(TelemetryMessage::OpenStream(OpenStream { stream: STREAM })),
    );
    assert_ended_silently(
        &ingress,
        id,
        0,
        &IngressClose::Helper(CloseReason::ExpectedHello {
            t: OpenStream::T.to_owned(),
        }),
    );
}

// ---------------------------------------------------------------------------
// After the handshake
// ---------------------------------------------------------------------------

#[test]
fn after_the_handshake_active() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(ACTIVE);
    assert_row(
        &mut ingress,
        id,
        &samples(),
        &[
            "ping",
            "pong",
            "open_stream",
            "record_batch",
            "dropped_range",
            "lost_on_reset",
            "close_stream",
        ],
    );
}

// ---------------------------------------------------------------------------
// Standing that changes
// ---------------------------------------------------------------------------

#[test]
fn the_lease_expiring_ends_every_connection_until_it_is_extended() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let first = ingress.open(ACTIVE);
    let second = ingress.open(OTHER_ACTIVE);
    let seen = [first, second].map(|id| ingress.conn(id).endpoint.frames().len());

    ingress.now = DEFAULT_LEASE_LENGTH;
    let expired = ingress.list.check_lease(ingress.now).unwrap();
    assert_eq!(expired, [first, second]);
    ingress.expire(&expired);
    for (id, seen) in [first, second].into_iter().zip(seen) {
        assert_error_then_end(
            &ingress,
            id,
            seen,
            &TelemetryError::LeaseExpired,
            &IngressClose::LeaseExpired,
        );
    }

    let refused = ingress.open(ACTIVE);
    assert_hello_refused(&ingress, refused, &TelemetryError::LeaseExpired);

    let confirmed = ingress.list.confirm(LIST_VERSION, ingress.now);
    assert!(confirmed.extended);
    assert_eq!(confirmed.expired, None);
    let id = ingress.open(ACTIVE);
    assert_eq!(ts(ingress.conn(id).endpoint.frames()), [HelloAck::T]);
    assert_kept(&mut ingress, id);
}

#[test]
fn suspending_an_open_connection_refuses_its_next_batch() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(ACTIVE);
    ingress.apply(diff(
        ACTIVE,
        EntryState::Suspended {
            reason: SuspendReason::Operator,
        },
    ));
    let seen = ingress.conn(id).endpoint.frames().len();
    assert_eq!(seen, 1, "nothing is said until the endpoint sends");

    ingress.endpoint_send(id, &record_batch());
    assert_error_then_end(
        &ingress,
        id,
        seen,
        &TelemetryError::Suspended,
        &IngressClose::Helper(CloseReason::Standing {
            t: RecordBatch::T.to_owned(),
        }),
    );
    assert!(ingress.conn(id).ingress.delivered.is_empty());
}

// ---------------------------------------------------------------------------
// Frame size limits
// ---------------------------------------------------------------------------

#[test]
fn a_hello_not_listed_is_received_up_to_64_kib() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let client = ingress.pki().endpoint_client(NOT_LISTED, TELEMETRY_ALPN);
    let id = ingress.connect(client, endpoint_config::<Telemetry>());
    ingress.endpoint_send(
        id,
        &padded(Hello::T, &hello_fields(), SERVER_OTHER_RECEIVE_LIMIT),
    );
    assert_hello_refused(&ingress, id, &TelemetryError::NotListed);

    let client = ingress.pki().endpoint_client(NOT_LISTED, TELEMETRY_ALPN);
    let id = ingress.connect(client, endpoint_config::<Telemetry>());
    ingress.endpoint_send(
        id,
        &padded(Hello::T, &hello_fields(), SERVER_OTHER_RECEIVE_LIMIT + 1),
    );
    assert_ended_silently(
        &ingress,
        id,
        0,
        &IngressClose::Helper(CloseReason::FrameTooLarge(FrameTooLarge {
            length: SERVER_OTHER_RECEIVE_LIMIT + 1,
            limit: SERVER_OTHER_RECEIVE_LIMIT,
        })),
    );
}

#[test]
fn an_active_connection_receives_up_to_4_mib() {
    active_receive_limit::<Telemetry>();
}

#[test]
fn the_endpoint_receives_up_to_4_mib() {
    let mut ingress = Ingress::<Telemetry>::listed();
    let id = ingress.open(ACTIVE);
    endpoint_receive_limit(&mut ingress, id);
}

// ---------------------------------------------------------------------------
// Unknown kinds
// ---------------------------------------------------------------------------

#[test]
fn the_endpoint_refuses_a_kind_it_does_not_know() {
    unknown_kind_from_the_ingress::<Telemetry>();
}
