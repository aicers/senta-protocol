//! The connection helpers, driven through the public API only, against each
//! other and against hand-made frames.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use jiff::Timestamp;
use senta_protocol::connection::{
    AcceptedKind, ClockCorrection, CloseReason, ConnectionKind, ENDPOINT_RECEIVE_LIMIT,
    EndpointAction, EndpointChannel, EndpointConfig, EndpointConnection, EndpointHandshake,
    Envelope, EnvelopeError, Frame, FrameTooLarge, Hello, HelloAck, IDLE_TIMEOUT, Message,
    PING_INTERVAL, Ping, Pong, SERVER_ACTIVE_RECEIVE_LIMIT, SERVER_OTHER_RECEIVE_LIMIT,
    ServerAction, ServerChannel, ServerConfig, ServerConnection, ServerHandshake, StandingVerdict,
    TelemetryEntry, Unsupported, VersionRange,
};
use uuid::Uuid;

const CRATE_VERSION: &str = "0.1.0";
const ENTRY: Uuid = Uuid::from_u128(0x1234);

fn wall(nanos: i64) -> Timestamp {
    Timestamp::from_nanosecond(i128::from(nanos) + 1_700_000_000_000_000_000).unwrap()
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (text(key), value.clone()))
            .collect(),
    )
}

fn nanos(at: Timestamp) -> Value {
    Value::Integer(i64::try_from(at.as_nanosecond()).unwrap().into())
}

fn frame(t: &str, body: &Value) -> Frame {
    Frame::new(t, body).unwrap()
}

fn envelope(frame: &Frame) -> Envelope {
    Envelope::parse(frame.payload()).unwrap()
}

fn decode<M: Message>(frame: &Frame) -> M {
    let envelope = envelope(frame);
    assert_eq!(envelope.t(), M::T);
    envelope.body().decode().unwrap()
}

/// The text keys of a frame's body, sorted.
fn body_keys(frame: &Frame) -> Vec<String> {
    let Value::Map(entries) = envelope(frame).body().decode::<Value>().unwrap() else {
        panic!("body is not a map");
    };
    let mut keys: Vec<String> = entries
        .into_iter()
        .map(|(key, _)| key.into_text().unwrap())
        .collect();
    keys.sort_unstable();
    keys
}

fn telemetry_channel(accepted_kinds: Vec<AcceptedKind>) -> ServerChannel {
    ServerChannel::Telemetry {
        entry_id: ENTRY,
        accepted_kinds,
    }
}

fn kinds() -> Vec<AcceptedKind> {
    vec![
        AcceptedKind {
            kind: 1,
            schema_min: 1,
            schema_max: 2,
        },
        AcceptedKind {
            kind: 1000,
            schema_min: 1,
            schema_max: 1,
        },
    ]
}

fn server(config: ServerConfig) -> ServerConnection {
    ServerConnection::new(config, Duration::ZERO)
}

fn endpoint(config: EndpointConfig) -> (EndpointConnection, Frame) {
    EndpointConnection::new(config, wall(0), Duration::ZERO).unwrap()
}

fn control_server() -> ServerConfig {
    ServerConfig::new(ServerChannel::Control, SERVER_ACTIVE_RECEIVE_LIMIT)
}

fn control_endpoint() -> EndpointConfig {
    EndpointConfig::new(EndpointChannel::Control, CRATE_VERSION)
}

fn telemetry_endpoint() -> EndpointConfig {
    EndpointConfig::new(
        EndpointChannel::Telemetry {
            expected_entry_id: ENTRY,
        },
        CRATE_VERSION,
    )
}

/// Runs a handshake: the server receives the `hello` at 1 ms, the endpoint
/// the `hello_ack` at 2 ms.
fn connect(
    server_config: ServerConfig,
    endpoint_config: EndpointConfig,
) -> (ServerConnection, EndpointConnection) {
    let mut server = server(server_config);
    let (mut endpoint, hello) = endpoint(endpoint_config);
    let actions = server.receive(hello.as_bytes(), wall(1), ms(1));
    let Some(ServerAction::Send(ack)) = actions.first() else {
        panic!("no hello_ack: {actions:?}");
    };
    let actions = endpoint.receive(ack.as_bytes(), wall(2), ms(2));
    assert!(
        matches!(actions.first(), Some(EndpointAction::Handshake(_))),
        "{actions:?}"
    );
    assert!(server.is_established());
    assert!(endpoint.is_established());
    (server, endpoint)
}

/// Sends the endpoint a hand-made `hello_ack` as its first message.
fn endpoint_receives_ack(config: EndpointConfig, ack: &Value) -> Vec<EndpointAction> {
    let (mut endpoint, _) = endpoint(config);
    let actions = endpoint.receive(frame(HelloAck::T, ack).as_bytes(), wall(1), ms(1));
    if !matches!(actions.first(), Some(EndpointAction::Handshake(_))) {
        assert!(endpoint.is_closed());
    }
    actions
}

fn ack_body(extra: &[(&str, Value)]) -> Value {
    let mut entries = vec![
        ("version", Value::Integer(1.into())),
        ("server_time", nanos(wall(5))),
    ];
    entries.extend_from_slice(extra);
    map(&entries)
}

fn kinds_value() -> Value {
    Value::Array(vec![map(&[
        ("kind", Value::Integer(1.into())),
        ("schema_min", Value::Integer(1.into())),
        ("schema_max", Value::Integer(1.into())),
    ])])
}

fn entry_value(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

// --- Negotiation ----------------------------------------------------------

#[test]
fn the_endpoint_starts_with_its_hello() {
    let (endpoint, hello) = EndpointConnection::new(
        control_endpoint().with_versions(VersionRange::new(1, 4)),
        wall(42),
        ms(7),
    )
    .unwrap();
    assert_eq!(endpoint.kind(), ConnectionKind::Control);
    assert!(!endpoint.is_established());
    assert_eq!(
        decode::<Hello>(&hello),
        Hello {
            crate_version: CRATE_VERSION.to_owned(),
            versions: VersionRange::new(1, 4),
            sent_at: wall(42),
        }
    );
}

#[test]
fn a_hello_outside_the_i64_range_fails_to_encode() {
    assert!(EndpointConnection::new(control_endpoint(), Timestamp::MAX, ms(0)).is_err());
}

#[test]
fn control_negotiation() {
    let mut server = server(control_server());
    assert_eq!(server.kind(), ConnectionKind::Control);
    let (mut endpoint, hello) = endpoint(control_endpoint());

    let actions = server.receive(hello.as_bytes(), wall(1_000), ms(10));
    let [ServerAction::Send(ack), ServerAction::Handshake(handshake)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(
        handshake,
        &ServerHandshake {
            version: 1,
            hello: decode::<Hello>(&hello),
        }
    );
    assert_eq!(body_keys(ack), ["server_time", "version"]);
    let ack_value = decode::<HelloAck>(ack);
    assert_eq!(ack_value.version, 1);
    assert_eq!(ack_value.server_time, wall(1_000));

    let actions = endpoint.receive(ack.as_bytes(), wall(2_000), ms(20));
    let [
        EndpointAction::Handshake(handshake),
        EndpointAction::ClockMeasured(_),
    ] = actions.as_slice()
    else {
        panic!("{actions:?}");
    };
    assert_eq!(
        handshake,
        &EndpointHandshake {
            version: 1,
            server_time: wall(1_000),
            telemetry: None,
        }
    );
}

#[test]
fn telemetry_negotiation_announces_the_entry() {
    for accepted in [kinds(), Vec::new()] {
        let mut server = server(ServerConfig::new(
            telemetry_channel(accepted.clone()),
            SERVER_ACTIVE_RECEIVE_LIMIT,
        ));
        assert_eq!(server.kind(), ConnectionKind::Telemetry);
        let (mut endpoint, hello) = endpoint(telemetry_endpoint());
        assert_eq!(endpoint.kind(), ConnectionKind::Telemetry);

        let actions = server.receive(hello.as_bytes(), wall(1), ms(1));
        let [ServerAction::Send(ack), ServerAction::Handshake(handshake)] = actions.as_slice()
        else {
            panic!("{actions:?}");
        };
        assert_eq!(handshake.version, 1);
        assert_eq!(handshake.hello.crate_version, CRATE_VERSION);
        assert_eq!(handshake.hello.versions, VersionRange::new(1, 1));
        assert_eq!(handshake.hello.sent_at, wall(0));
        assert_eq!(
            body_keys(ack),
            ["accepted_kinds", "entry_id", "server_time", "version"]
        );
        let ack_value = decode::<HelloAck>(ack);
        assert_eq!(ack_value.entry_id, Some(ENTRY));
        assert_eq!(ack_value.accepted_kinds.as_ref(), Some(&accepted));

        let actions = endpoint.receive(ack.as_bytes(), wall(2), ms(2));
        let Some(EndpointAction::Handshake(handshake)) = actions.first() else {
            panic!("{actions:?}");
        };
        assert_eq!(
            handshake,
            &EndpointHandshake {
                version: 1,
                server_time: wall(1),
                telemetry: Some(TelemetryEntry {
                    entry_id: ENTRY,
                    accepted_kinds: accepted,
                }),
            }
        );
        assert!(endpoint.is_established());
    }
}

#[test]
fn the_highest_common_version_is_chosen() {
    let mut server = server(control_server().with_versions(VersionRange::new(1, 3)));
    let (mut endpoint, hello) = endpoint(control_endpoint().with_versions(VersionRange::new(2, 5)));
    let actions = server.receive(hello.as_bytes(), wall(1), ms(1));
    let [ServerAction::Send(ack), ServerAction::Handshake(handshake)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(handshake.version, 3);
    assert_eq!(decode::<HelloAck>(ack).version, 3);
    let actions = endpoint.receive(ack.as_bytes(), wall(2), ms(2));
    assert!(matches!(
        actions.first(),
        Some(EndpointAction::Handshake(EndpointHandshake {
            version: 3,
            ..
        }))
    ));
}

#[test]
fn no_common_version_refuses_then_closes() {
    for (ours, theirs) in [
        (VersionRange::new(1, 1), VersionRange::new(2, 2)),
        (VersionRange::new(1, 3), VersionRange::new(3, 2)),
        (VersionRange::new(2, 1), VersionRange::new(1, 2)),
    ] {
        let mut server = server(control_server().with_versions(ours));
        let (mut endpoint, hello) = endpoint(control_endpoint().with_versions(theirs));
        let actions = server.receive(hello.as_bytes(), wall(1), ms(1));
        let [ServerAction::SendThenClose { frame, reason }] = actions.as_slice() else {
            panic!("{actions:?}");
        };
        assert_eq!(reason, &CloseReason::NoCommonVersion);
        assert_eq!(decode::<Unsupported>(frame), Unsupported::version());
        assert!(server.is_closed());

        let actions = endpoint.receive(frame.as_bytes(), wall(2), ms(2));
        assert_eq!(
            actions,
            [EndpointAction::Close(CloseReason::NoCommonVersion)]
        );
        assert!(endpoint.is_closed());
    }
}

#[test]
fn telemetry_verification() {
    let expected = EndpointChannel::Telemetry {
        expected_entry_id: ENTRY,
    };
    let other = Uuid::from_u128(0x9999);
    let config = || EndpointConfig::new(expected, CRATE_VERSION);

    // An empty list is valid.
    let actions = endpoint_receives_ack(
        config(),
        &ack_body(&[
            ("entry_id", entry_value(ENTRY)),
            ("accepted_kinds", Value::Array(Vec::new())),
        ]),
    );
    assert!(matches!(
        actions.first(),
        Some(EndpointAction::Handshake(EndpointHandshake {
            telemetry: Some(TelemetryEntry { accepted_kinds, .. }),
            ..
        })) if accepted_kinds.is_empty()
    ));

    let failures = [
        (
            ack_body(&[
                ("entry_id", entry_value(other)),
                ("accepted_kinds", kinds_value()),
            ]),
            CloseReason::EntryIdMismatch {
                expected: ENTRY,
                received: Some(other),
            },
        ),
        (
            ack_body(&[("accepted_kinds", kinds_value())]),
            CloseReason::EntryIdMismatch {
                expected: ENTRY,
                received: None,
            },
        ),
        (
            ack_body(&[("entry_id", Value::Null), ("accepted_kinds", kinds_value())]),
            CloseReason::EntryIdMismatch {
                expected: ENTRY,
                received: None,
            },
        ),
        (
            ack_body(&[("entry_id", entry_value(ENTRY))]),
            CloseReason::MissingAcceptedKinds,
        ),
        (
            ack_body(&[
                ("entry_id", entry_value(ENTRY)),
                ("accepted_kinds", Value::Null),
            ]),
            CloseReason::MissingAcceptedKinds,
        ),
    ];
    for (ack, reason) in failures {
        assert_eq!(
            endpoint_receives_ack(config(), &ack),
            [EndpointAction::Close(reason)]
        );
    }

    // A control connection does not look at either field.
    let actions = endpoint_receives_ack(
        control_endpoint(),
        &ack_body(&[
            ("entry_id", entry_value(other)),
            ("accepted_kinds", Value::Null),
        ]),
    );
    assert!(matches!(
        actions.first(),
        Some(EndpointAction::Handshake(EndpointHandshake {
            telemetry: None,
            ..
        }))
    ));
}

#[test]
fn a_version_outside_the_offered_range_closes() {
    let ack = map(&[
        ("version", Value::Integer(2.into())),
        ("server_time", nanos(wall(5))),
    ]);
    assert_eq!(
        endpoint_receives_ack(control_endpoint(), &ack),
        [EndpointAction::Close(CloseReason::VersionOutOfRange {
            version: 2
        })]
    );
}

#[test]
fn a_byte_string_is_not_a_list_of_accepted_kinds() {
    // h'' and h'010203' where an array belongs: neither is an empty or any
    // other list of kinds.
    for bytes in [Vec::new(), vec![1, 2, 3]] {
        let ack = ack_body(&[
            ("entry_id", entry_value(ENTRY)),
            ("accepted_kinds", Value::Bytes(bytes)),
        ]);
        let actions = endpoint_receives_ack(telemetry_endpoint(), &ack);
        assert!(
            matches!(
                actions.as_slice(),
                [EndpointAction::Close(CloseReason::MalformedBody { t, .. })] if t == HelloAck::T
            ),
            "{actions:?}"
        );
    }
}

#[test]
fn a_malformed_hello_ack_closes() {
    let ack = map(&[("version", text("one")), ("server_time", nanos(wall(5)))]);
    let actions = endpoint_receives_ack(control_endpoint(), &ack);
    assert!(matches!(
        actions.as_slice(),
        [EndpointAction::Close(CloseReason::MalformedBody { t, .. })] if t == HelloAck::T
    ));
}

// --- Server: processing order -------------------------------------------

#[test]
fn the_server_closes_when_the_first_message_is_not_hello() {
    for t in ["ping", "hello_ack", "unknown"] {
        let mut server = server(control_server().with_known_kinds(["unknown"]));
        let actions = server.receive(frame(t, &map(&[])).as_bytes(), wall(0), ms(1));
        assert_eq!(
            actions,
            [ServerAction::Close(CloseReason::ExpectedHello {
                t: t.to_owned()
            })]
        );
        assert!(server.is_closed());
    }
}

#[test]
fn the_server_closes_on_a_hello_after_the_handshake() {
    let (mut server, _) = connect(control_server(), control_endpoint());
    let (_, hello) = endpoint(control_endpoint());
    let actions = server.receive(hello.as_bytes(), wall(3), ms(3));
    assert_eq!(
        actions,
        [ServerAction::Close(CloseReason::HelloAfterHandshake)]
    );
}

/// A `hello` whose fields have the wrong types.
fn broken_hello() -> Frame {
    frame(
        Hello::T,
        &map(&[
            ("crate_version", Value::Integer(1.into())),
            ("versions", text("all")),
            ("sent_at", text("now")),
        ]),
    )
}

#[test]
fn a_broken_hello_closes_as_malformed_without_a_standing_check() {
    let mut server = server(control_server());
    let actions = server.receive(broken_hello().as_bytes(), wall(0), ms(1));
    assert!(matches!(
        actions.as_slice(),
        [ServerAction::Close(CloseReason::MalformedBody { t, .. })] if t == Hello::T
    ));
}

#[test]
fn the_standing_check_sees_the_first_hello() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let mut server = server(control_server().with_standing(move |t| {
        log.lock().unwrap().push(t.to_owned());
        StandingVerdict::Close
    }));
    // Closed by the standing check, not for the body: it was never read.
    let actions = server.receive(broken_hello().as_bytes(), wall(0), ms(1));
    assert_eq!(
        actions,
        [ServerAction::Close(CloseReason::Standing {
            t: Hello::T.to_owned()
        })]
    );
    assert_eq!(*seen.lock().unwrap(), ["hello"]);
}

#[test]
fn a_standing_frame_replaces_the_hello_ack() {
    let refusal = frame("telemetry_error", &map(&[("code", text("suspended"))]));
    let given = refusal.clone();
    let mut server = server(
        control_server().with_standing(move |_| StandingVerdict::SendThenClose(given.clone())),
    );
    let actions = server.receive(broken_hello().as_bytes(), wall(0), ms(1));
    assert_eq!(
        actions,
        [ServerAction::SendThenClose {
            frame: refusal,
            reason: CloseReason::Standing {
                t: Hello::T.to_owned()
            },
        }]
    );
    assert!(server.is_closed());
}

#[test]
fn an_unsupported_verdict_on_the_first_hello_closes() {
    let mut server = server(control_server().with_standing(|_| StandingVerdict::Unsupported));
    let (_, hello) = endpoint(control_endpoint());
    let actions = server.receive(hello.as_bytes(), wall(0), ms(1));
    assert_eq!(
        actions,
        [ServerAction::Close(CloseReason::Standing {
            t: Hello::T.to_owned()
        })]
    );
}

/// A server whose standing check accepts `hello` and decides every other
/// message by the verdict in `verdict`.
fn server_with_verdict(verdict: &Arc<Mutex<StandingVerdict>>) -> ServerConnection {
    let verdict = Arc::clone(verdict);
    let config = control_server()
        .with_known_kinds(["status"])
        .with_standing(move |t| {
            if t == Hello::T {
                StandingVerdict::Accept
            } else {
                verdict.lock().unwrap().clone()
            }
        });
    connect(config, control_endpoint()).0
}

/// A `ping` whose `sent_at` is not a time: it would close the connection
/// if it were read.
fn broken_ping() -> Frame {
    frame(Ping::T, &map(&[("sent_at", text("now"))]))
}

#[test]
fn standing_verdicts_after_the_handshake() {
    let verdict = Arc::new(Mutex::new(StandingVerdict::Accept));

    // Accept: handled as usual.
    let mut server = server_with_verdict(&verdict);
    let ping = Frame::from_message(&Ping { sent_at: wall(9) }).unwrap();
    let actions = server.receive(ping.as_bytes(), wall(10), ms(10));
    let [ServerAction::Send(pong)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(decode::<Pong>(pong).ping_sent_at, wall(9));

    // Unsupported: refused, kept, the body never read.
    *verdict.lock().unwrap() = StandingVerdict::Unsupported;
    let mut server = server_with_verdict(&verdict);
    for t in ["ping", "status", "never_heard_of"] {
        let actions = server.receive(
            frame(t, &map(&[("sent_at", text("now"))])).as_bytes(),
            wall(10),
            ms(10),
        );
        let [ServerAction::Send(refusal)] = actions.as_slice() else {
            panic!("{actions:?}");
        };
        assert_eq!(decode::<Unsupported>(refusal).kind, t);
        assert!(server.is_established());
    }

    // Send then close: the caller's frame, the body never read.
    let given = frame("telemetry_error", &map(&[]));
    *verdict.lock().unwrap() = StandingVerdict::SendThenClose(given.clone());
    let mut server = server_with_verdict(&verdict);
    let actions = server.receive(broken_ping().as_bytes(), wall(10), ms(10));
    assert_eq!(
        actions,
        [ServerAction::SendThenClose {
            frame: given,
            reason: CloseReason::Standing {
                t: Ping::T.to_owned()
            },
        }]
    );
    assert!(server.is_closed());

    // Close: closed, the body never read.
    *verdict.lock().unwrap() = StandingVerdict::Close;
    let mut server = server_with_verdict(&verdict);
    let actions = server.receive(broken_ping().as_bytes(), wall(10), ms(10));
    assert_eq!(
        actions,
        [ServerAction::Close(CloseReason::Standing {
            t: Ping::T.to_owned()
        })]
    );
}

// --- Both sides after the handshake ---------------------------------------

/// What one side does with one frame after the handshake, in a form both
/// sides share.
#[derive(Debug, PartialEq)]
enum Outcome {
    Send(Frame),
    Deliver(Envelope),
    Unsupported(Unsupported),
    Close(CloseReason),
    Nothing,
}

fn server_outcome(actions: Vec<ServerAction>) -> Outcome {
    let mut actions = actions.into_iter();
    let outcome = match actions.next() {
        None => Outcome::Nothing,
        Some(ServerAction::Send(frame)) => Outcome::Send(frame),
        Some(ServerAction::Deliver(envelope)) => Outcome::Deliver(envelope),
        Some(ServerAction::Unsupported(unsupported)) => Outcome::Unsupported(unsupported),
        Some(ServerAction::Close(reason)) => Outcome::Close(reason),
        Some(other) => panic!("{other:?}"),
    };
    assert_eq!(actions.next(), None);
    outcome
}

fn endpoint_outcome(actions: Vec<EndpointAction>) -> Outcome {
    let mut actions = actions.into_iter();
    let outcome = match actions.next() {
        None => Outcome::Nothing,
        Some(EndpointAction::Send(frame)) => Outcome::Send(frame),
        Some(EndpointAction::Deliver(envelope)) => Outcome::Deliver(envelope),
        Some(EndpointAction::Unsupported(unsupported)) => Outcome::Unsupported(unsupported),
        Some(EndpointAction::Close(reason)) => Outcome::Close(reason),
        Some(other) => panic!("{other:?}"),
    };
    assert_eq!(actions.next(), None);
    outcome
}

/// Feeds one frame to each side of a fresh connection that knows the
/// message `status`, and returns both outcomes and whether each side is
/// still open.
fn both_sides(frame: &Frame) -> [(Outcome, bool); 2] {
    let (mut server, mut endpoint) = connect(
        control_server().with_known_kinds(["status"]),
        control_endpoint().with_known_kinds(["status"]),
    );
    let server_side = server_outcome(server.receive(frame.as_bytes(), wall(10), ms(10)));
    let endpoint_side = endpoint_outcome(endpoint.receive(frame.as_bytes(), wall(10), ms(10)));
    [
        (server_side, !server.is_closed()),
        (endpoint_side, !endpoint.is_closed()),
    ]
}

#[test]
fn an_unknown_t_is_refused_and_the_connection_kept() {
    for (outcome, open) in both_sides(&frame("mystery", &Value::Integer(5.into()))) {
        let Outcome::Send(refusal) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            decode::<Unsupported>(&refusal),
            Unsupported {
                kind: "mystery".to_owned()
            }
        );
        assert!(open);
    }
}

#[test]
fn a_known_kind_is_delivered_undecoded() {
    // Not even a map: the helpers do not look.
    let sent = frame("status", &Value::Array(vec![Value::Bool(true)]));
    for (outcome, open) in both_sides(&sent) {
        assert_eq!(outcome, Outcome::Deliver(envelope(&sent)));
        assert!(open);
    }
}

#[test]
fn a_rejected_body_closes() {
    let (mut server, mut endpoint) = connect(
        control_server().with_known_kinds(["status"]),
        control_endpoint().with_known_kinds(["status"]),
    );
    let sent = frame("status", &text("garbage"));
    let actions = server.receive(sent.as_bytes(), wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [ServerAction::Deliver(_)]));
    assert_eq!(
        server.reject_body(),
        ServerAction::Close(CloseReason::BodyRejected)
    );
    assert!(server.is_closed());
    assert_eq!(server.receive(sent.as_bytes(), wall(10), ms(10)), []);

    let actions = endpoint.receive(sent.as_bytes(), wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [EndpointAction::Deliver(_)]));
    assert_eq!(
        endpoint.reject_body(),
        EndpointAction::Close(CloseReason::BodyRejected)
    );
    assert!(endpoint.is_closed());
}

/// A `status` body the caller rejects, then a `ping`, as one stream.
fn rejected_then_ping() -> Vec<u8> {
    let mut stream = frame("status", &text("garbage")).into_bytes();
    stream.extend_from_slice(
        Frame::from_message(&Ping { sent_at: wall(9) })
            .unwrap()
            .as_bytes(),
    );
    stream
}

/// A server past its handshake that handles `status`, and the `t`s its
/// standing check was asked about.
fn counted_server() -> (ServerConnection, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let (server, _) = connect(
        control_server()
            .with_known_kinds(["status"])
            .with_standing(move |t| {
                log.lock().unwrap().push(t.to_owned());
                StandingVerdict::Accept
            }),
        control_endpoint(),
    );
    seen.lock().unwrap().clear();
    (server, seen)
}

#[test]
fn frames_after_a_delivered_body_wait_for_the_verdict() {
    let stream = rejected_then_ping();

    // All at once: the ping is not looked at, not even by the standing
    // check, before the caller rejects the body.
    let (mut whole, seen) = counted_server();
    let actions = whole.receive(&stream, wall(10), ms(10));
    assert!(
        matches!(actions.as_slice(), [ServerAction::Deliver(_)]),
        "{actions:?}"
    );
    assert!(whole.is_body_pending());
    assert_eq!(*seen.lock().unwrap(), ["status"]);
    assert_eq!(
        whole.reject_body(),
        ServerAction::Close(CloseReason::BodyRejected)
    );
    assert_eq!(whole.receive(&[], wall(11), ms(11)), []);
    assert_eq!(*seen.lock().unwrap(), ["status"]);

    // A byte at a time, rejecting as soon as the body is delivered: the
    // same.
    let (mut single, seen) = counted_server();
    let mut rejected = false;
    for byte in &stream {
        let actions = single.receive(std::slice::from_ref(byte), wall(10), ms(10));
        if matches!(actions.as_slice(), [ServerAction::Deliver(_)]) {
            assert_eq!(
                single.reject_body(),
                ServerAction::Close(CloseReason::BodyRejected)
            );
            rejected = true;
        } else {
            assert_eq!(actions, [], "{actions:?}");
        }
    }
    assert!(rejected);
    assert_eq!(*seen.lock().unwrap(), ["status"]);

    // Accepted, the ping that waited is answered.
    let (mut accepting, seen) = counted_server();
    let actions = accepting.receive(&stream, wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [ServerAction::Deliver(_)]));
    let actions = accepting.accept_body(wall(12), ms(12));
    let [ServerAction::Send(pong)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(decode::<Pong>(pong).sent_at, wall(12));
    assert!(!accepting.is_body_pending());
    assert_eq!(*seen.lock().unwrap(), ["status", "ping"]);

    // The endpoint side waits the same way.
    let (_, mut endpoint) = connect(
        control_server(),
        control_endpoint().with_known_kinds(["status"]),
    );
    let actions = endpoint.receive(&stream, wall(10), ms(10));
    assert!(
        matches!(actions.as_slice(), [EndpointAction::Deliver(_)]),
        "{actions:?}"
    );
    assert!(endpoint.is_body_pending());
    assert_eq!(
        endpoint.reject_body(),
        EndpointAction::Close(CloseReason::BodyRejected)
    );
    assert_eq!(endpoint.receive(&[], wall(11), ms(11)), []);

    let (_, mut endpoint) = connect(
        control_server(),
        control_endpoint().with_known_kinds(["status"]),
    );
    let actions = endpoint.receive(&stream, wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [EndpointAction::Deliver(_)]));
    // The next receive takes the body as accepted.
    let actions = endpoint.receive(&[], wall(12), ms(12));
    assert!(
        matches!(actions.as_slice(), [EndpointAction::Send(_)]),
        "{actions:?}"
    );
}

#[test]
fn built_in_names_in_the_known_list_stay_built_in() {
    let (mut server, mut endpoint) = connect(
        control_server().with_known_kinds(["ping", "hello"]),
        control_endpoint().with_known_kinds(["ping"]),
    );
    let ping = Frame::from_message(&Ping { sent_at: wall(9) }).unwrap();
    let actions = server.receive(ping.as_bytes(), wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [ServerAction::Send(_)]));
    let actions = endpoint.receive(ping.as_bytes(), wall(10), ms(10));
    assert!(matches!(actions.as_slice(), [EndpointAction::Send(_)]));
    let (_, hello) = endpoint_pair_hello();
    assert_eq!(
        server.receive(hello.as_bytes(), wall(10), ms(10)),
        [ServerAction::Close(CloseReason::HelloAfterHandshake)]
    );
}

fn endpoint_pair_hello() -> (EndpointConnection, Frame) {
    endpoint(control_endpoint())
}

#[test]
fn malformed_built_in_bodies_close() {
    let mut duplicate = Vec::new();
    // {"sent_at": 1, "sent_at": 1}, as a ping.
    duplicate.extend_from_slice(&[0x82, 0x64]);
    duplicate.extend_from_slice(b"ping");
    duplicate.extend_from_slice(&[0xa2, 0x67]);
    duplicate.extend_from_slice(b"sent_at");
    duplicate.push(0x01);
    duplicate.push(0x67);
    duplicate.extend_from_slice(b"sent_at");
    duplicate.push(0x01);
    let duplicate = Frame::from_payload(&duplicate).unwrap();

    let cases = [
        (broken_ping(), Ping::T),
        (duplicate, Ping::T),
        (
            frame(Pong::T, &map(&[("sent_at", nanos(wall(1)))])),
            Pong::T,
        ),
        (
            frame(Unsupported::T, &map(&[("kind", Value::Integer(3.into()))])),
            Unsupported::T,
        ),
        (frame(HelloAck::T, &map(&[])), HelloAck::T),
    ];
    for (sent, t) in cases {
        let [(server, _), (endpoint, _)] = both_sides(&sent);
        for outcome in [server, endpoint] {
            assert!(
                matches!(&outcome, Outcome::Close(CloseReason::MalformedBody { t: got, .. }) if got == t),
                "{t}: {outcome:?}"
            );
        }
    }
    // A hello with a broken body after the handshake, at the endpoint.
    let [_, (endpoint, _)] = both_sides(&broken_hello());
    assert!(matches!(
        endpoint,
        Outcome::Close(CloseReason::MalformedBody { .. })
    ));
}

#[test]
fn a_ping_is_answered_with_a_pong() {
    let ping = Frame::from_message(&Ping { sent_at: wall(77) }).unwrap();
    for (outcome, open) in both_sides(&ping) {
        let Outcome::Send(pong) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            decode::<Pong>(&pong),
            Pong {
                ping_sent_at: wall(77),
                sent_at: wall(10),
            }
        );
        assert!(open);
    }
}

#[test]
fn a_chunked_unknown_key_is_ignored() {
    // ["ping", {"sent_at": …, "x": 1}], with "x" written as an
    // indefinite-length text string of one chunk: 7f 61 78 ff.
    let mut payload = vec![0x82, 0x64];
    payload.extend_from_slice(b"ping");
    payload.extend_from_slice(&[0xa2, 0x67]);
    payload.extend_from_slice(b"sent_at");
    payload.push(0x1b);
    payload.extend_from_slice(
        &u64::try_from(wall(77).as_nanosecond())
            .unwrap()
            .to_be_bytes(),
    );
    payload.extend_from_slice(&[0x7f, 0x61, b'x', 0xff, 0x01]);
    let ping = Frame::from_payload(&payload).unwrap();
    for (outcome, open) in both_sides(&ping) {
        let Outcome::Send(pong) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(decode::<Pong>(&pong).ping_sent_at, wall(77));
        assert!(open);
    }
}

#[test]
fn pongs_and_refusals_after_the_handshake_keep_the_connection() {
    let pong = Frame::from_message(&Pong {
        ping_sent_at: wall(1),
        sent_at: wall(2),
    })
    .unwrap();
    for (outcome, open) in both_sides(&pong) {
        assert_eq!(outcome, Outcome::Nothing);
        assert!(open);
    }
    let refusal = Frame::from_message(&Unsupported {
        kind: "status".to_owned(),
    })
    .unwrap();
    for (outcome, open) in both_sides(&refusal) {
        assert_eq!(
            outcome,
            Outcome::Unsupported(Unsupported {
                kind: "status".to_owned()
            })
        );
        assert!(open);
    }
}

#[test]
fn misplaced_hellos_and_acks_close() {
    let ack = Frame::from_message(&HelloAck {
        version: 1,
        server_time: wall(1),
        entry_id: None,
        accepted_kinds: None,
    })
    .unwrap();
    let unexpected = |t: &str| Outcome::Close(CloseReason::Unexpected { t: t.to_owned() });

    let [(server, _), (endpoint, _)] = both_sides(&ack);
    assert_eq!(server, unexpected(HelloAck::T));
    assert_eq!(endpoint, unexpected(HelloAck::T));

    let (_, hello) = endpoint_pair_hello();
    let [_, (endpoint, open)] = both_sides(&hello);
    assert_eq!(endpoint, unexpected(Hello::T));
    assert!(!open);
}

// --- Endpoint: the first message -------------------------------------------

#[test]
fn the_endpoints_first_message_other_than_an_ack_is_handed_over_then_closed() {
    let other_refusal = frame(Unsupported::T, &map(&[("kind", text("status"))]));
    let broken_refusal = frame(Unsupported::T, &map(&[("kind", Value::Integer(1.into()))]));
    let telemetry_error = frame("telemetry_error", &map(&[("code", text("not_listed"))]));
    let nowhere = frame("nowhere", &Value::Null);
    let ping = Frame::from_message(&Ping { sent_at: wall(1) }).unwrap();
    let pong = frame(Pong::T, &text("not even a map"));
    let (_, hello) = endpoint_pair_hello();

    for sent in [
        other_refusal,
        broken_refusal,
        telemetry_error,
        nowhere,
        ping,
        pong,
        hello,
    ] {
        let (mut endpoint, _) = endpoint(control_endpoint().with_known_kinds(["telemetry_error"]));
        let actions = endpoint.receive(sent.as_bytes(), wall(1), ms(1));
        let original = envelope(&sent);
        assert_eq!(
            actions,
            [
                EndpointAction::Deliver(original.clone()),
                EndpointAction::Close(CloseReason::ExpectedHelloAck {
                    t: original.t().to_owned()
                }),
            ]
        );
        assert!(endpoint.is_closed());
    }
}

#[test]
fn the_endpoints_first_message_refusing_the_version_closes() {
    let (mut endpoint, _) = endpoint(control_endpoint());
    let refusal = Frame::from_message(&Unsupported::version()).unwrap();
    assert_eq!(
        endpoint.receive(refusal.as_bytes(), wall(1), ms(1)),
        [EndpointAction::Close(CloseReason::NoCommonVersion)]
    );
}

// --- Bytes in pieces ---------------------------------------------------------

#[test]
fn bytes_one_at_a_time_act_as_bytes_all_at_once() {
    let (_, hello) = endpoint_pair_hello();
    let mut server_stream = hello.into_bytes();
    for sent in [
        Frame::from_message(&Ping { sent_at: wall(5) }).unwrap(),
        frame("status", &map(&[("ok", Value::Bool(true))])),
        frame("mystery", &Value::Null),
        Frame::from_message(&Pong {
            ping_sent_at: wall(1),
            sent_at: wall(2),
        })
        .unwrap(),
        frame(HelloAck::T, &map(&[])),
        frame("status", &Value::Null),
    ] {
        server_stream.extend_from_slice(sent.as_bytes());
    }

    let mut whole = server(control_server().with_known_kinds(["status"]));
    let mut all_at_once = whole.receive(&server_stream, wall(3), ms(3));
    // Each delivered body pauses the rest until it is accepted.
    while whole.is_body_pending() {
        all_at_once.extend(whole.accept_body(wall(3), ms(3)));
    }
    assert!(whole.is_closed(), "{all_at_once:?}");

    let mut single = server(control_server().with_known_kinds(["status"]));
    let mut one_at_a_time = Vec::new();
    for byte in &server_stream {
        one_at_a_time.extend(single.receive(std::slice::from_ref(byte), wall(3), ms(3)));
    }
    assert_eq!(one_at_a_time, all_at_once);
    // The status after the broken hello_ack is never looked at.
    assert!(matches!(
        all_at_once.last(),
        Some(ServerAction::Close(CloseReason::MalformedBody { t, .. })) if t == HelloAck::T
    ));
    assert_eq!(all_at_once.len(), 6, "{all_at_once:?}");

    // The endpoint side: the ack, then a ping and a known message.
    let mut ack_server = server(control_server());
    let (_, hello) = endpoint_pair_hello();
    let Some(ServerAction::Send(ack)) = ack_server
        .receive(hello.as_bytes(), wall(1), ms(1))
        .into_iter()
        .next()
    else {
        panic!("no ack");
    };
    let mut endpoint_stream = ack.into_bytes();
    endpoint_stream.extend_from_slice(
        Frame::from_message(&Ping { sent_at: wall(4) })
            .unwrap()
            .as_bytes(),
    );
    endpoint_stream.extend_from_slice(frame("status", &Value::Null).as_bytes());

    let (mut whole, _) = endpoint(control_endpoint().with_known_kinds(["status"]));
    let all_at_once = whole.receive(&endpoint_stream, wall(5), ms(5));
    assert_eq!(all_at_once.len(), 4, "{all_at_once:?}");
    let (mut single, _) = endpoint(control_endpoint().with_known_kinds(["status"]));
    let mut one_at_a_time = Vec::new();
    for byte in &endpoint_stream {
        one_at_a_time.extend(single.receive(std::slice::from_ref(byte), wall(5), ms(5)));
    }
    assert_eq!(one_at_a_time, all_at_once);
}

// --- Limits and envelopes --------------------------------------------------

/// A frame of exactly `len` payload bytes: `["status", h'00…']`.
fn status_frame_of(len: usize) -> Frame {
    // 0x82, 0x66 "status", then a byte string head of 1 + 4 bytes.
    let content = len - 1 - 7 - 5;
    let mut payload = vec![0x82, 0x66];
    payload.extend_from_slice(b"status");
    payload.push(0x5a);
    payload.extend_from_slice(&u32::try_from(content).unwrap().to_be_bytes());
    payload.resize(len, 0);
    let frame = Frame::from_payload(&payload).unwrap();
    assert_eq!(frame.payload().len(), len);
    frame
}

#[test]
fn a_lowered_server_limit_closes_on_the_length_prefix_alone() {
    let over = usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap() + 1;
    let big = status_frame_of(over);
    let (mut server, _) = connect(
        control_server().with_known_kinds(["status"]),
        control_endpoint(),
    );
    assert_eq!(server.receive_limit(), SERVER_ACTIVE_RECEIVE_LIMIT);

    let actions = server.receive(big.as_bytes(), wall(5), ms(5));
    assert!(
        matches!(actions.as_slice(), [ServerAction::Deliver(_)]),
        "{actions:?}"
    );

    server.set_receive_limit(SERVER_OTHER_RECEIVE_LIMIT);
    assert_eq!(server.receive_limit(), SERVER_OTHER_RECEIVE_LIMIT);
    let actions = server.receive(big.as_bytes().get(..4).unwrap(), wall(6), ms(6));
    assert_eq!(
        actions,
        [ServerAction::Close(CloseReason::FrameTooLarge(
            FrameTooLarge {
                length: 65_537,
                limit: 65_536,
            }
        ))]
    );
}

#[test]
fn helpers_accept_exactly_their_limit() {
    for limit in [SERVER_OTHER_RECEIVE_LIMIT, SERVER_ACTIVE_RECEIVE_LIMIT] {
        let (mut server, _) = connect(
            ServerConfig::new(ServerChannel::Control, limit).with_known_kinds(["status"]),
            control_endpoint(),
        );
        let exact = status_frame_of(usize::try_from(limit).unwrap());
        let actions = server.receive(exact.as_bytes(), wall(5), ms(5));
        assert!(matches!(actions.as_slice(), [ServerAction::Deliver(_)]));
        let actions = server.receive(&(limit + 1).to_be_bytes(), wall(5), ms(5));
        assert!(matches!(
            actions.as_slice(),
            [ServerAction::Close(CloseReason::FrameTooLarge(_))]
        ));
    }

    let (_, mut endpoint) = connect(
        control_server(),
        control_endpoint().with_known_kinds(["status"]),
    );
    let exact = status_frame_of(usize::try_from(ENDPOINT_RECEIVE_LIMIT).unwrap());
    let actions = endpoint.receive(exact.as_bytes(), wall(5), ms(5));
    assert!(matches!(actions.as_slice(), [EndpointAction::Deliver(_)]));
    let actions = endpoint.receive(&(ENDPOINT_RECEIVE_LIMIT + 1).to_be_bytes(), wall(5), ms(5));
    assert_eq!(
        actions,
        [EndpointAction::Close(CloseReason::FrameTooLarge(
            FrameTooLarge {
                length: ENDPOINT_RECEIVE_LIMIT + 1,
                limit: ENDPOINT_RECEIVE_LIMIT,
            }
        ))]
    );
}

#[test]
fn envelope_errors_close_at_once() {
    let cases: [(&[u8], EnvelopeError); 9] = [
        (&[], EnvelopeError::Empty),
        (&[0x82, 0x65, b'h'], EnvelopeError::Malformed),
        (
            &[0x82, 0x61, b'a', 0x00, 0x00],
            EnvelopeError::TrailingBytes,
        ),
        (&[0x81, 0x61, b'a'], EnvelopeError::WrongLength(1)),
        (
            &[0x83, 0x61, b'a', 0x00, 0x00],
            EnvelopeError::WrongLength(3),
        ),
        (
            &[0x9f, 0x61, b'a', 0x00, 0xff],
            EnvelopeError::IndefiniteLength,
        ),
        (&[0xa1, 0x61, b'a', 0x00], EnvelopeError::NotArray),
        (&[0x82, 0x01, 0x00], EnvelopeError::TypeNotText),
        // A byte string declaring 2³²−1 bytes, then three.
        (
            &[0x82, 0x61, b'a', 0x5a, 0xff, 0xff, 0xff, 0xff, 1, 2, 3],
            EnvelopeError::Malformed,
        ),
    ];
    for (payload, error) in cases {
        let frame = Frame::from_payload(payload).unwrap();
        let mut server = server(control_server());
        assert_eq!(
            server.receive(frame.as_bytes(), wall(0), ms(1)),
            [ServerAction::Close(CloseReason::Envelope(error))]
        );
        let (mut endpoint, _) = endpoint(control_endpoint());
        assert_eq!(
            endpoint.receive(frame.as_bytes(), wall(0), ms(1)),
            [EndpointAction::Close(CloseReason::Envelope(error))]
        );
    }
}

// --- Liveness ----------------------------------------------------------------

#[test]
fn pings_follow_the_handshake_then_each_other() {
    let (mut server, mut endpoint) = connect(control_server(), control_endpoint());
    // The server's handshake ended at 1 ms, the endpoint's at 2 ms.
    assert_eq!(server.next_deadline(), Some(ms(1) + PING_INTERVAL));
    assert_eq!(endpoint.next_deadline(), Some(ms(2) + PING_INTERVAL));

    let just_before = ms(1) + PING_INTERVAL - Duration::from_nanos(1);
    assert_eq!(server.poll(wall(1), just_before), None);
    let Some(ServerAction::Send(ping)) = server.poll(wall(60), ms(1) + PING_INTERVAL) else {
        panic!("no ping");
    };
    assert_eq!(decode::<Ping>(&ping), Ping { sent_at: wall(60) });
    assert_eq!(server.poll(wall(60), ms(1) + PING_INTERVAL), None);
    assert_eq!(server.next_deadline(), Some(ms(1) + 2 * PING_INTERVAL));

    assert_eq!(endpoint.poll(wall(1), ms(1) + PING_INTERVAL), None);
    assert!(matches!(
        endpoint.poll(wall(61), ms(2) + PING_INTERVAL),
        Some(EndpointAction::Send(_))
    ));
    // Kept alive by a frame, then polled long after two pings were due:
    // one ping.
    let keepalive = Frame::from_message(&Pong {
        ping_sent_at: wall(0),
        sent_at: wall(0),
    })
    .unwrap();
    assert_eq!(
        endpoint.receive(keepalive.as_bytes(), wall(170), ms(170_000)),
        []
    );
    let late = ms(2) + 3 * PING_INTERVAL + ms(30_000);
    assert!(matches!(
        endpoint.poll(wall(200), late),
        Some(EndpointAction::Send(_))
    ));
    assert_eq!(endpoint.poll(wall(200), late), None);
    assert_eq!(endpoint.next_deadline(), Some(late + PING_INTERVAL));
}

#[test]
fn no_ping_before_the_handshake() {
    let mut server = server(control_server());
    let (mut endpoint, _) = endpoint(control_endpoint());
    let before_idle = IDLE_TIMEOUT - Duration::from_nanos(1);
    for at in [PING_INTERVAL, 2 * PING_INTERVAL, before_idle] {
        assert_eq!(server.poll(wall(0), at), None);
        assert_eq!(endpoint.poll(wall(0), at), None);
    }
    assert_eq!(server.next_deadline(), Some(IDLE_TIMEOUT));
    assert_eq!(endpoint.next_deadline(), Some(IDLE_TIMEOUT));
}

#[test]
fn a_silent_connection_closes_after_the_idle_timeout() {
    // Nothing ever received: counted from the start.
    let mut server = ServerConnection::new(control_server(), ms(500));
    assert_eq!(
        server.poll(wall(0), ms(500) + IDLE_TIMEOUT - Duration::from_nanos(1)),
        None
    );
    assert_eq!(
        server.poll(wall(0), ms(500) + IDLE_TIMEOUT),
        Some(ServerAction::Close(CloseReason::IdleTimeout))
    );
    assert!(server.is_closed());
    assert_eq!(server.next_deadline(), None);
    assert_eq!(server.poll(wall(0), ms(500) + 2 * IDLE_TIMEOUT), None);

    let (mut endpoint, _) = EndpointConnection::new(control_endpoint(), wall(0), ms(500)).unwrap();
    assert_eq!(
        endpoint.poll(wall(0), ms(500) + IDLE_TIMEOUT),
        Some(EndpointAction::Close(CloseReason::IdleTimeout))
    );
}

#[test]
fn every_received_frame_restarts_the_idle_timeout() {
    let (mut server, _) = connect(
        control_server().with_known_kinds(["status"]),
        control_endpoint(),
    );
    // The hello arrived at 1 ms; a refused unknown message at 100 s.
    let actions = server.receive(
        frame("mystery", &Value::Null).as_bytes(),
        wall(0),
        ms(100_000),
    );
    assert!(matches!(actions.as_slice(), [ServerAction::Send(_)]));
    // Pings are due and sent meanwhile; they do not keep it alive.
    let mut at = ms(1) + PING_INTERVAL;
    while at < ms(100_000) + IDLE_TIMEOUT {
        assert!(matches!(
            server.poll(wall(0), at),
            Some(ServerAction::Send(_))
        ));
        at += PING_INTERVAL;
    }
    let close_at = ms(100_000) + IDLE_TIMEOUT;
    assert_eq!(
        server.poll(wall(0), close_at - Duration::from_nanos(1)),
        None
    );
    // Closing wins over a ping due at the same time.
    assert_eq!(
        server.poll(wall(0), close_at + PING_INTERVAL),
        Some(ServerAction::Close(CloseReason::IdleTimeout))
    );
}

// --- Clock correction --------------------------------------------------------

#[test]
fn the_handshake_measures_the_clock() {
    // Hello at wall 0, mono 0; the server stamps wall 1 s + 7 ns; the ack
    // arrives at mono 301 ns. RTT 301 ns, half 151 ns.
    let mut server = server(control_server());
    let (mut endpoint, hello) = endpoint(control_endpoint());
    let server_time = wall(1_000_000_007);
    let actions = server.receive(hello.as_bytes(), server_time, Duration::from_nanos(100));
    let Some(ServerAction::Send(ack)) = actions.first() else {
        panic!("{actions:?}");
    };
    let actions = endpoint.receive(ack.as_bytes(), wall(999), Duration::from_nanos(301));
    let [_, EndpointAction::ClockMeasured(measurement)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(measurement.offset_nanos(), 1_000_000_007 - 151);
    assert_eq!(measurement.uncertainty_nanos(), 151);
    let offset = measurement.offset();
    assert_eq!(offset.offset_ms, 999);
    assert_eq!(offset.uncertainty_ms, 1);
    assert_eq!(offset.measured_at, wall(301));

    let mut correction = ClockCorrection::new();
    correction.record(*measurement);
    assert_eq!(correction.offset(), Some(offset));
    assert!(!correction.exceeds_one_hour());
}

/// The endpoint's `ping` frames, sent at the given monotonic times with
/// the wall clock in step.
fn endpoint_ping(endpoint: &mut EndpointConnection, at: Duration) -> Ping {
    let stamp = wall(i64::try_from(at.as_nanos()).unwrap());
    let Some(EndpointAction::Send(ping)) = endpoint.poll(stamp, at) else {
        panic!("no ping at {at:?}");
    };
    decode::<Ping>(&ping)
}

fn pong_for(ping: &Ping, sent_at: Timestamp) -> Frame {
    Frame::from_message(&Pong {
        ping_sent_at: ping.sent_at,
        sent_at,
    })
    .unwrap()
}

#[test]
fn a_pong_for_the_latest_ping_measures_the_clock() {
    let (_, mut endpoint) = connect(control_server(), control_endpoint());
    let first_at = ms(2) + PING_INTERVAL;
    let ping = endpoint_ping(&mut endpoint, first_at);
    // The server is 5 s ahead; the round trip takes 10 ms.
    let server_time = ping
        .sent_at
        .checked_add(Duration::from_millis(5_005))
        .unwrap();
    let actions = endpoint.receive(
        pong_for(&ping, server_time).as_bytes(),
        wall(0),
        first_at + ms(10),
    );
    let [EndpointAction::ClockMeasured(measurement)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(measurement.offset().offset_ms, 5_000);
    assert_eq!(measurement.offset().uncertainty_ms, 5);
    assert_eq!(
        measurement.offset().measured_at,
        ping.sent_at.checked_add(Duration::from_millis(10)).unwrap()
    );
    assert_eq!(measurement.received_mono(), first_at + ms(10));

    // The same pong again: its ping is answered already.
    let actions = endpoint.receive(
        pong_for(&ping, server_time).as_bytes(),
        wall(0),
        first_at + ms(20),
    );
    assert_eq!(actions, []);
}

#[test]
fn a_pong_for_an_earlier_ping_does_not_measure() {
    let (_, mut endpoint) = connect(control_server(), control_endpoint());
    let first = endpoint_ping(&mut endpoint, ms(2) + PING_INTERVAL);
    let second_at = ms(2) + 2 * PING_INTERVAL;
    let second = endpoint_ping(&mut endpoint, second_at);

    let actions = endpoint.receive(
        pong_for(&first, wall(0)).as_bytes(),
        wall(0),
        second_at + ms(1),
    );
    assert_eq!(actions, []);
    // A pong for no ping at all.
    let stray = Ping { sent_at: wall(-5) };
    let actions = endpoint.receive(
        pong_for(&stray, wall(0)).as_bytes(),
        wall(0),
        second_at + ms(2),
    );
    assert_eq!(actions, []);
    // The latest still measures.
    let actions = endpoint.receive(
        pong_for(&second, wall(0)).as_bytes(),
        wall(0),
        second_at + ms(3),
    );
    assert!(matches!(
        actions.as_slice(),
        [EndpointAction::ClockMeasured(_)]
    ));
}

#[test]
fn a_pong_for_a_ping_sharing_the_latest_stamp_does_not_measure() {
    let (_, mut endpoint) = connect(control_server(), control_endpoint());
    // The wall clock stands still across two pings.
    let stamp = wall(500);
    let first_at = ms(2) + PING_INTERVAL;
    let Some(EndpointAction::Send(first)) = endpoint.poll(stamp, first_at) else {
        panic!("no first ping");
    };
    let second_at = first_at + PING_INTERVAL;
    let Some(EndpointAction::Send(second)) = endpoint.poll(stamp, second_at) else {
        panic!("no second ping");
    };
    let first = decode::<Ping>(&first);
    assert_eq!(first, decode::<Ping>(&second));

    // The first ping's pong, late: it cannot be told from the second's.
    let actions = endpoint.receive(
        pong_for(&first, wall(600)).as_bytes(),
        wall(0),
        second_at + ms(1),
    );
    assert_eq!(actions, []);
    let actions = endpoint.receive(
        pong_for(&first, wall(600)).as_bytes(),
        wall(0),
        second_at + ms(50),
    );
    assert_eq!(actions, []);

    // A wall clock stepped back is just as ambiguous.
    let third_at = second_at + PING_INTERVAL;
    let Some(EndpointAction::Send(third)) = endpoint.poll(wall(400), third_at) else {
        panic!("no third ping");
    };
    let actions = endpoint.receive(
        pong_for(&decode::<Ping>(&third), wall(600)).as_bytes(),
        wall(0),
        third_at + ms(1),
    );
    assert_eq!(actions, []);

    // A later stamp than every ping before it pairs again.
    let fourth_at = third_at + PING_INTERVAL;
    let Some(EndpointAction::Send(fourth)) = endpoint.poll(wall(501), fourth_at) else {
        panic!("no fourth ping");
    };
    let actions = endpoint.receive(
        pong_for(&decode::<Ping>(&fourth), wall(600)).as_bytes(),
        wall(0),
        fourth_at + ms(1),
    );
    assert!(
        matches!(actions.as_slice(), [EndpointAction::ClockMeasured(_)]),
        "{actions:?}"
    );
}

#[test]
fn a_backwards_monotonic_clock_does_not_measure() {
    // The ack arrives before the hello was sent.
    let mut server = server(control_server());
    let (mut endpoint, hello) =
        EndpointConnection::new(control_endpoint(), wall(0), ms(1_000)).unwrap();
    let actions = server.receive(hello.as_bytes(), wall(1), ms(1));
    let Some(ServerAction::Send(ack)) = actions.first() else {
        panic!("{actions:?}");
    };
    let actions = endpoint.receive(ack.as_bytes(), wall(2), ms(999));
    assert!(
        matches!(actions.as_slice(), [EndpointAction::Handshake(_)]),
        "{actions:?}"
    );

    // A pong arriving before its ping was sent.
    let ping_at = ms(999) + PING_INTERVAL;
    let ping = endpoint_ping(&mut endpoint, ping_at);
    let actions = endpoint.receive(
        pong_for(&ping, wall(0)).as_bytes(),
        wall(0),
        ping_at - ms(1),
    );
    assert_eq!(actions, []);
}

#[test]
fn clock_measurements_flow_from_server_pongs() {
    let (mut server, mut endpoint) = connect(control_server(), control_endpoint());
    let at = ms(2) + PING_INTERVAL;
    let Some(EndpointAction::Send(ping)) = endpoint.poll(wall(100), at) else {
        panic!("no ping");
    };
    let actions = server.receive(ping.as_bytes(), wall(200), at + ms(1));
    let [ServerAction::Send(pong)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    let actions = endpoint.receive(pong.as_bytes(), wall(300), at + ms(2));
    let [EndpointAction::ClockMeasured(measurement)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    // Server 200 ns against endpoint 100 ns + 1 ms.
    assert_eq!(measurement.offset_nanos(), 100 - 1_000_000);
}
