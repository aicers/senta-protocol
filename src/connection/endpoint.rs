//! The endpoint side of a connection: senta, to REview or to a telemetry
//! entry.

use std::collections::BTreeSet;
use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use super::cbor::EncodeError;
use super::clock::ClockMeasurement;
use super::envelope::Envelope;
use super::frame::{ENDPOINT_RECEIVE_LIMIT, Frame, TimedDecoder};
use super::liveness::{Due, Liveness};
use super::message::{
    AcceptedKind, BuiltIn, Hello, HelloAck, Message, Ping, Pong, Unsupported, VersionRange,
};
use super::{CloseReason, ConnectionKind, decode_builtin, pong_for, unsupported_for};

/// The kind of an endpoint-side connection, with what a telemetry
/// connection expects of the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointChannel {
    /// A control connection; `entry_id` and `accepted_kinds` in its
    /// `hello_ack` are not looked at.
    Control,
    /// A telemetry connection.
    Telemetry {
        /// The `entry_id` of the address entry chosen; the `hello_ack`
        /// must carry the same.
        expected_entry_id: Uuid,
    },
}

impl EndpointChannel {
    /// Returns the connection kind.
    #[must_use]
    pub fn kind(&self) -> ConnectionKind {
        match self {
            Self::Control => ConnectionKind::Control,
            Self::Telemetry { .. } => ConnectionKind::Telemetry,
        }
    }
}

/// How an [`EndpointConnection`] is set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfig {
    /// The connection kind, and on telemetry the entry expected.
    pub channel: EndpointChannel,
    /// The sender's crate version, sent in the `hello`.
    pub crate_version: String,
    /// The protocol versions the endpoint speaks, sent in the `hello`.
    pub versions: VersionRange,
    /// The message names the caller handles, beside the five built in. A
    /// built-in name here is still handled as built in.
    pub known_kinds: BTreeSet<String>,
}

impl EndpointConfig {
    /// Creates a configuration speaking the default versions, `1..=1`, and
    /// handling no message of its own.
    #[must_use]
    pub fn new(channel: EndpointChannel, crate_version: impl Into<String>) -> Self {
        Self {
            channel,
            crate_version: crate_version.into(),
            versions: VersionRange::default(),
            known_kinds: BTreeSet::new(),
        }
    }

    /// Sets the protocol versions the endpoint speaks.
    #[must_use]
    pub fn with_versions(mut self, versions: VersionRange) -> Self {
        self.versions = versions;
        self
    }

    /// Sets the message names the caller handles.
    #[must_use]
    pub fn with_known_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.known_kinds = kinds.into_iter().map(Into::into).collect();
        self
    }
}

/// What a telemetry entry announced in its `hello_ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEntry {
    /// The entry's identity, checked against the one expected.
    pub entry_id: Uuid,
    /// The record kinds the entry accepts, and the schema versions of each.
    pub accepted_kinds: Vec<AcceptedKind>,
}

/// What the endpoint learns from a completed, verified handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHandshake {
    /// The protocol version the server chose, within the endpoint's range.
    pub version: u16,
    /// The server's wall clock as it handled the `hello`.
    pub server_time: Timestamp,
    /// On a telemetry connection, what the entry announced; `None` on a
    /// control connection.
    pub telemetry: Option<TelemetryEntry>,
}

/// What an [`EndpointConnection`] asks its caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointAction {
    /// The handshake is complete and verified.
    Handshake(EndpointHandshake),
    /// A measurement of the clock offset, from the handshake or from a
    /// `pong` answering the latest `ping`.
    ClockMeasured(ClockMeasurement),
    /// A message, with its body undecoded: after the handshake, one of a
    /// kind the caller handles; as the first message, anything but a
    /// `hello_ack` or a version refusal, which is followed by
    /// [`EndpointAction::Close`]. After the handshake it is the last
    /// action of its call: the frames after it wait until the caller
    /// decodes the body and reports the outcome, through
    /// [`EndpointConnection::accept_body`] (or the next
    /// [`EndpointConnection::receive`]) or
    /// [`EndpointConnection::reject_body`].
    Deliver(Envelope),
    /// The server refused a message; the connection stays open.
    Unsupported(Unsupported),
    /// Send this frame.
    Send(Frame),
    /// Close the connection.
    Close(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingAck,
    Established,
    Closed,
}

/// The endpoint side of a connection, without I/O: it takes received bytes
/// and the time, and returns what to do.
///
/// It receives frames of up to [`ENDPOINT_RECEIVE_LIMIT`] bytes. Received
/// bytes may come in pieces of any size. Each complete frame becomes zero
/// or more [`EndpointAction`]s; once one of them closes the connection,
/// the bytes after it are not looked at, and every later call returns
/// nothing. A [`EndpointAction::Deliver`] after the handshake pauses
/// handling until the caller's verdict on its body, so how the bytes were
/// split changes nothing about what follows it.
#[derive(Debug)]
pub struct EndpointConnection {
    channel: EndpointChannel,
    versions: VersionRange,
    known_kinds: BTreeSet<String>,
    decoder: TimedDecoder,
    state: State,
    body_pending: bool,
    liveness: Liveness,
    hello_sent: (Timestamp, Duration),
    pending_ping: Option<(Timestamp, Duration)>,
    latest_ping_stamp: Option<Timestamp>,
}

impl EndpointConnection {
    /// Creates the endpoint side of a connection that starts at `wall` on
    /// the wall clock and `now` on the monotonic clock, and returns it with
    /// the `hello` to send first, stamped with `wall`.
    ///
    /// # Errors
    ///
    /// Returns an error when the `hello` fails to encode: when `wall` lies
    /// outside the range of an `i64` count of nanoseconds.
    pub fn new(
        config: EndpointConfig,
        wall: Timestamp,
        now: Duration,
    ) -> Result<(Self, Frame), EncodeError> {
        let hello = Hello {
            crate_version: config.crate_version,
            versions: config.versions,
            sent_at: wall,
        };
        let frame = Frame::from_message(&hello)?;
        let connection = Self {
            channel: config.channel,
            versions: config.versions,
            known_kinds: config.known_kinds,
            decoder: TimedDecoder::new(ENDPOINT_RECEIVE_LIMIT),
            body_pending: false,
            state: State::AwaitingAck,
            liveness: Liveness::new(now),
            hello_sent: (wall, now),
            pending_ping: None,
            latest_ping_stamp: None,
        };
        Ok((connection, frame))
    }

    /// Returns the connection kind.
    #[must_use]
    pub fn kind(&self) -> ConnectionKind {
        self.channel.kind()
    }

    /// Reports whether the handshake is complete and the connection open.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Reports whether the connection has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Takes received bytes and returns what to do about every frame they
    /// complete, up to and including the first [`EndpointAction::Deliver`].
    ///
    /// Called while a delivered body is pending, it takes that body as
    /// decoded first. `wall` is the wall clock now, put in a `pong`, and
    /// `now` the monotonic clock now, the time `bytes` arrived. A frame
    /// counts as received when its last byte arrived, not when it is
    /// handled: one held back behind a pending body keeps the time of the
    /// call that brought it in, for the round trip it ends and for the idle
    /// timeout alike.
    #[must_use]
    pub fn receive(&mut self, bytes: &[u8], wall: Timestamp, now: Duration) -> Vec<EndpointAction> {
        let mut actions = Vec::new();
        if self.is_closed() {
            return actions;
        }
        self.decoder.push(bytes, now, self.body_pending);
        self.body_pending = false;
        while !self.is_closed() && !self.body_pending {
            match self.decoder.next_frame(now) {
                Ok(None) => break,
                Ok(Some((payload, arrived))) => {
                    self.liveness.received(arrived);
                    self.handle(&payload, wall, arrived, &mut actions);
                }
                Err(error) => self.close(&mut actions, CloseReason::FrameTooLarge(error)),
            }
        }
        actions
    }

    /// Reports whether a delivered message's body awaits the caller's
    /// verdict: [`EndpointConnection::accept_body`] or
    /// [`EndpointConnection::reject_body`].
    #[must_use]
    pub fn is_body_pending(&self) -> bool {
        self.body_pending
    }

    /// Takes the body of the message just delivered as decoded, and
    /// handles the frames received after it.
    ///
    /// Equivalent to calling [`EndpointConnection::receive`] with no bytes;
    /// `wall` and `now` are as there. The frames it handles keep the times
    /// they arrived at, however long the verdict took.
    #[must_use]
    pub fn accept_body(&mut self, wall: Timestamp, now: Duration) -> Vec<EndpointAction> {
        self.receive(&[], wall, now)
    }

    /// Closes the connection because the body of a delivered message did
    /// not decode.
    ///
    /// Called while that body is pending, the frames received after it
    /// are never looked at, however the bytes were split.
    #[must_use]
    pub fn reject_body(&mut self) -> EndpointAction {
        self.body_pending = false;
        self.state = State::Closed;
        EndpointAction::Close(CloseReason::BodyRejected)
    }

    /// Returns what liveness asks for at `now` on the monotonic clock: a
    /// `ping` stamped with `wall`, closing a silent connection, or nothing.
    ///
    /// However late it is called, it sends one `ping` at most. The `ping`
    /// sent becomes the one a `pong` must answer to measure the clock
    /// offset, unless its `sent_at` is no later than that of a `ping` sent
    /// before it: a `pong` could not tell the two apart, so no `pong`
    /// measures until the next `ping`.
    #[must_use]
    pub fn poll(&mut self, wall: Timestamp, now: Duration) -> Option<EndpointAction> {
        if self.is_closed() {
            return None;
        }
        match self.liveness.due(now)? {
            Due::Close => {
                self.state = State::Closed;
                Some(EndpointAction::Close(CloseReason::IdleTimeout))
            }
            Due::Ping => {
                self.liveness.ping_sent(now);
                match Frame::from_message(&Ping { sent_at: wall }) {
                    Ok(frame) => {
                        // A pong names its ping by `sent_at` alone. Should
                        // the wall clock repeat or step back, an earlier
                        // ping may carry the same stamp, and a pong for it
                        // would pass for this one's: such a ping is not
                        // paired at all.
                        let ambiguous = self.latest_ping_stamp.is_some_and(|stamp| wall <= stamp);
                        self.latest_ping_stamp =
                            Some(self.latest_ping_stamp.map_or(wall, |stamp| stamp.max(wall)));
                        self.pending_ping = (!ambiguous).then_some((wall, now));
                        Some(EndpointAction::Send(frame))
                    }
                    Err(error) => {
                        self.state = State::Closed;
                        Some(EndpointAction::Close(CloseReason::Encode(error)))
                    }
                }
            }
        }
    }

    /// Returns when, on the monotonic clock, [`EndpointConnection::poll`]
    /// is next due, or `None` once the connection is closed.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        (!self.is_closed()).then(|| self.liveness.next_deadline())
    }

    fn close(&mut self, actions: &mut Vec<EndpointAction>, reason: CloseReason) {
        self.state = State::Closed;
        actions.push(EndpointAction::Close(reason));
    }

    fn send_or_close(
        &mut self,
        actions: &mut Vec<EndpointAction>,
        frame: Result<Frame, CloseReason>,
    ) {
        match frame {
            Ok(frame) => actions.push(EndpointAction::Send(frame)),
            Err(reason) => self.close(actions, reason),
        }
    }

    /// Handles one frame whose last byte arrived at `arrived` on the
    /// monotonic clock, which times the round trip it ends. A reply is
    /// stamped with `wall`, the wall clock when it is sent.
    fn handle(
        &mut self,
        payload: &[u8],
        wall: Timestamp,
        arrived: Duration,
        actions: &mut Vec<EndpointAction>,
    ) {
        let envelope = match Envelope::parse(payload) {
            Ok(envelope) => envelope,
            Err(error) => return self.close(actions, CloseReason::Envelope(error)),
        };
        match self.state {
            State::AwaitingAck => self.handle_first(envelope, arrived, actions),
            State::Established => self.handle_established(envelope, wall, arrived, actions),
            State::Closed => {}
        }
    }

    fn handle_first(
        &mut self,
        envelope: Envelope,
        arrived: Duration,
        actions: &mut Vec<EndpointAction>,
    ) {
        match envelope.t() {
            HelloAck::T => {
                let verified =
                    decode_builtin::<HelloAck>(&envelope).and_then(|ack| self.verify(ack));
                match verified {
                    Ok(handshake) => {
                        self.state = State::Established;
                        self.liveness.handshake_done(arrived);
                        let (hello_wall, hello_mono) = self.hello_sent;
                        let measurement = ClockMeasurement::from_round_trip(
                            hello_wall,
                            hello_mono,
                            arrived,
                            handshake.server_time,
                        );
                        actions.push(EndpointAction::Handshake(handshake));
                        if let Some(measurement) = measurement {
                            actions.push(EndpointAction::ClockMeasured(measurement));
                        }
                    }
                    Err(reason) => self.close(actions, reason),
                }
            }
            Unsupported::T
                if envelope
                    .body()
                    .decode::<Unsupported>()
                    .is_ok_and(|unsupported| unsupported.is_version()) =>
            {
                self.close(actions, CloseReason::NoCommonVersion);
            }
            t => {
                let reason = CloseReason::ExpectedHelloAck { t: t.to_owned() };
                actions.push(EndpointAction::Deliver(envelope));
                self.close(actions, reason);
            }
        }
    }

    fn verify(&self, ack: HelloAck) -> Result<EndpointHandshake, CloseReason> {
        if !self.versions.contains(ack.version) {
            return Err(CloseReason::VersionOutOfRange {
                version: ack.version,
            });
        }
        let telemetry = match self.channel {
            EndpointChannel::Control => None,
            EndpointChannel::Telemetry { expected_entry_id } => {
                if ack.entry_id != Some(expected_entry_id) {
                    return Err(CloseReason::EntryIdMismatch {
                        expected: expected_entry_id,
                        received: ack.entry_id,
                    });
                }
                let Some(accepted_kinds) = ack.accepted_kinds else {
                    return Err(CloseReason::MissingAcceptedKinds);
                };
                Some(TelemetryEntry {
                    entry_id: expected_entry_id,
                    accepted_kinds,
                })
            }
        };
        Ok(EndpointHandshake {
            version: ack.version,
            server_time: ack.server_time,
            telemetry,
        })
    }

    fn handle_established(
        &mut self,
        envelope: Envelope,
        wall: Timestamp,
        arrived: Duration,
        actions: &mut Vec<EndpointAction>,
    ) {
        let t = envelope.t();
        let builtin = BuiltIn::from_t(t);
        if builtin.is_none() && !self.known_kinds.contains(t) {
            return self.send_or_close(actions, unsupported_for(t));
        }
        match builtin {
            Some(BuiltIn::Hello) => {
                let reason = match decode_builtin::<Hello>(&envelope) {
                    Ok(_) => CloseReason::Unexpected { t: t.to_owned() },
                    Err(reason) => reason,
                };
                self.close(actions, reason);
            }
            Some(BuiltIn::HelloAck) => {
                let reason = match decode_builtin::<HelloAck>(&envelope) {
                    Ok(_) => CloseReason::Unexpected { t: t.to_owned() },
                    Err(reason) => reason,
                };
                self.close(actions, reason);
            }
            Some(BuiltIn::Ping) => {
                let pong = decode_builtin::<Ping>(&envelope).and_then(|ping| pong_for(&ping, wall));
                self.send_or_close(actions, pong);
            }
            Some(BuiltIn::Pong) => match decode_builtin::<Pong>(&envelope) {
                Ok(pong) => self.match_pong(&pong, arrived, actions),
                Err(reason) => self.close(actions, reason),
            },
            Some(BuiltIn::Unsupported) => match decode_builtin::<Unsupported>(&envelope) {
                Ok(unsupported) => actions.push(EndpointAction::Unsupported(unsupported)),
                Err(reason) => self.close(actions, reason),
            },
            None => {
                self.body_pending = true;
                actions.push(EndpointAction::Deliver(envelope));
            }
        }
    }

    /// Measures the clock offset from a `pong` answering the latest `ping`;
    /// a `pong` answering any other is ignored.
    fn match_pong(&mut self, pong: &Pong, arrived: Duration, actions: &mut Vec<EndpointAction>) {
        let Some((sent_wall, sent_mono)) = self.pending_ping else {
            return;
        };
        if pong.ping_sent_at != sent_wall {
            return;
        }
        self.pending_ping = None;
        if let Some(measurement) =
            ClockMeasurement::from_round_trip(sent_wall, sent_mono, arrived, pong.sent_at)
        {
            actions.push(EndpointAction::ClockMeasured(measurement));
        }
    }
}
