//! The server side of a connection: REview on a control connection, a
//! telemetry entry on a telemetry connection.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use super::envelope::Envelope;
use super::frame::{Frame, TimedDecoder};
use super::liveness::{Due, Liveness};
use super::message::{
    AcceptedKind, BuiltIn, Hello, HelloAck, Message, Ping, Pong, Unsupported, VersionRange,
};
use super::{CloseReason, ConnectionKind, decode_builtin, pong_for, unsupported_for};

/// The kind of a server-side connection, with what a telemetry entry
/// announces about itself in its `hello_ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerChannel {
    /// A control connection; its `hello_ack` carries neither `entry_id`
    /// nor `accepted_kinds`.
    Control,
    /// A telemetry connection; its `hello_ack` always carries both, an
    /// empty list as an empty list.
    Telemetry {
        /// This entry's identity.
        entry_id: Uuid,
        /// The record kinds this entry accepts.
        accepted_kinds: Vec<AcceptedKind>,
    },
}

impl ServerChannel {
    /// Returns the connection kind.
    #[must_use]
    pub fn kind(&self) -> ConnectionKind {
        match self {
            Self::Control => ConnectionKind::Control,
            Self::Telemetry { .. } => ConnectionKind::Telemetry,
        }
    }
}

/// What the standing check decides about a received message, from its `t`
/// alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandingVerdict {
    /// The message is handled as usual.
    Accept,
    /// The message is answered with `unsupported { kind: t }` and the
    /// connection kept; on the first `hello`, the connection is closed
    /// instead.
    Unsupported,
    /// The given frame is sent and the connection closed.
    SendThenClose(Frame),
    /// The connection is closed.
    Close,
}

/// A standing check: given a received message's `t`, it decides what
/// becomes of the message before its body is read.
pub type StandingCheck = Box<dyn FnMut(&str) -> StandingVerdict + Send>;

/// How a [`ServerConnection`] is set up.
pub struct ServerConfig {
    /// The connection kind, and on telemetry what the entry announces.
    pub channel: ServerChannel,
    /// The protocol versions the server speaks.
    pub versions: VersionRange,
    /// The limit received frames are checked against at first.
    pub receive_limit: u32,
    /// The message names the caller handles, beside the five built in. A
    /// built-in name here is still handled as built in.
    pub known_kinds: BTreeSet<String>,
    /// The standing check; without one, every message is accepted.
    pub standing: Option<StandingCheck>,
}

impl ServerConfig {
    /// Creates a configuration speaking the default versions, `1..=1`,
    /// handling no message of its own, and with no standing check.
    #[must_use]
    pub fn new(channel: ServerChannel, receive_limit: u32) -> Self {
        Self {
            channel,
            versions: VersionRange::default(),
            receive_limit,
            known_kinds: BTreeSet::new(),
            standing: None,
        }
    }

    /// Sets the protocol versions the server speaks.
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

    /// Sets the standing check.
    #[must_use]
    pub fn with_standing<F>(mut self, check: F) -> Self
    where
        F: FnMut(&str) -> StandingVerdict + Send + 'static,
    {
        self.standing = Some(Box::new(check));
        self
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("channel", &self.channel)
            .field("versions", &self.versions)
            .field("receive_limit", &self.receive_limit)
            .field("known_kinds", &self.known_kinds)
            .field("standing", &self.standing.is_some())
            .finish()
    }
}

/// What the server learns from a completed handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshake {
    /// The protocol version chosen.
    pub version: u16,
    /// The endpoint's `hello`.
    pub hello: Hello,
}

/// What a [`ServerConnection`] asks its caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    /// The handshake is complete.
    Handshake(ServerHandshake),
    /// A message of a kind the caller handles, with its body undecoded.
    /// It is the last action of its call: the frames after it wait until
    /// the caller decodes the body and reports the outcome, through
    /// [`ServerConnection::accept_body`] (or the next
    /// [`ServerConnection::receive`]) or [`ServerConnection::reject_body`].
    Deliver(Envelope),
    /// The endpoint refused a message; the connection stays open.
    Unsupported(Unsupported),
    /// Send this frame.
    Send(Frame),
    /// Send this frame, then close the connection.
    SendThenClose {
        /// The frame to send.
        frame: Frame,
        /// Why the connection closes.
        reason: CloseReason,
    },
    /// Close the connection.
    Close(CloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingHello,
    Established,
    Closed,
}

/// The server side of a connection, without I/O: it takes received bytes
/// and the time, and returns what to do.
///
/// Received bytes may come in pieces of any size. Each complete frame
/// becomes zero or more [`ServerAction`]s; once one of them closes the
/// connection, the bytes after it are not looked at, and every later call
/// returns nothing. A [`ServerAction::Deliver`] pauses handling until the
/// caller's verdict on its body, so how the bytes were split changes
/// nothing about what follows it.
pub struct ServerConnection {
    channel: ServerChannel,
    versions: VersionRange,
    known_kinds: BTreeSet<String>,
    standing: Option<StandingCheck>,
    decoder: TimedDecoder,
    state: State,
    body_pending: bool,
    liveness: Liveness,
}

impl ServerConnection {
    /// Creates the server side of a connection that started at `now` on
    /// the monotonic clock.
    #[must_use]
    pub fn new(config: ServerConfig, now: Duration) -> Self {
        Self {
            channel: config.channel,
            versions: config.versions,
            known_kinds: config.known_kinds,
            standing: config.standing,
            decoder: TimedDecoder::new(config.receive_limit),
            body_pending: false,
            state: State::AwaitingHello,
            liveness: Liveness::new(now),
        }
    }

    /// Returns the connection kind.
    #[must_use]
    pub fn kind(&self) -> ConnectionKind {
        self.channel.kind()
    }

    /// Returns the limit the next frame's length is checked against.
    #[must_use]
    pub fn receive_limit(&self) -> u32 {
        self.decoder.limit()
    }

    /// Changes the receive limit, as the endpoint's standing changes.
    ///
    /// The new limit applies from the next length prefix read; a frame
    /// whose prefix was already accepted completes under the old one.
    pub fn set_receive_limit(&mut self, limit: u32) {
        self.decoder.set_limit(limit);
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
    /// complete, up to and including the first [`ServerAction::Deliver`].
    ///
    /// Called while a delivered body is pending, it takes that body as
    /// decoded first. `wall` is the wall clock now, put in a `hello_ack` or
    /// `pong`, and `now` the monotonic clock now, the time `bytes` arrived.
    /// A frame counts as received, for the idle timeout, when its last byte
    /// arrived, not when it is handled: one held back behind a pending body
    /// keeps the time of the call that brought it in.
    #[must_use]
    pub fn receive(&mut self, bytes: &[u8], wall: Timestamp, now: Duration) -> Vec<ServerAction> {
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
                    self.handle(&payload, wall, now, &mut actions);
                }
                Err(error) => self.close(&mut actions, CloseReason::FrameTooLarge(error)),
            }
        }
        actions
    }

    /// Reports whether a delivered message's body awaits the caller's
    /// verdict: [`ServerConnection::accept_body`] or
    /// [`ServerConnection::reject_body`].
    #[must_use]
    pub fn is_body_pending(&self) -> bool {
        self.body_pending
    }

    /// Takes the body of the message just delivered as decoded, and
    /// handles the frames received after it.
    ///
    /// Equivalent to calling [`ServerConnection::receive`] with no bytes;
    /// `wall` and `now` are as there. The frames it handles keep the times
    /// they arrived at, however long the verdict took.
    #[must_use]
    pub fn accept_body(&mut self, wall: Timestamp, now: Duration) -> Vec<ServerAction> {
        self.receive(&[], wall, now)
    }

    /// Closes the connection because the body of a delivered message did
    /// not decode.
    ///
    /// Called while that body is pending, the frames received after it
    /// are never looked at, however the bytes were split.
    #[must_use]
    pub fn reject_body(&mut self) -> ServerAction {
        self.body_pending = false;
        self.state = State::Closed;
        ServerAction::Close(CloseReason::BodyRejected)
    }

    /// Returns what liveness asks for at `now` on the monotonic clock: a
    /// `ping` stamped with `wall`, closing a silent connection, or nothing.
    ///
    /// However late it is called, it sends one `ping` at most.
    #[must_use]
    pub fn poll(&mut self, wall: Timestamp, now: Duration) -> Option<ServerAction> {
        if self.is_closed() {
            return None;
        }
        match self.liveness.due(now)? {
            Due::Close => {
                self.state = State::Closed;
                Some(ServerAction::Close(CloseReason::IdleTimeout))
            }
            Due::Ping => {
                self.liveness.ping_sent(now);
                match Frame::from_message(&Ping { sent_at: wall }) {
                    Ok(frame) => Some(ServerAction::Send(frame)),
                    Err(error) => {
                        self.state = State::Closed;
                        Some(ServerAction::Close(CloseReason::Encode(error)))
                    }
                }
            }
        }
    }

    /// Returns when, on the monotonic clock, [`ServerConnection::poll`] is
    /// next due, or `None` once the connection is closed.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        (!self.is_closed()).then(|| self.liveness.next_deadline())
    }

    fn close(&mut self, actions: &mut Vec<ServerAction>, reason: CloseReason) {
        self.state = State::Closed;
        actions.push(ServerAction::Close(reason));
    }

    fn send_or_close(
        &mut self,
        actions: &mut Vec<ServerAction>,
        frame: Result<Frame, CloseReason>,
    ) {
        match frame {
            Ok(frame) => actions.push(ServerAction::Send(frame)),
            Err(reason) => self.close(actions, reason),
        }
    }

    /// Handles one frame, at `wall` on the wall clock and `now` on the
    /// monotonic clock: the time a reply is sent.
    fn handle(
        &mut self,
        payload: &[u8],
        wall: Timestamp,
        now: Duration,
        actions: &mut Vec<ServerAction>,
    ) {
        let envelope = match Envelope::parse(payload) {
            Ok(envelope) => envelope,
            Err(error) => return self.close(actions, CloseReason::Envelope(error)),
        };
        let t = envelope.t();
        let first = self.state == State::AwaitingHello;

        if first && t != Hello::T {
            return self.close(actions, CloseReason::ExpectedHello { t: t.to_owned() });
        }
        if !first && t == Hello::T {
            return self.close(actions, CloseReason::HelloAfterHandshake);
        }

        if let Some(standing) = self.standing.as_mut() {
            match standing(t) {
                StandingVerdict::Accept => {}
                StandingVerdict::Unsupported if !first => {
                    return self.send_or_close(actions, unsupported_for(t));
                }
                StandingVerdict::Unsupported | StandingVerdict::Close => {
                    return self.close(actions, CloseReason::Standing { t: t.to_owned() });
                }
                StandingVerdict::SendThenClose(frame) => {
                    self.state = State::Closed;
                    actions.push(ServerAction::SendThenClose {
                        frame,
                        reason: CloseReason::Standing { t: t.to_owned() },
                    });
                    return;
                }
            }
        }

        let builtin = BuiltIn::from_t(t);
        if builtin.is_none() && !self.known_kinds.contains(t) {
            return self.send_or_close(actions, unsupported_for(t));
        }

        match builtin {
            Some(BuiltIn::Hello) => match decode_builtin::<Hello>(&envelope) {
                Ok(hello) => self.negotiate(hello, wall, now, actions),
                Err(reason) => self.close(actions, reason),
            },
            Some(BuiltIn::Ping) => {
                let pong = decode_builtin::<Ping>(&envelope).and_then(|ping| pong_for(&ping, wall));
                self.send_or_close(actions, pong);
            }
            Some(BuiltIn::Pong) => {
                if let Err(reason) = decode_builtin::<Pong>(&envelope) {
                    self.close(actions, reason);
                }
            }
            Some(BuiltIn::Unsupported) => match decode_builtin::<Unsupported>(&envelope) {
                Ok(unsupported) => actions.push(ServerAction::Unsupported(unsupported)),
                Err(reason) => self.close(actions, reason),
            },
            Some(BuiltIn::HelloAck) => {
                let reason = match decode_builtin::<HelloAck>(&envelope) {
                    Ok(_) => CloseReason::Unexpected { t: t.to_owned() },
                    Err(reason) => reason,
                };
                self.close(actions, reason);
            }
            None => {
                self.body_pending = true;
                actions.push(ServerAction::Deliver(envelope));
            }
        }
    }

    fn negotiate(
        &mut self,
        hello: Hello,
        wall: Timestamp,
        now: Duration,
        actions: &mut Vec<ServerAction>,
    ) {
        let Some(version) = self.versions.highest_common(&hello.versions) else {
            match Frame::from_message(&Unsupported::version()) {
                Ok(frame) => {
                    self.state = State::Closed;
                    actions.push(ServerAction::SendThenClose {
                        frame,
                        reason: CloseReason::NoCommonVersion,
                    });
                }
                Err(error) => self.close(actions, CloseReason::Encode(error)),
            }
            return;
        };
        let (entry_id, accepted_kinds) = match &self.channel {
            ServerChannel::Control => (None, None),
            ServerChannel::Telemetry {
                entry_id,
                accepted_kinds,
            } => (Some(*entry_id), Some(accepted_kinds.clone())),
        };
        let ack = HelloAck {
            version,
            server_time: wall,
            entry_id,
            accepted_kinds,
        };
        match Frame::from_message(&ack) {
            Ok(frame) => {
                self.state = State::Established;
                self.liveness.handshake_done(now);
                actions.push(ServerAction::Send(frame));
                actions.push(ServerAction::Handshake(ServerHandshake { version, hello }));
            }
            Err(error) => self.close(actions, CloseReason::Encode(error)),
        }
    }
}

impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .field("channel", &self.channel)
            .field("versions", &self.versions)
            .field("known_kinds", &self.known_kinds)
            .field("standing", &self.standing.is_some())
            .field("decoder", &self.decoder)
            .field("state", &self.state)
            .field("liveness", &self.liveness)
            .finish()
    }
}
