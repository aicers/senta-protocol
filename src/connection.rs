//! The framing every connection shares, control and telemetry alike.
//!
//! A connection carries frames: a four-byte big-endian length, then one
//! CBOR value ([`Frame`], [`FrameDecoder`]). The value is an envelope, an
//! array `[t, b]` naming the message and holding its body ([`Envelope`]).
//! Bodies follow the CBOR rules of [`cbor`]. Five messages belong to the
//! framing itself: `hello` and `hello_ack` negotiate the protocol version,
//! `ping` and `pong` keep the connection alive, and `unsupported` refuses
//! a message.
//!
//! [`ServerConnection`] and [`EndpointConnection`] run either side of a
//! connection without doing any I/O: they take received bytes, the wall
//! clock as a [`jiff::Timestamp`] and the monotonic clock as the
//! [`std::time::Duration`] since an origin of the caller's choosing, and
//! return what to do as values. One helper, and one [`ClockCorrection`],
//! must always be given monotonic times from the same origin.
//!
//! The endpoint measures the server's clock offset from its round trips
//! ([`ClockMeasurement`]) and keeps the best recent one in a
//! [`ClockCorrection`]; [`reconnect_delay`] spaces its reconnections.
//!
//! ```
//! use std::time::Duration;
//!
//! use jiff::Timestamp;
//! use senta_protocol::connection::{
//!     EndpointAction, EndpointChannel, EndpointConfig, EndpointConnection, ServerAction,
//!     ServerChannel, ServerConfig, ServerConnection, SERVER_ACTIVE_RECEIVE_LIMIT,
//! };
//!
//! let wall = Timestamp::from_second(1_700_000_000)?;
//! let mut server = ServerConnection::new(
//!     ServerConfig::new(ServerChannel::Control, SERVER_ACTIVE_RECEIVE_LIMIT),
//!     Duration::ZERO,
//! );
//! let (mut endpoint, hello) = EndpointConnection::new(
//!     EndpointConfig::new(EndpointChannel::Control, "0.1.0"),
//!     wall,
//!     Duration::ZERO,
//! )?;
//!
//! let actions = server.receive(hello.as_bytes(), wall, Duration::from_millis(5));
//! let Some(ServerAction::Send(ack)) = actions.first() else {
//!     panic!("expected a hello_ack, got {actions:?}");
//! };
//! let actions = endpoint.receive(ack.as_bytes(), wall, Duration::from_millis(10));
//! assert!(matches!(actions.first(), Some(EndpointAction::Handshake(_))));
//! assert!(server.is_established() && endpoint.is_established());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod backoff;
pub mod cbor;
mod clock;
mod endpoint;
mod envelope;
mod frame;
mod liveness;
mod message;
mod server;

use std::fmt;

use jiff::Timestamp;
use uuid::Uuid;

pub use self::backoff::{BACKOFF_BASE, BACKOFF_CAP, reconnect_delay};
pub use self::cbor::{DecodeError, DecodeErrorKind, EncodeError};
pub use self::clock::{ClockCorrection, ClockMeasurement, ClockOffset, SELECTION_WINDOW};
pub use self::endpoint::{
    EndpointAction, EndpointChannel, EndpointConfig, EndpointConnection, EndpointHandshake,
    TelemetryEntry,
};
pub use self::envelope::{Body, Envelope, EnvelopeError};
pub use self::frame::{
    ENDPOINT_RECEIVE_LIMIT, Frame, FrameDecoder, FrameTooLarge, SERVER_ACTIVE_RECEIVE_LIMIT,
    SERVER_OTHER_RECEIVE_LIMIT,
};
pub use self::liveness::{IDLE_TIMEOUT, PING_INTERVAL};
pub use self::message::{
    AcceptedKind, Hello, HelloAck, Message, PROTOCOL_VERSION, Ping, Pong, Unsupported, VersionRange,
};
pub use self::server::{
    ServerAction, ServerChannel, ServerConfig, ServerConnection, ServerHandshake, StandingCheck,
    StandingVerdict,
};

/// The kind of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionKind {
    /// Between senta and REview.
    Control,
    /// Between senta and a telemetry entry of the event store.
    Telemetry,
}

/// Why a connection helper closed its connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// A frame's length exceeded the receive limit.
    FrameTooLarge(FrameTooLarge),
    /// A frame did not hold an envelope.
    Envelope(EnvelopeError),
    /// The server's first message was not a `hello`.
    ExpectedHello {
        /// The `t` received instead.
        t: String,
    },
    /// A `hello` arrived after the handshake.
    HelloAfterHandshake,
    /// The standing check refused a message.
    Standing {
        /// The `t` refused.
        t: String,
    },
    /// The body of a built-in message did not decode.
    MalformedBody {
        /// The message's `t`.
        t: String,
        /// Why it did not decode.
        error: DecodeError,
    },
    /// The caller reported that a delivered body did not decode.
    BodyRejected,
    /// A built-in message arrived where it has no place: a `hello_ack` at
    /// the server, or a `hello` or `hello_ack` at the endpoint after the
    /// handshake.
    Unexpected {
        /// The message's `t`.
        t: String,
    },
    /// The two sides share no protocol version.
    NoCommonVersion,
    /// The endpoint's first message was neither a `hello_ack` nor a
    /// version refusal.
    ExpectedHelloAck {
        /// The `t` received instead.
        t: String,
    },
    /// The `hello_ack` chose a version outside the endpoint's range.
    VersionOutOfRange {
        /// The version chosen.
        version: u16,
    },
    /// A telemetry `hello_ack` carried no `entry_id`, or not the one
    /// expected.
    EntryIdMismatch {
        /// The `entry_id` expected.
        expected: Uuid,
        /// The `entry_id` received, if any.
        received: Option<Uuid>,
    },
    /// A telemetry `hello_ack` carried no `accepted_kinds`.
    MissingAcceptedKinds,
    /// Nothing was received for [`IDLE_TIMEOUT`].
    IdleTimeout,
    /// A frame to send failed to encode.
    Encode(EncodeError),
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge(error) => write!(f, "{error}"),
            Self::Envelope(error) => write!(f, "{error}"),
            Self::ExpectedHello { t } => write!(f, "expected hello, received {t:?}"),
            Self::HelloAfterHandshake => f.write_str("hello after the handshake"),
            Self::Standing { t } => write!(f, "standing check refused {t:?}"),
            Self::MalformedBody { t, error } => write!(f, "body of {t:?}: {error}"),
            Self::BodyRejected => f.write_str("delivered body did not decode"),
            Self::Unexpected { t } => write!(f, "unexpected {t:?}"),
            Self::NoCommonVersion => f.write_str("no common protocol version"),
            Self::ExpectedHelloAck { t } => write!(f, "expected hello_ack, received {t:?}"),
            Self::VersionOutOfRange { version } => {
                write!(
                    f,
                    "hello_ack chose version {version}, outside the range offered"
                )
            }
            Self::EntryIdMismatch { expected, received } => match received {
                Some(received) => write!(f, "entry_id {received}, expected {expected}"),
                None => write!(f, "no entry_id, expected {expected}"),
            },
            Self::MissingAcceptedKinds => f.write_str("hello_ack without accepted_kinds"),
            Self::IdleTimeout => f.write_str("nothing received for too long"),
            Self::Encode(error) => write!(f, "{error}"),
        }
    }
}

/// Decodes the body of a built-in message, or says why the connection
/// closes.
fn decode_builtin<M: Message>(envelope: &Envelope) -> Result<M, CloseReason> {
    envelope
        .body()
        .decode()
        .map_err(|error| CloseReason::MalformedBody {
            t: M::T.to_owned(),
            error,
        })
}

/// Encodes the `pong` answering a `ping`, at `wall`.
fn pong_for(ping: &Ping, wall: Timestamp) -> Result<Frame, CloseReason> {
    Frame::from_message(&Pong {
        ping_sent_at: ping.sent_at,
        sent_at: wall,
    })
    .map_err(CloseReason::Encode)
}

/// Encodes the refusal of a message named `t`.
fn unsupported_for(t: &str) -> Result<Frame, CloseReason> {
    Frame::from_message(&Unsupported { kind: t.to_owned() }).map_err(CloseReason::Encode)
}
