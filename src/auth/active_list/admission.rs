//! What an endpoint's standing lets it send, and how large a frame it may
//! send.

use uuid::Uuid;

use crate::connection::{
    ConnectionKind, Hello, Message, Ping, Pong, SERVER_ACTIVE_RECEIVE_LIMIT,
    SERVER_OTHER_RECEIVE_LIMIT,
};
use crate::standing::SuspendReason;
use crate::telemetry_codes::TelemetryError;

const ENROLL_REQUEST: &str = "enroll_request";
const ENROLL_RESULT_POLL: &str = "enroll_result_poll";
const STATUS_REPORT: &str = "status_report";
const UNENROLL: &str = "unenroll";

/// The control `t`s an endpoint not on the list may send.
pub(super) const NOT_LISTED_CONTROL: [&str; 5] = [
    Hello::T,
    Ping::T,
    Pong::T,
    ENROLL_REQUEST,
    ENROLL_RESULT_POLL,
];

/// The control `t`s an endpoint whose license is pending may send.
pub(super) const LICENSE_PENDING_CONTROL: [&str; 6] = [
    Hello::T,
    Ping::T,
    Pong::T,
    STATUS_REPORT,
    ENROLL_RESULT_POLL,
    UNENROLL,
];

/// The control `t`s a suspended endpoint may send.
pub(super) const SUSPENDED_CONTROL: [&str; 5] =
    [Hello::T, Ping::T, Pong::T, STATUS_REPORT, UNENROLL];

/// An endpoint's standing at an ingress, from the active list and, at the
/// event store's ingress, the lease.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Standing {
    /// The ingress has had no full list since it started.
    Unready,
    /// The lease on the list has expired.
    LeaseExpired,
    /// The endpoint's key is not on the list.
    NotListed,
    /// The endpoint is listed and its license is pending.
    LicensePending,
    /// The endpoint is listed and suspended.
    Suspended {
        /// Why it is suspended.
        reason: SuspendReason,
    },
    /// The endpoint is listed and active.
    Active,
}

/// The ids of the list entry an endpoint's key matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointIdentity {
    /// The entry's `endpoint_id`: the id records from the connection must
    /// claim, and the one they are stored under.
    pub endpoint_id: Uuid,
    /// The entry's `customer_endpoint_id`.
    pub customer_endpoint_id: Uuid,
}

/// An endpoint's standing, with the ids of the list entry its key matched.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionStanding {
    /// The standing.
    pub standing: Standing,
    /// The matched entry's ids: present whenever an entry matched, the
    /// lease expired or not, and absent when none did or the list is
    /// [`Standing::Unready`].
    pub identity: Option<EndpointIdentity>,
}

/// What becomes of a received message, from the sender's standing and the
/// message's `t` alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Admission {
    /// The message is handled as usual.
    Accept,
    /// The message is answered with `unsupported { kind: t }` and the
    /// connection kept.
    Unsupported,
    /// The telemetry `error { error }`, without `stream`, is sent and the
    /// connection closed.
    ErrorThenClose(TelemetryError),
    /// The connection is closed without a word.
    Close,
}

/// Decides what becomes of a message named `message_kind` that an endpoint
/// of `standing` sent on a connection of kind `port`, before its body is
/// read.
///
/// | Standing | Control | Telemetry |
/// | --- | --- | --- |
/// | [`Standing::NotListed`] | `hello`, `ping`, `pong`, `enroll_request`, `enroll_result_poll` | `not_listed`, then close |
/// | [`Standing::LicensePending`] | `hello`, `ping`, `pong`, `status_report`, `enroll_result_poll`, `unenroll` | `not_listed`, then close |
/// | [`Standing::Suspended`] | `hello`, `ping`, `pong`, `status_report`, `unenroll` | `suspended`, then close |
/// | [`Standing::Active`] | everything | everything |
/// | [`Standing::LeaseExpired`] | close | `lease_expired`, then close |
/// | [`Standing::Unready`] | close | close |
///
/// On control, every `t` not listed for the standing, one this crate does
/// not know included, is [`Admission::Unsupported`].
#[must_use]
pub fn allowed(standing: &Standing, port: ConnectionKind, message_kind: &str) -> Admission {
    match port {
        ConnectionKind::Control => {
            let permitted: &[&str] = match standing {
                Standing::Active => return Admission::Accept,
                Standing::Unready | Standing::LeaseExpired => return Admission::Close,
                Standing::NotListed => &NOT_LISTED_CONTROL,
                Standing::LicensePending => &LICENSE_PENDING_CONTROL,
                Standing::Suspended { .. } => &SUSPENDED_CONTROL,
            };
            if permitted.contains(&message_kind) {
                Admission::Accept
            } else {
                Admission::Unsupported
            }
        }
        ConnectionKind::Telemetry => match standing {
            Standing::Active => Admission::Accept,
            Standing::Unready => Admission::Close,
            Standing::LeaseExpired => Admission::ErrorThenClose(TelemetryError::LeaseExpired),
            Standing::NotListed | Standing::LicensePending => {
                Admission::ErrorThenClose(TelemetryError::NotListed)
            }
            Standing::Suspended { .. } => Admission::ErrorThenClose(TelemetryError::Suspended),
        },
    }
}

impl Standing {
    /// Returns the largest frame, in bytes after the length prefix, that a
    /// server takes from an endpoint of this standing:
    /// [`SERVER_ACTIVE_RECEIVE_LIMIT`] when active and
    /// [`SERVER_OTHER_RECEIVE_LIMIT`] otherwise.
    #[must_use]
    pub fn receive_limit(&self) -> u32 {
        match self {
            Self::Active => SERVER_ACTIVE_RECEIVE_LIMIT,
            _ => SERVER_OTHER_RECEIVE_LIMIT,
        }
    }

    /// Returns the reason a control server is to send in a
    /// `suspend_notice`, or `None` when it sends none: on control, only a
    /// suspended endpoint is told.
    ///
    /// When to send it, and encoding it, are the caller's.
    #[must_use]
    pub fn suspend_notice(&self, port: ConnectionKind) -> Option<&SuspendReason> {
        match (self, port) {
            (Self::Suspended { reason }, ConnectionKind::Control) => Some(reason),
            _ => None,
        }
    }
}

#[cfg(feature = "telemetry")]
impl Admission {
    /// Returns the connection helper's standing verdict for this
    /// admission, to return from a
    /// [`crate::connection::StandingCheck`].
    ///
    /// [`Admission::ErrorThenClose`] becomes the frame of the telemetry
    /// `error { error }` without `stream`, sent before closing. Should that
    /// frame fail to encode, which no error this module produces does, the
    /// verdict is to close without it.
    #[must_use]
    pub fn to_standing_verdict(&self) -> crate::connection::StandingVerdict {
        use crate::connection::{Frame, StandingVerdict};
        use crate::telemetry::ErrorMessage;

        match self {
            Self::Accept => StandingVerdict::Accept,
            Self::Unsupported => StandingVerdict::Unsupported,
            Self::Close => StandingVerdict::Close,
            Self::ErrorThenClose(error) => Frame::from_message(&ErrorMessage {
                stream: None,
                error: error.clone(),
            })
            .map_or(StandingVerdict::Close, StandingVerdict::SendThenClose),
        }
    }
}
