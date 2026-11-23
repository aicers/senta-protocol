//! The messages of the control channel, and their envelopes.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{DocumentTarget, EnrollOutcome, Hardware, KeyStorage, KeysetPosition, StatusReport};
use crate::connection::{Body, DecodeError, EncodeError, Frame, Message, cbor};
use crate::host::OsInfo;
use crate::results::{CommandResultKind, DocumentResult};
use crate::standing::SuspendReason;

/// The largest diagnostic bundle a [`CommandResult`] carries: 1 MiB.
pub const BUNDLE_LIMIT: usize = 1024 * 1024;

/// The `t` of every control message, the names a caller hands the
/// connection helper as the kinds it handles
/// ([`ServerConfig::with_known_kinds`](crate::connection::ServerConfig::with_known_kinds),
/// [`EndpointConfig::with_known_kinds`](crate::connection::EndpointConfig::with_known_kinds)).
pub const MESSAGE_KINDS: [&str; 10] = [
    EnrollRequest::T,
    EnrollResultPoll::T,
    Unenroll::T,
    EnrollResult::T,
    StatusReport::T,
    Documents::T,
    DocumentAck::T,
    Command::T,
    CommandResult::T,
    SuspendNotice::T,
];

/// An endpoint's request to enroll, to REview.
///
/// Each new enrollment attempt takes a new `attempt_id`, and every
/// [`EnrollResultPoll`] asking for that attempt's result carries the same
/// `attempt_id`. Drawing the value and repeating the poll are the caller's;
/// this type only carries it.
///
/// It has no equality, since [`EnrollToken`] has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// The id of this enrollment attempt, new for each attempt.
    #[serde(with = "cbor::uuid")]
    pub attempt_id: Uuid,
    /// The key set the endpoint trusts.
    pub trusted_keyset: KeysetPosition,
    /// The recovery key version the endpoint trusts.
    pub trusted_recovery_key_version: u64,
    /// The `senta-enroll` JWS from the install configuration, as it is.
    pub enroll_token: EnrollToken,
    /// The endpoint's hardware identity.
    pub hardware: Hardware,
    /// The host name.
    pub hostname: String,
    /// The operating system.
    pub os: OsInfo,
    /// The version of senta.
    pub senta_version: String,
    /// Where the endpoint keeps its private key.
    pub key_storage: KeyStorage,
    /// Whether the endpoint runs in VDI mode.
    pub vdi_mode: bool,
}

/// An endpoint's question for the result of an enrollment attempt, to
/// REview.
///
/// `attempt_id` is the one of the [`EnrollRequest`] whose result is asked
/// for, unchanged; a new attempt takes a new one. Drawing the value and
/// repeating the poll are the caller's; this type only carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnrollResultPoll {
    /// The `attempt_id` of the enrollment request asked about.
    #[serde(with = "cbor::uuid")]
    pub attempt_id: Uuid,
}

/// An enrollment token: the `senta-enroll` JWS from the install
/// configuration, carried as text exactly as it was given.
///
/// It is a bearer credential for enrolling, so its `Debug` prints
/// `<redacted>`, and it has no equality, so that no comparison of it can
/// be timed. Nothing here checks that it is a compact JWS; the verifying
/// side does.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnrollToken(String);

impl EnrollToken {
    /// Wraps the token as it was given.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Returns the token's text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnrollToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollToken(<redacted>)")
    }
}

/// An uninstall token, carried as text.
///
/// Its `Debug` prints `<redacted>`, and it has no equality, so that no
/// comparison of it can be timed: whoever checks it compares its hash in
/// constant time.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UninstallToken(String);

impl UninstallToken {
    /// Wraps the token as it was entered.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Returns the token's text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UninstallToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UninstallToken(<redacted>)")
    }
}

/// An endpoint's notice that it is being uninstalled, to REview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unenroll {
    /// The uninstall token.
    pub uninstall_token: UninstallToken,
}

/// REview's answer to an enrollment request or poll, to the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResult {
    /// The outcome.
    pub outcome: EnrollOutcome,
}

impl EnrollResult {
    /// Returns the `senta-enroll-result` JWS and the catch-up chain, in the
    /// order received, of an approval, or `None` for any other outcome.
    ///
    /// The key set state machine takes the chain and checks the result
    /// from these strings; nothing here verifies them.
    #[must_use]
    pub fn approved(&self) -> Option<(&str, &[String])> {
        match &self.outcome {
            EnrollOutcome::Approved {
                enroll_result,
                chain,
            } => Some((enroll_result, chain)),
            _ => None,
        }
    }
}

/// Signed documents for the endpoint, from REview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Documents {
    /// The JWS of each document, in the order sent: the order is part of
    /// the contract (key sets go in version order) and is kept.
    pub documents: Vec<String>,
}

/// The endpoint's acknowledgement of one received document, to REview.
///
/// Its fields are the document identity the document version state
/// machine gives with each result: `typ` the header's `typ`; `target` the
/// target's kind and value, so a group target and an endpoint target of a
/// `senta-update` stay apart, and none for `senta-addresses`;
/// `recovery_epoch` for `senta-keyset` alone; and `version` the version of
/// that `typ` (`version`, `keyset_version` or `recovery_key_version`).
/// The two features share no types; the caller copies the values across.
///
/// An acknowledgement is sent for each item for which the state machine
/// gave a [`DocumentResult`], and not for an item it did not process. It
/// carries only the identity fields the state machine gave, leaving any
/// missing one empty; nothing parses the document again to fill it in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentAck {
    /// The document's `typ`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// What the document is addressed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DocumentTarget>,
    /// The recovery epoch, for a `senta-keyset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_epoch: Option<u64>,
    /// The document's version within its `typ`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// The outcome of receiving the document.
    pub result: DocumentResult,
}

/// A signed command for the endpoint, from REview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// The `senta-command` JWS, as received.
    pub command: String,
}

/// A diagnostic bundle of at most [`BUNDLE_LIMIT`] bytes.
///
/// It is made only through `TryFrom<Vec<u8>>`, which refuses a longer one,
/// so no bundle past the limit exists to encode, and decoding refuses one
/// too.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bundle(Vec<u8>);

impl Bundle {
    /// Returns the bundle's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the bundle's bytes, consuming it.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Bundle {
    type Error = BundleTooLarge;

    fn try_from(bytes: Vec<u8>) -> Result<Self, BundleTooLarge> {
        if bytes.len() > BUNDLE_LIMIT {
            return Err(BundleTooLarge { len: bytes.len() });
        }
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for Bundle {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bundle({} bytes)", self.0.len())
    }
}

/// A diagnostic bundle longer than [`BUNDLE_LIMIT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleTooLarge {
    len: usize,
}

impl BundleTooLarge {
    /// Returns the length, in bytes, of the bundle refused.
    #[must_use]
    pub fn size(&self) -> usize {
        self.len
    }
}

impl fmt::Display for BundleTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a diagnostic bundle of {} bytes exceeds the limit of {BUNDLE_LIMIT}",
            self.len
        )
    }
}

impl std::error::Error for BundleTooLarge {}

/// The endpoint's result of a command, to REview.
///
/// Only a result for which the command state machine gave a verified
/// `command_id` is answered with a `CommandResult`: a command accepted and
/// run, and a command rejected after verification, for its recovery epoch,
/// its target, its sequence or its expiry, as
/// [`CommandResultKind::Rejected`]. A command whose verification failed has
/// no `command_id`, whatever the reason (the signature, an unknown or
/// revoked kid, the key class, the compact form or the header, the
/// schema), and gets no `CommandResult`: the next status report carries
/// [`Problem::SignatureRejected`](super::Problem::SignatureRejected)
/// instead, with `typ` `senta-command`, `kid` the diagnostic kid the
/// command state machine gave with the rejection (empty when it gave none)
/// and `result` the [`DocumentResult`] inside that rejection. Nothing here
/// parses the JWS again to fill in a missing field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    /// The verified id of the command.
    #[serde(with = "cbor::uuid")]
    pub command_id: Uuid,
    /// The result.
    pub result: CommandResultKind,
    /// A diagnostic bundle, of at most [`BUNDLE_LIMIT`] bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "cbor::bytes::option"
    )]
    pub bundle: Option<Bundle>,
}

/// REview's notice that the endpoint is suspended, to the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuspendNotice {
    /// Why the endpoint is suspended.
    pub reason: SuspendReason,
}

/// Declares each control message's `t`, its variant of [`ControlMessage`],
/// and the decoding and encoding over all of them.
macro_rules! control_messages {
    ($($ty:ident => $t:literal),+ $(,)?) => {
        $(
            impl Message for $ty {
                const T: &'static str = $t;
            }

            impl From<$ty> for ControlMessage {
                fn from(message: $ty) -> Self {
                    Self::$ty(message)
                }
            }
        )+

        /// One control message, of any kind.
        #[derive(Debug, Clone)]
        #[non_exhaustive]
        pub enum ControlMessage {
            $(
                #[doc = concat!("A `", $t, "` message.")]
                $ty($ty),
            )+
        }

        impl ControlMessage {
            /// Decodes a control message from the `t` and the body `b` of
            /// a received envelope.
            ///
            /// # Errors
            ///
            /// Returns [`ControlDecodeError::UnknownKind`] when `t` is not
            /// one of [`MESSAGE_KINDS`], and [`ControlDecodeError::Body`]
            /// when the body of a known `t` does not decode.
            pub fn decode(t: &str, body: &Body) -> Result<Self, ControlDecodeError> {
                match t {
                    $(
                        $t => body
                            .decode::<$ty>()
                            .map(Self::$ty)
                            .map_err(|error| ControlDecodeError::Body { t: $t, error }),
                    )+
                    _ => Err(ControlDecodeError::UnknownKind { t: t.to_owned() }),
                }
            }

            /// Returns the message's `t`.
            #[must_use]
            pub fn t(&self) -> &'static str {
                match self {
                    $(Self::$ty(_) => $t,)+
                }
            }

            /// Encodes the message as a frame holding the envelope
            /// `[t, b]`.
            ///
            /// # Errors
            ///
            /// Returns an error when the body fails to encode, as a time
            /// outside the range of `i64` nanoseconds does, or the
            /// envelope is longer than `u32::MAX` bytes.
            pub fn to_frame(&self) -> Result<Frame, EncodeError> {
                match self {
                    $(Self::$ty(message) => Frame::from_message(message),)+
                }
            }
        }
    };
}

control_messages! {
    EnrollRequest => "enroll_request",
    EnrollResultPoll => "enroll_result_poll",
    Unenroll => "unenroll",
    EnrollResult => "enroll_result",
    StatusReport => "status_report",
    Documents => "documents",
    DocumentAck => "document_ack",
    Command => "command",
    CommandResult => "command_result",
    SuspendNotice => "suspend_notice",
}

/// Why a received envelope is not a control message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlDecodeError {
    /// The `t` is not one of [`MESSAGE_KINDS`].
    UnknownKind {
        /// The `t` received.
        t: String,
    },
    /// The body of a known message did not decode.
    Body {
        /// The message's `t`.
        t: &'static str,
        /// Why the body did not decode.
        error: DecodeError,
    },
}

impl fmt::Display for ControlDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind { t } => write!(f, "{t:?} is not a control message"),
            Self::Body { t, error } => write!(f, "body of {t:?}: {error}"),
        }
    }
}

impl std::error::Error for ControlDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnknownKind { .. } => None,
            Self::Body { error, .. } => Some(error),
        }
    }
}
