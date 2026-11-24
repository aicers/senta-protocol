//! The tagged enums control messages carry.
//!
//! Each decodes by the rules of [`crate::results`], described in the
//! documentation of [`crate::control`].

use std::{convert::Infallible, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::MapAccess};
use uuid::Uuid;

use super::serialize_entry;
use crate::connection::cbor;
use crate::results::{Class, DocumentResult, Tagged, TaggedVisitor};

const BAD_TOKEN: &str = "bad_token";
const TOKEN_REVOKED: &str = "token_revoked";
const TOKEN_EXPIRED: &str = "token_expired";
const RATE_LIMITED: &str = "rate_limited";
const DENIED: &str = "denied";

const AWAITING_APPROVAL: &str = "awaiting_approval";
const LICENSE_PENDING: &str = "license_pending";

const FILE: &str = "file";
const DPAPI: &str = "dpapi";
const TPM: &str = "tpm";
const SECURE_ENCLAVE: &str = "secure_enclave";

const BUILTIN: &str = "builtin";
const STANDALONE: &str = "standalone";
const NONE: &str = "none";

const APPLIED: &str = "applied";
const GPO_MANAGED: &str = "gpo_managed";
const OFF: &str = "off";

const CURRENT: &str = "current";
const PENDING: &str = "pending";
const PENDING_OFF_TARGET: &str = "pending_off_target";
const HALTED: &str = "halted";

const GROUP: &str = "group";
const ENDPOINT: &str = "endpoint";
const CUSTOMER: &str = "customer";
const INSTALL: &str = "install";

const SIGNATURE_REJECTED: &str = "signature_rejected";
const UNKNOWN_KID: &str = "unknown_kid";
const KEYSET_GAP: &str = "keyset_gap";
const UPDATE_FAILED: &str = "update_failed";
const UPDATE_ROLLED_BACK: &str = "update_rolled_back";
const SOURCE_UNREACHABLE: &str = "source_unreachable";
const PRIOR_EPOCH_STATE: &str = "prior_epoch_state";
const SYSMON_MISSING: &str = "sysmon_missing";
const CLOCK_SKEW: &str = "clock_skew";
const INSTALL_CONFIG_INVALID: &str = "install_config_invalid";
const SYSMON_STOPPED: &str = "sysmon_stopped";
const SYSMON_CONFIG_CHANGED: &str = "sysmon_config_changed";
const UNEXPECTED_RESTART: &str = "unexpected_restart";

const APPROVED: &str = "approved";
const REJECTED: &str = "rejected";

/// Why REview rejected an enrollment request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnrollRejectReason {
    /// The enrollment token does not verify, tagged `bad_token`.
    BadToken,
    /// The enrollment token was revoked, tagged `token_revoked`.
    TokenRevoked,
    /// The enrollment token has expired, tagged `token_expired`.
    TokenExpired,
    /// Too many enrollment requests, tagged `rate_limited`.
    RateLimited,
    /// An operator denied the enrollment, tagged `denied`.
    Denied,
    /// A reason this version of the crate does not know, by its tag.
    Other(String),
}

/// Why an enrollment request is still pending.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PendingReason {
    /// The enrollment awaits an operator's approval, tagged
    /// `awaiting_approval`.
    AwaitingApproval,
    /// The enrollment awaits a license, tagged `license_pending`.
    LicensePending,
    /// A reason this version of the crate does not know, by its tag.
    Other(String),
}

/// Where the endpoint keeps its private key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyStorage {
    /// A file, tagged `file`.
    File,
    /// Protected by Windows DPAPI, tagged `dpapi`.
    Dpapi,
    /// In a TPM, tagged `tpm`.
    Tpm,
    /// In the Apple Secure Enclave, tagged `secure_enclave`.
    SecureEnclave,
    /// A storage this version of the crate does not know, by its tag.
    Other(String),
}

/// The state of Sysmon on the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SysmonState {
    /// The Sysmon built into the operating system, tagged `builtin`.
    Builtin,
    /// A separately installed Sysmon, tagged `standalone`.
    Standalone,
    /// No Sysmon, tagged `none`.
    Absent,
    /// A state this version of the crate does not know, by its tag.
    Other(String),
}

/// The state of the audit policy the endpoint needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditPolicyState {
    /// The endpoint applied the audit policy, tagged `applied`.
    Applied,
    /// Group Policy manages the audit policy, tagged `gpo_managed`.
    GpoManaged,
    /// The audit policy is off, tagged `off`.
    Off,
    /// A state this version of the crate does not know, by its tag.
    Other(String),
}

/// The state of one document slot in a status report: whether a verified
/// document is waiting to be applied, and why.
///
/// How the document version state machine's outcomes map onto it:
///
/// - With no document waiting, the slot is [`Current`](Self::Current).
/// - A waiting document that is still being tried is
///   [`Pending`](Self::Pending), including after a first or second failed
///   attempt to apply it.
/// - A waiting document held back because it does not match the current
///   target is [`PendingOffTarget`](Self::PendingOffTarget), whatever its
///   history of failures.
/// - When the third attempt to apply a document fails, the slot halts:
///   [`Halted`](Self::Halted), with the `reason` of that failure's
///   [`DocumentResult::ApplyFailed`] as it is. The slot's
///   `verified_version` is then the halted version, and its
///   `applied_version` the last version of the current recovery epoch
///   applied successfully, or none (see
///   [`DocumentSlot`](super::DocumentSlot)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocumentSlotState {
    /// No document is waiting, tagged `current`.
    Current,
    /// A document is waiting to be applied, tagged `pending`.
    Pending,
    /// A document is waiting but is not addressed to the current target,
    /// tagged `pending_off_target`.
    PendingOffTarget,
    /// Applying the waiting document failed a third time and the slot
    /// stopped trying, tagged `halted`: `{"halted": {"reason": ...}}`.
    Halted {
        /// The reason of the third failure, as
        /// [`DocumentResult::ApplyFailed`] gave it.
        reason: String,
    },
    /// A state this version of the crate does not know, by its tag.
    Other(String),
}

/// What a signed document is addressed to.
///
/// A variant's value is carried as it is, not in a field map:
/// `{"group": <UUID>}`, `{"install": "<install id>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocumentTarget {
    /// A group, by its id, tagged `group`.
    Group(Uuid),
    /// One endpoint, by its id, tagged `endpoint`.
    Endpoint(Uuid),
    /// A customer, by its `customer_endpoint_id`, tagged `customer`.
    Customer(Uuid),
    /// An install, by its install id, tagged `install`.
    Install(String),
    /// A target this version of the crate does not know, by its tag.
    Other(String),
}

/// A problem the endpoint reports in its status report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// A signed document was rejected before any of its identity could be
    /// trusted, tagged `signature_rejected`.
    ///
    /// Among others, this is how a command whose verification failed is
    /// reported. The command state machine answers with a
    /// [`CommandResult`](super::CommandResult) only when it has a verified
    /// `command_id`. When verification itself fails, whatever the reason
    /// (the signature, an unknown or revoked kid, the key class, the
    /// compact form or the header, the schema), no `command_id` exists and
    /// no `CommandResult` is sent; instead the next status report carries
    /// this problem with `typ` set to `senta-command`, `kid` the
    /// diagnostic kid the state machine gave with the rejection (present
    /// only when the header could be read), and `result` the
    /// [`DocumentResult`] inside its rejection. The control channel never
    /// parses the JWS again to fill in a missing field.
    SignatureRejected {
        /// The `typ` of the rejected document, when known.
        typ: Option<String>,
        /// The kid of the rejected document, when its header could be
        /// read. For diagnosis only.
        kid: Option<String>,
        /// Why the document was rejected.
        result: DocumentResult,
    },
    /// A document was signed by a key the endpoint does not know, tagged
    /// `unknown_kid`.
    UnknownKid {
        /// The unknown kid.
        kid: String,
    },
    /// A key set arrived that skips past the next version after the one
    /// the endpoint has, tagged `keyset_gap`.
    KeysetGap,
    /// An update failed, tagged `update_failed`.
    UpdateFailed,
    /// An update was rolled back, tagged `update_rolled_back`.
    UpdateRolledBack,
    /// A destination the endpoint sends to could not be reached, tagged
    /// `source_unreachable`.
    SourceUnreachable,
    /// The endpoint still runs on state applied in a prior recovery epoch,
    /// tagged `prior_epoch_state`.
    PriorEpochState,
    /// Sysmon (on Linux, Sysmon for Linux) is not installed, tagged
    /// `sysmon_missing`.
    ///
    /// Sysmon that is installed but not running is
    /// [`SysmonStopped`](Self::SysmonStopped) instead.
    SysmonMissing,
    /// The endpoint's clock is too far from the server's, tagged
    /// `clock_skew`.
    ClockSkew,
    /// The install configuration is invalid, tagged
    /// `install_config_invalid`.
    InstallConfigInvalid,
    /// Sysmon (on Linux, Sysmon for Linux) is installed but its service or
    /// driver is not running, tagged `sysmon_stopped`.
    ///
    /// This differs from [`SysmonMissing`](Self::SysmonMissing), where
    /// Sysmon is not installed at all.
    SysmonStopped,
    /// The Sysmon configuration in effect differs from the one the endpoint
    /// applied from a signed policy, tagged `sysmon_config_changed`.
    ///
    /// It means the configuration was changed outside the endpoint. It is
    /// carried only when the endpoint has applied a configuration of its
    /// own: not when there is none, as when the customer chose to keep
    /// their existing Sysmon as it is, and not while the endpoint has not
    /// yet finished applying one. Once the two match again, whether the
    /// endpoint applied its configuration again or the change was
    /// reverted, the next status report no longer carries it.
    SysmonConfigChanged,
    /// The endpoint's previous run ended without a clean shutdown, tagged
    /// `unexpected_restart`.
    ///
    /// Such a run ended in a forced termination of the process, a crash, or
    /// an operating system crash or power loss. It is carried once, in the
    /// first status report after the endpoint starts again. A clean
    /// operating system shutdown or reboot, a restart for an update, and
    /// the first run after installation do not carry it. It is a signal,
    /// not evidence of tampering.
    UnexpectedRestart,
    /// A problem this version of the crate does not know, by its tag.
    Other(String),
}

/// The outcome of an enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnrollOutcome {
    /// The enrollment was approved, tagged `approved`.
    Approved {
        /// The `senta-enroll-result` JWS, as received.
        enroll_result: String,
        /// The catch-up chain: `senta-keyset` and `senta-recovery-key` JWS
        /// mixed in one ordered list, kept in the order received. It may be
        /// empty.
        chain: Vec<String>,
    },
    /// The enrollment is pending, tagged `pending`.
    Pending {
        /// Why it is pending.
        reason: PendingReason,
    },
    /// The enrollment was rejected, tagged `rejected`.
    Rejected {
        /// Why it was rejected.
        reason: EnrollRejectReason,
    },
    /// An outcome this version of the crate does not know, by its tag.
    Other(String),
}

/// Implements the CBOR shape of an enum whose variants, `Other` aside,
/// carry no content.
macro_rules! unit_tags {
    ($ty:ident, $expecting:literal, { $($variant:ident => $tag:ident),+ $(,)? }) => {
        impl $ty {
            fn tag(&self) -> &str {
                match self {
                    $(Self::$variant => $tag,)+
                    Self::Other(tag) => tag,
                }
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.tag())
            }
        }

        impl Tagged for $ty {
            type Content = Infallible;

            const EXPECTING: &'static str = $expecting;

            fn classify(tag: &str) -> Class<Self> {
                Class::Unit(match tag {
                    $($tag => Self::$variant,)+
                    _ => return Class::Unknown,
                })
            }

            fn read_content<'de, A: MapAccess<'de>>(
                content: Infallible,
                _map: &mut A,
            ) -> Result<Self, A::Error> {
                match content {}
            }

            fn other(tag: String) -> Self {
                Self::Other(tag)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_any(TaggedVisitor(PhantomData))
            }
        }
    };
}

unit_tags!(EnrollRejectReason, "an enrollment rejection reason tag, or a one-entry map from a tag", {
    BadToken => BAD_TOKEN,
    TokenRevoked => TOKEN_REVOKED,
    TokenExpired => TOKEN_EXPIRED,
    RateLimited => RATE_LIMITED,
    Denied => DENIED,
});

unit_tags!(PendingReason, "an enrollment pending reason tag, or a one-entry map from a tag", {
    AwaitingApproval => AWAITING_APPROVAL,
    LicensePending => LICENSE_PENDING,
});

unit_tags!(KeyStorage, "a key storage tag, or a one-entry map from a tag", {
    File => FILE,
    Dpapi => DPAPI,
    Tpm => TPM,
    SecureEnclave => SECURE_ENCLAVE,
});

unit_tags!(SysmonState, "a Sysmon state tag, or a one-entry map from a tag", {
    Builtin => BUILTIN,
    Standalone => STANDALONE,
    Absent => NONE,
});

unit_tags!(AuditPolicyState, "an audit policy state tag, or a one-entry map from a tag", {
    Applied => APPLIED,
    GpoManaged => GPO_MANAGED,
    Off => OFF,
});

/// The field map `{"reason": ...}`, borrowed to encode and owned to decode.
#[derive(Serialize, Deserialize)]
struct ReasonFields<R> {
    reason: R,
}

/// A UUID carried as a variant's value itself.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct UuidValue(#[serde(with = "cbor::uuid")] Uuid);

// --- DocumentSlotState ---------------------------------------------------

impl Serialize for DocumentSlotState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Current => CURRENT,
            Self::Pending => PENDING,
            Self::PendingOffTarget => PENDING_OFF_TARGET,
            Self::Halted { reason } => {
                return serialize_entry(
                    serializer,
                    HALTED,
                    &ReasonFields {
                        reason: reason.as_str(),
                    },
                );
            }
            Self::Other(tag) => tag,
        };
        serializer.serialize_str(tag)
    }
}

/// The variants of [`DocumentSlotState`] with content.
pub(crate) enum SlotContent {
    Halted,
}

impl Tagged for DocumentSlotState {
    type Content = SlotContent;

    const EXPECTING: &'static str = "a document slot state tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            CURRENT => Self::Current,
            PENDING => Self::Pending,
            PENDING_OFF_TARGET => Self::PendingOffTarget,
            HALTED => return Class::Content(SlotContent::Halted),
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: SlotContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        match content {
            SlotContent::Halted => {
                let ReasonFields { reason } = map.next_value::<ReasonFields<String>>()?;
                Ok(Self::Halted { reason })
            }
        }
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl<'de> Deserialize<'de> for DocumentSlotState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

// --- DocumentTarget ------------------------------------------------------

impl Serialize for DocumentTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Group(id) => serialize_entry(serializer, GROUP, &UuidValue(*id)),
            Self::Endpoint(id) => serialize_entry(serializer, ENDPOINT, &UuidValue(*id)),
            Self::Customer(id) => serialize_entry(serializer, CUSTOMER, &UuidValue(*id)),
            Self::Install(id) => serialize_entry(serializer, INSTALL, id.as_str()),
            Self::Other(tag) => serializer.serialize_str(tag),
        }
    }
}

/// The variants of [`DocumentTarget`], all of which have content.
pub(crate) enum TargetContent {
    Group,
    Endpoint,
    Customer,
    Install,
}

impl Tagged for DocumentTarget {
    type Content = TargetContent;

    const EXPECTING: &'static str = "a one-entry map from a document target tag to its value";

    fn classify(tag: &str) -> Class<Self> {
        Class::Content(match tag {
            GROUP => TargetContent::Group,
            ENDPOINT => TargetContent::Endpoint,
            CUSTOMER => TargetContent::Customer,
            INSTALL => TargetContent::Install,
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: TargetContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        Ok(match content {
            TargetContent::Group => Self::Group(map.next_value::<UuidValue>()?.0),
            TargetContent::Endpoint => Self::Endpoint(map.next_value::<UuidValue>()?.0),
            TargetContent::Customer => Self::Customer(map.next_value::<UuidValue>()?.0),
            TargetContent::Install => Self::Install(map.next_value()?),
        })
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl<'de> Deserialize<'de> for DocumentTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

// --- Problem -------------------------------------------------------------

/// The field map of [`Problem::SignatureRejected`], to encode.
#[derive(Serialize)]
struct SignatureRejectedOut<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    result: &'a DocumentResult,
}

/// The field map of [`Problem::SignatureRejected`], as decoded.
#[derive(Deserialize)]
struct SignatureRejectedIn {
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    result: DocumentResult,
}

/// The field map `{"kid": ...}`, borrowed to encode and owned to decode.
#[derive(Serialize, Deserialize)]
struct KidFields<K> {
    kid: K,
}

impl Serialize for Problem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::SignatureRejected { typ, kid, result } => {
                return serialize_entry(
                    serializer,
                    SIGNATURE_REJECTED,
                    &SignatureRejectedOut {
                        typ: typ.as_deref(),
                        kid: kid.as_deref(),
                        result,
                    },
                );
            }
            Self::UnknownKid { kid } => {
                return serialize_entry(serializer, UNKNOWN_KID, &KidFields { kid: kid.as_str() });
            }
            Self::KeysetGap => KEYSET_GAP,
            Self::UpdateFailed => UPDATE_FAILED,
            Self::UpdateRolledBack => UPDATE_ROLLED_BACK,
            Self::SourceUnreachable => SOURCE_UNREACHABLE,
            Self::PriorEpochState => PRIOR_EPOCH_STATE,
            Self::SysmonMissing => SYSMON_MISSING,
            Self::ClockSkew => CLOCK_SKEW,
            Self::InstallConfigInvalid => INSTALL_CONFIG_INVALID,
            Self::SysmonStopped => SYSMON_STOPPED,
            Self::SysmonConfigChanged => SYSMON_CONFIG_CHANGED,
            Self::UnexpectedRestart => UNEXPECTED_RESTART,
            Self::Other(tag) => tag,
        };
        serializer.serialize_str(tag)
    }
}

/// The variants of [`Problem`] with content.
pub(crate) enum ProblemContent {
    SignatureRejected,
    UnknownKid,
}

impl Tagged for Problem {
    type Content = ProblemContent;

    const EXPECTING: &'static str = "a problem tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            SIGNATURE_REJECTED => return Class::Content(ProblemContent::SignatureRejected),
            UNKNOWN_KID => return Class::Content(ProblemContent::UnknownKid),
            KEYSET_GAP => Self::KeysetGap,
            UPDATE_FAILED => Self::UpdateFailed,
            UPDATE_ROLLED_BACK => Self::UpdateRolledBack,
            SOURCE_UNREACHABLE => Self::SourceUnreachable,
            PRIOR_EPOCH_STATE => Self::PriorEpochState,
            SYSMON_MISSING => Self::SysmonMissing,
            CLOCK_SKEW => Self::ClockSkew,
            INSTALL_CONFIG_INVALID => Self::InstallConfigInvalid,
            SYSMON_STOPPED => Self::SysmonStopped,
            SYSMON_CONFIG_CHANGED => Self::SysmonConfigChanged,
            UNEXPECTED_RESTART => Self::UnexpectedRestart,
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: ProblemContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        Ok(match content {
            ProblemContent::SignatureRejected => {
                let SignatureRejectedIn { typ, kid, result } = map.next_value()?;
                Self::SignatureRejected { typ, kid, result }
            }
            ProblemContent::UnknownKid => {
                let KidFields { kid } = map.next_value::<KidFields<String>>()?;
                Self::UnknownKid { kid }
            }
        })
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl<'de> Deserialize<'de> for Problem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

// --- EnrollOutcome -------------------------------------------------------

/// The field map of [`EnrollOutcome::Approved`], to encode.
#[derive(Serialize)]
struct ApprovedOut<'a> {
    enroll_result: &'a str,
    chain: &'a [String],
}

/// The field map of [`EnrollOutcome::Approved`], as decoded.
#[derive(Deserialize)]
struct ApprovedIn {
    enroll_result: String,
    chain: Vec<String>,
}

impl Serialize for EnrollOutcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Approved {
                enroll_result,
                chain,
            } => serialize_entry(
                serializer,
                APPROVED,
                &ApprovedOut {
                    enroll_result,
                    chain,
                },
            ),
            Self::Pending { reason } => {
                serialize_entry(serializer, PENDING, &ReasonFields { reason })
            }
            Self::Rejected { reason } => {
                serialize_entry(serializer, REJECTED, &ReasonFields { reason })
            }
            Self::Other(tag) => serializer.serialize_str(tag),
        }
    }
}

/// The variants of [`EnrollOutcome`], all of which have content.
pub(crate) enum OutcomeContent {
    Approved,
    Pending,
    Rejected,
}

impl Tagged for EnrollOutcome {
    type Content = OutcomeContent;

    const EXPECTING: &'static str = "a one-entry map from an enrollment outcome tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Content(match tag {
            APPROVED => OutcomeContent::Approved,
            PENDING => OutcomeContent::Pending,
            REJECTED => OutcomeContent::Rejected,
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: OutcomeContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        Ok(match content {
            OutcomeContent::Approved => {
                let ApprovedIn {
                    enroll_result,
                    chain,
                } = map.next_value()?;
                Self::Approved {
                    enroll_result,
                    chain,
                }
            }
            OutcomeContent::Pending => {
                let ReasonFields { reason } = map.next_value::<ReasonFields<PendingReason>>()?;
                Self::Pending { reason }
            }
            OutcomeContent::Rejected => {
                let ReasonFields { reason } =
                    map.next_value::<ReasonFields<EnrollRejectReason>>()?;
                Self::Rejected { reason }
            }
        })
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl<'de> Deserialize<'de> for EnrollOutcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}
