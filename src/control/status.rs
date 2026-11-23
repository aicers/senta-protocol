//! The status report, and when to send it.

use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AuditPolicyState, DocumentSlotState, DocumentTarget, Hardware, KeyStorage, KeysetPosition,
    Problem, SysmonState,
};
use crate::connection::{ClockOffset, cbor};
use crate::host::{CollectionMode, OsInfo};

/// How long a status report whose content has not changed waits before it
/// is sent again: five minutes of the monotonic clock.
pub const STATUS_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The endpoint's periodic report of its state, to REview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// The endpoint software and its trust state.
    pub endpoint: EndpointStatus,
    /// One entry per document slot.
    pub documents: Vec<DocumentSlot>,
    /// What the endpoint collects.
    pub collection: CollectionStatus,
    /// How sending telemetry is going.
    pub transport: TransportStatus,
    /// The clock offset.
    pub clock: ClockStatus,
    /// The hardware identity.
    pub hardware: Hardware,
    /// The problems the endpoint reports.
    pub problems: Vec<Problem>,
}

/// The endpoint software and its trust state, in a [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointStatus {
    /// The version of senta.
    pub senta_version: String,
    /// The operating system.
    pub os: OsInfo,
    /// Where the endpoint keeps its private key.
    pub key_storage: KeyStorage,
    /// The key set the endpoint has.
    pub keyset: KeysetPosition,
    /// The recovery key version the endpoint has.
    pub recovery_key_version: u64,
}

/// The state of one document slot, in a [`StatusReport`].
///
/// `verified_version` and `applied_version` hold versions of the current
/// recovery epoch only: when the epoch changes, both become empty and start
/// again. A document applied in a prior epoch and still in use is reported
/// by `in_use`, its epoch and version, with `untrusted` true.
///
/// When the third attempt to apply a document fails, `state` is
/// [`DocumentSlotState::Halted`] with that failure's reason,
/// `verified_version` the halted version and `applied_version` the last
/// version of the current epoch applied successfully, or empty. So a slot
/// whose first document of a new epoch, right after recovery, fails three
/// times is `Halted`, with `verified_version` that version, no
/// `applied_version`, `in_use` the prior epoch and version, and
/// `untrusted` true. A waiting document still being tried after an earlier
/// failure is [`DocumentSlotState::Pending`], and one held back because it
/// does not match the current target is
/// [`DocumentSlotState::PendingOffTarget`], whatever its failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentSlot {
    /// The documents' `typ`.
    pub typ: String,
    /// What the slot's documents are addressed to; none for
    /// `senta-addresses`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DocumentTarget>,
    /// The latest version of the current epoch verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_version: Option<u64>,
    /// The latest version of the current epoch applied successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_version: Option<u64>,
    /// Whether a document is waiting, and why.
    pub state: DocumentSlotState,
    /// The document in use, when it was applied in a prior epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_use: Option<InUseDocument>,
    /// Whether the document in use was applied in a prior epoch, and so is
    /// not trusted.
    pub untrusted: bool,
}

/// The recovery epoch and version of the document a slot uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InUseDocument {
    /// The recovery epoch the document was applied in.
    pub recovery_epoch: u64,
    /// The document's version.
    pub version: u64,
}

/// What the endpoint collects, in a [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CollectionStatus {
    /// The collection mode.
    pub collection_mode: CollectionMode,
    /// The state of Sysmon.
    pub sysmon: SysmonStatus,
    /// The state of the audit policy.
    pub audit_policy: AuditPolicyState,
}

/// The state of Sysmon, in a [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SysmonStatus {
    /// Which Sysmon there is, if any.
    pub state: SysmonState,
    /// Its version, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// How sending telemetry is going, in a [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportStatus {
    /// One entry per telemetry entry of the event store.
    pub entries: Vec<EntryStatus>,
    /// The number of records in the local buffer.
    pub buffered_records: u64,
    /// The number of bytes in the local buffer.
    pub buffered_bytes: u64,
    /// The number of ranges of records dropped.
    pub dropped_ranges: u64,
    /// The number of records removed from the buffer because no entry
    /// accepts their kind.
    pub unsupported_dropped: u64,
}

/// One telemetry entry, in a [`TransportStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryStatus {
    /// The entry's id.
    #[serde(with = "cbor::uuid")]
    pub entry_id: Uuid,
    /// When a send to the entry last succeeded.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "cbor::timestamp::option"
    )]
    pub last_success_at: Option<Timestamp>,
}

/// The clock offset, in a [`StatusReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockStatus {
    /// The chosen measurement of the server's clock minus the endpoint's,
    /// as [`ClockOffset`] carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<ClockOffset>,
    /// Whether the chosen measurement is more than an hour off, as
    /// [`ClockMeasurement::exceeds_one_hour`](crate::connection::ClockMeasurement::exceeds_one_hour)
    /// decided it for that measurement, copied as it is. The decision is
    /// made on the offset before it was truncated to milliseconds, so it
    /// can differ at the boundary from one recomputed from `offset_ms`,
    /// and nothing here recomputes it. With no `offset`, it is false.
    pub exceeds_tolerance: bool,
}

/// Reports whether to send a status report now.
///
/// `last` is the monotonic time of the last report sent and that report,
/// or `None` if none has been sent; `now` is the monotonic time now, from
/// the same origin; and `current` is the report as it stands now. A report
/// is due when none has been sent, when [`STATUS_REPORT_INTERVAL`] or more
/// has passed since the last one (exactly the interval included), or when
/// `current` differs from the last report in any field. When `now` is
/// before the last send, no time has passed. When the caller refills the
/// report's values is the caller's choice.
#[must_use]
pub fn should_send_status_report(
    last: Option<(Duration, &StatusReport)>,
    now: Duration,
    current: &StatusReport,
) -> bool {
    let Some((sent_at, sent)) = last else {
        return true;
    };
    now.saturating_sub(sent_at) >= STATUS_REPORT_INTERVAL || sent != current
}
