//! The control channel: the messages senta and REview exchange over a
//! control connection (ALPN `senta-control/1`), on top of the framing,
//! envelope, version negotiation and liveness of [`crate::connection`].
//!
//! The endpoint enrolls ([`EnrollRequest`], [`EnrollResultPoll`],
//! [`EnrollResult`]) and unenrolls ([`Unenroll`]), reports its state
//! ([`StatusReport`], sent when [`should_send_status_report`] says so),
//! receives signed documents ([`Documents`]) and acknowledges each
//! ([`DocumentAck`]), receives signed commands ([`Command`]) and answers
//! them ([`CommandResult`]), and is told when it is suspended
//! ([`SuspendNotice`]). [`ControlMessage`] holds any one of them:
//! [`ControlMessage::decode`] reads one from a received envelope's `t` and
//! body, and [`ControlMessage::to_frame`] encodes one. [`MESSAGE_KINDS`]
//! lists their `t`s, for the connection helper's known kinds.
//!
//! Signed documents travel as JWS strings, carried exactly as received:
//! nothing here checks their compact form, header or signature. Taking a
//! chain, processing documents and judging commands belong to the state
//! machines of `auth`, which work on those strings.
//!
//! [`machine_id_hash`] computes the hardware identifier hash that
//! [`Hardware`] carries.
//!
//! # CBOR shape
//!
//! Every body, and every struct inside one, is a map with its field names
//! as text keys, decoded by [`crate::connection::cbor::from_slice`]: a map
//! holding a key twice at any depth fails to decode, a field the receiver
//! does not know is ignored at any depth, and a missing or mistyped
//! required field fails to decode. An optional field with no value is not
//! sent, and a missing key and a null both read as no value. A UUID is a
//! byte string of 16 bytes, a point in time integer nanoseconds since the
//! Unix epoch, a byte value a byte string, a JWS a text string, and an
//! integer an unsigned integer unless its type says otherwise.
//!
//! Every enum here is a snake_case text tag decoded by the rules of
//! [`crate::results`]: a variant without content is its tag as text, and
//! one with content the one-entry map `{tag: content}`. A tag this crate
//! does not know becomes `Other(tag)`, whether it comes as text or as a
//! one-entry map whose content is discarded; a known tag without content
//! that comes as a map is its variant; a known tag that needs content but
//! comes as text, a map with no entry or more than one, a map key that is
//! not text, and any value that is neither text nor a map are errors. A
//! field the receiver does not know is ignored in a content's field map
//! too. `Other(s)` encodes as the text `s`, so it survives a round trip
//! only when `s` is not one of the enum's tags.
//!
//! ```
//! use senta_protocol::connection::Envelope;
//! use senta_protocol::control::{ControlMessage, SuspendNotice};
//! use senta_protocol::standing::SuspendReason;
//!
//! let frame = ControlMessage::from(SuspendNotice {
//!     reason: SuspendReason::Operator,
//! })
//! .to_frame()?;
//! let envelope = Envelope::parse(frame.payload())?;
//! let ControlMessage::SuspendNotice(notice) =
//!     ControlMessage::decode(envelope.t(), envelope.body())?
//! else {
//!     panic!("expected a suspend_notice");
//! };
//! assert_eq!(notice.reason, SuspendReason::Operator);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod hardware;
mod messages;
mod status;
mod tags;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

pub use self::hardware::{Hardware, InvalidMachineId, MachineId, machine_id_hash};
pub use self::messages::{
    BUNDLE_LIMIT, Bundle, BundleTooLarge, Command, CommandResult, ControlDecodeError,
    ControlMessage, DocumentAck, Documents, EnrollRequest, EnrollResult, EnrollResultPoll,
    EnrollToken, MESSAGE_KINDS, SuspendNotice, Unenroll, UninstallToken,
};
pub use self::status::{
    ClockStatus, CollectionStatus, DocumentSlot, EndpointStatus, EntryStatus, InUseDocument,
    STATUS_REPORT_INTERVAL, StatusReport, SysmonStatus, TransportStatus, should_send_status_report,
};
pub use self::tags::{
    AuditPolicyState, DocumentSlotState, DocumentTarget, EnrollOutcome, EnrollRejectReason,
    KeyStorage, PendingReason, Problem, SysmonState,
};

/// A position in the key set's history: a recovery epoch and the key set
/// version within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeysetPosition {
    /// The recovery epoch.
    pub recovery_epoch: u64,
    /// The key set version within the epoch.
    pub keyset_version: u64,
}

/// Serializes a variant with content as the one-entry map `{tag: content}`.
fn serialize_entry<S: Serializer, V: Serialize + ?Sized>(
    serializer: S,
    tag: &str,
    content: &V,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry(tag, content)?;
    map.end()
}
