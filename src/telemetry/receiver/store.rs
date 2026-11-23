//! The persistent state of the telemetry entry's stream state machine, the
//! changes it writes, and the store it writes them to.

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use crate::telemetry::{LastStored, SeqRange};
use crate::telemetry_codes::DropReason;

/// A stream of one endpoint, as the entry keys its state.
///
/// The endpoint is always the connection's endpoint id, never the
/// `endpoint_id` of a record's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiverFlowKey {
    /// The endpoint id of the connection the stream arrived on.
    pub endpoint_id: Uuid,
    /// The stream's id.
    pub stream: Uuid,
}

/// The persistent state of one stream at one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiverFlowState {
    /// The highest sequence number acknowledged, `A`: every sequence number
    /// up to it was stored or covered by a dropped range.
    pub a: u64,
    /// The last record actually stored, `(L, H)`, or `None` when the entry
    /// has stored no record of the stream, even if dropped ranges moved
    /// `A` on.
    pub last_stored: Option<LastStored>,
    /// When the stream was closed, or `None` while it is the endpoint's
    /// open stream.
    pub closed_at: Option<Timestamp>,
}

impl ReceiverFlowState {
    /// Returns the state of a stream just opened: `A = 0`, nothing stored,
    /// open.
    #[must_use]
    pub fn opened() -> Self {
        Self {
            a: 0,
            last_stored: None,
            closed_at: None,
        }
    }

    /// Returns whether the stream is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }
}

/// The whole persistent stream state of one entry, as a store gives it
/// back.
///
/// The state machine keeps at most one open stream per endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiverEntryState {
    /// Every stream the entry remembers, open or closed, by endpoint and
    /// stream.
    pub flows: BTreeMap<ReceiverFlowKey, ReceiverFlowState>,
}

impl ReceiverEntryState {
    /// Returns the open stream of `endpoint_id`, if it has one.
    #[must_use]
    pub fn open_flow(&self, endpoint_id: Uuid) -> Option<Uuid> {
        self.endpoint_flows(endpoint_id)
            .find(|(_, state)| state.is_open())
            .map(|(key, _)| key.stream)
    }

    /// Returns the streams `endpoint_id` has at the entry.
    pub(super) fn endpoint_flows(
        &self,
        endpoint_id: Uuid,
    ) -> impl Iterator<Item = (&ReceiverFlowKey, &ReceiverFlowState)> {
        let first = ReceiverFlowKey {
            endpoint_id,
            stream: Uuid::nil(),
        };
        let last = ReceiverFlowKey {
            endpoint_id,
            stream: Uuid::max(),
        };
        self.flows.range(first..=last)
    }

    /// Applies one written change; a record or a loss record changes
    /// nothing here, since the state does not hold them.
    pub(super) fn apply(&mut self, change: &ReceiverChange) {
        match change {
            ReceiverChange::SetFlow { key, state } => {
                self.flows.insert(*key, *state);
            }
            ReceiverChange::RemoveFlow(key) => {
                self.flows.remove(key);
            }
            ReceiverChange::AppendRecord(_) | ReceiverChange::AppendLoss(_) => {}
        }
    }
}

/// A record the entry stores.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverRecord {
    /// The source's identity: the endpoint id of the connection the record
    /// arrived on, never the `endpoint_id` of the record's header.
    pub endpoint_id: Uuid,
    /// The stream's id.
    pub stream: Uuid,
    /// The record's sequence number.
    pub seq: u64,
    /// The record's bytes exactly as received, never re-encoded.
    pub bytes: Vec<u8>,
}

/// Why a range of records was lost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverLossReason {
    /// The endpoint dropped the range and said why in a `dropped_range`.
    Dropped(DropReason),
    /// The endpoint lost the range when its state was reset, as a
    /// `lost_on_reset` reported.
    LostOnReset,
}

/// A loss record the entry keeps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverLoss {
    /// The source's identity: the endpoint id of the connection the report
    /// arrived on.
    pub endpoint_id: Uuid,
    /// The stream the records were lost from.
    pub stream: Uuid,
    /// The sequence numbers lost, `from` at most `to`.
    pub range: SeqRange,
    /// Why they were lost.
    pub reason: ReceiverLossReason,
}

/// One change of a [`ReceiverStore::write`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceiverChange {
    /// Sets a stream's state, replacing any the entry had.
    SetFlow {
        /// The stream.
        key: ReceiverFlowKey,
        /// Its new state.
        state: ReceiverFlowState,
    },
    /// Forgets a stream's state. Its records and loss records stay.
    RemoveFlow(ReceiverFlowKey),
    /// Adds a record, beside any the store already holds.
    AppendRecord(ReceiverRecord),
    /// Adds a loss record, beside any the store already holds.
    AppendLoss(ReceiverLoss),
}

/// The persistent store a telemetry entry's [`super::ReceiverStream`]
/// writes to, implemented by the caller.
///
/// # Keys
///
/// Every call names the entry it is for, `entry_id`, and every key in it —
/// a stream's state, a record, a loss record — belongs to that entry. Two
/// entries may share one store: the store keeps their streams, records and
/// loss records apart, so the same endpoint id and stream id at two entries
/// are two streams.
///
/// The endpoint id of every key is the source's identity: the endpoint id
/// of the connection, never the `endpoint_id` a record's header carries.
///
/// # Atomicity and durability
///
/// Each [`write`](Self::write) is one batch, written atomically:
///
/// - **Success** means the whole batch is durable — in a production store,
///   read back after a process restart; in a replicated store, replicated
///   as the store requires. The state machine acknowledges records, and
///   answers that depend on a change, only after the write succeeded.
/// - **An error** means none of the batch took effect.
///
/// # Appending
///
/// Records and loss records are only ever added. A record whose entry,
/// endpoint, stream id and sequence number are those of a record already
/// held — as happens when a stream whose closed state was pruned is opened
/// again under the same id — neither replaces that record nor is dropped:
/// a successful write means the new record is durable beside the old one.
/// Removing a stream's state ([`ReceiverChange::RemoveFlow`]) leaves its
/// records and loss records where they are. How the store keys them inside
/// is its own choice.
///
/// # Loss records
///
/// The state machine writes a [`ReceiverLossReason::LostOnReset`] loss
/// record for an `(entry, endpoint, stream, from, to)` only when
/// [`has_lost_on_reset`](Self::has_lost_on_reset) says none is held, so a
/// `lost_on_reset` received again — after a restart, or after the stream's
/// state was pruned — adds no second one. A
/// [`ReceiverLossReason::Dropped`] loss record of the same coordinates does
/// not count, and does not stop one from being written; nor does a
/// `LostOnReset` one stop a dropped range from being recorded.
pub trait ReceiverStore {
    /// The error a read or write gives.
    type Error;

    /// Reads back every stream state `entry_id` has; an entry that never
    /// wrote one has none.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the state cannot be read.
    fn load(&self, entry_id: Uuid) -> Result<ReceiverEntryState, Self::Error>;

    /// Returns whether `entry_id` holds a [`ReceiverLossReason::LostOnReset`]
    /// loss record of `range` in `stream` of `endpoint_id`.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the loss records cannot be read.
    fn has_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        range: SeqRange,
    ) -> Result<bool, Self::Error>;

    /// Writes `changes` for `entry_id`, in order, as one atomic batch.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written; then none
    /// of it took effect.
    fn write(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<(), Self::Error>;
}

impl<S: ReceiverStore + ?Sized> ReceiverStore for &mut S {
    type Error = S::Error;

    fn load(&self, entry_id: Uuid) -> Result<ReceiverEntryState, Self::Error> {
        (**self).load(entry_id)
    }

    fn has_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        range: SeqRange,
    ) -> Result<bool, Self::Error> {
        (**self).has_lost_on_reset(entry_id, endpoint_id, stream, range)
    }

    fn write(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<(), Self::Error> {
        (**self).write(entry_id, changes)
    }
}
