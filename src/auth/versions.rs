//! The document version state machine: which version of each policy,
//! group assignment, address document and update an endpoint has verified
//! and applied, and how that changes.
//!
//! `senta-policy`, `senta-assign`, `senta-addresses` and `senta-update`
//! documents are ordered by version within a [`Slot`], a (`typ`, target)
//! pair. For each slot [`DocumentVersions`] keeps two versions apart: the
//! *verified* version, of the last document accepted, which is stored as a
//! pending document before it is applied; and the *applied* version, of
//! the last document applied, whose content is the slot's *current*
//! document. An endpoint that stops between the two resumes the
//! application when it starts again.
//!
//! Each document goes through [`DocumentVersions::receive`], which checks it
//! in a fixed order and reports the first result that applies. Documents of
//! an earlier recovery epoch, of an earlier version, or addressed to
//! another group or endpoint are rejected. When the recovery epoch moves
//! on, every slot's versions start again from nothing, so that a version a
//! leaked key raised cannot hold back the documents of the new epoch; what
//! a slot applied in an earlier epoch is still used, and marked as not
//! trusted until a document of the new epoch replaces it.
//!
//! [`receive_documents`] takes the signed documents of one `Documents`
//! message: the key set and recovery key documents first, through the key
//! set state machine, then the others.
//!
//! Everything here is sans-IO. The caller passes the time and the senta
//! version in, applies documents through a [`DocumentApplier`] it
//! implements, and keeps the state through a [`VersionStore`] it
//! implements; [`MemoryVersionStore`] and [`MemoryTrustStore`] are
//! implementations in memory.

mod identity;
mod list;
mod receive;
mod state;
#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

pub use self::identity::{DocumentIdentity, DocumentTarget};
pub use self::list::{
    DocumentEntry, DocumentsError, DocumentsOutcome, EntryOutcome, receive_documents,
};
pub use self::receive::Receipt;
use self::state::SlotState;
pub use self::state::VersionState;
use super::documents::{
    AddressesContent, AssignContent, PolicyContent, UpdateContent, UpdateTarget,
};
use super::jws::Typ;
use super::jws::strict::LowerUuid;
use super::keyset::TrustState;

/// How many failed applications of one version halt it.
const MAX_APPLY_ATTEMPTS: u32 = 3;

/// A (`typ`, target) pair, within which documents are ordered by version.
///
/// Slots order as their variants do, then by group id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    /// The `senta-assign` of the endpoint itself.
    Assign,
    /// The `senta-addresses`, one per customer.
    Addresses,
    /// The `senta-policy` of a group, by `group_id`.
    Policy(LowerUuid),
    /// The `senta-update` addressed to a group, by `group_id`.
    GroupUpdate(LowerUuid),
    /// The `senta-update` addressed to the endpoint itself.
    EndpointUpdate,
}

impl Slot {
    /// Returns the `typ` of the documents of the slot.
    #[must_use]
    pub fn typ(self) -> Typ {
        match self {
            Self::Assign => Typ::Assign,
            Self::Addresses => Typ::Addresses,
            Self::Policy(_) => Typ::Policy,
            Self::GroupUpdate(_) | Self::EndpointUpdate => Typ::Update,
        }
    }
}

/// The verified content of a document of one of the four `typ`s that have
/// versions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentContent {
    /// A `senta-policy`.
    Policy(PolicyContent),
    /// A `senta-assign`.
    Assign(AssignContent),
    /// A `senta-addresses`.
    Addresses(AddressesContent),
    /// A `senta-update`.
    Update(UpdateContent),
}

impl DocumentContent {
    /// Returns the slot the document belongs to.
    #[must_use]
    pub fn slot(&self) -> Slot {
        match self {
            Self::Policy(content) => Slot::Policy(content.group_id),
            Self::Assign(_) => Slot::Assign,
            Self::Addresses(_) => Slot::Addresses,
            Self::Update(content) => match content.target() {
                UpdateTarget::Group(group_id) => Slot::GroupUpdate(group_id),
                UpdateTarget::Endpoint(_) => Slot::EndpointUpdate,
            },
        }
    }

    /// Returns the `typ` of the document.
    #[must_use]
    pub fn typ(&self) -> Typ {
        self.slot().typ()
    }

    /// Returns the document's `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> u64 {
        match self {
            Self::Policy(content) => content.recovery_epoch.get(),
            Self::Assign(content) => content.recovery_epoch.get(),
            Self::Addresses(content) => content.recovery_epoch().get(),
            Self::Update(content) => content.recovery_epoch().get(),
        }
    }

    /// Returns the document's `version`.
    #[must_use]
    pub fn version(&self) -> u64 {
        match self {
            Self::Policy(content) => content.version.get(),
            Self::Assign(content) => content.version.get(),
            Self::Addresses(content) => content.version().get(),
            Self::Update(content) => content.version().get(),
        }
    }
}

/// A storage layer's failure, as the [`VersionStore`] or [`TrustStore`]
/// implementation reports it.
pub struct StoreError(Box<dyn Error + Send + Sync + 'static>);

impl StoreError {
    /// Creates the error from the storage layer's own error or message.
    #[must_use]
    pub fn new(error: impl Into<Box<dyn Error + Send + Sync + 'static>>) -> Self {
        Self(error.into())
    }

    /// Returns the storage layer's own error.
    #[must_use]
    pub fn get_ref(&self) -> &(dyn Error + Send + Sync + 'static) {
        &*self.0
    }
}

impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StoreError").field(&self.0).finish()
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

/// Where the document version state is kept, which the caller implements.
///
/// The state is one [`VersionState`] value, which serializes through serde,
/// written and read whole. Each change [`DocumentVersions`] makes is one
/// [`save`](Self::save) of the whole value, so that whatever point the
/// endpoint stops at, the state read back is one that was written as a
/// whole, and its parts agree with one another.
pub trait VersionStore {
    /// Reads the state last written, or `None` if none ever was.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the storage layer cannot be read.
    fn load(&self) -> Result<Option<VersionState>, StoreError>;

    /// Replaces the stored state with `state`, as one atomic write.
    ///
    /// Success means that the whole of `state` is what this storage layer
    /// reads back from now on. An error means that none of it was written,
    /// and the storage layer reads back what it did before.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the state could not be written; nothing of
    /// it was then.
    fn save(&mut self, state: &VersionState) -> Result<(), StoreError>;
}

impl<S: VersionStore + ?Sized> VersionStore for &mut S {
    fn load(&self) -> Result<Option<VersionState>, StoreError> {
        (**self).load()
    }

    fn save(&mut self, state: &VersionState) -> Result<(), StoreError> {
        (**self).save(state)
    }
}

/// Where the trust state ([`TrustState`]) is kept, which the caller
/// implements.
///
/// The contract is that of [`VersionStore`]: one atomic write of the whole
/// value, after which it is what reads back, or an error after which
/// nothing of it was written.
pub trait TrustStore {
    /// Reads the trust state last written, or `None` if none ever was.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the storage layer cannot be read.
    fn load(&self) -> Result<Option<TrustState>, StoreError>;

    /// Replaces the stored trust state with `state`, as one atomic write.
    ///
    /// Success means that the whole of `state` is what this storage layer
    /// reads back from now on. An error means that none of it was written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the state could not be written; nothing of
    /// it was then.
    fn save(&mut self, state: &TrustState) -> Result<(), StoreError>;
}

impl<T: TrustStore + ?Sized> TrustStore for &mut T {
    fn load(&self) -> Result<Option<TrustState>, StoreError> {
        (**self).load()
    }

    fn save(&mut self, state: &TrustState) -> Result<(), StoreError> {
        (**self).save(state)
    }
}

/// A [`VersionStore`] in memory, which never fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryVersionStore {
    state: Option<VersionState>,
}

impl MemoryVersionStore {
    /// Creates a store that has never been written.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the state last written, or `None` if none ever was.
    #[must_use]
    pub fn state(&self) -> Option<&VersionState> {
        self.state.as_ref()
    }
}

impl VersionStore for MemoryVersionStore {
    fn load(&self) -> Result<Option<VersionState>, StoreError> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &VersionState) -> Result<(), StoreError> {
        self.state = Some(state.clone());
        Ok(())
    }
}

/// A [`TrustStore`] in memory, which never fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryTrustStore {
    state: Option<TrustState>,
}

impl MemoryTrustStore {
    /// Creates a store that has never been written.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store holding `state`, as the trust chain leaves it at
    /// installation.
    #[must_use]
    pub fn with_state(state: TrustState) -> Self {
        Self { state: Some(state) }
    }

    /// Returns the trust state last written, or `None` if none ever was.
    #[must_use]
    pub fn state(&self) -> Option<&TrustState> {
        self.state.as_ref()
    }
}

impl TrustStore for MemoryTrustStore {
    fn load(&self) -> Result<Option<TrustState>, StoreError> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &TrustState) -> Result<(), StoreError> {
        self.state = Some(state.clone());
        Ok(())
    }
}

/// What applies a verified document, which the caller implements: puts a
/// policy into force, records a group assignment, switches addresses, takes
/// an update.
///
/// [`DocumentVersions`] calls it synchronously. **Applying the same
/// document more than once must have the same result as applying it
/// once**: an endpoint that stops after applying a document and before the
/// state records it applies the same document again when it resumes.
///
/// Applying a `senta-update` means taking the document in; which version to
/// install is decided by [`DocumentVersions::current_update`], since an
/// update addressed to the endpoint comes before one addressed to its
/// group.
pub trait DocumentApplier {
    /// Applies `content`.
    ///
    /// # Errors
    ///
    /// Returns why applying failed, which is reported as
    /// [`DocumentResult::ApplyFailed`](crate::results::DocumentResult::ApplyFailed).
    fn apply(&mut self, content: &DocumentContent) -> Result<(), String>;
}

impl<F: FnMut(&DocumentContent) -> Result<(), String>> DocumentApplier for F {
    fn apply(&mut self, content: &DocumentContent) -> Result<(), String> {
        self(content)
    }
}

/// Why an operation of [`DocumentVersions`] did not complete; unlike a
/// [`DocumentResult`](crate::results::DocumentResult), it is not reported
/// for a document.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VersionsError {
    /// The [`VersionStore`] failed. The state in memory is still the one
    /// stored.
    #[error("the document version store failed")]
    Store(#[source] StoreError),
    /// The trust state passed in has a recovery epoch below the stored one:
    /// it is not the trust state the endpoint has stored. Nothing was
    /// written.
    #[error("the trust state's recovery epoch {trust_epoch} is behind the stored {stored_epoch}")]
    TrustBehind {
        /// The recovery epoch of the document version state.
        stored_epoch: u64,
        /// The recovery epoch of the trust state passed in.
        trust_epoch: u64,
    },
    /// [`DocumentVersions::create`] found a state already stored, which it
    /// leaves alone: starting the versions over would take old documents
    /// again.
    #[error("the document version store already holds a state")]
    AlreadyCreated,
    /// [`DocumentVersions::restore`] found no state stored.
    #[error("the document version store holds no state")]
    NotCreated,
    /// [`DocumentVersions::install_addresses`] found the address slot
    /// already holding a verified version, which it leaves alone.
    #[error("the address slot already has a verified version")]
    AddressesAlreadyVerified,
    /// [`DocumentVersions::set_endpoint_id`] was given an endpoint id other
    /// than the one already set.
    #[error("the endpoint id is already set to another one")]
    EndpointIdMismatch {
        /// The endpoint id already set.
        have: LowerUuid,
        /// The endpoint id given.
        given: LowerUuid,
    },
}

/// The alarm a `Conflict` raises: a document of a version already verified
/// with other content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConflictAlarm {
    /// The slot.
    pub slot: Slot,
    /// The version.
    pub version: u64,
}

/// What a slot is doing, for the status report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotStatus {
    /// No pending document.
    Normal,
    /// A pending document waits to be applied.
    Pending,
    /// A pending document of a group the endpoint is not assigned to now
    /// waits until it is again.
    PendingOutOfTarget,
    /// The verified version failed to apply three times and is no longer
    /// tried; reported as `ApplyFailed { reason }`. The current document
    /// stays in use, and a higher version is still taken.
    Halted {
        /// Why the last application failed.
        reason: String,
    },
}

/// The report of one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotReport {
    /// The slot.
    pub slot: Slot,
    /// The verified version, or `None` if there is none in this epoch.
    pub verified_version: Option<u64>,
    /// The applied version, or `None` if there is none in this epoch.
    pub applied_version: Option<u64>,
    /// What the slot is doing.
    pub status: SlotStatus,
    /// The (recovery epoch, version) of the current document, if there is
    /// one.
    pub current: Option<(u64, u64)>,
    /// Whether the current document was applied in an earlier recovery
    /// epoch and is not trusted.
    pub untrusted: bool,
}

/// The update whose `target_version` the endpoint follows now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentUpdate<'a> {
    /// The slot it is the current document of.
    pub slot: Slot,
    /// Its content.
    pub content: &'a UpdateContent,
    /// Whether it was applied in an earlier recovery epoch and is not
    /// trusted.
    pub untrusted: bool,
}

/// The document version state machine of an endpoint, over the store `S`
/// that keeps its state.
///
/// The state in memory is always the one last stored: each change is
/// written to the store first, and kept only once the write succeeded.
///
/// Every method that takes a [`TrustState`] relies on the caller for one
/// thing: the trust state passed in is the endpoint's current one **and has
/// already been stored**, so that the document version state never rests
/// on a trust state that a restart would lose. [`receive_documents`] stores
/// it before using it.
#[derive(Debug)]
pub struct DocumentVersions<S> {
    store: S,
    state: VersionState,
}

impl<S: VersionStore> DocumentVersions<S> {
    /// Creates the state of an endpoint that has just installed, without an
    /// endpoint id, at the recovery epoch of `trust` and with every slot
    /// empty, and writes it to `store`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::AlreadyCreated`] without writing anything if
    /// `store` already holds a state, and [`VersionsError::Store`] if
    /// reading or writing `store` fails.
    pub fn create(mut store: S, trust: &TrustState) -> Result<Self, VersionsError> {
        if store.load().map_err(VersionsError::Store)?.is_some() {
            return Err(VersionsError::AlreadyCreated);
        }
        let state = VersionState::new(trust.recovery_epoch());
        store.save(&state).map_err(VersionsError::Store)?;
        Ok(Self { store, state })
    }

    /// Makes the state machine again from the state `store` holds, as an
    /// endpoint does when it starts again.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::NotCreated`] if `store` was never written,
    /// and [`VersionsError::Store`] if reading it fails.
    pub fn restore(store: S) -> Result<Self, VersionsError> {
        let state = store
            .load()
            .map_err(VersionsError::Store)?
            .ok_or(VersionsError::NotCreated)?;
        Ok(Self { store, state })
    }
}

impl<S> DocumentVersions<S> {
    /// Returns the state, as last stored.
    #[must_use]
    pub fn state(&self) -> &VersionState {
        &self.state
    }

    /// Returns the store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the store, consuming `self`.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Returns the recovery epoch the state is at.
    #[must_use]
    pub fn recovery_epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Returns the endpoint's own id, or `None` before it has enrolled.
    #[must_use]
    pub fn endpoint_id(&self) -> Option<LowerUuid> {
        self.state.endpoint_id
    }

    /// Returns the group the endpoint is assigned to now: the `group_id` of
    /// the `senta-assign` applied in the current recovery epoch, or `None`
    /// if none has been.
    #[must_use]
    pub fn current_group(&self) -> Option<LowerUuid> {
        let current = self.state.slots.get(&Slot::Assign)?.current.as_ref()?;
        if current.epoch != self.state.epoch {
            return None;
        }
        match &current.content {
            DocumentContent::Assign(content) => Some(content.group_id),
            _ => None,
        }
    }

    /// Returns the report of `slot`; a slot that holds nothing reports no
    /// version, no current document and [`SlotStatus::Normal`].
    #[must_use]
    pub fn report(&self, slot: Slot) -> SlotReport {
        match self.state.slots.get(&slot) {
            Some(state) => self.report_of(slot, state),
            None => self.report_of(slot, &SlotState::default()),
        }
    }

    /// Returns the report of every slot that holds anything, in slot order.
    #[must_use]
    pub fn reports(&self) -> Vec<SlotReport> {
        self.state
            .slots
            .iter()
            .map(|(&slot, state)| self.report_of(slot, state))
            .collect()
    }

    /// Returns whether any slot's current document was applied in an
    /// earlier recovery epoch and is not trusted, which the status report
    /// raises as `Problem::PriorEpochState`.
    #[must_use]
    pub fn has_untrusted(&self) -> bool {
        self.state.slots.values().any(|state| state.untrusted)
    }

    /// Returns the content of the current document of `slot`: the last one
    /// applied, kept across recovery epochs and while a later version is
    /// pending or halted.
    #[must_use]
    pub fn current_content(&self, slot: Slot) -> Option<&DocumentContent> {
        self.state
            .slots
            .get(&slot)?
            .current
            .as_ref()
            .map(|current| &current.content)
    }

    /// Returns the update the endpoint follows now.
    ///
    /// The current update addressed to the endpoint comes first, if it has
    /// a `target_version`. If it has a `null` one, which releases the
    /// endpoint, or there is none, the current update of the group in the
    /// current `senta-assign` document is used, whether or not that
    /// assignment is trusted. Without either there is none.
    #[must_use]
    pub fn current_update(&self) -> Option<CurrentUpdate<'_>> {
        if let Some(update) = self.current_update_of(Slot::EndpointUpdate)
            && update.content.target_version().is_some()
        {
            return Some(update);
        }
        let group_id = match self.current_content(Slot::Assign)? {
            DocumentContent::Assign(content) => content.group_id,
            _ => return None,
        };
        self.current_update_of(Slot::GroupUpdate(group_id))
    }

    fn current_update_of(&self, slot: Slot) -> Option<CurrentUpdate<'_>> {
        let state = self.state.slots.get(&slot)?;
        match &state.current.as_ref()?.content {
            DocumentContent::Update(content) => Some(CurrentUpdate {
                slot,
                content,
                untrusted: state.untrusted,
            }),
            _ => None,
        }
    }

    fn report_of(&self, slot: Slot, state: &SlotState) -> SlotReport {
        let status = if state.halted {
            SlotStatus::Halted {
                reason: state.last_failure.clone().unwrap_or_default(),
            }
        } else {
            match &state.pending {
                None => SlotStatus::Normal,
                Some(pending) if self.is_target(pending, self.current_group()) => {
                    SlotStatus::Pending
                }
                Some(_) => SlotStatus::PendingOutOfTarget,
            }
        };
        SlotReport {
            slot,
            verified_version: state.verified.map(|verified| verified.version),
            applied_version: state.applied,
            status,
            current: state
                .current
                .as_ref()
                .map(|current| (current.epoch, current.version)),
            untrusted: state.untrusted,
        }
    }

    /// Returns whether `content` is addressed to this endpoint, with
    /// `group` the group it is assigned to now: an assignment or an
    /// endpoint update must name its endpoint id, which it must have; a
    /// policy or a group update must name `group`; an address document is
    /// for every endpoint.
    fn is_target(&self, content: &DocumentContent, group: Option<LowerUuid>) -> bool {
        let own = |endpoint_id: LowerUuid| self.state.endpoint_id == Some(endpoint_id);
        match content {
            DocumentContent::Assign(content) => own(content.endpoint_id),
            DocumentContent::Policy(content) => group == Some(content.group_id),
            DocumentContent::Addresses(_) => true,
            DocumentContent::Update(content) => match content.target() {
                UpdateTarget::Endpoint(endpoint_id) => own(endpoint_id),
                UpdateTarget::Group(group_id) => group == Some(group_id),
            },
        }
    }
}
