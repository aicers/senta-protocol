//! Receiving a document, resuming pending documents, and the recovery
//! epoch moving on.

use std::cmp::Ordering;

use jiff::Timestamp;

use super::identity::{self, DocumentIdentity, VersionedTyp};
use super::state::{SlotState, VerifiedVersion, VersionState};
use super::{
    ConflictAlarm, DocumentApplier, DocumentContent, DocumentVersions, MAX_APPLY_ATTEMPTS, Slot,
    VersionStore, VersionsError,
};
use crate::auth::documents::{
    AddressesContent, MAX_UPDATE_LIFETIME, SemVer, UpdateContent, VerifiedDocument,
    check_validity_window,
};
use crate::auth::jws::strict::LowerUuid;
use crate::auth::keyset::{EpochChange, TrustState};
use crate::results::DocumentResult;

/// The outcome of receiving one document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub(super) identity: DocumentIdentity,
    pub(super) result: DocumentResult,
    pub(super) conflict: Option<ConflictAlarm>,
    pub(super) epoch_aligned: bool,
}

impl Receipt {
    /// Returns what the document is, as far as it was read.
    #[must_use]
    pub fn identity(&self) -> &DocumentIdentity {
        &self.identity
    }

    /// Returns the result of receiving the document.
    #[must_use]
    pub fn result(&self) -> &DocumentResult {
        &self.result
    }

    /// Returns the alarm a `Conflict` raises, present exactly when the
    /// result is `Conflict`.
    #[must_use]
    pub fn conflict(&self) -> Option<ConflictAlarm> {
        self.conflict
    }

    /// Returns whether the versions were started over for a later recovery
    /// epoch before the document was looked at.
    #[must_use]
    pub fn epoch_aligned(&self) -> bool {
        self.epoch_aligned
    }
}

impl<S: VersionStore> DocumentVersions<S> {
    /// Receives one `senta-policy`, `senta-assign`, `senta-addresses` or
    /// `senta-update` JWS, and applies it with `applier` if it is to be.
    ///
    /// `trust` must be the endpoint's current trust state, **already
    /// stored**; `now` is the endpoint's own clock and `senta_version` the
    /// senta version installed now.
    ///
    /// If the recovery epoch of `trust` is above the stored one, the
    /// versions first start over for it, as
    /// [`epoch_changed`](Self::epoch_changed) does; that stays written
    /// whatever the result. Then the first of these to hold decides the
    /// result:
    ///
    /// 1. The header's `typ` is none of the four: `SchemaError`. The JWS
    ///    fails verification by its `typ`'s `verify_<typ>` against `trust`:
    ///    that failure's result.
    /// 2. Its `recovery_epoch` is not that of `trust`: `EpochMismatch`.
    /// 3. It is not addressed to this endpoint: `WrongTarget`. An
    ///    assignment or an endpoint update must name the endpoint's own id,
    ///    so neither is taken before the endpoint has one; a policy or a
    ///    group update must name the group of the `senta-assign` applied in
    ///    the current recovery epoch, so neither is taken before one is.
    /// 4. Against the slot's verified version V, its version v is below V:
    ///    `Stale`. v is V with another content hash: `Conflict`, with a
    ///    [`ConflictAlarm`]. v is V with the same hash, and V is applied:
    ///    `Duplicate`; halted: `ApplyFailed` with the last reason, without
    ///    applying; pending: the pending document is applied again, without
    ///    step 5. Otherwise it is a new document.
    /// 5. A new `senta-update` is out of its validity window by `now`, with
    ///    a lifetime of at most 30 days: `NotYetValid` or `Expired`. Its
    ///    `target_version` is below `senta_version` by SemVer precedence and
    ///    `rollback` is false: `SchemaError`.
    /// 6. A new document is stored as the slot's pending document,
    ///    replacing one not yet applied, and applied.
    /// 7. Applied: `Applied`, and the slot's applied version and current
    ///    document are the document's. Failed: `ApplyFailed` with the
    ///    reason; the third failure of a version halts it.
    ///
    /// A document received again goes through every step again, so its
    /// signature is verified against `trust` each time. Results of steps 1
    /// to 5 write nothing.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::TrustBehind`], having written nothing, if
    /// the recovery epoch of `trust` is below the stored one, and
    /// [`VersionsError::Store`] if a write fails; the state is then still
    /// the stored one, and a document whose application succeeded is
    /// applied again by [`resume`](Self::resume).
    pub fn receive<A: DocumentApplier + ?Sized>(
        &mut self,
        jws: &str,
        trust: &TrustState,
        now: Timestamp,
        senta_version: &SemVer,
        applier: &mut A,
    ) -> Result<Receipt, VersionsError> {
        let epoch_aligned = self.align_to(trust)?;
        let typ = identity::header_typ(jws);
        let versioned = typ.as_deref().and_then(VersionedTyp::from_header);
        let mut receipt = Receipt {
            identity: DocumentIdentity::of_typ(typ),
            result: DocumentResult::SchemaError,
            conflict: None,
            epoch_aligned,
        };
        let Some(versioned) = versioned else {
            return Ok(receipt);
        };
        let (content, payload_hash) = match versioned.verify(jws, trust) {
            Ok(verified) => verified,
            Err(error) => {
                receipt.result = error.result();
                return Ok(receipt);
            }
        };
        receipt.identity.read_content(&content);
        let slot = content.slot();
        let version = content.version();
        receipt.result = self.judge(
            content,
            payload_hash,
            trust.recovery_epoch(),
            now,
            senta_version,
            applier,
        )?;
        if receipt.result == DocumentResult::Conflict {
            receipt.conflict = Some(ConflictAlarm { slot, version });
        }
        Ok(receipt)
    }

    /// Steps 2 to 7 of [`receive`](Self::receive).
    fn judge<A: DocumentApplier + ?Sized>(
        &mut self,
        content: DocumentContent,
        payload_hash: [u8; 32],
        epoch: u64,
        now: Timestamp,
        senta_version: &SemVer,
        applier: &mut A,
    ) -> Result<DocumentResult, VersionsError> {
        if content.recovery_epoch() != epoch {
            return Ok(DocumentResult::EpochMismatch);
        }
        if !self.is_target(&content, self.current_group()) {
            return Ok(DocumentResult::WrongTarget);
        }
        let slot = content.slot();
        let version = content.version();
        if let Some(state) = self.state.slots.get(&slot)
            && let Some(verified) = state.verified
        {
            match version.cmp(&verified.version) {
                Ordering::Less => return Ok(DocumentResult::Stale),
                Ordering::Equal if verified.payload_hash != payload_hash => {
                    return Ok(DocumentResult::Conflict);
                }
                Ordering::Equal if state.applied == Some(version) => {
                    return Ok(DocumentResult::Duplicate);
                }
                Ordering::Equal if state.halted => {
                    return Ok(DocumentResult::ApplyFailed {
                        reason: state.last_failure.clone().unwrap_or_default(),
                    });
                }
                Ordering::Equal if state.pending.is_some() => {
                    return self.apply_pending(slot, applier);
                }
                // A verified version neither applied nor pending is taken as
                // new; the state never leaves one so.
                Ordering::Equal | Ordering::Greater => {}
            }
        }
        if let DocumentContent::Update(update) = &content
            && let Err(result) = check_new_update(update, now, senta_version)
        {
            return Ok(result);
        }

        let mut next = self.state.slots.get(&slot).cloned().unwrap_or_default();
        next.accept(version, payload_hash, content);
        self.write_slot(slot, next)?;
        self.apply_pending(slot, applier)
    }

    /// Applies the pending documents of the slots that have one and are not
    /// halted, as an endpoint does when it starts again or retries an
    /// application that failed, and returns the result of each application
    /// in the order made.
    ///
    /// `trust` must be the endpoint's current trust state, **already
    /// stored**. If its recovery epoch is above the stored one, the
    /// versions first start over for it, which discards every pending
    /// document.
    ///
    /// The pending `senta-assign` is applied first. The other slots follow
    /// in slot order, each only if its document is addressed to the
    /// endpoint as step 3 of [`receive`](Self::receive) judges it, with the
    /// group the assignment left: the new one if it applied, the one before
    /// if it failed or there was none. A pending document of another group
    /// is kept, reported as [`SlotStatus::PendingOutOfTarget`], and applied
    /// by a later resume once the endpoint is assigned to that group again.
    ///
    /// The stored, verified content is applied; the signature, validity
    /// window and rollback rule are not looked at again, since the version
    /// was accepted already. Each application is recorded as in step 7 of
    /// [`receive`](Self::receive).
    ///
    /// [`SlotStatus::PendingOutOfTarget`]: super::SlotStatus::PendingOutOfTarget
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::TrustBehind`], having written and applied
    /// nothing, if the recovery epoch of `trust` is below the stored one,
    /// and [`VersionsError::Store`] if a write fails; the slots after it are
    /// then not applied.
    pub fn resume<A: DocumentApplier + ?Sized>(
        &mut self,
        trust: &TrustState,
        applier: &mut A,
    ) -> Result<Vec<(Slot, DocumentResult)>, VersionsError> {
        self.align_to(trust)?;
        let mut results = Vec::new();
        if self.is_resumable(Slot::Assign) {
            results.push((Slot::Assign, self.apply_pending(Slot::Assign, applier)?));
        }
        let group = self.current_group();
        let slots: Vec<Slot> = self
            .state
            .slots
            .iter()
            .filter(|&(&slot, state)| {
                slot != Slot::Assign
                    && !state.halted
                    && state
                        .pending
                        .as_ref()
                        .is_some_and(|pending| self.is_target(pending, group))
            })
            .map(|(&slot, _)| slot)
            .collect();
        for slot in slots {
            results.push((slot, self.apply_pending(slot, applier)?));
        }
        Ok(results)
    }

    /// Takes the recovery epoch moving on, as the key set state machine
    /// reports it: if `change.new_epoch` is above the stored epoch, every
    /// slot's verified and applied versions start over from none, and its
    /// pending document, failures and halt are dropped. Each current
    /// document is kept, and one applied in an earlier epoch is marked as
    /// not trusted. That is one write.
    ///
    /// The trust state that reported `change` must be **already stored**.
    /// A change to an epoch not above the stored one, one that arrived late
    /// or a second time, changes nothing. Returns whether the versions
    /// started over.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::Store`] if the write fails; nothing has
    /// changed then.
    pub fn epoch_changed(&mut self, change: EpochChange) -> Result<bool, VersionsError> {
        if change.new_epoch <= self.state.epoch {
            return Ok(false);
        }
        self.start_epoch(change.new_epoch)?;
        Ok(true)
    }

    /// Records the address document of the install configuration, whose
    /// trust chain has been verified, as the address slot's verified,
    /// applied and current document, without calling an applier; the trust
    /// chain calls this before the endpoint enrolls.
    ///
    /// Returns `EpochMismatch`, writing nothing, if the document's
    /// `recovery_epoch` is not the stored one, and `Applied` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::AddressesAlreadyVerified`], writing
    /// nothing, if the address slot already has a verified version, and
    /// [`VersionsError::Store`] if the write fails.
    pub fn install_addresses(
        &mut self,
        document: VerifiedDocument<AddressesContent>,
    ) -> Result<DocumentResult, VersionsError> {
        let slot = Slot::Addresses;
        let existing = self.state.slots.get(&slot);
        if existing.is_some_and(|state| state.verified.is_some()) {
            return Err(VersionsError::AddressesAlreadyVerified);
        }
        let payload_hash = *document.payload_hash();
        let content = DocumentContent::Addresses(document.into_content());
        let epoch = content.recovery_epoch();
        if epoch != self.state.epoch {
            return Ok(DocumentResult::EpochMismatch);
        }
        let version = content.version();
        let mut next = existing.cloned().unwrap_or_default();
        next.verified = Some(VerifiedVersion {
            version,
            payload_hash,
        });
        next.complete(content);
        self.write_slot(slot, next)?;
        Ok(DocumentResult::Applied)
    }

    /// Sets the endpoint's own id, once it has enrolled.
    ///
    /// Setting the id already set changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::EndpointIdMismatch`], writing nothing, if
    /// another id is set already, and [`VersionsError::Store`] if the write
    /// fails.
    pub fn set_endpoint_id(&mut self, endpoint_id: LowerUuid) -> Result<(), VersionsError> {
        match self.state.endpoint_id {
            Some(have) if have == endpoint_id => Ok(()),
            Some(have) => Err(VersionsError::EndpointIdMismatch {
                have,
                given: endpoint_id,
            }),
            None => {
                self.state.endpoint_id = Some(endpoint_id);
                if let Err(error) = self.store.save(&self.state) {
                    self.state.endpoint_id = None;
                    return Err(VersionsError::Store(error));
                }
                Ok(())
            }
        }
    }

    /// Starts the versions over if the recovery epoch of `trust` is above
    /// the stored one; returns whether it did.
    fn align_to(&mut self, trust: &TrustState) -> Result<bool, VersionsError> {
        let trust_epoch = trust.recovery_epoch();
        match trust_epoch.cmp(&self.state.epoch) {
            Ordering::Less => Err(VersionsError::TrustBehind {
                stored_epoch: self.state.epoch,
                trust_epoch,
            }),
            Ordering::Equal => Ok(false),
            Ordering::Greater => self.start_epoch(trust_epoch).map(|()| true),
        }
    }

    fn start_epoch(&mut self, epoch: u64) -> Result<(), VersionsError> {
        let mut next = VersionState {
            epoch,
            endpoint_id: self.state.endpoint_id,
            slots: self.state.slots.clone(),
        };
        next.slots.retain(|_, state| state.current.is_some());
        for state in next.slots.values_mut() {
            state.verified = None;
            state.pending = None;
            state.applied = None;
            state.clear_failures();
            if state
                .current
                .as_ref()
                .is_some_and(|current| current.epoch < epoch)
            {
                state.untrusted = true;
            }
        }
        self.store.save(&next).map_err(VersionsError::Store)?;
        self.state = next;
        Ok(())
    }

    fn is_resumable(&self, slot: Slot) -> bool {
        self.state
            .slots
            .get(&slot)
            .is_some_and(|state| state.pending.is_some() && !state.halted)
    }

    /// Applies the pending document of `slot` and records the outcome.
    ///
    /// Every caller has just found or written a pending document in `slot`;
    /// a slot without one has nothing to apply, and the result is then that
    /// of its current document, `Applied`.
    fn apply_pending<A: DocumentApplier + ?Sized>(
        &mut self,
        slot: Slot,
        applier: &mut A,
    ) -> Result<DocumentResult, VersionsError> {
        let Some(mut next) = self.state.slots.get(&slot).cloned() else {
            return Ok(DocumentResult::Applied);
        };
        let Some(pending) = next.pending.take() else {
            return Ok(DocumentResult::Applied);
        };
        let result = match applier.apply(&pending) {
            Ok(()) => {
                next.complete(pending);
                DocumentResult::Applied
            }
            Err(reason) => {
                next.pending = Some(pending);
                next.failures = next.failures.saturating_add(1);
                next.halted = next.failures >= MAX_APPLY_ATTEMPTS;
                next.last_failure = Some(reason.clone());
                DocumentResult::ApplyFailed { reason }
            }
        };
        self.write_slot(slot, next)?;
        Ok(result)
    }

    /// Writes the state with `next` as the state of `slot`, keeping the
    /// previous one in memory if the write fails.
    fn write_slot(&mut self, slot: Slot, next: SlotState) -> Result<(), VersionsError> {
        let previous = self.state.slots.insert(slot, next);
        if let Err(error) = self.store.save(&self.state) {
            match previous {
                Some(previous) => {
                    self.state.slots.insert(slot, previous);
                }
                None => {
                    self.state.slots.remove(&slot);
                }
            }
            return Err(VersionsError::Store(error));
        }
        Ok(())
    }
}

/// Checks a new `senta-update` against its validity window and the rollback
/// rule.
fn check_new_update(
    update: &UpdateContent,
    now: Timestamp,
    senta_version: &SemVer,
) -> Result<(), DocumentResult> {
    check_validity_window(
        now,
        update.issued_at(),
        update.expires_at(),
        MAX_UPDATE_LIFETIME,
    )?;
    if let Some(target_version) = update.target_version()
        && target_version.cmp_precedence(senta_version) == Ordering::Less
        && !update.rollback()
    {
        return Err(DocumentResult::SchemaError);
    }
    Ok(())
}
