//! Receiving the signed documents of one `Documents` message.

use jiff::Timestamp;

use super::identity::{self, DocumentIdentity, VersionedTyp};
use super::{
    ConflictAlarm, DocumentApplier, DocumentVersions, StoreError, TrustStore, VersionStore,
    VersionsError,
};
use crate::auth::documents::SemVer;
use crate::auth::jws::Typ;
use crate::auth::keyset::{ChainOutcome, EpochChange, TrustState};
use crate::results::DocumentResult;

/// What became of one document of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryOutcome {
    /// The document was processed, with this result.
    Processed(DocumentResult),
    /// The document was not processed: a key set or recovery key document
    /// after the one its chain stopped at. No acknowledgement is sent for
    /// it; the server sends it again from the status report.
    NotProcessed,
}

/// One document of the list: what it is, as far as it was read, and what
/// became of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentEntry {
    identity: DocumentIdentity,
    outcome: EntryOutcome,
}

impl DocumentEntry {
    /// Returns what the document is, as far as it was read.
    #[must_use]
    pub fn identity(&self) -> &DocumentIdentity {
        &self.identity
    }

    /// Returns what became of the document.
    #[must_use]
    pub fn outcome(&self) -> &EntryOutcome {
        &self.outcome
    }
}

/// The outcome of receiving the documents of one `Documents` message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocumentsOutcome {
    entries: Vec<DocumentEntry>,
    conflicts: Vec<ConflictAlarm>,
    epoch_changes: Vec<EpochChange>,
}

impl DocumentsOutcome {
    /// Returns one entry per document, in the order of the list.
    #[must_use]
    pub fn entries(&self) -> &[DocumentEntry] {
        &self.entries
    }

    /// Returns the alarms the `Conflict` results raised, in the order
    /// processed.
    #[must_use]
    pub fn conflicts(&self) -> &[ConflictAlarm] {
        &self.conflicts
    }

    /// Returns the recovery epoch changes the key set documents brought, in
    /// order.
    #[must_use]
    pub fn epoch_changes(&self) -> &[EpochChange] {
        &self.epoch_changes
    }
}

/// Why [`receive_documents`] did not complete. No acknowledgement is sent
/// for the list either way.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DocumentsError {
    /// The trust state the key set and recovery key documents changed could
    /// not be stored. The caller's trust state is the one passed in, and
    /// nothing was written to the document version state; receiving the
    /// same list again takes the chain again.
    #[error("storing the updated trust state failed")]
    TrustStore {
        /// The trust store's failure.
        #[source]
        source: StoreError,
        /// What the chain did to the trust state that was not stored; not
        /// to be acknowledged.
        chain: ChainOutcome,
    },
    /// Processing a policy, assignment, address document or update, or
    /// taking an epoch change, failed with this error; the documents after
    /// it were not processed. The trust state was stored, and the caller's
    /// trust state is the new one; what the documents before it wrote
    /// stays written.
    #[error(transparent)]
    Versions(#[from] VersionsError),
}

/// How a document of the list is processed, by its header's `typ`.
enum Route {
    Chain,
    Versioned(VersionedTyp),
    Rejected,
}

/// Receives the signed documents of one `Documents` message, `documents`,
/// in the order the catch-up rules give.
///
/// `trust` is the endpoint's current trust state, as stored in
/// `trust_store`; `versions`, `now`, `senta_version` and `applier` are what
/// [`DocumentVersions::receive`] takes.
///
/// 1. Each document is routed by its header's `typ`. One whose header does
///    not read, or whose `typ` is none of `senta-keyset`,
///    `senta-recovery-key`, `senta-policy`, `senta-assign`,
///    `senta-addresses` and `senta-update`, is a `SchemaError`.
/// 2. The `senta-keyset` and `senta-recovery-key` documents, in the order
///    of the list, go to [`TrustState::receive_chain`] on a copy of
///    `trust`. If the chain stops, the chain documents after it are
///    [`EntryOutcome::NotProcessed`].
/// 3. If the chain changed the trust state, it is written to `trust_store`,
///    and only once that succeeded does `trust` become the new one. If the
///    write fails, this returns [`DocumentsError::TrustStore`], `trust` is
///    left as it was, and nothing is written to `versions`; so receiving
///    the same list again takes the chain again.
/// 4. Each recovery epoch change the chain brought goes to
///    [`DocumentVersions::epoch_changed`].
/// 5. Every `senta-assign` goes to [`DocumentVersions::receive`] with the
///    new trust state, then the other documents in the order of the list,
///    so that a policy for the group a new assignment names is taken
///    whatever the order.
///
/// The entries are in the order of the list.
///
/// # Errors
///
/// Returns [`DocumentsError::TrustStore`] as in step 3, and
/// [`DocumentsError::Versions`] if step 4 or 5 fails, leaving the rest of
/// the documents unprocessed. In either case no acknowledgement is to be
/// sent for the list.
pub fn receive_documents<J, T, S, A>(
    documents: &[J],
    trust: &mut TrustState,
    trust_store: &mut T,
    versions: &mut DocumentVersions<S>,
    now: Timestamp,
    senta_version: &SemVer,
    applier: &mut A,
) -> Result<DocumentsOutcome, DocumentsError>
where
    J: AsRef<str>,
    T: TrustStore + ?Sized,
    S: VersionStore,
    A: DocumentApplier + ?Sized,
{
    let mut entries = Vec::with_capacity(documents.len());
    let mut chain = Vec::new();
    let mut assignments = Vec::new();
    let mut others = Vec::new();
    for (index, jws) in documents.iter().map(AsRef::as_ref).enumerate() {
        let typ = identity::header_typ(jws);
        let route = match typ.as_deref() {
            Some(text) if text == Typ::Keyset.as_str() || text == Typ::RecoveryKey.as_str() => {
                Route::Chain
            }
            Some(text) => VersionedTyp::from_header(text).map_or(Route::Rejected, Route::Versioned),
            None => Route::Rejected,
        };
        let (identity, outcome) = match route {
            Route::Chain => {
                chain.push((index, jws));
                (
                    DocumentIdentity::of_key_document(jws, typ),
                    EntryOutcome::NotProcessed,
                )
            }
            Route::Versioned(versioned) => {
                if versioned == VersionedTyp::Assign {
                    assignments.push((index, jws));
                } else {
                    others.push((index, jws));
                }
                (DocumentIdentity::of_typ(typ), EntryOutcome::NotProcessed)
            }
            Route::Rejected => (
                DocumentIdentity::of_typ(typ),
                EntryOutcome::Processed(DocumentResult::SchemaError),
            ),
        };
        entries.push(DocumentEntry { identity, outcome });
    }

    let mut updated = trust.clone();
    let chain_documents: Vec<&str> = chain.iter().map(|&(_, jws)| jws).collect();
    let chain_outcome = updated.receive_chain(&chain_documents);
    if updated != *trust {
        if let Err(source) = trust_store.save(&updated) {
            return Err(DocumentsError::TrustStore {
                source,
                chain: chain_outcome,
            });
        }
        *trust = updated;
    }
    for (result, &(index, _)) in chain_outcome.results().iter().zip(&chain) {
        if let Some(entry) = entries.get_mut(index) {
            entry.outcome = EntryOutcome::Processed(result.clone());
        }
    }

    for &change in chain_outcome.epoch_changes() {
        versions.epoch_changed(change)?;
    }

    let mut conflicts = Vec::new();
    for (index, jws) in assignments.into_iter().chain(others) {
        let receipt = versions.receive(jws, trust, now, senta_version, applier)?;
        conflicts.extend(receipt.conflict);
        if let Some(entry) = entries.get_mut(index) {
            entry.outcome = EntryOutcome::Processed(receipt.result);
            entry.identity = receipt.identity;
        }
    }

    Ok(DocumentsOutcome {
        entries,
        conflicts,
        epoch_changes: chain_outcome.epoch_changes().to_vec(),
    })
}
