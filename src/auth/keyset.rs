//! The key set state machine: which customer keys an endpoint trusts, and
//! how that changes.
//!
//! An endpoint trusts the customer keys of one key set (`senta-keyset`),
//! ordered by (recovery epoch, version), and one recovery key, numbered by
//! its own version. [`TrustState`] holds both and takes the documents that
//! move them on:
//!
//! - an ordinary rotation, the next version of the same epoch, signed by the
//!   current key set's `current_kid`;
//! - a recovery, the version 1 of a later epoch, signed by the recovery key
//!   the endpoint trusts; it raises the epoch, which an [`EpochChange`]
//!   reports;
//! - a recovery key replacement (`senta-recovery-key`), the next recovery
//!   key version, signed by the current recovery key.
//!
//! The server sends the documents an endpoint missed as a catch-up chain,
//! which [`build_catch_up_chain`] puts in order and
//! [`TrustState::receive_chain`] takes. [`receive_enroll_result`] takes the
//! chain that comes with an approved enrollment and then the
//! `senta-enroll-result` itself.
//!
//! Everything here is sans-IO: no network, no disk. The state is a value
//! the caller stores, through serde, and processing a document changes it
//! only when the document is applied.
//!
//! Every other document signed by a customer key is verified against the
//! state through its [`KeySource`] implementation.

mod catch_up;
mod enroll;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

pub use self::catch_up::{CatchUpBaseline, CatchUpError, build_catch_up_chain};
pub use self::enroll::{EnrollAttempt, EnrollFailure, EnrollOutcome, receive_enroll_result};
use super::documents::{
    self, CustomerKeyName, CustomerKid, DocumentError, InspectedDocument, InstallId, KeysetContent,
    KeysetEntry, PositiveInteger, RecoveryKeyContent, VerifiedDocument,
};
use super::jws::strict::LowerUuid;
use super::jws::{Jwk, KeyKind, KeyLookup, KeySource, Kid, Typ, VerifyError};
use crate::results::DocumentResult;

/// The prefix of a recovery key's kid.
const RECOVERY_KID_PREFIX: &str = "recovery-";

/// Returns the kid of the recovery key of version `version` of the install
/// `install_id`, `recovery-<install id>:<version>`.
fn recovery_kid(install_id: &InstallId, version: u64) -> String {
    format!("{RECOVERY_KID_PREFIX}{install_id}:{version}")
}

/// What an endpoint trusts: its key set and its recovery key.
///
/// It holds the install id, the key set the endpoint has — its
/// `customer_endpoint_id`, `customer_key_name`, (recovery epoch, version),
/// `keys`, `current_kid` and `revoked_kids` — and the recovery key the
/// endpoint trusts with its version.
///
/// It serializes and deserializes through serde, so that the caller can
/// store it; a state read back gives the same verdicts as the one written.
/// Each `receive_*` method changes it only when the document is applied, and
/// leaves it exactly as it was for every other result.
///
/// As a [`KeySource`] it is the key lookup for every other document a
/// customer key signs: policies, assignments, addresses, updates, commands
/// and enrollment results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustState {
    install_id: InstallId,
    keyset: KeysetContent,
    recovery_key: Jwk,
    recovery_key_version: PositiveInteger,
}

/// The recovery epoch moving on, which applying a key set signed by the
/// recovery key brings.
///
/// The document and command state machines restart their version and
/// sequence floors on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochChange {
    /// The recovery epoch before the key set was applied.
    pub old_epoch: u64,
    /// The recovery epoch of the key set applied.
    pub new_epoch: u64,
}

/// The outcome of receiving one `senta-keyset` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysetReceipt {
    result: DocumentResult,
    epoch_change: Option<EpochChange>,
}

impl KeysetReceipt {
    fn without_epoch_change(result: DocumentResult) -> Self {
        Self {
            result,
            epoch_change: None,
        }
    }

    /// Returns the result of receiving the document.
    #[must_use]
    pub fn result(&self) -> &DocumentResult {
        &self.result
    }

    /// Returns the result, consuming `self`.
    #[must_use]
    pub fn into_result(self) -> DocumentResult {
        self.result
    }

    /// Returns the epoch change, present exactly when a key set signed by
    /// the recovery key was applied.
    #[must_use]
    pub fn epoch_change(&self) -> Option<EpochChange> {
        self.epoch_change
    }
}

/// The outcome of receiving a list of key set and recovery key documents in
/// order, a catch-up chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainOutcome {
    results: Vec<DocumentResult>,
    stopped: bool,
    epoch_changes: Vec<EpochChange>,
}

impl ChainOutcome {
    /// Returns the result of each document processed, in order: every
    /// document when the chain did not stop, and the documents up to and
    /// including the one it stopped at when it did.
    #[must_use]
    pub fn results(&self) -> &[DocumentResult] {
        &self.results
    }

    /// Returns whether processing stopped at a document whose result was
    /// neither `Applied` nor `Duplicate`, leaving the documents after it
    /// unprocessed.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Returns the index of the document processing stopped at and its
    /// result, or `None` when every document was applied or a duplicate.
    #[must_use]
    pub fn stopped_at(&self) -> Option<(usize, &DocumentResult)> {
        if !self.stopped {
            return None;
        }
        let index = self.results.len().checked_sub(1)?;
        self.results.last().map(|result| (index, result))
    }

    /// Returns the epoch changes the applied documents brought, in order.
    #[must_use]
    pub fn epoch_changes(&self) -> &[EpochChange] {
        &self.epoch_changes
    }
}

impl TrustState {
    /// Creates the state of an endpoint that trusts `keyset`, with the
    /// recovery key `recovery_key` of version `recovery_key_version`, for
    /// the install `install_id`.
    ///
    /// The arguments are those of the endpoint's install configuration: its
    /// `keyset`, `install_id`, `recovery_key` and `recovery_key_version`.
    /// This does not establish that they are trustworthy. The caller must
    /// already have verified the install configuration's chain — the
    /// deployment certificate, the install signing key's signature, the key
    /// set signed by its own `current_kid` and the customer identifiers
    /// agreeing — which the trust chain does; that `keyset` is a
    /// [`VerifiedDocument`] shows only that its signature verified under the
    /// key it was checked with.
    #[must_use]
    pub fn new(
        keyset: VerifiedDocument<KeysetContent>,
        install_id: InstallId,
        recovery_key: Jwk,
        recovery_key_version: PositiveInteger,
    ) -> Self {
        Self {
            install_id,
            keyset: keyset.into_content(),
            recovery_key,
            recovery_key_version,
        }
    }

    /// Returns the install id.
    #[must_use]
    pub fn install_id(&self) -> &InstallId {
        &self.install_id
    }

    /// Returns the `customer_endpoint_id` of the key set.
    #[must_use]
    pub fn customer_endpoint_id(&self) -> LowerUuid {
        self.keyset.customer_endpoint_id()
    }

    /// Returns the `customer_key_name` of the current key set.
    #[must_use]
    pub fn customer_key_name(&self) -> &CustomerKeyName {
        self.keyset.customer_key_name()
    }

    /// Returns the recovery epoch of the current key set.
    #[must_use]
    pub fn recovery_epoch(&self) -> u64 {
        self.keyset.recovery_epoch().get()
    }

    /// Returns the version, within its recovery epoch, of the current key
    /// set.
    #[must_use]
    pub fn keyset_version(&self) -> u64 {
        self.keyset.keyset_version().get()
    }

    /// Returns the keys of the current key set, never empty.
    #[must_use]
    pub fn keys(&self) -> &[KeysetEntry] {
        self.keyset.keys()
    }

    /// Returns the `current_kid` of the current key set.
    #[must_use]
    pub fn current_kid(&self) -> &CustomerKid {
        self.keyset.current_kid()
    }

    /// Returns the `revoked_kids` of the current key set.
    #[must_use]
    pub fn revoked_kids(&self) -> &[CustomerKid] {
        self.keyset.revoked_kids()
    }

    /// Returns the recovery key the endpoint trusts.
    #[must_use]
    pub fn recovery_key(&self) -> &Jwk {
        &self.recovery_key
    }

    /// Returns the version of the recovery key the endpoint trusts.
    #[must_use]
    pub fn recovery_key_version(&self) -> u64 {
        self.recovery_key_version.get()
    }

    /// Receives one `senta-keyset` JWS and applies it if it is the next key
    /// set.
    ///
    /// The first of these to hold decides the result:
    ///
    /// 1. The JWS fails the reading before its signature is verified: that
    ///    failure's result.
    /// 2. Its `customer_endpoint_id` is not the state's: `WrongTarget`.
    /// 3. Its (epoch, version) is at most the state's (E, N): `Duplicate`,
    ///    without checking the signature, whoever signed it.
    /// 4. Its epoch is E and its version N + 2 or more: `KeysetGap`, without
    ///    checking the signature.
    /// 5. Its epoch is E and its version N + 1: signed by a revoked kid,
    ///    `RevokedKid`; by any kid but `current_kid`, `UnknownKid`; with a
    ///    signature that does not verify under `current_kid`'s key,
    ///    `BadSignature`. Otherwise `Applied`.
    /// 6. Its epoch is above E and its kid a customer kid: `KeysetGap`,
    ///    without checking the signature.
    /// 7. Its epoch is above E and its kid a recovery kid: a version other
    ///    than 1, `SchemaError`; a kid of another install or of a recovery
    ///    key version below the state's V, `UnknownKid`; of a version above
    ///    V, `RecoveryKeyGap`; a signature that does not verify under the
    ///    recovery key, `BadSignature`. Otherwise `Applied`, with an
    ///    [`EpochChange`]. The epoch may skip ahead by more than one.
    ///
    /// Applying replaces the whole key set with the document's: its epoch
    /// and version, `keys`, `current_kid`, `revoked_kids` and
    /// `customer_key_name`.
    pub fn receive_keyset(&mut self, jws: &str) -> KeysetReceipt {
        match documents::inspect_keyset(jws) {
            Ok(inspected) => self.receive_inspected_keyset(jws, &inspected),
            Err(error) => KeysetReceipt::without_epoch_change(error.result()),
        }
    }

    /// Receives one `senta-recovery-key` JWS and applies it if it is the
    /// next recovery key.
    ///
    /// The first of these to hold decides the result:
    ///
    /// 1. The JWS fails the reading before its signature is verified: that
    ///    failure's result.
    /// 2. Its `install_id` is not the state's: `WrongTarget`.
    /// 3. Its `recovery_key_version` is at most the state's V: `Duplicate`,
    ///    without checking the signature.
    /// 4. Its version is V + 2 or more: `RecoveryKeyGap`.
    /// 5. Its version is V + 1: a kid other than
    ///    `recovery-<install id>:<V>`, `UnknownKid`; a signature that does
    ///    not verify under the recovery key, `BadSignature`. Otherwise
    ///    `Applied`, and the document's key and version replace the state's.
    pub fn receive_recovery_key(&mut self, jws: &str) -> DocumentResult {
        match documents::inspect_recovery_key(jws) {
            Ok(inspected) => self.receive_inspected_recovery_key(jws, &inspected),
            Err(error) => error.result(),
        }
    }

    /// Receives a list of `senta-keyset` and `senta-recovery-key` JWSs in
    /// order, such as a catch-up chain or the key documents of a
    /// `Documents` message.
    ///
    /// Each document is read as a key set first; one whose `typ` is
    /// `senta-recovery-key` instead goes to
    /// [`receive_recovery_key`](Self::receive_recovery_key), and any other
    /// `typ` is a `SchemaError`. An `Applied` document changes the state and
    /// a `Duplicate` one is skipped; at any other result processing stops,
    /// and the documents after it are not processed. What the documents
    /// before it applied stays applied.
    pub fn receive_chain<S: AsRef<str>>(&mut self, chain: &[S]) -> ChainOutcome {
        let mut outcome = ChainOutcome::default();
        for jws in chain {
            let receipt = self.receive_chain_document(jws.as_ref());
            if let Some(change) = receipt.epoch_change {
                outcome.epoch_changes.push(change);
            }
            let proceed = matches!(
                receipt.result,
                DocumentResult::Applied | DocumentResult::Duplicate
            );
            outcome.results.push(receipt.result);
            if !proceed {
                outcome.stopped = true;
                break;
            }
        }
        outcome
    }

    fn receive_chain_document(&mut self, jws: &str) -> KeysetReceipt {
        match documents::inspect_keyset(jws) {
            Ok(inspected) => self.receive_inspected_keyset(jws, &inspected),
            Err(DocumentError::Verify(VerifyError::TypMismatch { header, .. }))
                if header.typ() == Typ::RecoveryKey.as_str() =>
            {
                KeysetReceipt::without_epoch_change(self.receive_recovery_key(jws))
            }
            Err(error) => KeysetReceipt::without_epoch_change(error.result()),
        }
    }

    fn receive_inspected_keyset(
        &mut self,
        jws: &str,
        inspected: &InspectedDocument<KeysetContent>,
    ) -> KeysetReceipt {
        let content = inspected.content();
        if content.customer_endpoint_id() != self.keyset.customer_endpoint_id() {
            return KeysetReceipt::without_epoch_change(DocumentResult::WrongTarget);
        }
        let have_epoch = self.recovery_epoch();
        let have_version = self.keyset_version();
        let epoch = content.recovery_epoch().get();
        let version = content.keyset_version().get();
        if (epoch, version) <= (have_epoch, have_version) {
            return KeysetReceipt::without_epoch_change(DocumentResult::Duplicate);
        }
        let gap = DocumentResult::KeysetGap {
            have_epoch,
            have_version,
        };
        let kid = inspected.kid();

        if epoch == have_epoch {
            // `version` is above `have_version` here.
            if version - have_version > 1 {
                return KeysetReceipt::without_epoch_change(gap);
            }
            if self.is_revoked(kid) {
                return KeysetReceipt::without_epoch_change(DocumentResult::RevokedKid);
            }
            if kid.as_str() != self.keyset.current_kid().as_str() {
                return KeysetReceipt::without_epoch_change(DocumentResult::UnknownKid);
            }
            let key_source = CurrentKidSource {
                keyset: &self.keyset,
            };
            return match documents::verify_keyset(jws, &key_source) {
                Ok(verified) => {
                    self.keyset = verified.into_content();
                    KeysetReceipt {
                        result: DocumentResult::Applied,
                        epoch_change: None,
                    }
                }
                Err(error) => KeysetReceipt::without_epoch_change(error.result()),
            };
        }

        // `epoch` is above `have_epoch` here.
        match kid.kind() {
            KeyKind::Customer => KeysetReceipt::without_epoch_change(gap),
            KeyKind::Recovery => {
                if version != 1 {
                    return KeysetReceipt::without_epoch_change(DocumentResult::SchemaError);
                }
                if kid.install_id() != Some(self.install_id.as_str()) {
                    return KeysetReceipt::without_epoch_change(DocumentResult::UnknownKid);
                }
                let have = self.recovery_key_version();
                match kid.version().map(|signer| signer.cmp(&have)) {
                    Some(std::cmp::Ordering::Equal) => {}
                    Some(std::cmp::Ordering::Greater) => {
                        return KeysetReceipt::without_epoch_change(
                            DocumentResult::RecoveryKeyGap { have },
                        );
                    }
                    Some(std::cmp::Ordering::Less) | None => {
                        return KeysetReceipt::without_epoch_change(DocumentResult::UnknownKid);
                    }
                }
                match documents::verify_keyset(jws, &self.recovery_key_source()) {
                    Ok(verified) => {
                        self.keyset = verified.into_content();
                        KeysetReceipt {
                            result: DocumentResult::Applied,
                            epoch_change: Some(EpochChange {
                                old_epoch: have_epoch,
                                new_epoch: self.recovery_epoch(),
                            }),
                        }
                    }
                    Err(error) => KeysetReceipt::without_epoch_change(error.result()),
                }
            }
            // The reading has already rejected every other kind for a key
            // set, as `WrongKeyClass`.
            KeyKind::Vendor | KeyKind::InstallSigning => {
                KeysetReceipt::without_epoch_change(DocumentResult::WrongKeyClass)
            }
        }
    }

    fn receive_inspected_recovery_key(
        &mut self,
        jws: &str,
        inspected: &InspectedDocument<RecoveryKeyContent>,
    ) -> DocumentResult {
        let content = inspected.content();
        if content.install_id != self.install_id {
            return DocumentResult::WrongTarget;
        }
        let have = self.recovery_key_version();
        let version = content.recovery_key_version.get();
        if version <= have {
            return DocumentResult::Duplicate;
        }
        if version - have > 1 {
            return DocumentResult::RecoveryKeyGap { have };
        }
        match documents::verify_recovery_key(jws, &self.recovery_key_source()) {
            Ok(verified) => {
                let content = verified.into_content();
                self.recovery_key = content.recovery_key;
                self.recovery_key_version = content.recovery_key_version;
                DocumentResult::Applied
            }
            Err(error) => error.result(),
        }
    }

    fn is_revoked(&self, kid: &Kid) -> bool {
        kid.kind() == KeyKind::Customer
            && self
                .keyset
                .revoked_kids()
                .iter()
                .any(|revoked| revoked.as_str() == kid.as_str())
    }

    fn recovery_key_source(&self) -> RecoveryKeySource {
        RecoveryKeySource {
            kid: recovery_kid(&self.install_id, self.recovery_key_version()),
            key: self.recovery_key,
        }
    }
}

impl KeySource for TrustState {
    /// Finds a customer key of the current key set.
    ///
    /// A kid that is not a customer kid, or a lookup that does not allow a
    /// customer key, is unknown. A kid of `keys`, compared as the whole kid
    /// string, is found as a customer key; one of `revoked_kids` is revoked;
    /// any other is unknown.
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        if !allowed.contains(&KeyKind::Customer) || kid.kind() != KeyKind::Customer {
            return KeyLookup::Unknown;
        }
        if let Some(entry) = self
            .keyset
            .keys()
            .iter()
            .find(|entry| entry.kid.as_str() == kid.as_str())
        {
            return KeyLookup::Found {
                key: entry.key.public_key(),
                kind: KeyKind::Customer,
            };
        }
        if self.is_revoked(kid) {
            KeyLookup::Revoked
        } else {
            KeyLookup::Unknown
        }
    }
}

/// The key lookup for the next key set of the same epoch: only the current
/// key set's `current_kid`.
struct CurrentKidSource<'a> {
    keyset: &'a KeysetContent,
}

impl KeySource for CurrentKidSource<'_> {
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        let current = self.keyset.current_kid();
        if !allowed.contains(&KeyKind::Customer)
            || kid.kind() != KeyKind::Customer
            || kid.as_str() != current.as_str()
        {
            return KeyLookup::Unknown;
        }
        self.keyset
            .keys()
            .iter()
            .find(|entry| entry.kid == *current)
            .map_or(KeyLookup::Unknown, |entry| KeyLookup::Found {
                key: entry.key.public_key(),
                kind: KeyKind::Customer,
            })
    }
}

/// The key lookup for a document the recovery key signs: only the recovery
/// key the endpoint trusts, under `recovery-<install id>:<version>`.
struct RecoveryKeySource {
    kid: String,
    key: Jwk,
}

impl KeySource for RecoveryKeySource {
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        if allowed.contains(&KeyKind::Recovery)
            && kid.kind() == KeyKind::Recovery
            && kid.as_str() == self.kid
        {
            KeyLookup::Found {
                key: self.key.public_key(),
                kind: KeyKind::Recovery,
            }
        } else {
            KeyLookup::Unknown
        }
    }
}
