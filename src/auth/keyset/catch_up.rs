//! Building the catch-up chain on the server side: the key set and recovery
//! key documents an endpoint missed, in the order it can apply them.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ops::Bound;

use uuid::Uuid;

use super::recovery_kid;
use crate::auth::documents::{self, DocumentError, InstallId};
use crate::auth::jws::KeyKind;

/// What the endpoint already trusts, from which the chain starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatchUpBaseline {
    /// The recovery epoch of the key set the endpoint trusts.
    pub recovery_epoch: u64,
    /// The version, within that epoch, of the key set the endpoint trusts.
    pub keyset_version: u64,
    /// The version of the recovery key the endpoint trusts.
    pub recovery_key_version: u64,
}

/// Why the history given to [`build_catch_up_chain`] makes no catch-up
/// chain.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatchUpError {
    /// A key set document does not read as a `senta-keyset`.
    #[error("key set document {index} does not read as a `senta-keyset`")]
    UnreadableKeyset {
        /// Its index in the key set documents.
        index: usize,
        /// Why it does not read.
        #[source]
        source: DocumentError,
    },
    /// A recovery key document does not read as a `senta-recovery-key`.
    #[error("recovery key document {index} does not read as a `senta-recovery-key`")]
    UnreadableRecoveryKey {
        /// Its index in the recovery key documents.
        index: usize,
        /// Why it does not read.
        #[source]
        source: DocumentError,
    },
    /// A key set document is for another customer endpoint id.
    #[error("key set document {index} is for another customer endpoint id")]
    KeysetWrongCustomer {
        /// Its index in the key set documents.
        index: usize,
    },
    /// A key set document is signed by the recovery key of another install.
    #[error("key set document {index} is signed by another install's recovery key")]
    KeysetForeignRecoveryKey {
        /// Its index in the key set documents.
        index: usize,
    },
    /// A recovery key document is for another install.
    #[error("recovery key document {index} is for another install")]
    RecoveryKeyWrongInstall {
        /// Its index in the recovery key documents.
        index: usize,
    },
    /// A recovery key document of version `v` is not signed by
    /// `recovery-<install id>:<v - 1>`.
    #[error(
        "recovery key document {index}, of version {version}, is not signed by the recovery key \
         before it"
    )]
    RecoveryKeyWrongSigner {
        /// Its index in the recovery key documents.
        index: usize,
        /// Its `recovery_key_version`.
        version: u64,
    },
    /// Two key set documents of the same (epoch, version) differ in content.
    #[error("key set documents of epoch {epoch} version {version} differ in content")]
    KeysetConflict {
        /// The recovery epoch.
        epoch: u64,
        /// The version.
        version: u64,
    },
    /// Two recovery key documents of the same version differ in content.
    #[error("recovery key documents of version {version} differ in content")]
    RecoveryKeyConflict {
        /// The recovery key version.
        version: u64,
    },
    /// A key set version is missing.
    #[error("key set epoch {epoch} version {version} is missing")]
    MissingKeyset {
        /// The recovery epoch.
        epoch: u64,
        /// The missing version.
        version: u64,
    },
    /// A recovery key version is missing.
    #[error("recovery key version {version} is missing")]
    MissingRecoveryKey {
        /// The missing version.
        version: u64,
    },
    /// The version 1 of an epoch after the baseline's has no copy signed by
    /// a recovery key, only re-signed ones.
    #[error("key set epoch {epoch} version 1 has no copy signed by a recovery key")]
    MissingRecoverySigned {
        /// The recovery epoch.
        epoch: u64,
    },
    /// The version 1 of an epoch is signed by a recovery key older than the
    /// one the endpoint trusts at that point of the chain.
    #[error(
        "key set epoch {epoch} version 1 is signed by recovery key {signer}, older than the \
         trusted {trusted}"
    )]
    RecoverySignerBehind {
        /// The recovery epoch.
        epoch: u64,
        /// The version of the recovery key that signed it.
        signer: u64,
        /// The recovery key version the endpoint trusts at that point.
        trusted: u64,
    },
    /// The version 1 of an epoch is signed by a recovery key newer than any
    /// the history reaches.
    #[error(
        "key set epoch {epoch} version 1 is signed by recovery key {signer}, beyond the highest \
         reachable {reachable}"
    )]
    RecoverySignerAhead {
        /// The recovery epoch.
        epoch: u64,
        /// The version of the recovery key that signed it.
        signer: u64,
        /// The highest recovery key version the history reaches.
        reachable: u64,
    },
}

/// One signed copy of a key set.
struct KeysetCopy<'a> {
    jws: &'a str,
    /// The version of the recovery key that signed it, or `None` for a
    /// customer key.
    recovery_signer: Option<u64>,
}

/// The copies of one key set (epoch, version), all of the same content.
struct KeysetGroup<'a> {
    payload_hash: [u8; 32],
    copies: Vec<KeysetCopy<'a>>,
}

/// The copies of one recovery key version, all of the same content.
struct RecoveryKeyGroup<'a> {
    payload_hash: [u8; 32],
    copies: Vec<&'a str>,
}

/// Builds the catch-up chain for an endpoint at `baseline`, from the
/// history of one customer and one install.
///
/// `keysets` and `recovery_keys` are every `senta-keyset` and
/// `senta-recovery-key` JWS kept for the customer `customer_endpoint_id`
/// and the install `install_id`, in any order. **No signature is
/// verified**: the server carries the documents as the signer issued them,
/// so every document is only read, as
/// [`inspect_keyset`](documents::inspect_keyset) and
/// [`inspect_recovery_key`](documents::inspect_recovery_key) read it. The
/// signers are checked only as far as the errors below say; any other is
/// assumed to be right, as it is in a history the signer issued.
///
/// Copies of the same key set (epoch, version), or of the same recovery
/// key version, with the same content hash are one document. The copy the
/// chain carries is the one whose JWS is smallest byte by byte: among the
/// copies signed by a recovery key, for the version 1 of an epoch above the
/// baseline's, and among all copies otherwise.
///
/// The chain holds every key set above the baseline's (epoch, version) and
/// every recovery key above its version, in the order the endpoint applies
/// them:
///
/// 1. the baseline epoch's versions after the baseline's, in order;
/// 2. for each later epoch in order, the recovery key replacements not yet
///    placed up to the version that signed its version 1, then that
///    version 1 signed by the recovery key, then its versions from 2 in
///    order;
/// 3. the remaining recovery key replacements, in order.
///
/// A history no newer than the baseline gives an empty chain. The output
/// is the same for the same documents in any order.
///
/// # Errors
///
/// Returns [`CatchUpError`] when the history makes no chain, checking every
/// document, those at or below the baseline included:
///
/// - a document does not read;
/// - a key set is for another `customer_endpoint_id`, a recovery key for
///   another `install_id`, or a key set is signed by the recovery key of
///   another install;
/// - a recovery key of version `v` is not signed by
///   `recovery-<install_id>:<v - 1>`;
/// - two documents of the same key set (epoch, version), or of the same
///   recovery key version, differ in content;
/// - a version is missing: of the baseline epoch after the baseline's
///   version, of a later epoch from 1, or of the recovery key after the
///   baseline's, each up to the highest given;
/// - the version 1 of an epoch after the baseline's has no copy signed by a
///   recovery key;
/// - that copy's recovery key is older than the one the endpoint trusts at
///   that point of the chain, or newer than the highest the history
///   reaches: the baseline's or the highest replacement given.
pub fn build_catch_up_chain<'a, K: AsRef<str>, R: AsRef<str>>(
    customer_endpoint_id: Uuid,
    install_id: &InstallId,
    keysets: &'a [K],
    recovery_keys: &'a [R],
    baseline: CatchUpBaseline,
) -> Result<Vec<&'a str>, CatchUpError> {
    let keysets = group_keysets(customer_endpoint_id, install_id, keysets)?;
    let recovery_keys = group_recovery_keys(install_id, recovery_keys)?;

    let highest_recovery_key = recovery_keys
        .keys()
        .next_back()
        .copied()
        .unwrap_or(0)
        .max(baseline.recovery_key_version);
    let mut trusted_recovery_key = baseline.recovery_key_version;
    let mut chain = Vec::new();
    let mut epoch = baseline.recovery_epoch;
    let mut last_version = baseline.keyset_version;

    let after_baseline = (
        Bound::Excluded((baseline.recovery_epoch, baseline.keyset_version)),
        Bound::Unbounded,
    );
    for (&(group_epoch, version), group) in keysets.range(after_baseline) {
        if group_epoch == epoch {
            let expected = last_version.saturating_add(1);
            if version != expected {
                return Err(CatchUpError::MissingKeyset {
                    epoch,
                    version: expected,
                });
            }
            chain.push(smallest(group.copies.iter().map(|copy| copy.jws)));
            last_version = version;
            continue;
        }

        // A later epoch starts with its version 1, signed by a recovery key.
        if version != 1 {
            return Err(CatchUpError::MissingKeyset {
                epoch: group_epoch,
                version: 1,
            });
        }
        let Some((jws, signer)) = group
            .copies
            .iter()
            .filter_map(|copy| copy.recovery_signer.map(|signer| (copy.jws, signer)))
            .min_by_key(|&(jws, _)| jws)
        else {
            return Err(CatchUpError::MissingRecoverySigned { epoch: group_epoch });
        };
        if signer < trusted_recovery_key {
            return Err(CatchUpError::RecoverySignerBehind {
                epoch: group_epoch,
                signer,
                trusted: trusted_recovery_key,
            });
        }
        if signer > highest_recovery_key {
            return Err(CatchUpError::RecoverySignerAhead {
                epoch: group_epoch,
                signer,
                reachable: highest_recovery_key,
            });
        }
        push_recovery_keys(&mut chain, &recovery_keys, trusted_recovery_key, signer)?;
        trusted_recovery_key = signer;
        chain.push(jws);
        epoch = group_epoch;
        last_version = 1;
    }
    push_recovery_keys(
        &mut chain,
        &recovery_keys,
        trusted_recovery_key,
        highest_recovery_key,
    )?;
    Ok(chain)
}

/// Reads every key set, checks it, and groups the copies by (epoch,
/// version).
fn group_keysets<'a, K: AsRef<str>>(
    customer_endpoint_id: Uuid,
    install_id: &InstallId,
    keysets: &'a [K],
) -> Result<BTreeMap<(u64, u64), KeysetGroup<'a>>, CatchUpError> {
    let mut groups: BTreeMap<(u64, u64), KeysetGroup<'a>> = BTreeMap::new();
    for (index, jws) in keysets.iter().enumerate() {
        let jws = jws.as_ref();
        let inspected = documents::inspect_keyset(jws)
            .map_err(|source| CatchUpError::UnreadableKeyset { index, source })?;
        let content = inspected.content();
        if content.customer_endpoint_id().get() != customer_endpoint_id {
            return Err(CatchUpError::KeysetWrongCustomer { index });
        }
        let kid = inspected.kid();
        let recovery_signer = if kid.kind() == KeyKind::Recovery {
            if kid.install_id() != Some(install_id.as_str()) {
                return Err(CatchUpError::KeysetForeignRecoveryKey { index });
            }
            kid.version()
        } else {
            None
        };
        let epoch = content.recovery_epoch().get();
        let version = content.keyset_version().get();
        let copy = KeysetCopy {
            jws,
            recovery_signer,
        };
        match groups.entry((epoch, version)) {
            Entry::Vacant(entry) => {
                entry.insert(KeysetGroup {
                    payload_hash: *inspected.payload_hash(),
                    copies: vec![copy],
                });
            }
            Entry::Occupied(mut entry) => {
                let group = entry.get_mut();
                if group.payload_hash != *inspected.payload_hash() {
                    return Err(CatchUpError::KeysetConflict { epoch, version });
                }
                group.copies.push(copy);
            }
        }
    }
    Ok(groups)
}

/// Reads every recovery key, checks it, and groups the copies by version.
fn group_recovery_keys<'a, R: AsRef<str>>(
    install_id: &InstallId,
    recovery_keys: &'a [R],
) -> Result<BTreeMap<u64, RecoveryKeyGroup<'a>>, CatchUpError> {
    let mut groups: BTreeMap<u64, RecoveryKeyGroup<'a>> = BTreeMap::new();
    for (index, jws) in recovery_keys.iter().enumerate() {
        let jws = jws.as_ref();
        let inspected = documents::inspect_recovery_key(jws)
            .map_err(|source| CatchUpError::UnreadableRecoveryKey { index, source })?;
        let content = inspected.content();
        if content.install_id != *install_id {
            return Err(CatchUpError::RecoveryKeyWrongInstall { index });
        }
        let version = content.recovery_key_version.get();
        // A version 1 has no key before it, so no kid can be its signer.
        let signed_by_previous = version
            .checked_sub(1)
            .is_some_and(|previous| inspected.kid().as_str() == recovery_kid(install_id, previous));
        if !signed_by_previous {
            return Err(CatchUpError::RecoveryKeyWrongSigner { index, version });
        }
        match groups.entry(version) {
            Entry::Vacant(entry) => {
                entry.insert(RecoveryKeyGroup {
                    payload_hash: *inspected.payload_hash(),
                    copies: vec![jws],
                });
            }
            Entry::Occupied(mut entry) => {
                let group = entry.get_mut();
                if group.payload_hash != *inspected.payload_hash() {
                    return Err(CatchUpError::RecoveryKeyConflict { version });
                }
                group.copies.push(jws);
            }
        }
    }
    Ok(groups)
}

/// Appends the recovery keys after `from` up to `to`, in order.
fn push_recovery_keys<'a>(
    chain: &mut Vec<&'a str>,
    recovery_keys: &BTreeMap<u64, RecoveryKeyGroup<'a>>,
    from: u64,
    to: u64,
) -> Result<(), CatchUpError> {
    let mut version = from;
    while version < to {
        version += 1;
        let group = recovery_keys
            .get(&version)
            .ok_or(CatchUpError::MissingRecoveryKey { version })?;
        chain.push(smallest(group.copies.iter().copied()));
    }
    Ok(())
}

/// Returns the JWS that is smallest byte by byte.
fn smallest<'a>(copies: impl Iterator<Item = &'a str>) -> &'a str {
    copies
        .min()
        .expect("every group is made with one copy and only grows")
}
