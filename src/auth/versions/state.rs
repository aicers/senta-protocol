//! The stored state of the document version state machine.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DocumentContent, Slot};
use crate::auth::jws::strict::LowerUuid;

/// The whole document version state of an endpoint, as a [`VersionStore`]
/// keeps it.
///
/// It holds the recovery epoch the versions belong to, the endpoint's own
/// id once it has one, and for each [`Slot`] that holds anything: the
/// verified version with its content hash, the pending document, the count
/// of failed applications, whether the version is halted and why the last
/// application failed, the applied version, the current document with its
/// recovery epoch and version, and whether that document is not trusted.
///
/// It serializes and deserializes through serde; a state read back behaves
/// as the one written. Only [`DocumentVersions`] makes or changes one.
///
/// [`VersionStore`]: super::VersionStore
/// [`DocumentVersions`]: super::DocumentVersions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionState {
    pub(super) epoch: u64,
    pub(super) endpoint_id: Option<LowerUuid>,
    #[serde(with = "slot_entries")]
    pub(super) slots: BTreeMap<Slot, SlotState>,
}

impl VersionState {
    pub(super) fn new(epoch: u64) -> Self {
        Self {
            epoch,
            endpoint_id: None,
            slots: BTreeMap::new(),
        }
    }
}

/// The state of one slot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SlotState {
    /// The verified version and its content hash.
    pub(super) verified: Option<VerifiedVersion>,
    /// The verified content not yet applied.
    pub(super) pending: Option<DocumentContent>,
    /// How many times applying the verified version failed.
    pub(super) failures: u32,
    /// Whether the verified version is no longer tried.
    pub(super) halted: bool,
    /// Why the last application failed.
    pub(super) last_failure: Option<String>,
    /// The applied version.
    pub(super) applied: Option<u64>,
    /// The document applied last, in this recovery epoch or an earlier
    /// one.
    pub(super) current: Option<CurrentDocument>,
    /// Whether `current` was applied in an earlier recovery epoch.
    pub(super) untrusted: bool,
}

impl SlotState {
    /// Records `content`, of `version` with the content hash
    /// `payload_hash`, as the pending document, with no failure yet.
    pub(super) fn accept(
        &mut self,
        version: u64,
        payload_hash: [u8; 32],
        content: DocumentContent,
    ) {
        self.verified = Some(VerifiedVersion {
            version,
            payload_hash,
        });
        self.pending = Some(content);
        self.clear_failures();
    }

    /// Records `content` as applied: the applied version and the current
    /// document are its, it is trusted, and nothing is pending.
    pub(super) fn complete(&mut self, content: DocumentContent) {
        let version = content.version();
        self.applied = Some(version);
        self.current = Some(CurrentDocument {
            epoch: content.recovery_epoch(),
            version,
            content,
        });
        self.untrusted = false;
        self.pending = None;
        self.clear_failures();
    }

    pub(super) fn clear_failures(&mut self) {
        self.failures = 0;
        self.halted = false;
        self.last_failure = None;
    }
}

/// A verified version and the SHA-256 of its content bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifiedVersion {
    pub(super) version: u64,
    pub(super) payload_hash: [u8; 32],
}

/// The document a slot applied last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentDocument {
    pub(super) epoch: u64,
    pub(super) version: u64,
    pub(super) content: DocumentContent,
}

/// Serializes the slots as a list of `{slot, state}` entries, since a slot
/// that carries a group id is no map key a format such as JSON takes.
mod slot_entries {
    use std::collections::BTreeMap;

    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Slot, SlotState};

    #[derive(Serialize)]
    struct EntryRef<'a> {
        slot: &'a Slot,
        state: &'a SlotState,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        slot: Slot,
        state: SlotState,
    }

    pub(super) fn serialize<S: Serializer>(
        slots: &BTreeMap<Slot, SlotState>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(slots.iter().map(|(slot, state)| EntryRef { slot, state }))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Slot, SlotState>, D::Error> {
        let mut slots = BTreeMap::new();
        for entry in Vec::<Entry>::deserialize(deserializer)? {
            if slots.insert(entry.slot, entry.state).is_some() {
                return Err(D::Error::custom("a slot appears twice"));
            }
        }
        Ok(slots)
    }
}
