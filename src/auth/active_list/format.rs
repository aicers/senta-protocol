//! The active list's entries and the updates that carry them.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::spki_eq;
use crate::connection::{DecodeError, EncodeError, cbor};
use crate::standing::SuspendReason;

/// What an endpoint on the active list may do.
///
/// It decodes from the three tags below only: a tag this crate does not
/// know is an error, so that a state not understood is never guessed at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// The endpoint may send everything. Tagged `active`.
    Active,
    /// The endpoint is registered and its license is not yet granted.
    /// Tagged `license_pending`.
    LicensePending,
    /// The endpoint is suspended, for `reason`. Tagged `suspended`, as the
    /// one-entry map `{"suspended": {"reason": reason}}`.
    ///
    /// An entry whose `reason` is [`SuspendReason::Other`] decodes, and is
    /// refused when the update holding it is applied.
    Suspended {
        /// Why the endpoint is suspended.
        reason: SuspendReason,
    },
}

/// What an operator decided about an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorStatus {
    /// The operator leaves the endpoint active.
    Active,
    /// The operator suspended the endpoint.
    Suspended,
    /// The operator revoked the endpoint's registration.
    Revoked,
}

/// What the license holds against an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenseRestriction {
    /// The license covers the endpoint.
    None,
    /// The license for the endpoint is not yet granted.
    Pending,
    /// The license does not cover the endpoint.
    Suspended,
}

impl EntryState {
    /// Combines an operator's decision and the license's restriction into
    /// one state.
    ///
    /// The strongest wins, from strongest to weakest `Revoked`, `Operator`,
    /// `License`, `LicensePending` and `Active`: a revoked endpoint is
    /// suspended as [`SuspendReason::Revoked`], a suspended one as
    /// [`SuspendReason::Operator`]; otherwise a license suspension is
    /// [`SuspendReason::License`], a pending license
    /// [`EntryState::LicensePending`], and anything else
    /// [`EntryState::Active`].
    #[must_use]
    pub fn combine(operator: OperatorStatus, license: LicenseRestriction) -> Self {
        match (operator, license) {
            (OperatorStatus::Revoked, _) => Self::Suspended {
                reason: SuspendReason::Revoked,
            },
            (OperatorStatus::Suspended, _) => Self::Suspended {
                reason: SuspendReason::Operator,
            },
            (OperatorStatus::Active, LicenseRestriction::Suspended) => Self::Suspended {
                reason: SuspendReason::License,
            },
            (OperatorStatus::Active, LicenseRestriction::Pending) => Self::LicensePending,
            (OperatorStatus::Active, LicenseRestriction::None) => Self::Active,
        }
    }
}

/// One endpoint on the active list.
///
/// Its equality compares `spki_sha256` in constant time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    /// The endpoint's id.
    #[serde(with = "cbor::uuid")]
    pub endpoint_id: Uuid,
    /// The SHA-256 of the endpoint's SubjectPublicKeyInfo, as
    /// [`crate::auth::tls::peer_spki_hash`] computes it. A byte string of
    /// any other length than 32 fails to decode.
    #[serde(with = "cbor::bytes")]
    pub spki_sha256: [u8; 32],
    /// The id the customer knows the endpoint by.
    #[serde(with = "cbor::uuid")]
    pub customer_endpoint_id: Uuid,
    /// What the endpoint may do.
    pub state: EntryState,
}

impl PartialEq for ListEntry {
    fn eq(&self, other: &Self) -> bool {
        // Every field is compared, so the SPKI comparison's time does not
        // depend on the other fields either.
        let spki = spki_eq(&self.spki_sha256, &other.spki_sha256);
        let ids = self.endpoint_id == other.endpoint_id
            && self.customer_endpoint_id == other.customer_endpoint_id;
        spki & ids & (self.state == other.state)
    }
}

impl Eq for ListEntry {}

/// An update of the active list, pushed by REview to an ingress.
///
/// # CBOR shape
///
/// A one-entry map from the tag `full` or `diff` to the variant's field
/// map, decoded by [`crate::connection::cbor::from_slice`]: a map holding a
/// key twice at any depth fails to decode, and a field this crate does not
/// know is ignored at any depth. An entry is the map of [`ListEntry`]'s
/// fields, a UUID a byte string of 16 bytes, and a version an unsigned
/// integer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListUpdate {
    /// The whole list, replacing whatever list there was, whatever its
    /// version. Tagged `full`.
    Full {
        /// The version of this list.
        version: u64,
        /// Every endpoint on the list.
        entries: Vec<ListEntry>,
    },
    /// The changes from the list at `base_version` to the list at
    /// `version`. Tagged `diff`.
    Diff {
        /// The version the changes apply to.
        base_version: u64,
        /// The version of the list they make.
        version: u64,
        /// The entries added, or replacing the entry with the same
        /// `endpoint_id`.
        upserts: Vec<ListEntry>,
        /// The `endpoint_id`s of the entries removed.
        #[serde(with = "uuid_list")]
        removals: Vec<Uuid>,
    },
}

impl ListUpdate {
    /// Decodes an update from its CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not one well-formed CBOR value,
    /// hold a map with a duplicate key, or are not the shape of an update:
    /// among others an `spki_sha256` that is not 32 bytes, and a `state`
    /// tag this crate does not know.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        cbor::from_slice(bytes)
    }

    /// Encodes the update as CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoder fails, which it does not for any
    /// value of this type.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        cbor::to_vec(self)
    }
}

/// A serde helper writing a list of UUIDs as an array of 16-byte byte
/// strings.
mod uuid_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    use crate::connection::cbor;

    #[derive(Serialize, Deserialize)]
    struct Repr(#[serde(with = "cbor::uuid")] Uuid);

    pub(super) fn serialize<S: Serializer>(
        value: &[Uuid],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(|id| Repr(*id)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Uuid>, D::Error> {
        let ids = Vec::<Repr>::deserialize(deserializer)?;
        Ok(ids.into_iter().map(|Repr(id)| id).collect())
    }
}
