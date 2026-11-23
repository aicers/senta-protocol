//! The active list: which endpoints an ingress takes messages from, and
//! what each may send.
//!
//! REview pushes the list to the event store's ingress as [`ListUpdate`]s,
//! a full list or a diff from a version, and holds one itself. Each entry
//! ([`ListEntry`]) names an endpoint by its key's SPKI hash and carries an
//! [`EntryState`], which [`EntryState::combine`] makes from an operator's
//! decision and the license.
//!
//! [`ActiveList`] holds the list applied, and the connections open at the
//! ingress: after the TLS handshake, the caller registers each connection
//! with the SPKI hash of its peer's key, and [`ActiveList::standing`] judges
//! it. A connection with the key of one already open replaces it, and a key
//! whose connections replace each other too often from more than one
//! address is reported as a [`DuplicateKey`]. At the event store's ingress
//! the list is held under a [`Lease`]: unless REview confirms the version
//! applied within the lease's length, every endpoint is refused.
//!
//! [`allowed`] decides from an endpoint's [`Standing`] and a message's `t`
//! whether the message is taken, before its body is read;
//! [`Admission::to_standing_verdict`], with the `telemetry` feature, turns
//! that into the standing check of a
//! [`crate::connection::ServerConnection`]. [`Standing::receive_limit`]
//! picks the frame size limit and [`Standing::suspend_notice`] whether a
//! control server tells the endpoint it is suspended.
//!
//! Everything here is sans-IO. The monotonic time is passed in as a
//! [`std::time::Duration`] since an origin of the caller's choosing, and
//! what to close, send or report comes back as values. Nothing is
//! persisted.
//!
//! SPKI hashes are compared in constant time, by
//! [`subtle::ConstantTimeEq`], wherever they are compared: looking a key
//! up included.
//!
//! ```
//! use std::time::Duration;
//!
//! use senta_protocol::auth::active_list::{
//!     ActiveList, ConnectionId, EntryState, Lease, ListEntry, ListUpdate, Standing,
//! };
//! use uuid::Uuid;
//!
//! let spki = [7; 32];
//! let mut list = ActiveList::new(Some(Lease::default()));
//! assert_eq!(list.standing(&spki, Duration::ZERO).standing, Standing::Unready);
//!
//! let update = ListUpdate::Full {
//!     version: 1,
//!     entries: vec![ListEntry {
//!         endpoint_id: Uuid::from_u128(1),
//!         spki_sha256: spki,
//!         customer_endpoint_id: Uuid::from_u128(2),
//!         state: EntryState::Active,
//!     }],
//! };
//! let update = ListUpdate::decode(&update.encode()?)?;
//! let outcome = list.apply(update, Duration::from_secs(1));
//! assert_eq!(outcome.result?.version, 1);
//!
//! let _ = list.register(
//!     ConnectionId(1),
//!     &spki,
//!     "192.0.2.1".parse()?,
//!     Duration::from_secs(2),
//! );
//! let standing = list.standing(&spki, Duration::from_secs(3));
//! assert_eq!(standing.standing, Standing::Active);
//! assert_eq!(standing.identity.map(|id| id.endpoint_id), Some(Uuid::from_u128(1)));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod admission;
mod format;
mod list;
#[cfg(test)]
mod tests;

use std::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;

pub use self::admission::{Admission, ConnectionStanding, EndpointIdentity, Standing, allowed};
pub use self::format::{EntryState, LicenseRestriction, ListEntry, ListUpdate, OperatorStatus};
pub use self::list::{
    ActiveList, Applied, ApplyError, ApplyOutcome, ConfirmOutcome, ConnectionChange, ConnectionId,
    DEFAULT_LEASE_LENGTH, DUPLICATE_KEY_THRESHOLD, DUPLICATE_KEY_WINDOW, DuplicateKey, Lease,
    RegisterOutcome,
};

/// Compares two SPKI hashes in constant time.
fn spki_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// An SPKI hash as a map key, compared in constant time.
#[derive(Debug, Clone, Copy)]
struct SpkiKey([u8; 32]);

impl PartialEq for SpkiKey {
    fn eq(&self, other: &Self) -> bool {
        spki_eq(&self.0, &other.0)
    }
}

impl Eq for SpkiKey {}

impl Hash for SpkiKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
