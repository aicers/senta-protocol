//! The active list an ingress holds, the lease on it, and the connections
//! it judges.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use uuid::Uuid;

use super::admission::{ConnectionStanding, EndpointIdentity, Standing};
use super::format::{EntryState, ListEntry, ListUpdate};
use super::{SpkiKey, spki_eq};
use crate::standing::SuspendReason;

/// The lease length a [`Lease`] starts with: 30 minutes.
pub const DEFAULT_LEASE_LENGTH: Duration = Duration::from_secs(30 * 60);

/// How far back replacements of one key's connection are counted toward a
/// [`DuplicateKey`]: 10 minutes.
pub const DUPLICATE_KEY_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How many replacements within [`DUPLICATE_KEY_WINDOW`], from at least two
/// addresses, make a [`DuplicateKey`].
pub const DUPLICATE_KEY_THRESHOLD: usize = 3;

/// The caller's identifier of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(pub u64);

/// The lease an event store ingress holds on its active list: unless it is
/// extended within its length, every endpoint is refused.
///
/// It is extended when a confirmation names the version applied, and when a
/// full list is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    length: Duration,
    extended_at: Option<Duration>,
    expiry_delivered: bool,
}

impl Lease {
    /// Creates a lease of the given length, not yet started: it starts when
    /// the first full list is applied.
    #[must_use]
    pub fn new(length: Duration) -> Self {
        Self {
            length,
            extended_at: None,
            expiry_delivered: false,
        }
    }

    /// Returns the lease length.
    #[must_use]
    pub fn length(&self) -> Duration {
        self.length
    }

    /// Returns when the lease expires on the monotonic clock: the last
    /// extension plus the length. `None` before the lease starts, and when
    /// the sum overflows, in which case it never expires.
    fn deadline(&self) -> Option<Duration> {
        self.extended_at?.checked_add(self.length)
    }

    fn is_expired(&self, now: Duration) -> bool {
        self.deadline().is_some_and(|deadline| now >= deadline)
    }

    fn extend(&mut self, now: Duration) {
        self.extended_at = Some(now);
        self.expiry_delivered = false;
    }
}

impl Default for Lease {
    /// Returns a lease of [`DEFAULT_LEASE_LENGTH`].
    fn default() -> Self {
        Self::new(DEFAULT_LEASE_LENGTH)
    }
}

/// Why an update was refused. A refused update changes nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError {
    /// A diff's `base_version` is not the version applied, or no full list
    /// has been applied yet. A diff is checked for this before anything
    /// else, so it is the refusal of any such diff, malformed or not.
    #[error("the diff applies to version {base_version}, and the list is at {current:?}")]
    VersionMismatch {
        /// The diff's `base_version`.
        base_version: u64,
        /// The version applied, `None` before the first full list.
        current: Option<u64>,
    },
    /// A diff's `version` is not greater than its `base_version`.
    #[error("the diff's version {version} does not follow its base version {base_version}")]
    VersionNotAdvanced {
        /// The diff's `base_version`.
        base_version: u64,
        /// The diff's `version`.
        version: u64,
    },
    /// An entry is suspended for a reason this crate does not know.
    #[error("the entry for endpoint {endpoint_id} is suspended for an unknown reason")]
    UnknownReason {
        /// The entry's `endpoint_id`.
        endpoint_id: Uuid,
    },
    /// A full list holds two entries with the same `endpoint_id`, or a diff
    /// names one twice among its upserts, or among both its upserts and
    /// its removals.
    #[error("endpoint {endpoint_id} appears more than once")]
    RepeatedEndpoint {
        /// The repeated `endpoint_id`.
        endpoint_id: Uuid,
    },
    /// Two entries of the list the update makes have the same
    /// `spki_sha256`.
    #[error("endpoints {first} and {second} share a key")]
    DuplicateSpki {
        /// One entry's `endpoint_id`.
        first: Uuid,
        /// The other's.
        second: Uuid,
    },
}

/// An open connection whose standing or identity an applied update changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionChange {
    /// The connection.
    pub connection: ConnectionId,
    /// Its standing now.
    pub standing: Standing,
    /// The ids of the entry its key matches now, if any.
    pub identity: Option<EndpointIdentity>,
    /// Whether to close the connection: the entry its key matched is gone,
    /// or is now another endpoint's. The ids a connection was judged under
    /// do not change while it is open.
    pub close: bool,
}

/// What an applied update did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The version now applied.
    pub version: u64,
    /// The open connections whose standing or identity changed, by
    /// connection id.
    pub changes: Vec<ConnectionChange>,
}

/// What [`ActiveList::apply`] comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ApplyOutcome {
    /// When the lease's expiry came to light in this call, the connections
    /// open at that moment, to send `lease_expired` and close. They are in
    /// no [`Applied::changes`].
    pub expired: Option<Vec<ConnectionId>>,
    /// The update applied, or why it was refused.
    pub result: Result<Applied, ApplyError>,
}

/// What [`ActiveList::confirm`] comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ConfirmOutcome {
    /// As [`ApplyOutcome::expired`].
    pub expired: Option<Vec<ConnectionId>>,
    /// Whether the lease was extended: the list has a lease and the
    /// version confirmed is the one applied.
    pub extended: bool,
}

/// One key's connections replaced each other too often, from more than one
/// address: two hosts may hold the same key.
///
/// Its equality compares `spki_sha256` in constant time.
#[derive(Debug, Clone)]
pub struct DuplicateKey {
    /// The key's SPKI hash.
    pub spki_sha256: [u8; 32],
    /// The `endpoint_id` of the entry with that key, if the list has one.
    pub endpoint_id: Option<Uuid>,
    /// The distinct source addresses of the connections in the
    /// replacements counted, closed and new alike, in ascending order.
    pub addresses: Vec<IpAddr>,
    /// How many replacements were counted.
    pub replacements: usize,
}

impl PartialEq for DuplicateKey {
    fn eq(&self, other: &Self) -> bool {
        let spki = spki_eq(&self.spki_sha256, &other.spki_sha256);
        spki & (self.endpoint_id == other.endpoint_id)
            & (self.addresses == other.addresses)
            & (self.replacements == other.replacements)
    }
}

impl Eq for DuplicateKey {}

/// What [`ActiveList::register`] comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RegisterOutcome {
    /// As [`ApplyOutcome::expired`]; the connection registered is never in
    /// it.
    pub expired: Option<Vec<ConnectionId>>,
    /// The connection the new one replaced, to close: the one open with the
    /// same key.
    pub replaced: Option<ConnectionId>,
    /// The duplicate key this replacement revealed, to report to REview.
    pub duplicate_key: Option<DuplicateKey>,
}

/// The list applied: its version, its entries, and its keys.
#[derive(Debug, Clone)]
struct Listed {
    version: u64,
    entries: HashMap<Uuid, ListEntry>,
    by_spki: HashMap<SpkiKey, Uuid>,
}

impl Listed {
    fn entry(&self, spki: &SpkiKey) -> Option<&ListEntry> {
        self.by_spki.get(spki).and_then(|id| self.entries.get(id))
    }
}

#[derive(Debug, Clone)]
struct ConnectionRecord {
    spki: SpkiKey,
    address: IpAddr,
    /// Whether the connection was among those a lease expiry returned: it
    /// is already to be closed, and no later result names it again.
    expired: bool,
}

#[derive(Debug, Clone, Copy)]
struct Replacement {
    at: Duration,
    addresses: [IpAddr; 2],
}

/// The active list an ingress holds, with the connections it judges.
///
/// REview's control ingress and the event store's telemetry ingress hold
/// one each; the latter with a [`Lease`]. It starts
/// [`Standing::Unready`], with no version, and is ready once a full list is
/// applied. Nothing is persisted: an ingress that restarts starts unready.
///
/// It is sans-IO: the monotonic time is passed in, as the
/// [`Duration`] since an origin of the caller's choosing, always the same
/// one; and what to close or report comes back as values.
#[derive(Debug, Clone)]
pub struct ActiveList {
    listed: Option<Listed>,
    lease: Option<Lease>,
    connections: HashMap<ConnectionId, ConnectionRecord>,
    by_spki: HashMap<SpkiKey, ConnectionId>,
    replacements: HashMap<SpkiKey, VecDeque<Replacement>>,
}

impl ActiveList {
    /// Creates an unready list, with `lease` at the event store's ingress
    /// and without one at REview's.
    #[must_use]
    pub fn new(lease: Option<Lease>) -> Self {
        Self {
            listed: None,
            lease,
            connections: HashMap::new(),
            by_spki: HashMap::new(),
            replacements: HashMap::new(),
        }
    }

    /// Reports whether a full list has been applied.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.listed.is_some()
    }

    /// Returns the version applied, `None` before the first full list.
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.listed.as_ref().map(|listed| listed.version)
    }

    /// Returns the entry with the given `endpoint_id`.
    #[must_use]
    pub fn entry(&self, endpoint_id: &Uuid) -> Option<&ListEntry> {
        self.listed.as_ref()?.entries.get(endpoint_id)
    }

    /// Returns every entry of the list, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = &ListEntry> {
        self.listed
            .iter()
            .flat_map(|listed| listed.entries.values())
    }

    /// Returns the lease, if the list has one.
    #[must_use]
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// Returns when the lease expires on the monotonic clock: `None` without
    /// a lease or before it starts.
    #[must_use]
    pub fn lease_deadline(&self) -> Option<Duration> {
        self.lease.as_ref().and_then(Lease::deadline)
    }

    /// Returns the connections registered and not yet removed, in no
    /// particular order.
    pub fn connections(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.connections.keys().copied()
    }

    /// Returns the standing of an endpoint whose key's SPKI hash is
    /// `spki_sha256`, at `now`, with the ids of the entry it matched.
    ///
    /// [`Standing::Unready`] comes first, then [`Standing::LeaseExpired`]
    /// once the lease has reached its deadline, then the matched entry's
    /// state, or [`Standing::NotListed`]. It only reads: an expiry is
    /// delivered by the calls that take the time and change the list.
    #[must_use]
    pub fn standing(&self, spki_sha256: &[u8; 32], now: Duration) -> ConnectionStanding {
        self.standing_of(&SpkiKey(*spki_sha256), now)
    }

    /// Reports whether the lease has expired, and delivers the expiry the
    /// first time it comes to light: the connections open at that moment,
    /// to send `lease_expired` and close.
    ///
    /// It returns `None` without a lease, before the deadline, and once the
    /// expiry has been delivered, by this or any other call, until the
    /// lease is extended again.
    #[must_use]
    pub fn check_lease(&mut self, now: Duration) -> Option<Vec<ConnectionId>> {
        self.prune_replacements(now);
        self.deliver_expiry(now)
    }

    /// Takes REview's confirmation that the list it pushes is at `version`,
    /// at `now`.
    ///
    /// The lease is extended only when `version` is the version applied;
    /// before the first full list, or for any other version, nothing
    /// changes. An expiry that comes to light here is delivered first.
    pub fn confirm(&mut self, version: u64, now: Duration) -> ConfirmOutcome {
        self.prune_replacements(now);
        let expired = self.deliver_expiry(now);
        let matches = self.version() == Some(version);
        let extended = match self.lease.as_mut() {
            Some(lease) if matches => {
                lease.extend(now);
                true
            }
            _ => false,
        };
        ConfirmOutcome { expired, extended }
    }

    /// Applies an update at `now`.
    ///
    /// A full list replaces the list whatever its version and the version
    /// applied, and counts as the confirmation of its version: it starts or
    /// extends the lease. A diff applies only to the version applied, and
    /// does not extend the lease. An expiry that comes to light here is
    /// delivered first, whatever becomes of the update.
    ///
    /// An update is refused whole, changing nothing, when an entry is
    /// suspended for [`SuspendReason::Other`], a full list names an
    /// `endpoint_id` twice, the resulting list would hold one key twice, a
    /// diff's `version` does not exceed its `base_version`, a diff names an
    /// `endpoint_id` twice among its upserts or among its upserts and
    /// removals, or a diff's `base_version` is not the version applied. A
    /// diff whose `base_version` is not the version applied, or that comes
    /// before the first full list, is refused with
    /// [`ApplyError::VersionMismatch`], carrying the version applied,
    /// whatever else is wrong with it; any other refusal of a diff is of
    /// one based on the version applied. A removal of an `endpoint_id` not
    /// on the list is ignored.
    ///
    /// The changes it returns are the open connections whose standing, or
    /// the ids of the entry their key matches, differ from before. Those
    /// whose ids changed, or whose entry is gone, are to be closed.
    pub fn apply(&mut self, update: ListUpdate, now: Duration) -> ApplyOutcome {
        self.prune_replacements(now);
        let expired = self.deliver_expiry(now);
        let result = match update {
            ListUpdate::Full { version, entries } => self.apply_full(version, entries, now),
            ListUpdate::Diff {
                base_version,
                version,
                upserts,
                removals,
            } => self.apply_diff(base_version, version, upserts, &removals, now),
        };
        ApplyOutcome { expired, result }
    }

    /// Registers a connection whose handshake completed at `now`, from the
    /// key whose SPKI hash is `spki_sha256` and from `address`; only the IP
    /// address counts, never the port, and an IPv4 address mapped into
    /// IPv6 counts as that IPv4 address.
    ///
    /// A connection already open with the same key is replaced, listed or
    /// not: it is returned, to be closed, and forgotten, so that removing
    /// it later leaves the new one registered. When the key's replacements
    /// within the last [`DUPLICATE_KEY_WINDOW`], this one included, number
    /// [`DUPLICATE_KEY_THRESHOLD`] or more and their connections came from
    /// two addresses or more, the [`DuplicateKey`] is returned too.
    ///
    /// An expiry that comes to light here is delivered first, with the
    /// connections open before this one.
    pub fn register(
        &mut self,
        connection: ConnectionId,
        spki_sha256: &[u8; 32],
        address: IpAddr,
        now: Duration,
    ) -> RegisterOutcome {
        self.prune_replacements(now);
        let expired = self.deliver_expiry(now);
        self.remove(connection);
        let spki = SpkiKey(*spki_sha256);
        let address = address.to_canonical();
        let replaced = self.by_spki.insert(spki, connection);
        let mut replaced_address = None;
        if let Some(old) = replaced {
            replaced_address = self.connections.remove(&old).map(|record| record.address);
        }
        self.connections.insert(
            connection,
            ConnectionRecord {
                spki,
                address,
                expired: false,
            },
        );
        let duplicate_key = replaced_address
            .and_then(|old_address| self.record_replacement(spki, [old_address, address], now));
        RegisterOutcome {
            expired,
            replaced,
            duplicate_key,
        }
    }

    /// Forgets a closed connection. Returns whether it was registered.
    pub fn remove(&mut self, connection: ConnectionId) -> bool {
        let Some(record) = self.connections.remove(&connection) else {
            return false;
        };
        if let Entry::Occupied(slot) = self.by_spki.entry(record.spki)
            && *slot.get() == connection
        {
            slot.remove();
        }
        true
    }

    fn standing_of(&self, spki: &SpkiKey, now: Duration) -> ConnectionStanding {
        let Some(listed) = &self.listed else {
            return ConnectionStanding {
                standing: Standing::Unready,
                identity: None,
            };
        };
        let entry = listed.entry(spki);
        let identity = entry.map(|entry| EndpointIdentity {
            endpoint_id: entry.endpoint_id,
            customer_endpoint_id: entry.customer_endpoint_id,
        });
        let standing = if self
            .lease
            .as_ref()
            .is_some_and(|lease| lease.is_expired(now))
        {
            Standing::LeaseExpired
        } else {
            match entry.map(|entry| &entry.state) {
                None => Standing::NotListed,
                Some(EntryState::Active) => Standing::Active,
                Some(EntryState::LicensePending) => Standing::LicensePending,
                Some(EntryState::Suspended { reason }) => Standing::Suspended {
                    reason: reason.clone(),
                },
            }
        };
        ConnectionStanding { standing, identity }
    }

    fn deliver_expiry(&mut self, now: Duration) -> Option<Vec<ConnectionId>> {
        let lease = self.lease.as_mut()?;
        if lease.expiry_delivered || !lease.is_expired(now) {
            return None;
        }
        lease.expiry_delivered = true;
        let mut expired: Vec<ConnectionId> = self
            .connections
            .iter_mut()
            .filter(|(_, record)| !record.expired)
            .map(|(id, record)| {
                record.expired = true;
                *id
            })
            .collect();
        expired.sort_unstable();
        Some(expired)
    }

    fn apply_full(
        &mut self,
        version: u64,
        entries: Vec<ListEntry>,
        now: Duration,
    ) -> Result<Applied, ApplyError> {
        let mut by_id = HashMap::with_capacity(entries.len());
        let mut by_spki = HashMap::with_capacity(entries.len());
        for entry in entries {
            check_reason(&entry)?;
            if let Some(first) = by_spki.insert(SpkiKey(entry.spki_sha256), entry.endpoint_id) {
                if first == entry.endpoint_id {
                    return Err(ApplyError::RepeatedEndpoint { endpoint_id: first });
                }
                return Err(ApplyError::DuplicateSpki {
                    first,
                    second: entry.endpoint_id,
                });
            }
            let endpoint_id = entry.endpoint_id;
            if by_id.insert(endpoint_id, entry).is_some() {
                return Err(ApplyError::RepeatedEndpoint { endpoint_id });
            }
        }

        let candidates: Vec<ConnectionId> = self.connections.keys().copied().collect();
        let before = self.snapshot(&candidates, now);
        self.listed = Some(Listed {
            version,
            entries: by_id,
            by_spki,
        });
        if let Some(lease) = self.lease.as_mut() {
            lease.extend(now);
        }
        Ok(Applied {
            version,
            changes: self.changes(before, now),
        })
    }

    fn apply_diff(
        &mut self,
        base_version: u64,
        version: u64,
        upserts: Vec<ListEntry>,
        removals: &[Uuid],
        now: Duration,
    ) -> Result<Applied, ApplyError> {
        // The version comes first, so that a pusher out of step always
        // learns the version to resend from, however malformed its diff.
        // Every other refusal below is of a diff based on the version
        // applied.
        let listed = match self.listed.as_ref() {
            Some(listed) if listed.version == base_version => listed,
            _ => {
                return Err(ApplyError::VersionMismatch {
                    base_version,
                    current: self.version(),
                });
            }
        };
        if version <= base_version {
            return Err(ApplyError::VersionNotAdvanced {
                base_version,
                version,
            });
        }
        let mut upserted = HashSet::with_capacity(upserts.len());
        let mut new_spkis = HashMap::with_capacity(upserts.len());
        for entry in &upserts {
            check_reason(entry)?;
            if !upserted.insert(entry.endpoint_id) {
                return Err(ApplyError::RepeatedEndpoint {
                    endpoint_id: entry.endpoint_id,
                });
            }
            if let Some(first) = new_spkis.insert(SpkiKey(entry.spki_sha256), entry.endpoint_id) {
                return Err(ApplyError::DuplicateSpki {
                    first,
                    second: entry.endpoint_id,
                });
            }
        }
        let removed: HashSet<Uuid> = removals.iter().copied().collect();
        if let Some(endpoint_id) = removed.iter().find(|id| upserted.contains(id)) {
            return Err(ApplyError::RepeatedEndpoint {
                endpoint_id: *endpoint_id,
            });
        }
        // An entry that keeps its key would collide with an upsert taking
        // that key; one removed or upserted gives its old key up.
        for (spki, endpoint_id) in &new_spkis {
            if let Some(owner) = listed.by_spki.get(spki)
                && !upserted.contains(owner)
                && !removed.contains(owner)
            {
                return Err(ApplyError::DuplicateSpki {
                    first: *owner,
                    second: *endpoint_id,
                });
            }
        }

        let touched_spkis: Vec<SpkiKey> = removed
            .iter()
            .chain(upserted.iter())
            .filter_map(|id| listed.entries.get(id))
            .map(|entry| SpkiKey(entry.spki_sha256))
            .chain(new_spkis.keys().copied())
            .collect();
        let candidates: Vec<ConnectionId> = touched_spkis
            .iter()
            .filter_map(|spki| self.by_spki.get(spki).copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let before = self.snapshot(&candidates, now);

        let listed = self
            .listed
            .as_mut()
            .expect("the version check above found a list applied");
        for id in removed.iter().chain(upserted.iter()) {
            if let Some(old) = listed.entries.remove(id) {
                listed.by_spki.remove(&SpkiKey(old.spki_sha256));
            }
        }
        for entry in upserts {
            listed
                .by_spki
                .insert(SpkiKey(entry.spki_sha256), entry.endpoint_id);
            listed.entries.insert(entry.endpoint_id, entry);
        }
        listed.version = version;
        Ok(Applied {
            version,
            changes: self.changes(before, now),
        })
    }

    /// Returns the standing of each candidate connection not already
    /// returned by a lease expiry.
    fn snapshot(
        &self,
        candidates: &[ConnectionId],
        now: Duration,
    ) -> Vec<(ConnectionId, ConnectionStanding)> {
        candidates
            .iter()
            .filter_map(|id| {
                let record = self.connections.get(id)?;
                (!record.expired).then(|| (*id, self.standing_of(&record.spki, now)))
            })
            .collect()
    }

    fn changes(
        &self,
        before: Vec<(ConnectionId, ConnectionStanding)>,
        now: Duration,
    ) -> Vec<ConnectionChange> {
        let mut changes: Vec<ConnectionChange> = before
            .into_iter()
            .filter_map(|(id, before)| {
                let record = self.connections.get(&id)?;
                let after = self.standing_of(&record.spki, now);
                if after == before {
                    return None;
                }
                let close = before.identity.is_some() && before.identity != after.identity;
                Some(ConnectionChange {
                    connection: id,
                    standing: after.standing,
                    identity: after.identity,
                    close,
                })
            })
            .collect();
        changes.sort_unstable_by_key(|change| change.connection);
        changes
    }

    /// Drops the replacements no longer within [`DUPLICATE_KEY_WINDOW`] of
    /// `now`, and the keys left with none.
    fn prune_replacements(&mut self, now: Duration) {
        self.replacements.retain(|_, replacements| {
            replacements.retain(|replacement| in_window(replacement.at, now));
            !replacements.is_empty()
        });
    }

    fn record_replacement(
        &mut self,
        spki: SpkiKey,
        addresses: [IpAddr; 2],
        now: Duration,
    ) -> Option<DuplicateKey> {
        let replacements = self.replacements.entry(spki).or_default();
        replacements.push_back(Replacement { at: now, addresses });
        let counted: Vec<&Replacement> = replacements
            .iter()
            .filter(|replacement| replacement.at <= now && in_window(replacement.at, now))
            .collect();
        if counted.len() < DUPLICATE_KEY_THRESHOLD {
            return None;
        }
        let mut addresses: Vec<IpAddr> = counted
            .iter()
            .flat_map(|replacement| replacement.addresses)
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.len() < 2 {
            return None;
        }
        let endpoint_id = self
            .listed
            .as_ref()
            .and_then(|listed| listed.entry(&spki))
            .map(|entry| entry.endpoint_id);
        Some(DuplicateKey {
            spki_sha256: spki.0,
            endpoint_id,
            addresses,
            replacements: counted.len(),
        })
    }
}

/// Reports whether a replacement at `at` is still counted at `now`: less
/// than [`DUPLICATE_KEY_WINDOW`] before it. One after `now`, which only a
/// clock going backwards makes, is kept.
fn in_window(at: Duration, now: Duration) -> bool {
    now.checked_sub(at)
        .is_none_or(|elapsed| elapsed < DUPLICATE_KEY_WINDOW)
}

fn check_reason(entry: &ListEntry) -> Result<(), ApplyError> {
    match &entry.state {
        EntryState::Suspended {
            reason: SuspendReason::Other(_),
        } => Err(ApplyError::UnknownReason {
            endpoint_id: entry.endpoint_id,
        }),
        _ => Ok(()),
    }
}
