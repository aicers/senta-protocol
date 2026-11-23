//! The persistent state of a [`SenderStream`](super::SenderStream), the
//! store it is written to, and the change one call writes.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::flow::{CloseStream, LostOnReset};
use crate::connection::{AcceptedKind, cbor};
use crate::telemetry_codes::DropReason;

/// A storage layer's failure, as the [`SenderStore`] implementation
/// reports it.
pub struct SenderStoreError(Box<dyn Error + Send + Sync + 'static>);

impl SenderStoreError {
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

impl fmt::Debug for SenderStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SenderStoreError").field(&self.0).finish()
    }
}

impl fmt::Display for SenderStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for SenderStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

/// Where a [`SenderStream`](super::SenderStream) keeps its persistent
/// state, which the caller implements.
///
/// The state is a map from [`SenderStateKey`] to [`SenderStateEntry`]:
/// one entry for the stream's small scalar state, and one per record, per
/// hash ledger entry, per dropped range and so on. Both types serialize
/// and deserialize through serde (the crate's own CBOR, `cbor::to_vec` and
/// `cbor::from_slice`, round-trips them), and an entry read back behaves
/// as the one written.
///
/// **Each state-changing call of the stream is one atomic
/// [`commit`](Self::commit)**, and that commit carries only what the call
/// changed: the records it added or removed, never the bytes of a record
/// it left alone. Whatever point the endpoint stops at, the state read
/// back is the one before or the one after a whole call.
pub trait SenderStore {
    /// Reads every entry last written, in any order, or none if nothing
    /// ever was.
    ///
    /// # Errors
    ///
    /// Returns [`SenderStoreError`] if the storage layer cannot be read.
    fn load(&self) -> Result<Vec<(SenderStateKey, SenderStateEntry)>, SenderStoreError>;

    /// Applies `change` as one atomic write: every key of
    /// [`SenderStateChange::removes`] is removed, and every entry of
    /// [`SenderStateChange::puts`] written under its key, replacing what
    /// was there. No key appears in both, nor twice.
    ///
    /// Success means that the whole change is what this storage layer
    /// reads back from now on. An error means that none of it was written,
    /// and the storage layer reads back what it did before.
    ///
    /// # Errors
    ///
    /// Returns [`SenderStoreError`] if the change could not be written;
    /// nothing of it was then.
    fn commit(&mut self, change: &SenderStateChange) -> Result<(), SenderStoreError>;
}

impl<S: SenderStore + ?Sized> SenderStore for &mut S {
    fn load(&self) -> Result<Vec<(SenderStateKey, SenderStateEntry)>, SenderStoreError> {
        (**self).load()
    }

    fn commit(&mut self, change: &SenderStateChange) -> Result<(), SenderStoreError> {
        (**self).commit(change)
    }
}

/// A [`SenderStore`] in memory, into which a test can inject write
/// failures.
///
/// Cloning it takes a snapshot: a stream opened on the clone later starts
/// from the state as it was, as a restored disk snapshot would.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemorySenderStore {
    entries: BTreeMap<SenderStateKey, SenderStateEntry>,
    failures: u32,
    commits: u64,
}

impl MemorySenderStore {
    /// Creates a store that has never been written.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the next `count` commits fail, writing nothing.
    pub fn fail_next_commits(&mut self, count: u32) {
        self.failures = count;
    }

    /// Returns the number of commits that succeeded.
    #[must_use]
    pub fn commits(&self) -> u64 {
        self.commits
    }

    /// Returns the entries held, by key.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<SenderStateKey, SenderStateEntry> {
        &self.entries
    }
}

impl SenderStore for MemorySenderStore {
    fn load(&self) -> Result<Vec<(SenderStateKey, SenderStateEntry)>, SenderStoreError> {
        Ok(self
            .entries
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect())
    }

    fn commit(&mut self, change: &SenderStateChange) -> Result<(), SenderStoreError> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err(SenderStoreError::new("injected write failure"));
        }
        for key in &change.removes {
            self.entries.remove(key);
        }
        for (key, entry) in &change.puts {
            self.entries.insert(key.clone(), entry.clone());
        }
        self.commits += 1;
        Ok(())
    }
}

/// What one state-changing call of a
/// [`SenderStream`](super::SenderStream) writes: entries to put and keys to
/// remove, applied together by [`SenderStore::commit`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SenderStateChange {
    pub(super) puts: Vec<(SenderStateKey, SenderStateEntry)>,
    pub(super) removes: Vec<SenderStateKey>,
}

impl SenderStateChange {
    /// Returns the entries to write, each under its key.
    #[must_use]
    pub fn puts(&self) -> &[(SenderStateKey, SenderStateEntry)] {
        &self.puts
    }

    /// Returns the keys to remove.
    #[must_use]
    pub fn removes(&self) -> &[SenderStateKey] {
        &self.removes
    }

    /// Returns whether the change writes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.removes.is_empty()
    }
}

/// The key of one entry of a sender's persistent state. Opaque; it orders,
/// compares and serializes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SenderStateKey(pub(super) Key);

/// One entry of a sender's persistent state. Opaque; it serializes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SenderStateEntry(pub(super) Entry);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(super) enum Key {
    Meta,
    Collected(u64),
    Queued(u64),
    Ledger(u64),
    Dropped(u64),
    Announced(u64),
    Acked(u64),
    Notice(u64),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum Entry {
    Meta(Meta),
    Collected(Collected),
    Queued(Queued),
    Ledger(#[serde(with = "cbor::bytes")] [u8; 16]),
    Dropped(Dropped),
    Announced(u64),
    Acked(#[serde(with = "cbor::timestamp")] Timestamp),
    Notice(Notice),
}

/// The stream's scalar state.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Meta {
    #[serde(with = "cbor::uuid::option")]
    pub(super) endpoint_id: Option<Uuid>,
    #[serde(with = "uuid_list")]
    pub(super) entries: Vec<Uuid>,
    #[serde(with = "cbor::uuid::option")]
    pub(super) target: Option<Uuid>,
    /// The accepted kinds last verified at each entry.
    pub(super) accepted: Vec<EntryKinds>,
    /// The time of the last valid `Ack` from each entry.
    pub(super) last_success: Vec<EntrySuccess>,
    pub(super) flow: Option<FlowId>,
    /// `K`, the last sequence number acknowledged.
    pub(super) k: u64,
    /// `M`, the highest sequence number given.
    pub(super) m: u64,
    /// `S`, the highest sequence number sent.
    pub(super) s: u64,
    /// The collection order the next record collected takes.
    pub(super) next_order: u64,
    /// The count of dropped ranges created.
    pub(super) dropped_ranges: u64,
    /// The count of records dropped without a sequence number.
    pub(super) unsupported: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntryKinds {
    #[serde(with = "cbor::uuid")]
    pub(super) entry: Uuid,
    pub(super) kinds: Vec<AcceptedKind>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntrySuccess {
    #[serde(with = "cbor::uuid")]
    pub(super) entry: Uuid,
    #[serde(with = "cbor::timestamp")]
    pub(super) at: Timestamp,
}

/// The current stream and the entry it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FlowId {
    #[serde(with = "cbor::uuid")]
    pub(super) stream: Uuid,
    #[serde(with = "cbor::uuid")]
    pub(super) entry: Uuid,
}

/// A record in the collection buffer, without a sequence number. `bytes`
/// is a record encoding whose `endpoint_id`, `stream` and `seq` are not
/// yet the ones it is sent with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Collected {
    #[serde(with = "cbor::bytes")]
    pub(super) bytes: Vec<u8>,
    pub(super) kind: u16,
    pub(super) schema: u16,
    #[serde(with = "cbor::timestamp")]
    pub(super) retained_since: Timestamp,
}

/// A record in the send queue, under its sequence number, with its bytes
/// fixed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Queued {
    #[serde(with = "cbor::bytes")]
    pub(super) bytes: Vec<u8>,
    #[serde(with = "cbor::bytes")]
    pub(super) hash: [u8; 16],
    pub(super) kind: u16,
    pub(super) schema: u16,
    /// The collection order, which it takes back if it returns to the
    /// collection buffer.
    pub(super) order: u64,
    #[serde(with = "cbor::timestamp")]
    pub(super) retained_since: Timestamp,
}

/// A range of dropped sequence numbers, under its first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dropped {
    pub(super) to: u64,
    pub(super) reason: DropReason,
}

/// A notice to send before the current stream's `open_stream`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Notice {
    Lost(LostOnReset),
    Close(CloseStream),
}

/// A serde helper writing a list of UUIDs as an array of byte strings.
mod uuid_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    use crate::connection::cbor;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Id(#[serde(with = "cbor::uuid")] Uuid);

    pub(super) fn serialize<S: Serializer>(ids: &[Uuid], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(ids.iter().map(|id| Id(*id)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Uuid>, D::Error> {
        Ok(Vec::<Id>::deserialize(deserializer)?
            .into_iter()
            .map(|id| id.0)
            .collect())
    }
}

/// A map whose changes are logged, so that a call can be undone, or
/// written as the change it made.
#[derive(Debug)]
pub(super) struct Table<K, V> {
    map: BTreeMap<K, V>,
    /// The value each key touched since the last commit held before it
    /// was first touched.
    undo: BTreeMap<K, Option<V>>,
}

impl<K: Ord + Copy, V> Default for Table<K, V> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
            undo: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Copy, V> Table<K, V> {
    pub(super) fn from_map(map: BTreeMap<K, V>) -> Self {
        Self {
            map,
            undo: BTreeMap::new(),
        }
    }

    pub(super) fn map(&self) -> &BTreeMap<K, V> {
        &self.map
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    pub(super) fn insert(&mut self, key: K, value: V) {
        let old = self.map.insert(key, value);
        self.undo.entry(key).or_insert(old);
    }

    pub(super) fn remove(&mut self, key: &K) -> bool {
        match self.map.remove(key) {
            Some(old) => {
                self.undo.entry(*key).or_insert(Some(old));
                true
            }
            None => false,
        }
    }

    /// Removes every key.
    pub(super) fn clear(&mut self) {
        let keys: Vec<K> = self.map.keys().copied().collect();
        for key in &keys {
            self.remove(key);
        }
    }

    /// Puts every touched key back to what it held before.
    pub(super) fn rollback(&mut self) {
        for (key, old) in std::mem::take(&mut self.undo) {
            match old {
                Some(value) => {
                    self.map.insert(key, value);
                }
                None => {
                    self.map.remove(&key);
                }
            }
        }
    }

    /// Forgets the log, once the change is written.
    pub(super) fn settle(&mut self) {
        self.undo.clear();
    }
}

impl<K: Ord + Copy, V: Clone> Table<K, V> {
    /// Adds the touched keys to `change`: a put for each key holding a
    /// value, a remove for each that held one before and holds none now.
    pub(super) fn write_change(
        &self,
        change: &mut SenderStateChange,
        key: impl Fn(K) -> Key,
        entry: impl Fn(V) -> Entry,
    ) {
        for (k, old) in &self.undo {
            match self.map.get(k) {
                Some(value) => change.puts.push((
                    SenderStateKey(key(*k)),
                    SenderStateEntry(entry(value.clone())),
                )),
                None if old.is_some() => change.removes.push(SenderStateKey(key(*k))),
                None => {}
            }
        }
    }
}
