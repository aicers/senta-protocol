//! A [`ReceiverStore`] held in memory, with failures a test can inject.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use uuid::Uuid;

use super::store::{
    ReceiverChange, ReceiverEntryState, ReceiverLoss, ReceiverLossReason, ReceiverRecord,
    ReceiverStore,
};
use crate::telemetry::SeqRange;

/// A [`ReceiverStore`] held in memory.
///
/// It does not survive a process restart. Within the process it keeps the
/// trait's meaning: a [`ReceiverStream`](super::ReceiverStream) made again
/// from the same store reads back every batch written, records and loss
/// records are only ever added, and the entries sharing it are kept apart.
///
/// Cloning it gives another handle to the same store, so that several
/// entries can share it and a test can look into it, or make it fail,
/// while a state machine holds it. Failures are off until a test turns
/// them on with [`fail_writes`](Self::fail_writes) or
/// [`fail_reads`](Self::fail_reads); a failed call changes nothing.
#[derive(Clone, Debug, Default)]
pub struct MemoryReceiverStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: BTreeMap<Uuid, ReceiverEntryState>,
    records: Vec<(Uuid, ReceiverRecord)>,
    losses: Vec<(Uuid, ReceiverLoss)>,
    fail_writes: bool,
    fail_reads: bool,
    writes: u64,
}

/// Why a call to a [`MemoryReceiverStore`] failed: always a failure a test
/// injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryReceiverStoreError {
    /// A read failed.
    Read,
    /// A write failed, and wrote nothing.
    Write,
}

impl fmt::Display for MemoryReceiverStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "injected read failure of the memory receiver store",
            Self::Write => "injected write failure of the memory receiver store",
        })
    }
}

impl std::error::Error for MemoryReceiverStoreError {}

impl MemoryReceiverStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while the lock was held cannot leave a batch in part:
        // every write is checked before the first change is made.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes every later write fail, writing nothing, while `fail` is
    /// `true`.
    pub fn fail_writes(&self, fail: bool) {
        self.lock().fail_writes = fail;
    }

    /// Makes every later read fail while `fail` is `true`.
    pub fn fail_reads(&self, fail: bool) {
        self.lock().fail_reads = fail;
    }

    /// Returns the number of writes that succeeded.
    #[must_use]
    pub fn writes(&self) -> u64 {
        self.lock().writes
    }

    /// Returns the stream states `entry_id` has, whether or not reads
    /// fail.
    #[must_use]
    pub fn state(&self, entry_id: Uuid) -> ReceiverEntryState {
        self.lock()
            .entries
            .get(&entry_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the records `entry_id` stored, in the order they were
    /// written.
    #[must_use]
    pub fn records(&self, entry_id: Uuid) -> Vec<ReceiverRecord> {
        self.lock()
            .records
            .iter()
            .filter(|(entry, _)| *entry == entry_id)
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Returns the loss records `entry_id` kept, in the order they were
    /// written.
    #[must_use]
    pub fn losses(&self, entry_id: Uuid) -> Vec<ReceiverLoss> {
        self.lock()
            .losses
            .iter()
            .filter(|(entry, _)| *entry == entry_id)
            .map(|(_, loss)| loss.clone())
            .collect()
    }
}

impl ReceiverStore for MemoryReceiverStore {
    type Error = MemoryReceiverStoreError;

    fn load(&self, entry_id: Uuid) -> Result<ReceiverEntryState, Self::Error> {
        let inner = self.lock();
        if inner.fail_reads {
            return Err(MemoryReceiverStoreError::Read);
        }
        Ok(inner.entries.get(&entry_id).cloned().unwrap_or_default())
    }

    fn has_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        range: SeqRange,
    ) -> Result<bool, Self::Error> {
        let inner = self.lock();
        if inner.fail_reads {
            return Err(MemoryReceiverStoreError::Read);
        }
        Ok(inner.losses.iter().any(|(entry, loss)| {
            *entry == entry_id
                && loss.endpoint_id == endpoint_id
                && loss.stream == stream
                && loss.range == range
                && loss.reason == ReceiverLossReason::LostOnReset
        }))
    }

    fn write(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<(), Self::Error> {
        let mut inner = self.lock();
        if inner.fail_writes {
            return Err(MemoryReceiverStoreError::Write);
        }
        for change in changes {
            match change {
                ReceiverChange::AppendRecord(record) => inner.records.push((entry_id, record)),
                ReceiverChange::AppendLoss(loss) => inner.losses.push((entry_id, loss)),
                change @ (ReceiverChange::SetFlow { .. } | ReceiverChange::RemoveFlow(_)) => {
                    inner.entries.entry(entry_id).or_default().apply(&change);
                }
            }
        }
        inner.writes += 1;
        Ok(())
    }
}
