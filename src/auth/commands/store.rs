//! The persistent state of the command state machine, and the store it is
//! written to.

use std::collections::BTreeMap;
use std::convert::Infallible;

use jiff::Timestamp;

use crate::auth::jws::strict::LowerUuid;
use crate::results::CommandResultKind;

/// Where a command the state machine has recorded stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordStatus {
    /// The command was accepted and no result has been written for it yet:
    /// it is running, or the endpoint stopped before its result was
    /// written. Either way it is not run again.
    Running,
    /// The command's result: `Done` or `Failed` once it ran, or
    /// `Rejected` when it was rejected at the sequence or validity window
    /// check.
    Finished(CommandResultKind),
}

/// What the state machine keeps of one command, under its `command_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRecord {
    /// The command's `expires_at`. The record is kept until one hour after
    /// it.
    pub expires_at: Timestamp,
    /// Where the command stands.
    pub status: RecordStatus,
}

/// The whole persistent state of the command state machine, as a store
/// gives it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCommandState {
    /// The endpoint's own `endpoint_id`.
    pub endpoint_id: LowerUuid,
    /// The recovery epoch the sequence floor belongs to.
    pub epoch: u64,
    /// The `seq` of the last command accepted in `epoch`, or `None` when no
    /// command has been accepted in it; then any `seq` passes.
    pub last_seq: Option<u64>,
    /// The records, by `command_id`.
    pub records: BTreeMap<LowerUuid, CommandRecord>,
}

impl StoredCommandState {
    /// Returns the state [`CommandStore::create`] writes: no sequence floor
    /// and no records.
    #[must_use]
    pub fn new(endpoint_id: LowerUuid, epoch: u64) -> Self {
        Self {
            endpoint_id,
            epoch,
            last_seq: None,
            records: BTreeMap::new(),
        }
    }

    pub(super) fn reset_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.last_seq = None;
    }

    pub(super) fn accept(&mut self, seq: u64, command_id: LowerUuid, expires_at: Timestamp) {
        self.last_seq = Some(seq);
        self.records.insert(
            command_id,
            CommandRecord {
                expires_at,
                status: RecordStatus::Running,
            },
        );
    }

    pub(super) fn finish(&mut self, command_id: LowerUuid, result: &CommandResultKind) {
        if let Some(record) = self.records.get_mut(&command_id) {
            record.status = RecordStatus::Finished(result.clone());
        }
    }

    pub(super) fn reject(
        &mut self,
        command_id: LowerUuid,
        expires_at: Timestamp,
        result: &CommandResultKind,
    ) {
        self.records.insert(
            command_id,
            CommandRecord {
                expires_at,
                status: RecordStatus::Finished(result.clone()),
            },
        );
    }

    pub(super) fn prune(&mut self, command_ids: &[LowerUuid]) {
        for command_id in command_ids {
            self.records.remove(command_id);
        }
    }
}

/// The persistent store the command state machine writes its state to,
/// implemented by the caller.
///
/// Each write method is one batch, written atomically:
///
/// - **Success** means the whole batch is read back by
///   [`load`](Self::load) from this store — in a production store, after a
///   process restart too.
/// - **An error** means none of the batch took effect.
///
/// So wherever the endpoint stops, the state read back holds no batch in
/// part, and the values inside a batch never disagree. The state machine
/// changes its own copy of the state only after a write succeeded, so on an
/// error the two stay the same.
///
/// The state machine calls [`create`](Self::create) only on a store whose
/// [`load`](Self::load) gave `None`, and every other write method only on a
/// store holding a state.
pub trait CommandStore {
    /// The error a read or write gives.
    type Error;

    /// Reads the whole state back, or `None` when no state was ever
    /// created in this store.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the state cannot be read.
    fn load(&self) -> Result<Option<StoredCommandState>, Self::Error>;

    /// Writes a new state: `endpoint_id`, `epoch`, no sequence floor and no
    /// records, as [`StoredCommandState::new`] makes it.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn create(&mut self, endpoint_id: LowerUuid, epoch: u64) -> Result<(), Self::Error>;

    /// Writes an acceptance: the last accepted `seq` becomes `seq`, and
    /// `command_id` gets a [`RecordStatus::Running`] record expiring at
    /// `expires_at`.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn accept(
        &mut self,
        seq: u64,
        command_id: LowerUuid,
        expires_at: Timestamp,
    ) -> Result<(), Self::Error>;

    /// Writes a result: the [`RecordStatus::Running`] record of
    /// `command_id` becomes [`RecordStatus::Finished`] with `result`, its
    /// `expires_at` unchanged.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn finish(
        &mut self,
        command_id: LowerUuid,
        result: &CommandResultKind,
    ) -> Result<(), Self::Error>;

    /// Writes a rejection: `command_id` gets a [`RecordStatus::Finished`]
    /// record of `result` expiring at `expires_at`. The last accepted `seq`
    /// does not change.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn reject(
        &mut self,
        command_id: LowerUuid,
        expires_at: Timestamp,
        result: &CommandResultKind,
    ) -> Result<(), Self::Error>;

    /// Writes an epoch reconciliation: the epoch becomes `epoch` and there
    /// is no last accepted `seq`. The records do not change.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn reset_epoch(&mut self, epoch: u64) -> Result<(), Self::Error>;

    /// Writes a pruning: the records of `command_ids` are removed.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the batch was not written.
    fn prune(&mut self, command_ids: &[LowerUuid]) -> Result<(), Self::Error>;
}

impl<S: CommandStore + ?Sized> CommandStore for &mut S {
    type Error = S::Error;

    fn load(&self) -> Result<Option<StoredCommandState>, Self::Error> {
        (**self).load()
    }

    fn create(&mut self, endpoint_id: LowerUuid, epoch: u64) -> Result<(), Self::Error> {
        (**self).create(endpoint_id, epoch)
    }

    fn accept(
        &mut self,
        seq: u64,
        command_id: LowerUuid,
        expires_at: Timestamp,
    ) -> Result<(), Self::Error> {
        (**self).accept(seq, command_id, expires_at)
    }

    fn finish(
        &mut self,
        command_id: LowerUuid,
        result: &CommandResultKind,
    ) -> Result<(), Self::Error> {
        (**self).finish(command_id, result)
    }

    fn reject(
        &mut self,
        command_id: LowerUuid,
        expires_at: Timestamp,
        result: &CommandResultKind,
    ) -> Result<(), Self::Error> {
        (**self).reject(command_id, expires_at, result)
    }

    fn reset_epoch(&mut self, epoch: u64) -> Result<(), Self::Error> {
        (**self).reset_epoch(epoch)
    }

    fn prune(&mut self, command_ids: &[LowerUuid]) -> Result<(), Self::Error> {
        (**self).prune(command_ids)
    }
}

/// A [`CommandStore`] held in memory.
///
/// It does not survive a process restart. Within the process it keeps the
/// trait's meaning: a state machine made again from the same store, through
/// [`CommandStateMachine::restore`](super::CommandStateMachine::restore),
/// reads back every batch written, and no write fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryCommandStore {
    state: Option<StoredCommandState>,
}

impl MemoryCommandStore {
    /// Creates an empty store, holding no state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the state held, or `None` when none was created.
    #[must_use]
    pub fn state(&self) -> Option<&StoredCommandState> {
        self.state.as_ref()
    }

    /// Empties the store, as a caller enrolling the endpoint again does
    /// before creating a new state.
    pub fn clear(&mut self) {
        self.state = None;
    }
}

impl CommandStore for MemoryCommandStore {
    type Error = Infallible;

    fn load(&self) -> Result<Option<StoredCommandState>, Infallible> {
        Ok(self.state.clone())
    }

    fn create(&mut self, endpoint_id: LowerUuid, epoch: u64) -> Result<(), Infallible> {
        self.state = Some(StoredCommandState::new(endpoint_id, epoch));
        Ok(())
    }

    fn accept(
        &mut self,
        seq: u64,
        command_id: LowerUuid,
        expires_at: Timestamp,
    ) -> Result<(), Infallible> {
        if let Some(state) = &mut self.state {
            state.accept(seq, command_id, expires_at);
        }
        Ok(())
    }

    fn finish(
        &mut self,
        command_id: LowerUuid,
        result: &CommandResultKind,
    ) -> Result<(), Infallible> {
        if let Some(state) = &mut self.state {
            state.finish(command_id, result);
        }
        Ok(())
    }

    fn reject(
        &mut self,
        command_id: LowerUuid,
        expires_at: Timestamp,
        result: &CommandResultKind,
    ) -> Result<(), Infallible> {
        if let Some(state) = &mut self.state {
            state.reject(command_id, expires_at, result);
        }
        Ok(())
    }

    fn reset_epoch(&mut self, epoch: u64) -> Result<(), Infallible> {
        if let Some(state) = &mut self.state {
            state.reset_epoch(epoch);
        }
        Ok(())
    }

    fn prune(&mut self, command_ids: &[LowerUuid]) -> Result<(), Infallible> {
        if let Some(state) = &mut self.state {
            state.prune(command_ids);
        }
        Ok(())
    }
}
