//! The command state machine: what an endpoint does with a `senta-command`.
//!
//! [`CommandStateMachine`] judges each command REview signs with a customer
//! key, never runs the same command twice, keeps out old and expired
//! commands by their `seq` and the endpoint's own clock, and restarts its
//! sequence floor when the recovery key moves the recovery epoch on.
//!
//! It is sans-IO. It runs no command: a command that passes comes back as
//! [`CommandVerdict::Execute`], and the caller runs it and writes the result
//! back with [`CommandStateMachine::finish`]. Its persistent state goes
//! through a [`CommandStore`] the caller implements, one atomic batch per
//! change; [`MemoryCommandStore`] is an implementation in memory. The time
//! is the endpoint's own clock, passed in; no time a server reported is
//! taken.
//!
//! # Persistent state
//!
//! - the endpoint's own `endpoint_id`;
//! - the stored recovery epoch;
//! - the `seq` of the last command accepted in that epoch, or none;
//! - a record for each `command_id` seen past the target check: its
//!   `expires_at` and either [`RecordStatus::Running`] or its result.
//!
//! # Retention
//!
//! A record is kept until one hour after its command's `expires_at`, and
//! [`CommandStateMachine::prune`] removes it after that. The crate stores
//! only the result's kind, never the diagnostic bundle a `diagnose` command
//! makes. The caller keeps that bundle, findable by `command_id`, from
//! before it writes `Done` until `prune` removes the record, and sends it
//! again whenever a stored `Done` comes back for that `command_id`.

mod store;
#[cfg(test)]
mod tests;

use jiff::{SignedDuration, Timestamp};

pub use self::store::{
    CommandRecord, CommandStore, MemoryCommandStore, RecordStatus, StoredCommandState,
};
use super::documents::{
    CLOCK_SKEW, CommandContent, MAX_COMMAND_LIFETIME, check_validity_window, verify_command,
};
use super::jws::strict::LowerUuid;
use super::keyset::{EpochChange, TrustState};
use crate::results::{CommandResultKind, DocumentResult};

/// How long after its command's `expires_at` a record is kept: the clock
/// skew, the last moment the command itself could still pass the validity
/// window.
const RETENTION_AFTER_EXPIRY: SignedDuration = CLOCK_SKEW;

/// What receiving one `senta-command` comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandVerdict {
    /// The command was accepted and is to be run now. The caller runs it and
    /// writes its result with [`CommandStateMachine::finish`].
    Execute(CommandContent),
    /// The command passed verification and is not to be run; `result` is
    /// what to report for it: a rejection, or the result stored for a
    /// command already seen.
    Report {
        /// The verified `command_id`.
        command_id: LowerUuid,
        /// The result to report.
        result: CommandResultKind,
    },
    /// The command did not pass verification, so it carries no
    /// `command_id` that can be trusted. Its result is
    /// [`CommandResultKind::Rejected`] with `result`.
    Unverified {
        /// Why verification failed.
        result: DocumentResult,
        /// The header's `kid` as the header held it, when the header could
        /// be read; for diagnostics only, such as control's
        /// `Problem::SignatureRejected`, and never a ground for a decision.
        kid: Option<String>,
    },
}

impl CommandVerdict {
    /// Returns the verified `command_id`, absent only when verification
    /// failed.
    #[must_use]
    pub fn command_id(&self) -> Option<LowerUuid> {
        match self {
            Self::Execute(content) => Some(content.command_id()),
            Self::Report { command_id, .. } => Some(*command_id),
            Self::Unverified { .. } => None,
        }
    }

    /// Returns the result to report, or `None` when the command is to be
    /// run.
    #[must_use]
    pub fn result(&self) -> Option<CommandResultKind> {
        match self {
            Self::Execute(_) => None,
            Self::Report { result, .. } => Some(result.clone()),
            Self::Unverified { result, .. } => Some(CommandResultKind::Rejected(result.clone())),
        }
    }
}

/// Why a call to the command state machine failed, apart from judging a
/// command.
#[derive(Debug, thiserror::Error)]
pub enum CommandError<E> {
    /// The store failed. A write that failed took no effect, and the state
    /// machine's state is the same as the store's.
    #[error("the command store failed")]
    Store(#[source] E),
    /// [`CommandStateMachine::create`] was called on a store that already
    /// holds a state; nothing was written.
    #[error("the command store already holds a command state")]
    AlreadyCreated,
    /// [`CommandStateMachine::restore`] was called on a store that holds no
    /// state.
    #[error("the command store holds no command state")]
    NotCreated,
    /// The trust state passed is of an earlier recovery epoch than the one
    /// stored; nothing was written.
    #[error(
        "the trust state's recovery epoch {trust_epoch} is behind the stored epoch {stored_epoch}"
    )]
    TrustStateBehind {
        /// The trust state's recovery epoch.
        trust_epoch: u64,
        /// The stored recovery epoch.
        stored_epoch: u64,
    },
    /// [`CommandStateMachine::finish`] was given a `command_id` that has no
    /// running record: one that is unknown, or already has a result.
    /// Nothing was changed.
    #[error("command {} is not running", .command_id.get())]
    NotRunning {
        /// The `command_id` given.
        command_id: LowerUuid,
    },
    /// [`CommandStateMachine::finish`] was given a result other than `Done`
    /// or `Failed`. Nothing was changed.
    #[error("a command can only finish as done or failed")]
    NotACompletion,
}

/// The command state machine of one endpoint, over its [`CommandStore`].
///
/// It holds a copy of the stored state, which it changes only after the
/// store has written the change. Pass `&mut store` as the store to keep
/// using the store after the state machine is gone.
#[derive(Debug)]
pub struct CommandStateMachine<S> {
    store: S,
    state: StoredCommandState,
}

impl<S: CommandStore> CommandStateMachine<S> {
    /// Creates the state of an endpoint just enrolled as `endpoint_id`, at
    /// the recovery epoch of `trust`, and writes it to `store`.
    ///
    /// The state starts with no sequence floor and no records. A caller
    /// enrolling the endpoint again empties the store first; a caller
    /// starting again uses [`restore`](Self::restore).
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::AlreadyCreated`], writing nothing, when the
    /// store already holds a state: wiping its records and floor could run
    /// an accepted command again. Returns [`CommandError::Store`] when the
    /// store fails to read or write.
    pub fn create(
        mut store: S,
        endpoint_id: LowerUuid,
        trust: &TrustState,
    ) -> Result<Self, CommandError<S::Error>> {
        if store.load().map_err(CommandError::Store)?.is_some() {
            return Err(CommandError::AlreadyCreated);
        }
        let epoch = trust.recovery_epoch();
        store
            .create(endpoint_id, epoch)
            .map_err(CommandError::Store)?;
        Ok(Self {
            store,
            state: StoredCommandState::new(endpoint_id, epoch),
        })
    }

    /// Makes the state machine again from the state `store` holds.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::NotCreated`] when the store holds no state,
    /// and [`CommandError::Store`] when it fails to read.
    pub fn restore(store: S) -> Result<Self, CommandError<S::Error>> {
        let state = store
            .load()
            .map_err(CommandError::Store)?
            .ok_or(CommandError::NotCreated)?;
        Ok(Self { store, state })
    }

    /// Returns the state, the same as the store's.
    #[must_use]
    pub fn state(&self) -> &StoredCommandState {
        &self.state
    }

    /// Returns the endpoint's own `endpoint_id`.
    #[must_use]
    pub fn endpoint_id(&self) -> LowerUuid {
        self.state.endpoint_id
    }

    /// Returns the stored recovery epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Returns the `seq` of the last command accepted in the stored epoch,
    /// or `None` when none has been.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.state.last_seq
    }

    /// Returns the record of `command_id`, if there is one.
    #[must_use]
    pub fn record(&self, command_id: LowerUuid) -> Option<&CommandRecord> {
        self.state.records.get(&command_id)
    }

    /// Returns the store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the store, consuming `self`.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Receives one `senta-command` JWS and judges it against `trust` and
    /// the endpoint's own clock `now`.
    ///
    /// When `trust`'s recovery epoch is above the stored one, the state
    /// first reconciles to it — the new epoch, no sequence floor, the
    /// records kept — and that write stays, whatever the command comes to.
    /// Then the first of these to hold decides the verdict:
    ///
    /// 1. Verifying the JWS with `trust`'s customer keys fails:
    ///    [`CommandVerdict::Unverified`] with that failure's result and the
    ///    header's kid. The command's `recovery_epoch` is not the current
    ///    one: `Rejected(EpochMismatch)`.
    /// 2. Its `endpoint_id` is not the endpoint's: `Rejected(WrongTarget)`.
    /// 3. Its `command_id` has a record: the stored result, as it is, or
    ///    `AlreadyDone` when the record is running. The command is not run
    ///    again, and its content is not compared.
    /// 4. Its `seq` is at most the last accepted one: `Rejected(Stale)`,
    ///    and a record of that rejection is written.
    /// 5. Its validity window fails against `now`, with a lifetime of at
    ///    most [`MAX_COMMAND_LIFETIME`]: `Rejected(Expired)` or
    ///    `Rejected(NotYetValid)`, as [`check_validity_window`] decides, and
    ///    a record of that rejection is written.
    /// 6. Otherwise the acceptance is written — the last accepted `seq`
    ///    becomes the command's, and its record is running — and the
    ///    verdict is [`CommandVerdict::Execute`].
    ///
    /// Steps 1 to 3 write nothing more. Only an acceptance raises the
    /// sequence floor, so an expired command does not hold back the ones
    /// after it. Every verdict but [`CommandVerdict::Unverified`] carries
    /// the verified `command_id`.
    ///
    /// The caller passes the endpoint's latest stored trust state, never
    /// an earlier one, and passes an [`EpochChange`] to
    /// [`apply_epoch_change`](Self::apply_epoch_change) only after storing
    /// the trust state that reported it: a key can be revoked within the
    /// same epoch, which only the latest trust state knows.
    ///
    /// The crate stores only the result's kind. The caller keeps the
    /// diagnostic bundle of a command it writes `Done` for, findable by
    /// `command_id`, until [`prune`](Self::prune) removes that record; when
    /// a stored `Done` comes back here, the caller sends the bundle again
    /// with it.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::TrustStateBehind`], writing nothing, when
    /// `trust`'s recovery epoch is below the stored one, and
    /// [`CommandError::Store`] when a write fails. A failed acceptance
    /// writes nothing and runs nothing, so the same command received again
    /// is judged as it was the first time; an epoch reconciliation written
    /// before it stays.
    pub fn receive(
        &mut self,
        jws: &str,
        trust: &TrustState,
        now: Timestamp,
    ) -> Result<CommandVerdict, CommandError<S::Error>> {
        let trust_epoch = trust.recovery_epoch();
        if trust_epoch < self.state.epoch {
            return Err(CommandError::TrustStateBehind {
                trust_epoch,
                stored_epoch: self.state.epoch,
            });
        }
        self.reconcile(trust_epoch)?;

        let content = match verify_command(jws, trust) {
            Ok(verified) => verified.into_content(),
            Err(error) => {
                return Ok(CommandVerdict::Unverified {
                    result: error.result(),
                    kid: error.header().map(|header| header.kid().to_owned()),
                });
            }
        };
        let command_id = content.command_id();
        let report = |result: DocumentResult| CommandVerdict::Report {
            command_id,
            result: CommandResultKind::Rejected(result),
        };
        if content.recovery_epoch().get() != trust_epoch {
            return Ok(report(DocumentResult::EpochMismatch));
        }
        if content.endpoint_id() != self.state.endpoint_id {
            return Ok(report(DocumentResult::WrongTarget));
        }
        if let Some(record) = self.state.records.get(&command_id) {
            let result = match &record.status {
                RecordStatus::Running => CommandResultKind::AlreadyDone,
                RecordStatus::Finished(result) => result.clone(),
            };
            return Ok(CommandVerdict::Report { command_id, result });
        }

        let seq = content.seq().get();
        let expires_at = content.expires_at();
        let rejection = if self.state.last_seq.is_some_and(|last| seq <= last) {
            Some(DocumentResult::Stale)
        } else {
            check_validity_window(now, content.issued_at(), expires_at, MAX_COMMAND_LIFETIME).err()
        };
        if let Some(rejection) = rejection {
            let result = CommandResultKind::Rejected(rejection);
            self.store
                .reject(command_id, expires_at, &result)
                .map_err(CommandError::Store)?;
            self.state.reject(command_id, expires_at, &result);
            return Ok(CommandVerdict::Report { command_id, result });
        }

        self.store
            .accept(seq, command_id, expires_at)
            .map_err(CommandError::Store)?;
        self.state.accept(seq, command_id, expires_at);
        Ok(CommandVerdict::Execute(content))
    }

    /// Takes an epoch change the key set state machine reported, and
    /// reconciles the state to its new epoch: no sequence floor, the
    /// records kept.
    ///
    /// The caller passes the change only after storing the trust state
    /// that reported it, and passes [`receive`](Self::receive) the latest
    /// stored trust state, never an earlier one: a key can be revoked
    /// within the same epoch, which only the latest trust state knows. A
    /// change whose new epoch is at most the stored one — a late change,
    /// or the same change twice — does nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Store`] when the write fails; then nothing
    /// changed.
    pub fn apply_epoch_change(
        &mut self,
        change: EpochChange,
    ) -> Result<(), CommandError<S::Error>> {
        self.reconcile(change.new_epoch)
    }

    /// Writes the result of an accepted command once it has run: `Done` or
    /// `Failed`.
    ///
    /// For `Done`, the caller first stores the command's diagnostic bundle
    /// where it can find it again by `command_id` after a restart, and only
    /// then writes `Done`. Stopping between the two then leaves the record
    /// running, which reports `AlreadyDone`, and never a `Done` with no
    /// bundle to send. The caller keeps the bundle until
    /// [`prune`](Self::prune) removes the record.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::NotACompletion`] for a result other than
    /// `Done` or `Failed`, [`CommandError::NotRunning`] when `command_id`
    /// has no running record, and [`CommandError::Store`] when the write
    /// fails. Nothing changes on any of them.
    pub fn finish(
        &mut self,
        command_id: LowerUuid,
        result: CommandResultKind,
    ) -> Result<(), CommandError<S::Error>> {
        if !matches!(
            result,
            CommandResultKind::Done | CommandResultKind::Failed { .. }
        ) {
            return Err(CommandError::NotACompletion);
        }
        let running = self
            .state
            .records
            .get(&command_id)
            .is_some_and(|record| record.status == RecordStatus::Running);
        if !running {
            return Err(CommandError::NotRunning { command_id });
        }
        self.store
            .finish(command_id, &result)
            .map_err(CommandError::Store)?;
        self.state.finish(command_id, &result);
        Ok(())
    }

    /// Removes every record kept past its retention, `now > expires_at +
    /// 1 hour`, running ones included, and returns the removed
    /// `command_id`s in order.
    ///
    /// The crate stores only the result's kind; the caller, which kept the
    /// diagnostic bundle of each command it wrote `Done` for, discards the
    /// bundle of each `command_id` returned. A pruned command received
    /// again is judged from the start: at a time no earlier than `now` it
    /// is not run, but rejected as `Stale` by the sequence floor or else as
    /// `Expired`.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Store`] when the write fails; then nothing
    /// was removed.
    pub fn prune(&mut self, now: Timestamp) -> Result<Vec<LowerUuid>, CommandError<S::Error>> {
        let expired: Vec<LowerUuid> = self
            .state
            .records
            .iter()
            .filter(|(_, record)| now.duration_since(record.expires_at) > RETENTION_AFTER_EXPIRY)
            .map(|(command_id, _)| *command_id)
            .collect();
        if expired.is_empty() {
            return Ok(expired);
        }
        self.store.prune(&expired).map_err(CommandError::Store)?;
        self.state.prune(&expired);
        Ok(expired)
    }

    fn reconcile(&mut self, epoch: u64) -> Result<(), CommandError<S::Error>> {
        if epoch <= self.state.epoch {
            return Ok(());
        }
        self.store.reset_epoch(epoch).map_err(CommandError::Store)?;
        self.state.reset_epoch(epoch);
        Ok(())
    }
}
