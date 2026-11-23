//! The telemetry entry's stream state machine: what an entry does with the
//! telemetry messages an endpoint sends it.
//!
//! See [`ReceiverStream`].

mod memory;
mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use jiff::{SignedDuration, Timestamp};
use uuid::Uuid;

pub use self::memory::{MemoryReceiverStore, MemoryReceiverStoreError};
pub use self::store::{
    ReceiverChange, ReceiverEntryState, ReceiverFlowKey, ReceiverFlowState, ReceiverLoss,
    ReceiverLossReason, ReceiverRecord, ReceiverStore,
};
use super::{
    Ack, CloseStream, DroppedRange, ErrorMessage, LastStored, LostOnReset, OpenStream, Record,
    RecordBatch, ResumeInfo, SeqRange, TelemetryMessage, kind, record_hash,
};
use crate::connection::AcceptedKind;
use crate::telemetry_codes::TelemetryError;

/// How long an entry remembers a closed stream: 30 days from when it was
/// closed. Until then the stream's id is refused with
/// [`TelemetryError::Closed`]; from then on it is a stream the entry has
/// never seen, and [`ReceiverStream::prune`] forgets its state.
pub const RECEIVER_CLOSED_RETENTION: SignedDuration = SignedDuration::from_hours(30 * 24);

/// The source of the opening numbers that tie a connection to the opening
/// of a stream it saw. Shared by every [`ReceiverStream`] in the process,
/// so that a [`ReceiverConnection`] passed to another state machine than
/// the one it opened streams on never matches an opening there.
static NEXT_OPENING: AtomicU64 = AtomicU64::new(0);

fn next_opening() -> u64 {
    NEXT_OPENING.fetch_add(1, Ordering::Relaxed)
}

/// What the caller does after a message: send the messages back on the
/// connection, or close it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ReceiverOutput {
    /// Send these messages on the connection, in order, and keep it. The
    /// list is empty when the message gets no answer.
    Reply(Vec<TelemetryMessage>),
    /// Send nothing and close the connection.
    Disconnect,
}

impl ReceiverOutput {
    fn none() -> Self {
        Self::Reply(Vec::new())
    }

    fn one(message: TelemetryMessage) -> Self {
        Self::Reply(vec![message])
    }

    fn error(stream: Uuid, error: TelemetryError) -> Self {
        Self::one(error_message(stream, error))
    }
}

fn error_message(stream: Uuid, error: TelemetryError) -> TelemetryMessage {
    TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: Some(stream),
        error,
    })
}

fn ack(stream: Uuid, a: u64) -> TelemetryMessage {
    TelemetryMessage::Ack(Ack { stream, a })
}

/// The state of one telemetry connection at the entry. It is not
/// persistent: the caller makes one when the connection's `hello` is
/// accepted and drops it with the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverConnection {
    endpoint_id: Uuid,
    accepted_kinds: Vec<AcceptedKind>,
    /// The streams this connection opened, each with the opening it saw.
    opened: BTreeMap<Uuid, u64>,
    halted: bool,
}

impl ReceiverConnection {
    /// Creates the state of a connection from `endpoint_id` that was sent
    /// `accepted_kinds` in its `HelloAck`.
    ///
    /// `endpoint_id` is the `endpoint_id` of the active list entry whose
    /// SPKI matched the connection's certificate.
    #[must_use]
    pub fn new(endpoint_id: Uuid, accepted_kinds: Vec<AcceptedKind>) -> Self {
        Self {
            endpoint_id,
            accepted_kinds,
            opened: BTreeMap::new(),
            halted: false,
        }
    }

    /// Returns the connection's endpoint id, the source's identity.
    #[must_use]
    pub fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }

    /// Returns the record kinds the connection's `HelloAck` accepted.
    #[must_use]
    pub fn accepted_kinds(&self) -> &[AcceptedKind] {
        &self.accepted_kinds
    }

    /// Returns whether the connection is halted: it was told to close and
    /// answers nothing more.
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    fn key(&self, stream: Uuid) -> ReceiverFlowKey {
        ReceiverFlowKey {
            endpoint_id: self.endpoint_id,
            stream,
        }
    }
}

/// A record of a batch, decoded as far as the state machine reads it.
struct Received {
    seq: u64,
    kind: u16,
    schema: u16,
    bytes: Vec<u8>,
}

/// The telemetry stream state machine of one entry, over its
/// [`ReceiverStore`].
///
/// It keeps, for each endpoint at one entry, the open
/// stream and, for each stream, the cumulative acknowledgement `A` and the
/// last record stored `(L, H)`. It stores only records that continue a
/// stream without a gap, records what the endpoint reports dropped or lost,
/// answers `open_stream` with the stream's [`ResumeInfo`], and remembers
/// closed streams for [`RECEIVER_CLOSED_RETENTION`].
///
/// It is sans-IO. It reads no socket, disk or clock: the caller passes in
/// the messages a connection received, already decoded, and the wall
/// clock, and sends the messages that come back. Its persistent state and
/// the records it stores go through a [`ReceiverStore`] the caller
/// implements, one atomic write per call; [`MemoryReceiverStore`] is an
/// implementation in memory.
///
/// # The caller's contract
///
/// - **One entry.** A `ReceiverStream` is the state of one entry, named by
///   its `entry_id`, which every key it passes the store carries. Several
///   entries may share a store; one entry has one `ReceiverStream`.
/// - **The source is the connection.** A connection's
///   [`ReceiverConnection`] is made with the endpoint id the active list
///   matched to the connection's certificate. That id, never the
///   `endpoint_id` of a record's header, is the source's identity in every
///   key; a record whose header names another endpoint is refused.
/// - **In order, one at a time.** The messages of a connection are passed
///   in the order they were received, one call at a time, and no two calls
///   about the same endpoint overlap, whichever connections they come
///   from. The `&mut self` of every call keeps calls from overlapping.
/// - **Batches past a size limit.** A `record_batch` that decodes but is
///   past a size limit
///   ([`TelemetryDecodeError::BatchTooLarge`](crate::telemetry::TelemetryDecodeError::BatchTooLarge)) is not
///   reported to the connection helper as a message that failed to decode,
///   which would close the connection: its `stream` is passed to
///   [`receive_batch_too_large`](Self::receive_batch_too_large), which answers it with
///   [`TelemetryError::TooLarge`] and keeps the connection.
///
/// # Writes, acknowledgements and failures
///
/// Every call that changes something makes all of its changes in one
/// [`ReceiverStore::write`]: the records a batch stores together with the
/// batch's last `A` and `(L, H)`; the stream an `open_stream` closes
/// together with the one it opens. The state machine acknowledges a record,
/// and sends any answer that depends on a change, only after that write
/// succeeded, which means the change is durable. A call that changes
/// nothing writes nothing.
///
/// When a write fails, or a read the call needs, the state machine's own
/// state stays as it was before the call, nothing is sent, and the caller
/// is told to close the connection ([`ReceiverOutput::Disconnect`]). The
/// connection is then halted: every later message on it, an `open_stream`
/// of a new stream included, gets no answer and the same
/// [`ReceiverOutput::Disconnect`]. Since a failed call answers nothing, an
/// endpoint learns whether its `lost_on_reset` or `close_stream` was
/// written from the [`ResumeInfo`] of the next stream it opens on the same
/// connection.
///
/// Every [`ReceiverOutput::Disconnect`] halts the connection the same way,
/// including the ones that follow no failure: a `record_batch` holding a
/// record that does not decode or whose header names another endpoint or
/// stream, which stores and acknowledges none of the batch, and a message
/// only an entry sends.
///
/// A `ReceiverStream` made again from the store with
/// [`restore`](Self::restore) judges every message as the one before it
/// would have. What belongs to a connection — the streams it opened, the
/// kinds it accepts, whether it is halted — is not persistent.
///
/// It holds a copy of the entry's stored stream state, which it changes
/// only after the store has written the change.
#[derive(Debug)]
pub struct ReceiverStream<S> {
    entry_id: Uuid,
    store: S,
    state: ReceiverEntryState,
    /// The opening of each open stream, which a connection must have seen
    /// to send data on it. Not persistent: a stream opened before a restart
    /// gets one when a connection opens it again.
    openings: BTreeMap<ReceiverFlowKey, u64>,
}

impl<S: ReceiverStore> ReceiverStream<S> {
    /// Makes the state machine of entry `entry_id` from the state `store`
    /// holds for it. An entry that never wrote anything starts with no
    /// streams.
    ///
    /// # Errors
    ///
    /// Returns the store's error when it fails to read; no state machine
    /// is made.
    pub fn restore(entry_id: Uuid, store: S) -> Result<Self, S::Error> {
        let state = store.load(entry_id)?;
        Ok(Self {
            entry_id,
            store,
            state,
            openings: BTreeMap::new(),
        })
    }

    /// Returns the entry's identity.
    #[must_use]
    pub fn entry_id(&self) -> Uuid {
        self.entry_id
    }

    /// Returns the entry's stream state.
    #[must_use]
    pub fn state(&self) -> &ReceiverEntryState {
        &self.state
    }

    /// Returns the state of `stream` of `endpoint_id`, if the entry
    /// remembers it.
    #[must_use]
    pub fn flow(&self, endpoint_id: Uuid, stream: Uuid) -> Option<&ReceiverFlowState> {
        self.state.flows.get(&ReceiverFlowKey {
            endpoint_id,
            stream,
        })
    }

    /// Returns the store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the store, consuming the state machine.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Handles a telemetry message received on `connection` at `now`.
    ///
    /// The messages only an entry sends — `resume_info`, `ack` and `error`
    /// — change nothing and close the connection.
    pub fn receive(
        &mut self,
        connection: &mut ReceiverConnection,
        message: TelemetryMessage,
        now: Timestamp,
    ) -> ReceiverOutput {
        if connection.halted {
            return ReceiverOutput::Disconnect;
        }
        let output = match message {
            TelemetryMessage::OpenStream(message) => self.open_stream(connection, message, now),
            TelemetryMessage::RecordBatch(batch) => self.record_batch(connection, batch, now),
            TelemetryMessage::DroppedRange(message) => self.dropped_range(connection, message, now),
            TelemetryMessage::CloseStream(message) => self.close_stream(connection, message, now),
            TelemetryMessage::LostOnReset(message) => self.lost_on_reset(connection, message),
            TelemetryMessage::ResumeInfo(_)
            | TelemetryMessage::Ack(_)
            | TelemetryMessage::ErrorMessage(_) => ReceiverOutput::Disconnect,
        };
        if output == ReceiverOutput::Disconnect {
            connection.halted = true;
        }
        output
    }

    /// Handles a `record_batch` of `stream` received on `connection` at
    /// `now` that decoded but is past a size limit.
    ///
    /// Nothing is stored or acknowledged, and the connection is kept: the
    /// answer is [`TelemetryError::Closed`] or
    /// [`TelemetryError::UnknownStream`] when the stream's state refuses
    /// data, and [`TelemetryError::TooLarge`] otherwise.
    pub fn receive_batch_too_large(
        &mut self,
        connection: &mut ReceiverConnection,
        stream: Uuid,
        now: Timestamp,
    ) -> ReceiverOutput {
        if connection.halted {
            return ReceiverOutput::Disconnect;
        }
        let error = match self.check_data(connection, stream, now) {
            Ok(_) => TelemetryError::TooLarge,
            Err(error) => error,
        };
        ReceiverOutput::error(stream, error)
    }

    /// Forgets the state of every stream closed at least
    /// [`RECEIVER_CLOSED_RETENTION`] before `now`, in one write, and
    /// returns the streams forgotten. Their records and loss records stay
    /// in the store.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the write failed; then nothing was
    /// forgotten.
    pub fn prune(&mut self, now: Timestamp) -> Result<Vec<ReceiverFlowKey>, S::Error> {
        let expired: Vec<ReceiverFlowKey> = self
            .state
            .flows
            .iter()
            .filter(|(_, state)| is_expired(state, now))
            .map(|(key, _)| *key)
            .collect();
        if expired.is_empty() {
            return Ok(expired);
        }
        let changes: Vec<ReceiverChange> = expired
            .iter()
            .map(|key| ReceiverChange::RemoveFlow(*key))
            .collect();
        self.commit(changes)?;
        Ok(expired)
    }

    /// Writes `changes` and, once written, applies them to the state.
    fn commit(&mut self, changes: Vec<ReceiverChange>) -> Result<(), S::Error> {
        let flow_changes: Vec<ReceiverChange> = changes
            .iter()
            .filter(|change| {
                matches!(
                    change,
                    ReceiverChange::SetFlow { .. } | ReceiverChange::RemoveFlow(_)
                )
            })
            .cloned()
            .collect();
        self.store.write(self.entry_id, changes)?;
        for change in &flow_changes {
            self.state.apply(change);
            let key = match change {
                ReceiverChange::SetFlow { key, state } if !state.is_open() => key,
                ReceiverChange::RemoveFlow(key) => key,
                _ => continue,
            };
            self.openings.remove(key);
        }
        Ok(())
    }

    /// Judges whether `stream` takes data from `connection`: the stream
    /// must not be remembered as closed, and must be the endpoint's open
    /// stream, opened on this connection and not closed since.
    fn check_data(
        &self,
        connection: &ReceiverConnection,
        stream: Uuid,
        now: Timestamp,
    ) -> Result<ReceiverFlowState, TelemetryError> {
        let key = connection.key(stream);
        let Some(state) = self.state.flows.get(&key) else {
            return Err(TelemetryError::UnknownStream);
        };
        if is_remembered_closed(state, now) {
            return Err(TelemetryError::Closed);
        }
        let opened_here = match (self.openings.get(&key), connection.opened.get(&stream)) {
            (Some(current), Some(seen)) => current == seen,
            _ => false,
        };
        if state.is_open() && opened_here {
            Ok(*state)
        } else {
            Err(TelemetryError::UnknownStream)
        }
    }

    fn open_stream(
        &mut self,
        connection: &mut ReceiverConnection,
        OpenStream { stream }: OpenStream,
        now: Timestamp,
    ) -> ReceiverOutput {
        let key = connection.key(stream);
        let state = match self.state.flows.get(&key) {
            Some(state) if is_remembered_closed(state, now) => {
                return ReceiverOutput::error(stream, TelemetryError::Closed);
            }
            Some(state) if state.is_open() => *state,
            _ => {
                let mut changes: Vec<ReceiverChange> = self
                    .state
                    .endpoint_flows(connection.endpoint_id)
                    .filter(|(_, state)| state.is_open())
                    .map(|(key, state)| ReceiverChange::SetFlow {
                        key: *key,
                        state: ReceiverFlowState {
                            closed_at: Some(now),
                            ..*state
                        },
                    })
                    .collect();
                let state = ReceiverFlowState::opened();
                changes.push(ReceiverChange::SetFlow { key, state });
                if self.commit(changes).is_err() {
                    return ReceiverOutput::Disconnect;
                }
                state
            }
        };
        let opening = *self.openings.entry(key).or_insert_with(next_opening);
        connection.opened.insert(stream, opening);
        ReceiverOutput::one(TelemetryMessage::ResumeInfo(ResumeInfo {
            stream,
            a: state.a,
            last_stored: state.last_stored,
        }))
    }

    fn record_batch(
        &mut self,
        connection: &ReceiverConnection,
        batch: RecordBatch,
        now: Timestamp,
    ) -> ReceiverOutput {
        let stream = batch.stream();
        let state = match self.check_data(connection, stream, now) {
            Ok(state) => state,
            Err(error) => return ReceiverOutput::error(stream, error),
        };
        let mut received = Vec::with_capacity(batch.records().len());
        for bytes in batch.into_records() {
            let Ok(record) = Record::from_bytes(&bytes) else {
                return ReceiverOutput::Disconnect;
            };
            if record.header.endpoint_id != connection.endpoint_id || record.header.stream != stream
            {
                return ReceiverOutput::Disconnect;
            }
            received.push(Received {
                seq: record.header.seq,
                kind: record.kind,
                schema: record.schema,
                bytes,
            });
        }

        let mut next = state;
        let mut changes = Vec::new();
        let mut stopped = None;
        for record in received {
            if record.seq <= next.a {
                continue;
            }
            // `next.a` is below `record.seq`, so below `u64::MAX`.
            let expected = next.a.saturating_add(1);
            if record.seq > expected {
                stopped = Some(TelemetryError::Gap { expected });
                break;
            }
            if !kind::accepts(&connection.accepted_kinds, record.kind, record.schema) {
                stopped = Some(TelemetryError::UnsupportedKind);
                break;
            }
            next.a = record.seq;
            next.last_stored = Some(LastStored {
                seq: record.seq,
                hash: record_hash(&record.bytes),
            });
            changes.push(ReceiverChange::AppendRecord(ReceiverRecord {
                endpoint_id: connection.endpoint_id,
                stream,
                seq: record.seq,
                bytes: record.bytes,
            }));
        }
        if !changes.is_empty() {
            changes.push(ReceiverChange::SetFlow {
                key: connection.key(stream),
                state: next,
            });
            if self.commit(changes).is_err() {
                return ReceiverOutput::Disconnect;
            }
        }
        let mut messages = vec![ack(stream, next.a)];
        if let Some(error) = stopped {
            messages.push(error_message(stream, error));
        }
        ReceiverOutput::Reply(messages)
    }

    fn dropped_range(
        &mut self,
        connection: &ReceiverConnection,
        DroppedRange {
            stream,
            from,
            to,
            reason,
        }: DroppedRange,
        now: Timestamp,
    ) -> ReceiverOutput {
        let state = match self.check_data(connection, stream, now) {
            Ok(state) => state,
            Err(error) => return ReceiverOutput::error(stream, error),
        };
        if from > to {
            return ReceiverOutput::error(stream, TelemetryError::BadRange);
        }
        if to <= state.a {
            return ReceiverOutput::one(ack(stream, state.a));
        }
        // `state.a` is below `to`, so below `u64::MAX`.
        let expected = state.a.saturating_add(1);
        if from > expected {
            return ReceiverOutput::error(stream, TelemetryError::Gap { expected });
        }
        let changes = vec![
            ReceiverChange::AppendLoss(ReceiverLoss {
                endpoint_id: connection.endpoint_id,
                stream,
                range: SeqRange { from: expected, to },
                reason: ReceiverLossReason::Dropped(reason),
            }),
            ReceiverChange::SetFlow {
                key: connection.key(stream),
                state: ReceiverFlowState { a: to, ..state },
            },
        ];
        if self.commit(changes).is_err() {
            return ReceiverOutput::Disconnect;
        }
        ReceiverOutput::one(ack(stream, to))
    }

    fn close_stream(
        &mut self,
        connection: &ReceiverConnection,
        CloseStream { stream }: CloseStream,
        now: Timestamp,
    ) -> ReceiverOutput {
        let key = connection.key(stream);
        let Some(state) = self.state.flows.get(&key).filter(|state| state.is_open()) else {
            return ReceiverOutput::none();
        };
        let changes = vec![ReceiverChange::SetFlow {
            key,
            state: ReceiverFlowState {
                closed_at: Some(now),
                ..*state
            },
        }];
        match self.commit(changes) {
            Ok(()) => ReceiverOutput::none(),
            Err(_) => ReceiverOutput::Disconnect,
        }
    }

    fn lost_on_reset(
        &mut self,
        connection: &ReceiverConnection,
        LostOnReset { old_stream, ranges }: LostOnReset,
    ) -> ReceiverOutput {
        if ranges.iter().any(|range| range.from > range.to) {
            return ReceiverOutput::error(old_stream, TelemetryError::BadRange);
        }
        let mut changes = Vec::new();
        // A message may carry as many ranges as its frame holds, so a range
        // repeated within it is found in a set rather than by scanning the
        // ranges before it; `changes` keeps the order they arrived in.
        let mut new_ranges = BTreeSet::new();
        for range in ranges {
            if new_ranges.contains(&(range.from, range.to)) {
                continue;
            }
            match self.store.has_lost_on_reset(
                self.entry_id,
                connection.endpoint_id,
                old_stream,
                range,
            ) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => return ReceiverOutput::Disconnect,
            }
            new_ranges.insert((range.from, range.to));
            changes.push(ReceiverChange::AppendLoss(ReceiverLoss {
                endpoint_id: connection.endpoint_id,
                stream: old_stream,
                range,
                reason: ReceiverLossReason::LostOnReset,
            }));
        }
        if changes.is_empty() {
            return ReceiverOutput::none();
        }
        match self.commit(changes) {
            Ok(()) => ReceiverOutput::none(),
            Err(_) => ReceiverOutput::Disconnect,
        }
    }
}

/// Returns whether a stream is closed and still remembered at `now`: closed
/// less than [`RECEIVER_CLOSED_RETENTION`] before it.
fn is_remembered_closed(state: &ReceiverFlowState, now: Timestamp) -> bool {
    state
        .closed_at
        .is_some_and(|closed_at| now.duration_since(closed_at) < RECEIVER_CLOSED_RETENTION)
}

/// Returns whether a stream is closed and no longer remembered at `now`.
fn is_expired(state: &ReceiverFlowState, now: Timestamp) -> bool {
    state
        .closed_at
        .is_some_and(|closed_at| now.duration_since(closed_at) >= RECEIVER_CLOSED_RETENTION)
}
