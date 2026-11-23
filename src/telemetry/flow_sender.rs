//! The endpoint's side of a telemetry stream: [`SenderStream`].
//!
//! The sender holds the records it collects, gives them sequence numbers,
//! fixes their bytes once and resends exactly those bytes, and from the
//! entry's cumulative acknowledgements and the `resume_info` of each
//! reconnection decides whether to carry on with its stream or to open a
//! new one. It is sans-IO: it reads no socket, disk or clock, and takes
//! everything as values from its caller.

mod engine;
mod store;

use std::fmt;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use uuid::Uuid;

use self::engine::{Core, State, Verdict};
use self::store::Collected;
pub use self::store::{
    MemorySenderStore, SenderStateChange, SenderStateEntry, SenderStateKey, SenderStore,
    SenderStoreError,
};
use crate::connection::TelemetryEntry;
use crate::telemetry::{Record, RecordEncodeError, TelemetryMessage};

/// The default retention of a record not yet acknowledged: 30 days.
pub const SENDER_DEFAULT_RETENTION: SignedDuration = SignedDuration::from_hours(30 * 24);

/// How a [`SenderStream`] bounds what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderConfig {
    /// The most records the collection buffer holds; past it, the oldest
    /// collected are deleted.
    pub collect_limit: usize,
    /// The most bytes of records the send queue holds, acknowledged
    /// copies included; past it, acknowledged copies are deleted first,
    /// oldest first, then unacknowledged records, lowest sequence number
    /// first.
    pub queue_limit: u64,
    /// How long a record not yet acknowledged is kept, from when it was
    /// collected, by the wall clock. A record whose age reaches it is
    /// deleted.
    pub retention: SignedDuration,
}

impl SenderConfig {
    /// Creates a configuration with the given limits and the default
    /// retention, [`SENDER_DEFAULT_RETENTION`].
    #[must_use]
    pub fn new(collect_limit: usize, queue_limit: u64) -> Self {
        Self {
            collect_limit,
            queue_limit,
            retention: SENDER_DEFAULT_RETENTION,
        }
    }

    /// Sets the retention.
    #[must_use]
    pub fn with_retention(mut self, retention: SignedDuration) -> Self {
        self.retention = retention;
        self
    }
}

/// A connection the caller opened to a telemetry entry, as
/// [`SenderStream::connect`] named it.
///
/// The caller tags every input of the connection with it. An input tagged
/// with any connection but the current one, such as an answer arriving
/// after its connection ended, changes nothing and produces nothing. A
/// connection is valid only for the [`SenderStream`] that named it; none
/// survives a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderConnection {
    id: u64,
    entry_id: Uuid,
}

impl SenderConnection {
    /// Returns the `entry_id` of the entry the connection is to: the
    /// target when it was opened.
    #[must_use]
    pub fn entry_id(&self) -> Uuid {
        self.entry_id
    }
}

/// What a [`SenderStream`] asks its caller to do, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderAction {
    /// Send this message on the current connection.
    Send(TelemetryMessage),
    /// Close the current connection. It has already ended for the stream:
    /// its later inputs are ignored.
    Disconnect,
    /// The target entry changed: connect to this one.
    Connect {
        /// The `entry_id` of the entry to connect to.
        entry_id: Uuid,
    },
}

/// What [`SenderStream::connect`] gives back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderConnected {
    /// The new connection, or `None` when there is no target to connect
    /// to.
    pub connection: Option<SenderConnection>,
    /// What to do, the deadlines handled by the call included.
    pub actions: Vec<SenderAction>,
}

/// A record left over from a sender whose sequence state was lost, for
/// [`SenderStream::recover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderRecovered {
    /// The record's bytes, as they were last fixed.
    pub bytes: Vec<u8>,
    /// When its retention started: when it was collected.
    pub retained_since: Timestamp,
}

/// Where the current stream stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderPosition {
    /// The stream's id.
    pub stream: Uuid,
    /// The `entry_id` of the entry the stream belongs to.
    pub entry_id: Uuid,
    /// `K`, the last sequence number acknowledged.
    pub acknowledged: u64,
    /// `M`, the highest sequence number given.
    pub assigned: u64,
    /// `S`, the highest sequence number sent.
    pub sent: u64,
}

/// The last successful delivery to one listed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderEntryStatus {
    /// The entry's `entry_id`.
    pub entry_id: Uuid,
    /// The wall clock of the last valid `ack` from it, if any.
    pub last_success: Option<Timestamp>,
}

/// The values the `transport` field of a control status report carries,
/// for the caller to copy there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderStatus {
    /// Each entry of the current list, in its order.
    pub entries: Vec<SenderEntryStatus>,
    /// The records in the collection buffer.
    pub collected_records: u64,
    /// The records in the send queue, acknowledged copies included.
    pub queued_records: u64,
    /// The byte length of the records in the send queue.
    pub queued_bytes: u64,
    /// How many ranges of dropped sequence numbers were created. A range
    /// that extends one of the same reason next to it is not a new one,
    /// nor is one carried over to a new stream at the same entry.
    pub dropped_ranges: u64,
    /// How many records were deleted from the collection buffer, by its
    /// limit or its retention, without a sequence number: the
    /// `unsupported` dropped count.
    pub unsupported: u64,
}

/// Why a [`SenderStream`] call failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum SenderError {
    /// The store failed to read or write. A failed write left the stream
    /// as it was before the call.
    Store(SenderStoreError),
    /// The stored state is not one a [`SenderStream`] wrote.
    Corrupt {
        /// What is wrong with it.
        reason: String,
    },
    /// A collected record breaks a rule of [`Record::to_bytes`].
    Record(RecordEncodeError),
    /// The endpoint is registered under another id.
    EndpointIdMismatch {
        /// The id registered.
        registered: Uuid,
        /// The id given.
        given: Uuid,
    },
    /// A recovered record does not decode, or does not encode again.
    Recovered {
        /// The record's position in the list given, from 0.
        index: usize,
        /// Why.
        reason: String,
    },
}

impl fmt::Display for SenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "sender store: {error}"),
            Self::Corrupt { reason } => write!(f, "stored sender state: {reason}"),
            Self::Record(error) => write!(f, "collected record: {error}"),
            Self::EndpointIdMismatch { registered, given } => {
                write!(f, "the endpoint is registered as {registered}, not {given}")
            }
            Self::Recovered { index, reason } => write!(f, "recovered record {index}: {reason}"),
        }
    }
}

impl std::error::Error for SenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::Corrupt { .. } | Self::EndpointIdMismatch { .. } | Self::Recovered { .. } => None,
        }
    }
}

/// The endpoint's side of a telemetry stream, as a state machine that does
/// no I/O.
///
/// # Inputs and outputs
///
/// The caller passes in what happens — collected records
/// ([`collect`](Self::collect)), the end of registration with the
/// `endpoint_id` it settled ([`register`](Self::register)), the list of
/// telemetry entries ([`set_entries`](Self::set_entries)), a connection
/// opened ([`connect`](Self::connect)) or ended
/// ([`disconnected`](Self::disconnected)), the entry's `hello_ack`
/// ([`hello_ack`](Self::hello_ack)), the telemetry messages received
/// ([`receive`](Self::receive)), and the passing of time
/// ([`tick`](Self::tick)) — and gets back [`SenderAction`]s: messages to
/// send, a connection to close, an entry to connect to.
/// [`status`](Self::status) gives the values of a status report.
///
/// # Times
///
/// Every call that takes the time takes both clocks. `wall` is the wall
/// clock: a record's retention runs from the `wall` of the call that
/// collected it, an acknowledged copy is kept 24 hours from the `wall` of
/// its first acknowledgement, and the last successful delivery is the
/// `wall` of an `ack`. `now` is a monotonic clock, as the time since an
/// origin of the caller's choosing, the same origin for every call of one
/// stream: the 30 minutes before the endpoint moves to the next entry run
/// on it. The monotonic clock does not survive a restart, so those 30
/// minutes start again from the `now` passed to [`open`](Self::open).
///
/// A call that takes the time handles it in this order: it judges its
/// input (an input of another connection is ignored, and an invalid
/// message on the current one only disconnects, both without handling
/// any deadline); records a valid `hello_ack`'s arrival, so that one
/// arriving at the 30-minute mark keeps the entry; handles the deadlines
/// (retention, acknowledged copies, the node move); and then does the
/// input's own work.
///
/// # Connections
///
/// [`connect`](Self::connect) names a new connection to the current
/// target, and the caller tags every later input of that connection with
/// it. The [`TelemetryEntry`] passed to [`hello_ack`](Self::hello_ack)
/// must be the one the connection helper reported for this connection,
/// whose `entry_id` it already checked against the entry it connected to
/// (a mismatch closes the connection there and is never passed in). The
/// stream checks it again: an `entry_id` other than the connection's
/// target disconnects. A connection ends when the caller reports it
/// ([`disconnected`](Self::disconnected)), when the stream asks for it to
/// be closed ([`SenderAction::Disconnect`]), or when another is opened.
///
/// # Registration and new stream ids
///
/// Records collected before registration wait in the collection buffer;
/// [`register`](Self::register) gives the `endpoint_id` every record moved
/// afterwards carries, and moves what may be moved in the same call. A
/// different id later is an error; the same id again changes nothing.
///
/// The caller supplies new stream ids: [`hello_ack`](Self::hello_ack) and
/// [`receive`](Self::receive) take a fresh one, which the stream uses only
/// if that call opens a new stream. It must differ from every stream id
/// this endpoint used before (a random UUID does). Retrying a failed call
/// with the same id repeats it exactly.
///
/// # Persistence
///
/// The state is kept through a [`SenderStore`]. **Each call that changes
/// the state writes everything it changed as one atomic commit**, the
/// deadlines it handled first included, and only then returns what to
/// do: sending is a change too, since it raises `S` and the history of
/// announced losses. If the commit fails, the call returns the error,
/// produces nothing, and leaves the stream exactly as it was, so giving it
/// the same input again handles it as the first time.
///
/// A stream [`open`](Self::open)ed on a store makes the same decisions it
/// would have made before the restart: the target, the current stream and
/// its entry, the accepted kinds last verified there, the buffers and
/// ledgers and the counts all come back. No connection does. A store that
/// went back to an older snapshot is a stream with an older state, which
/// the next `resume_info` judges.
///
/// # Notices and the entry's contract
///
/// When a new stream replaces one at the same entry, the `lost_on_reset`
/// and `close_stream` about the old one are kept, and sent on every
/// connection before the new stream's `open_stream`, until a valid
/// `resume_info` for the new stream arrives on a connection that sent
/// them. This relies on the entry handling the messages of one connection
/// in order, idempotently, and, when it fails to store a notice, closing
/// the connection without answering the messages after it: a
/// `resume_info` answering the `open_stream` then proves the notices
/// before it were stored. Notices for an entry are dropped when the
/// stream moves to another entry.
#[derive(Debug)]
pub struct SenderStream<S> {
    store: S,
    core: Core,
}

impl<S: SenderStore> SenderStream<S> {
    /// Opens the stream on `store`: from the state it holds, or empty when
    /// it holds none. `now` is the monotonic clock, from which the 30
    /// minutes before a node move start again.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the store cannot be read, and
    /// [`SenderError::Corrupt`] when what it holds is not a sender's
    /// state.
    pub fn open(store: S, config: SenderConfig, now: Duration) -> Result<Self, SenderError> {
        let entries = store.load().map_err(SenderError::Store)?;
        let state = State::load(entries).map_err(|reason| SenderError::Corrupt { reason })?;
        Ok(Self {
            store,
            core: Core::new(config, state, now),
        })
    }

    /// Opens the stream on `store` after its sequence state was lost,
    /// from the records left over, in their original order.
    ///
    /// Whatever the store holds of the current stream (its records,
    /// ledgers and notices) is replaced: the records are taken as
    /// unacknowledged and without a stream, and the next `hello_ack`
    /// opens a new stream that renumbers them by the same rule as any new
    /// stream, records of a kind the entry does not accept going back to
    /// the collection buffer. The rest of the state (registration,
    /// entries, target, accepted kinds, counts) is kept. The change is
    /// written before this returns.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`open`](Self::open),
    /// [`SenderError::Recovered`] when a record does not decode or encode
    /// again, and [`SenderError::Store`] when the change cannot be
    /// written.
    pub fn recover(
        store: S,
        config: SenderConfig,
        records: Vec<SenderRecovered>,
        now: Duration,
    ) -> Result<Self, SenderError> {
        let mut decoded = Vec::with_capacity(records.len());
        for (index, recovered) in records.into_iter().enumerate() {
            let record =
                Record::from_bytes(&recovered.bytes).map_err(|error| SenderError::Recovered {
                    index,
                    reason: error.to_string(),
                })?;
            record.to_bytes().map_err(|error| SenderError::Recovered {
                index,
                reason: error.to_string(),
            })?;
            decoded.push((recovered.bytes, record, recovered.retained_since));
        }
        let mut stream = Self::open(store, config, now)?;
        stream.run(|core, _| core.install_orphans(decoded))?;
        Ok(stream)
    }

    /// Runs one call: its rules, then sending, then one commit of what
    /// changed, everything undone if the commit fails.
    fn run<T>(
        &mut self,
        rules: impl FnOnce(&mut Core, &mut Vec<SenderAction>) -> T,
    ) -> Result<(T, Vec<SenderAction>), SenderError> {
        let snapshot = self.core.snapshot();
        let mut actions = Vec::new();
        let value = rules(&mut self.core, &mut actions);
        self.core.pump(&mut actions);
        let change = self.core.state.change(Core::snapshot_meta(&snapshot));
        if !change.is_empty()
            && let Err(error) = self.store.commit(&change)
        {
            self.core.restore(snapshot);
            return Err(SenderError::Store(error));
        }
        self.core.state.settle();
        Ok((value, actions))
    }

    /// Collects a record.
    ///
    /// The record's `endpoint_id`, `stream` and `seq` are ignored: the
    /// stream fills them in when it gives the record a sequence number.
    /// The record waits in the collection buffer until the endpoint is
    /// registered, a stream is open at the target, and the entry's
    /// accepted kinds take its `kind` and `schema`; then it is moved to
    /// the send queue in collection order, its bytes fixed and its hash
    /// taken. Its retention starts at `wall`.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Record`] when the record breaks a rule of
    /// [`Record::to_bytes`] (nothing changes then), and
    /// [`SenderError::Store`] when the change cannot be written.
    pub fn collect(
        &mut self,
        mut record: Record,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        record.header.endpoint_id = Uuid::nil();
        record.header.stream = Uuid::nil();
        record.header.seq = 0;
        let bytes = record.to_bytes().map_err(SenderError::Record)?;
        let collected = Collected {
            bytes,
            kind: record.kind,
            schema: record.schema,
            retained_since: wall,
        };
        self.run(|core, out| {
            core.deadlines(wall, now, out);
            core.collect(collected);
        })
        .map(|((), actions)| actions)
    }

    /// Takes the `endpoint_id` registration settled.
    ///
    /// Every record moved to the send queue from now on carries it. When a
    /// stream and its entry's accepted kinds are already known, the
    /// records waiting in the collection buffer are moved in this same
    /// call. Giving the id already registered changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::EndpointIdMismatch`] when another id is
    /// registered (nothing changes then: an endpoint installed again
    /// starts from an empty state), and [`SenderError::Store`] when the
    /// change cannot be written.
    pub fn register(&mut self, endpoint_id: Uuid) -> Result<Vec<SenderAction>, SenderError> {
        match self.core.state.meta.endpoint_id {
            Some(registered) if registered == endpoint_id => Ok(Vec::new()),
            Some(registered) => Err(SenderError::EndpointIdMismatch {
                registered,
                given: endpoint_id,
            }),
            None => self
                .run(|core, _| core.register(endpoint_id))
                .map(|((), actions)| actions),
        }
    }

    /// Takes the `entry_id`s of the verified address document's
    /// `telemetry_entries`, in order.
    ///
    /// The target stays if the new list holds it; otherwise it becomes the
    /// list's first entry, and a current connection is closed. An empty
    /// list leaves no target.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn set_entries(
        &mut self,
        entries: Vec<Uuid>,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        self.run(|core, out| {
            core.deadlines(wall, now, out);
            core.set_entries(entries, now, out);
        })
        .map(|((), actions)| actions)
    }

    /// Names a new connection to the current target, after handling the
    /// deadlines, which may move the target first. A connection open
    /// before ends.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn connect(
        &mut self,
        wall: Timestamp,
        now: Duration,
    ) -> Result<SenderConnected, SenderError> {
        let (opened, actions) = self.run(|core, out| {
            core.deadlines(wall, now, out);
            core.open_connection(now)
        })?;
        Ok(SenderConnected {
            connection: opened.map(|(id, entry_id)| SenderConnection { id, entry_id }),
            actions,
        })
    }

    /// Takes the end of a connection.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn disconnected(
        &mut self,
        connection: SenderConnection,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        if !self.is_current(connection) {
            return Ok(Vec::new());
        }
        self.run(|core, out| {
            core.end_connection(now);
            core.deadlines(wall, now, out);
        })
        .map(|((), actions)| actions)
    }

    /// Takes the entry's `hello_ack` on `connection`, as the connection
    /// helper reported it.
    ///
    /// `entry` must come from this connection's handshake, its `entry_id`
    /// already checked by the helper against the entry connected to. The
    /// accepted kinds become the ones last verified at that entry. With no
    /// current stream, or one at another entry, a new stream opens with
    /// the id `new_stream`; otherwise the current one is offered again.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn hello_ack(
        &mut self,
        connection: SenderConnection,
        entry: &TelemetryEntry,
        new_stream: Uuid,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        match self.core.judge_hello(connection.id, entry) {
            Verdict::Ignore => return Ok(Vec::new()),
            Verdict::Noop => {}
            _ => return Ok(self.disconnect(now)),
        }
        self.run(|core, out| {
            core.mark_hello();
            core.deadlines(wall, now, out);
            core.hello_ack(entry, new_stream, wall, out);
        })
        .map(|((), actions)| actions)
    }

    /// Takes a telemetry message received on `connection`.
    ///
    /// A `resume_info` answering the awaited `open_stream` runs the
    /// reconnection judgment; an `ack` within what this connection may
    /// acknowledge raises `K`; a `closed` answering the awaited
    /// `open_stream` opens a new stream. `new_stream` is used only if a
    /// new stream opens. An invalid message — a `resume_info` answering
    /// nothing, of another stream or with `last_stored` past `a`; an `ack`
    /// of the current stream past `K` without the right to acknowledge it
    /// or past `C`; any other error; a message only an endpoint sends —
    /// only closes the connection. An `ack` of another stream, or not
    /// past `K`, does nothing itself.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn receive(
        &mut self,
        connection: SenderConnection,
        message: &TelemetryMessage,
        new_stream: Uuid,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        let verdict = self.core.judge(connection.id, message);
        match verdict {
            Verdict::Ignore => return Ok(Vec::new()),
            Verdict::Invalid => return Ok(self.disconnect(now)),
            Verdict::Noop | Verdict::Resume(_) | Verdict::Ack(_) | Verdict::Closed => {}
        }
        self.run(|core, out| {
            core.deadlines(wall, now, out);
            match verdict {
                Verdict::Resume(info) => core.resume(&info, new_stream, wall, out),
                Verdict::Ack(a) => core.ack(a, wall),
                Verdict::Closed => core.closed(new_stream, wall, out),
                Verdict::Ignore | Verdict::Invalid | Verdict::Noop => {}
            }
        })
        .map(|((), actions)| actions)
    }

    /// Handles the deadlines alone: retention, acknowledged copies, and
    /// the node move.
    ///
    /// # Errors
    ///
    /// Returns [`SenderError::Store`] when the change cannot be written.
    pub fn tick(
        &mut self,
        wall: Timestamp,
        now: Duration,
    ) -> Result<Vec<SenderAction>, SenderError> {
        self.run(|core, out| core.deadlines(wall, now, out))
            .map(|((), actions)| actions)
    }

    fn disconnect(&mut self, now: Duration) -> Vec<SenderAction> {
        self.core.end_connection(now);
        vec![SenderAction::Disconnect]
    }

    fn is_current(&self, connection: SenderConnection) -> bool {
        self.core
            .conn
            .as_ref()
            .is_some_and(|conn| conn.id == connection.id)
    }
}

impl<S> SenderStream<S> {
    /// Returns the values of a status report.
    #[must_use]
    pub fn status(&self) -> SenderStatus {
        let meta = &self.core.state.meta;
        SenderStatus {
            entries: meta
                .entries
                .iter()
                .map(|entry_id| SenderEntryStatus {
                    entry_id: *entry_id,
                    last_success: meta
                        .last_success
                        .iter()
                        .find(|success| success.entry == *entry_id)
                        .map(|success| success.at),
                })
                .collect(),
            collected_records: u64::try_from(self.core.state.collect.len())
                .expect("a count in memory fits in a u64 on every supported target"),
            queued_records: u64::try_from(self.core.state.queue.len())
                .expect("a count in memory fits in a u64 on every supported target"),
            queued_bytes: self.core.state.queue_bytes,
            dropped_ranges: meta.dropped_ranges,
            unsupported: meta.unsupported,
        }
    }

    /// Returns the `entry_id` of the entry to connect to, if any.
    #[must_use]
    pub fn target(&self) -> Option<Uuid> {
        self.core.state.meta.target
    }

    /// Returns the registered `endpoint_id`, if any.
    #[must_use]
    pub fn endpoint_id(&self) -> Option<Uuid> {
        self.core.state.meta.endpoint_id
    }

    /// Returns where the current stream stands, or `None` when there is
    /// none.
    #[must_use]
    pub fn position(&self) -> Option<SenderPosition> {
        let meta = &self.core.state.meta;
        meta.flow.map(|flow| SenderPosition {
            stream: flow.stream,
            entry_id: flow.entry,
            acknowledged: meta.k,
            assigned: meta.m,
            sent: meta.s,
        })
    }

    /// Returns the current connection, if any.
    #[must_use]
    pub fn connection(&self) -> Option<SenderConnection> {
        self.core.conn.as_ref().map(|conn| SenderConnection {
            id: conn.id,
            entry_id: conn.entry,
        })
    }

    /// Returns the store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the store, to change it outside the stream (a test injects
    /// write failures this way).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Returns the store, consuming the stream.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

#[cfg(test)]
mod tests;
