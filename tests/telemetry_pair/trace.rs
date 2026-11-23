//! What a run observed, and what the model expected, in the order it
//! happened. The judges read nothing else, so a mutation test changes a
//! run's trace and checks that a judge catches it.

use std::collections::{BTreeMap, BTreeSet};

use senta_protocol::telemetry::{
    ReceiverFlowKey, ReceiverFlowState, ReceiverOutput, SeqRange, TelemetryMessage,
};
use senta_protocol::telemetry_codes::DropReason;
use uuid::Uuid;

use crate::fixture::Mark;

pub type AssignId = u64;
pub type RecoveryId = usize;
/// One lifetime of a stream's state at an entry.
pub type Lt = u64;
pub type LinkId = u64;

/// One sequence number of a stream as the endpoint holds it: a record's
/// body, or a dropped sequence number. Both name the assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Record {
        mark: Mark,
        assign: AssignId,
    },
    Dropped {
        reason: DropReason,
        assign: AssignId,
    },
}

/// An assignment: the endpoint gave `mark` the sequence number `seq` of
/// `stream` (nil for a record left over without a stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assign {
    pub mark: Mark,
    pub stream: Uuid,
    pub seq: u64,
}

/// Why a stream was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reset {
    Fresh,
    EntryChanged,
    Lost { a: u64 },
    Same,
    Closed,
}

/// A reconnection judgment or a stream transition.
#[derive(Debug, Clone)]
pub struct Recovery {
    pub ev: usize,
    pub entry: Uuid,
    pub link: Option<LinkId>,
    /// `None` for a resumption of the same stream.
    pub reset: Option<Reset>,
    pub old_stream: Option<Uuid>,
    pub stream: Uuid,
    /// An allowed recovery for the duplicate judgment.
    pub allowed: bool,
    /// The recovery targets, before the accepted kinds filter them.
    pub targets: BTreeSet<Mark>,
    /// The records waiting in the collection buffer. The duplicate
    /// judgment counts them with the targets of an allowed recovery, which
    /// the issue does not (see the pull request's deviations): a record
    /// already stored can wait there again, and then no target set holds
    /// it. It got there by an endpoint going back to a snapshot that held
    /// it there, or by an earlier recovery that sent it back as a refused
    /// kind, perhaps at another entry. A record collected and not moved
    /// since was never stored, so it never needs the allowance.
    pub waiting: BTreeSet<Mark>,
    /// The expected list, from `start`.
    pub start: u64,
    pub list: Vec<Item>,
    /// The records the send queue held before the recovery.
    pub pre_queue: BTreeSet<Mark>,
    /// Records of the targets sent back to the collection buffer.
    pub returned: Vec<Mark>,
    /// The notices expected before every `open_stream` of the new stream:
    /// the ranges of `lost_on_reset`, and whether `close_stream` follows.
    pub notices: Option<Notices>,
    /// The `unsupported` count the call added, as expected and as the
    /// status reported.
    pub unsupported_expected: u64,
    pub unsupported_observed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notices {
    pub lost: Vec<(u64, u64)>,
    pub close: bool,
    /// The assignment of every old sequence number the `lost_on_reset`
    /// carries.
    pub links: BTreeMap<u64, AssignId>,
}

/// What an ingress commit wrote, tied to what the endpoint sent.
#[derive(Debug, Clone)]
pub enum CommitItem {
    Record {
        key: ReceiverFlowKey,
        seq: u64,
        mark: Option<Mark>,
        bytes: Vec<u8>,
        assign: Option<AssignId>,
    },
    Dropped {
        key: ReceiverFlowKey,
        range: SeqRange,
        reason: DropReason,
        assigns: Vec<AssignId>,
    },
    Lor {
        key: ReceiverFlowKey,
        range: SeqRange,
        assigns: Vec<AssignId>,
    },
    Flow {
        key: ReceiverFlowKey,
        state: ReceiverFlowState,
    },
    /// A stream's state forgotten.
    Remove,
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub ev: usize,
    pub entry: Uuid,
    /// The lifetime of the key's state the change belongs to, if any.
    pub lt: Option<Lt>,
    pub item: CommitItem,
}

/// A record of a `record_batch`, as sent.
#[derive(Debug, Clone)]
pub struct SentRecord {
    pub seq: u64,
    pub mark: Option<Mark>,
    pub bytes: Vec<u8>,
    /// The model's assignment at that sequence number when it was sent.
    pub assign: Option<AssignId>,
}

/// An `ack` the entry sent, with the coverage of its lifetime then.
#[derive(Debug, Clone)]
pub struct AckFact {
    pub lt: Option<Lt>,
    pub a: u64,
    pub covered: u64,
}

/// A `resume_info` the entry sent, with the hash the test expects of its
/// `last_stored`.
#[derive(Debug, Clone)]
pub struct ResumeFact {
    pub lt: Option<Lt>,
    pub a: u64,
    pub last: Option<(u64, [u8; 16])>,
    pub expected_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub enum Ev {
    /// A message the endpoint sent.
    Emit {
        link: LinkId,
        entry: Uuid,
        msg: TelemetryMessage,
        payload_len: usize,
        /// For a `record_batch`, its records.
        records: Vec<SentRecord>,
        /// For a `dropped_range`, the assignment of each sequence number;
        /// for a `lost_on_reset`, of each sequence number its ranges hold.
        assigns: Vec<(u64, AssignId)>,
        /// What the model holds at each sequence number sent.
        model: Vec<Option<Item>>,
    },
    Recovery(RecoveryId),
    /// The model deleted the body of `seq` of `stream`.
    Erase {
        stream: Uuid,
        seq: u64,
        reason: DropReason,
    },
    /// The notices of a recovery stopped being sent: a valid `resume_info`
    /// of the new stream came on a connection that sent them.
    NoticesDone {
        recovery: RecoveryId,
    },
    /// The endpoint dropped the notices of a recovery.
    NoticesDropped {
        recovery: RecoveryId,
        entry_changed: bool,
    },
    /// The endpoint got back, from a snapshot, the notices of a recovery
    /// it had dropped: they go out again.
    Revived {
        recovery: RecoveryId,
    },
    /// The `lost_on_reset` loss records of the old stream at the entry: a
    /// new baseline.
    Baseline {
        recovery: RecoveryId,
        ranges: Vec<(u64, u64)>,
    },
    /// The `lost_on_reset` loss records of the old stream the entry's
    /// store holds when the notices of a recovery are done.
    Held {
        recovery: RecoveryId,
        ranges: Vec<(u64, u64)>,
    },
    /// The endpoint lost state.
    EndpointLoss,
    /// An entry forgot the closed streams it no longer remembers: the
    /// commits of this event's index.
    Pruned,
    /// A message delivered to an entry, and its answer.
    Deliver {
        entry: Uuid,
        link: LinkId,
        msg: TelemetryMessage,
        /// The state of the message's stream before, with its lifetime.
        before: Option<(Option<Lt>, ReceiverFlowState)>,
        /// A write failure was injected and this call consumed it.
        injected: bool,
        /// The connection was halted before.
        halted: bool,
        output: ReceiverOutput,
        acks: Vec<AckFact>,
        resume: Option<ResumeFact>,
    },
    /// The model and the endpoint disagree.
    Violation(String),
    /// An event a mutation test took out, left in its place so that the
    /// other events keep their indices.
    Removed,
}

/// Where the model leaves each record at the end of a run.
#[derive(Debug, Clone, Default)]
pub struct Final {
    /// Records in the collection buffer.
    pub collected: BTreeSet<Mark>,
    /// The recoveries the final state went through.
    pub lineage: BTreeSet<RecoveryId>,
    /// How the endpoint let records go, in the final state's history.
    pub fates: Vec<(Mark, Fate)>,
    /// Every record collected in the final state's history: a record
    /// collected only in a state the endpoint later lost is not among
    /// them.
    pub known: BTreeSet<Mark>,
    /// Records a loss of the endpoint's state took away in the final
    /// state's history, with every copy and everything that could report
    /// them.
    pub erased: BTreeSet<Mark>,
}

/// How the endpoint let a record go without storing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Deleted from the collection buffer and counted as `unsupported`.
    Unsupported,
    /// Its dropped sequence number was dropped with its stream when the
    /// entry changed.
    Abandoned,
    /// Sent back to the collection buffer by an `A < K` transition and
    /// deleted there in the same transition: only that recovery's
    /// `lost_on_reset` reports it.
    LostOnResetOnly(RecoveryId),
}

#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub events: Vec<Ev>,
    pub recoveries: Vec<Recovery>,
    pub commits: Vec<Commit>,
    /// The `A` of the snapshot each lifetime restored from one starts at:
    /// its first write is held against it as against any other.
    pub starts: BTreeMap<Lt, u64>,
    pub assigns: Vec<Assign>,
    /// Every record collected.
    pub marks: BTreeSet<Mark>,
    pub final_state: Final,
}

impl Trace {
    pub fn push(&mut self, ev: Ev) -> usize {
        self.events.push(ev);
        self.events.len() - 1
    }

    pub fn violation(&mut self, text: String) {
        self.push(Ev::Violation(text));
    }

    pub fn assign(&mut self, mark: Mark, stream: Uuid, seq: u64) -> AssignId {
        self.assigns.push(Assign { mark, stream, seq });
        u64::try_from(self.assigns.len() - 1).unwrap()
    }

    pub fn assign_of(&self, id: AssignId) -> &Assign {
        &self.assigns[usize::try_from(id).unwrap()]
    }

    pub fn add_recovery(&mut self, recovery: Recovery) -> RecoveryId {
        let id = self.recoveries.len();
        self.recoveries.push(recovery);
        let ev = self.push(Ev::Recovery(id));
        self.recoveries[id].ev = ev;
        id
    }
}
