//! The operations a run is made of, and the strategies that generate them.
//!
//! Every operation is a plain value whose `Debug` form is the Rust that
//! makes it (with `Op`, `Kind`, `Size`, `Kinds`, `List`, `Entry` and
//! `Step` in scope), so a failing case proptest prints can be pasted into
//! a fixed case as it is. An operation that does not apply to the state a
//! run is in is skipped.

use jiff::SignedDuration;
use proptest::prelude::*;
use uuid::Uuid;

use crate::fixture::{E1, E2, E3, Kind, Kinds, List, Size};

/// An entry, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    E1,
    E2,
    E3,
}

impl Entry {
    pub fn id(self) -> Uuid {
        match self {
            Self::E1 => E1,
            Self::E2 => E2,
            Self::E3 => E3,
        }
    }
}

/// How far the clocks move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Minute,
    Hour,
    /// The retention the run's endpoint is configured with.
    Retention,
    /// One minute short of 24 hours.
    AlmostDay,
    /// 24 hours and a minute: past the hold of an acknowledged copy.
    Day,
    /// 31 days: past the retention of every configuration and the 30 days
    /// an entry remembers a closed stream.
    Month,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// The endpoint collects a record.
    Collect(Kind, Size),
    /// The endpoint opens a connection to its target.
    Connect,
    /// The entry of the connection answers its `Hello`, accepting the kinds.
    Hello(Kinds),
    /// Delivers up to that many of the endpoint's messages to the entry.
    ToEntry(u8),
    /// Delivers up to that many of the entry's messages to the endpoint.
    ToEndpoint(u8),
    /// Loses the entry's next `ack` or `resume_info` on its way.
    LoseReply,
    /// The connection breaks.
    Disconnect,
    /// Delivers everything both ways until nothing moves.
    Exchange,
    /// Opens a connection, answers its `Hello` with the kinds, and
    /// exchanges until nothing moves.
    Session(Kinds),
    /// The clocks move on.
    Advance(Step),
    /// The endpoint handles its deadlines.
    Tick,
    /// The endpoint gets a new address list.
    SetEntries(List),
    /// The endpoint cannot reach its target for 30 minutes.
    Unreachable,
    /// A snapshot of the endpoint's store is taken.
    Snapshot,
    /// The endpoint's store goes back to a snapshot.
    Rollback(u8),
    /// The endpoint's store comes back empty.
    LoseState,
    /// The endpoint starts from records left over, without its sequence
    /// state: those of the last sent that the mask picks.
    Recover(u16),
    /// The endpoint's next commits fail.
    FailEndpoint(u8),
    /// A snapshot of an entry's store is taken.
    EntrySnapshot(Entry),
    /// An entry's store goes back to a snapshot.
    EntryRestore(Entry, u8),
    /// An entry's store is emptied.
    EntryClear(Entry),
    /// An entry's next write fails.
    FailEntryWrite(Entry),
    /// An entry forgets the closed streams it no longer remembers.
    Prune(Entry),
}

/// What a run's endpoint is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    pub collect_limit: usize,
    pub queue_limit: u64,
    pub retention_hours: i64,
    pub list: List,
}

impl Setup {
    pub fn retention(&self) -> SignedDuration {
        SignedDuration::from_hours(self.retention_hours)
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            collect_limit: 64,
            queue_limit: 1 << 20,
            retention_hours: 30 * 24,
            list: List::E123,
        }
    }
}

fn entry() -> impl Strategy<Value = Entry> {
    prop_oneof![Just(Entry::E1), Just(Entry::E2), Just(Entry::E3)]
}

fn kinds() -> impl Strategy<Value = Kinds> {
    prop_oneof![
        4 => Just(Kinds::All),
        2 => Just(Kinds::NoProc2),
        2 => Just(Kinds::NoNet),
        1 => Just(Kinds::OnlyNet),
        1 => Just(Kinds::Proc1Only),
    ]
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        3 => Just(Kind::Proc1),
        1 => Just(Kind::Proc2),
        2 => Just(Kind::Net),
    ]
}

fn size() -> impl Strategy<Value = Size> {
    prop_oneof![
        60 => Just(Size::Normal),
        1 => Just(Size::Limit),
        1 => Just(Size::Huge),
    ]
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        3 => Just(Step::Minute),
        3 => Just(Step::Hour),
        2 => Just(Step::Retention),
        1 => Just(Step::AlmostDay),
        2 => Just(Step::Day),
        1 => Just(Step::Month),
    ]
}

fn list() -> impl Strategy<Value = List> {
    prop_oneof![
        3 => Just(List::E123),
        2 => Just(List::E21),
        2 => Just(List::E1),
        1 => Just(List::E2),
        1 => Just(List::E31),
        1 => Just(List::Empty),
    ]
}

pub fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        40 => (kind(), size()).prop_map(|(kind, size)| Op::Collect(kind, size)),
        24 => kinds().prop_map(Op::Session),
        6 => Just(Op::Connect),
        6 => kinds().prop_map(Op::Hello),
        10 => (1u8..6).prop_map(Op::ToEntry),
        10 => (1u8..6).prop_map(Op::ToEndpoint),
        8 => Just(Op::Exchange),
        6 => Just(Op::LoseReply),
        8 => Just(Op::Disconnect),
        10 => step().prop_map(Op::Advance),
        2 => Just(Op::Tick),
        4 => list().prop_map(Op::SetEntries),
        2 => Just(Op::Unreachable),
        8 => Just(Op::Snapshot),
        2 => any::<u8>().prop_map(Op::Rollback),
        1 => Just(Op::LoseState),
        1 => any::<u16>().prop_map(Op::Recover),
        3 => (1u8..3).prop_map(Op::FailEndpoint),
        8 => entry().prop_map(Op::EntrySnapshot),
        5 => (entry(), any::<u8>()).prop_map(|(e, i)| Op::EntryRestore(e, i)),
        1 => entry().prop_map(Op::EntryClear),
        6 => entry().prop_map(Op::FailEntryWrite),
        2 => entry().prop_map(Op::Prune),
    ]
}

pub fn setup() -> impl Strategy<Value = Setup> {
    (
        prop_oneof![1 => Just(1usize), 2 => Just(3), 3 => Just(64)],
        prop_oneof![1 => Just(1_500u64), 2 => Just(4_000), 3 => Just(1 << 20)],
        prop_oneof![Just(2i64), Just(30), Just(30 * 24)],
        prop_oneof![Just(List::E123), Just(List::E21), Just(List::E1)],
    )
        .prop_map(
            |(collect_limit, queue_limit, retention_hours, list)| Setup {
                collect_limit,
                queue_limit,
                retention_hours,
                list,
            },
        )
}
