//! Fixed cases, each a named scenario run on its own and judged like any
//! random run, then checked for what makes it the scenario it is.

use std::collections::BTreeMap;

use jiff::SignedDuration;
use senta_protocol::telemetry::{
    LastStored, OpenStream, ReceiverConnection, ReceiverOutput, ReceiverStream, RecordBatch,
    TelemetryMessage,
};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use uuid::Uuid;

use crate::fixture::{
    E1, ENDPOINT,
    Kind::{Net, Proc1, Proc2},
    Kinds,
    Kinds::{All, NoNet, Proc1Only},
    List, Mark,
    Size::{Huge, Normal},
    expected_hash, make_record, wire,
};
use crate::harness::World;
use crate::ingress::TestStore;
use crate::judge;
use crate::ops::{
    Entry,
    Op::{
        Advance, Connect, Disconnect, EntryRestore, EntrySnapshot, Exchange, FailEntryWrite, Hello,
        LoseReply, LoseState, Prune, Rollback, Session, SetEntries, Snapshot, Tick, ToEndpoint,
        ToEntry,
    },
    Setup, Step,
};
use crate::trace::{CommitItem, Ev, Item, LinkId, Recovery, Reset, Trace};

pub fn world(setup: Setup) -> World {
    World::new(setup)
}

fn run(world: &mut World, ops: &[crate::ops::Op]) {
    for op in ops {
        world.run(*op);
    }
}

/// Drains, judges, and returns the trace of a run that must pass.
pub fn finish(world: World, kinds: Kinds) -> Trace {
    let trace = world.finish(kinds);
    if let Err(failures) = judge::judge(&trace) {
        panic!("{failures}");
    }
    trace
}

pub fn recoveries(trace: &Trace, reset: Option<Reset>) -> Vec<(usize, &Recovery)> {
    trace
        .recoveries
        .iter()
        .enumerate()
        .filter(|(_, r)| r.reset == reset)
        .collect()
}

fn lost_recovery(trace: &Trace) -> (usize, &Recovery) {
    let found: Vec<_> = trace
        .recoveries
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.reset, Some(Reset::Lost { .. })))
        .collect();
    assert_eq!(found.len(), 1, "one A < K transition: {found:?}");
    found[0]
}

/// The messages the endpoint sent after event `ev`, with their links.
pub fn sent_after(trace: &Trace, ev: usize) -> Vec<(LinkId, TelemetryMessage)> {
    trace.events[ev..]
        .iter()
        .filter_map(|e| match e {
            Ev::Emit { link, msg, .. } => Some((*link, msg.clone())),
            _ => None,
        })
        .collect()
}

fn record_commits(trace: &Trace, mark: Mark) -> Vec<(Uuid, usize, Uuid, u64)> {
    trace
        .commits
        .iter()
        .filter_map(|c| match &c.item {
            CommitItem::Record {
                mark: Some(m),
                key,
                seq,
                ..
            } if *m == mark => Some((c.entry, c.ev, key.stream, *seq)),
            _ => None,
        })
        .collect()
}

fn lor_commits(trace: &Trace) -> Vec<(u64, u64)> {
    trace
        .commits
        .iter()
        .filter_map(|c| match &c.item {
            CommitItem::Lor { range, .. } => Some((range.from, range.to)),
            _ => None,
        })
        .collect()
}

fn marks(list: &[Item]) -> Vec<Option<Mark>> {
    list.iter()
        .map(|item| match item {
            Item::Record { mark, .. } => Some(*mark),
            Item::Dropped { .. } => None,
        })
        .collect()
}

fn kinds_sent(messages: &[(LinkId, TelemetryMessage)]) -> Vec<&'static str> {
    messages.iter().map(|(_, m)| m.t()).collect()
}

/// A connection to the target, its `hello_ack` with `kinds`, and the
/// endpoint's `open_stream` delivered and answered: the reconnection
/// judgment has run when this returns, nothing else delivered.
fn reconnect(world: &mut World, kinds: Kinds) {
    run(world, &[Connect, Hello(kinds), ToEntry(1), ToEndpoint(1)]);
}

const SHORT: Setup = Setup {
    collect_limit: 64,
    queue_limit: 1 << 20,
    retention_hours: 2,
    list: List::E123,
};

#[test]
fn a_lost_ack_then_an_expired_body_acknowledged_at_step_6_is_lost_on_reset() {
    let mut w = world(SHORT);
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    w.collect(Proc1, Normal);
    w.collect(Proc1, Normal);
    run(
        &mut w,
        &[
            ToEntry(5),
            LoseReply,
            LoseReply,
            Advance(Step::Retention),
            Tick,
        ],
    );
    run(&mut w, &[Disconnect, Session(All)]);
    // Step 6 acknowledged 1 and 2 without a copy of either.
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.reset, Some(Reset::Lost { a: 0 }));
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 2)]);
    assert!(r.targets.is_empty());
    assert_eq!(lor_commits(&trace), [(1, 2)]);
}

/// Shared by mutation tests: an `A < K` transition with no copy left of
/// 1 to 3.
pub fn a_below_k_with_no_copy() -> World {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    for _ in 0..3 {
        w.collect(Proc1, Normal);
    }
    run(&mut w, &[Exchange, Advance(Step::Day), Tick]);
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    w
}

#[test]
fn a_below_k_with_no_copy_reports_every_number() {
    let trace = finish(a_below_k_with_no_copy(), All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 3)]);
    assert!(r.list.is_empty());
}

#[test]
fn a_below_k_with_some_copies_resends_them_and_reports_the_rest() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    w.collect(Proc1, Normal);
    w.collect(Proc1, Normal);
    w.run(Exchange);
    w.advance(SignedDuration::from_hours(12));
    let r3 = w.collect(Proc1, Normal);
    let r4 = w.collect(Proc1, Normal);
    w.run(Exchange);
    w.advance(SignedDuration::from_hours(13));
    run(&mut w, &[Tick, EntryRestore(Entry::E1, 0), Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 2)]);
    assert_eq!(marks(&r.list), [Some(r3), Some(r4)]);
}

#[test]
fn a_below_k_leaves_an_announced_loss_out() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    w.collect(Proc1, Normal);
    w.collect(Proc1, Huge);
    w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, Advance(Step::Day), Tick]);
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 1), (3, 3)]);
}

/// Shared by a mutation test: a resumption of the same stream whose
/// `(A, M]` holds a dropped number between records.
pub fn same_stream_with_dropped_and_records() -> (World, Mark) {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Normal);
    w.collect(Proc1, Huge);
    let r3 = w.collect(Proc1, Normal);
    run(&mut w, &[ToEntry(1), Disconnect, Session(All)]);
    (w, r3)
}

#[test]
fn a_resumed_stream_resends_dropped_numbers_and_records_in_place() {
    let (w, r3) = same_stream_with_dropped_and_records();
    let trace = finish(w, All);
    let resumed: Vec<_> = recoveries(&trace, None)
        .into_iter()
        .filter(|(_, r)| r.start == 2)
        .collect();
    assert_eq!(resumed.len(), 1);
    let r = resumed[0].1;
    assert_eq!(
        r.list.first(),
        Some(&Item::Dropped {
            reason: DropReason::TooLarge,
            assign: match r.list[0] {
                Item::Dropped { assign, .. } | Item::Record { assign, .. } => assign,
            },
        })
    );
    assert_eq!(marks(&r.list), [None, Some(r3)]);
}

#[test]
fn narrower_kinds_close_the_old_stream_and_its_late_data_is_closed() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    let n1 = w.collect(Net, Normal);
    w.collect(Proc1, Normal);
    w.collect(Proc1, Normal);
    let late = w
        .trace
        .events
        .iter()
        .find_map(|ev| match ev {
            Ev::Emit {
                msg: TelemetryMessage::RecordBatch(batch),
                ..
            } => Some(batch.clone()),
            _ => None,
        })
        .unwrap();
    run(&mut w, &[Disconnect, Session(NoNet)]);
    let answer = w.poke(TelemetryMessage::RecordBatch(late.clone()));
    let trace = finish(w, All);
    let same = recoveries(&trace, Some(Reset::Same));
    assert_eq!(same.len(), 1);
    let r = same[0].1;
    assert!(r.notices.as_ref().unwrap().lost.is_empty());
    assert_eq!(r.returned, [n1]);
    let after = sent_after(&trace, r.ev);
    assert_eq!(kinds_sent(&after[..2]), ["close_stream", "open_stream"]);
    assert_eq!(
        answer,
        ReceiverOutput::Reply(vec![TelemetryMessage::ErrorMessage(
            senta_protocol::telemetry::ErrorMessage {
                stream: Some(late.stream()),
                error: TelemetryError::Closed,
            }
        )])
    );
}

#[test]
fn a_below_k_with_narrower_kinds_returns_copies_committed_once_widened() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    let p1 = w.collect(Proc1, Normal);
    let n2 = w.collect(Net, Normal);
    let p3 = w.collect(Proc1, Normal);
    run(
        &mut w,
        &[Exchange, EntryRestore(Entry::E1, 0), Session(NoNet)],
    );
    run(&mut w, &[Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert!(r.notices.as_ref().unwrap().lost.is_empty());
    assert!(r.notices.as_ref().unwrap().close);
    assert_eq!(marks(&r.list), [Some(p1), Some(p3)]);
    assert_eq!(r.returned, [n2]);
    assert!(
        record_commits(&trace, n2)
            .iter()
            .any(|(entry, ev, _, _)| *entry == E1 && *ev > r.ev)
    );
}

/// Shared by a mutation test: an `A < K` transition whose copy goes back
/// to a full collection buffer, which deletes it with an older waiting
/// record.
pub fn copy_deleted_by_a_full_buffer_with_a_waiting_record() -> World {
    let mut w = world(Setup {
        collect_limit: 2,
        ..Setup::default()
    });
    run(&mut w, &[Session(NoNet), EntrySnapshot(Entry::E1)]);
    w.collect(Net, Normal);
    w.collect(Proc2, Normal);
    w.collect(Proc2, Normal);
    w.collect(Net, Normal);
    run(
        &mut w,
        &[Exchange, EntryRestore(Entry::E1, 0), Session(Proc1Only)],
    );
    w
}

#[test]
fn a_copy_deleted_by_a_full_buffer_with_a_waiting_record_is_lost_on_reset() {
    let w = copy_deleted_by_a_full_buffer_with_a_waiting_record();
    let trace = finish(w, Proc1Only);
    let (_, r) = lost_recovery(&trace);
    // Copy 1 went, copy 2 stayed; the waiting record older than both was
    // deleted with it and counted as unsupported.
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 1)]);
    assert_eq!((r.unsupported_expected, r.unsupported_observed), (1, 1));
    assert_eq!(lor_commits(&trace), [(1, 1)]);
}

#[test]
fn a_copy_deleted_by_a_full_buffer_alone_is_lost_on_reset_and_not_unsupported() {
    let mut w = world(Setup {
        collect_limit: 1,
        ..Setup::default()
    });
    run(&mut w, &[Session(NoNet), EntrySnapshot(Entry::E1)]);
    w.collect(Proc2, Normal);
    w.collect(Net, Normal);
    run(
        &mut w,
        &[Exchange, EntryRestore(Entry::E1, 0), Session(Proc1Only)],
    );
    let trace = finish(w, Proc1Only);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 1)]);
    assert_eq!((r.unsupported_expected, r.unsupported_observed), (0, 0));
}

#[test]
fn a_renumbered_copy_dropped_by_the_queue_limit_is_reported_by_the_new_stream_only() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    let r1 = w.collect(Proc1, Normal);
    let r2 = w.collect(Proc1, Normal);
    let r3 = w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, Disconnect]);
    let len = u64::try_from(w.sent_bytes(r1).len()).unwrap();
    w.restart_with_queue_limit(2 * len);
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert!(r.notices.as_ref().unwrap().lost.is_empty());
    assert_eq!(marks(&r.list), [None, Some(r2), Some(r3)]);
    let reported = trace.commits.iter().any(|c| match &c.item {
        CommitItem::Dropped {
            reason, assigns, ..
        } => {
            *reason == DropReason::BufferOverflow
                && assigns.iter().any(|a| trace.assign_of(*a).mark == r1)
        }
        _ => false,
    });
    assert!(reported);
}

#[test]
fn a_too_large_number_carried_to_the_new_stream_reports_its_record() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Net, Normal);
    let big = w.collect(Proc1, Huge);
    run(&mut w, &[Disconnect, Session(NoNet)]);
    let trace = finish(w, All);
    let (_, r) = recoveries(&trace, Some(Reset::Same))[0];
    let carried = trace.commits.iter().any(|c| match &c.item {
        CommitItem::Dropped {
            key,
            reason,
            assigns,
            ..
        } => {
            key.stream == r.stream
                && *reason == DropReason::TooLarge
                && assigns.iter().any(|a| {
                    let assign = trace.assign_of(*a);
                    assign.mark == big && assign.stream == r.stream
                })
        }
        _ => false,
    });
    assert!(carried);
}

#[test]
fn an_empty_store_opens_a_new_stream_at_the_first_hello_ack() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, LoseState, Session(All)]);
    let trace = finish(w, All);
    let fresh = recoveries(&trace, Some(Reset::Fresh));
    let (_, r) = fresh.last().unwrap();
    let after = sent_after(&trace, r.ev);
    assert_eq!(kinds_sent(&after[..1]), ["open_stream"]);
    assert_eq!(after[0].0, r.link.unwrap());
    assert!(r.notices.as_ref().unwrap().lost.is_empty());
    assert!(!r.notices.as_ref().unwrap().close);
}

#[test]
fn records_left_without_sequence_state_are_renumbered_and_refused_ones_wait() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    let p1 = w.collect(Proc1, Normal);
    let n2 = w.collect(Net, Normal);
    let p3 = w.collect(Proc1, Normal);
    w.run(Exchange);
    w.recover_marks(&[p1, n2, p3]);
    w.run(Session(NoNet));
    let trace = finish(w, NoNet);
    let fresh = recoveries(&trace, Some(Reset::Fresh));
    let (_, r) = fresh.last().unwrap();
    assert_eq!(marks(&r.list), [Some(p1), Some(p3)]);
    assert_eq!(r.returned, [n2]);
    let after = sent_after(&trace, r.ev);
    assert_eq!(kinds_sent(&after[..1]), ["open_stream"]);
    assert!(trace.final_state.collected.contains(&n2));
}

#[test]
fn a_loss_announced_in_a_state_rolled_back_is_still_lost_on_reset() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, Disconnect]);
    w.collect(Proc1, Huge);
    // The snapshot holds 2 dropped and not yet announced.
    w.run(Snapshot);
    run(&mut w, &[Session(All), Advance(Step::Day), Tick]);
    run(&mut w, &[Rollback(0), Session(All)]);
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 2)]);
}

#[test]
fn a_refused_record_between_copies_and_unacknowledged_ones_goes_back() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    let c1 = w.collect(Proc1, Normal);
    let n2 = w.collect(Net, Normal);
    run(&mut w, &[Exchange, Disconnect]);
    let u3 = w.collect(Proc1, Normal);
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(NoNet)]);
    let trace = finish(w, NoNet);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(marks(&r.list), [Some(c1), Some(u3)]);
    assert_eq!(r.returned, [n2]);
    assert!(r.notices.as_ref().unwrap().lost.is_empty());
}

#[test]
fn back_at_the_first_entry_before_the_other_hello_ack_the_stream_carries_on() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    let r1 = w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, Disconnect]);
    let r2 = w.collect(Proc1, Normal);
    run(
        &mut w,
        &[SetEntries(List::E2), Connect, SetEntries(List::E1)],
    );
    w.run(Session(All));
    let trace = finish(w, All);
    assert!(recoveries(&trace, Some(Reset::EntryChanged)).is_empty());
    assert_eq!(record_commits(&trace, r1).len(), 1);
    let commits = record_commits(&trace, r2);
    assert_eq!(commits.len(), 1);
    assert_eq!((commits[0].0, commits[0].3), (E1, 2));
}

#[test]
fn back_at_the_first_entry_after_the_other_hello_ack_a_new_stream_opens() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    let r1 = w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, SetEntries(List::E2), Session(All)]);
    let r2 = w.collect(Proc1, Normal);
    run(&mut w, &[Disconnect, SetEntries(List::E1), Session(All)]);
    let trace = finish(w, All);
    let changed = recoveries(&trace, Some(Reset::EntryChanged));
    assert_eq!(changed.len(), 2);
    let (_, back) = changed[1];
    assert_eq!(back.entry, E1);
    assert_eq!(marks(&back.list), [Some(r2)]);
    assert_eq!(record_commits(&trace, r1).len(), 1);
    assert!(record_commits(&trace, r2).iter().all(|c| c.0 == E1));
    assert!(
        recoveries(&trace, Some(Reset::EntryChanged))
            .iter()
            .all(|(_, r)| r.notices.as_ref().unwrap()
                == &crate::trace::Notices {
                    lost: Vec::new(),
                    close: false,
                    links: BTreeMap::new(),
                })
    );
}

#[test]
fn a_lost_on_reset_dropped_by_an_entry_change_before_it_is_stored_excuses_its_record() {
    let mut w = world(Setup {
        collect_limit: 1,
        ..Setup::default()
    });
    run(&mut w, &[Session(NoNet), EntrySnapshot(Entry::E1)]);
    let c = w.collect(Proc2, Normal);
    w.collect(Net, Normal);
    run(&mut w, &[Exchange, EntryRestore(Entry::E1, 0)]);
    reconnect(&mut w, Proc1Only);
    run(
        &mut w,
        &[Disconnect, SetEntries(List::E2), Session(Proc1Only)],
    );
    let trace = finish(w, Proc1Only);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 1)]);
    assert!(lor_commits(&trace).is_empty());
    assert!(
        record_commits(&trace, c)
            .iter()
            .all(|(_, ev, _, _)| *ev < r.ev)
    );
}

#[test]
fn a_rolled_back_endpoint_reopening_a_closed_stream_gets_closed_and_opens_a_new_one() {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), Snapshot]);
    w.collect(Net, Normal);
    run(
        &mut w,
        &[Disconnect, Session(NoNet), Rollback(0), Session(All)],
    );
    let trace = finish(w, All);
    let closed = recoveries(&trace, Some(Reset::Closed));
    assert_eq!(closed.len(), 1);
    let (_, r) = closed[0];
    let after = sent_after(&trace, r.ev);
    assert_eq!(kinds_sent(&after[..1]), ["open_stream"]);
    assert_eq!(after[0].0, r.link.unwrap());
    assert!(
        after
            .iter()
            .take_while(|(_, m)| !matches!(m, TelemetryMessage::RecordBatch(_)))
            .all(|(_, m)| matches!(m, TelemetryMessage::OpenStream(_)))
    );
}

/// Shared by mutation tests: the endpoint, rolled back, reopens a stream
/// whose closed state the entry forgot; the old lifetime holds a loss of
/// sequence number 1, the new one assigns 1 to another record.
pub fn forgotten_stream_reopened() -> (World, Mark, Mark) {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), Snapshot]);
    let old = w.collect(Proc1, Huge);
    w.run(Exchange);
    w.collect(Net, Normal);
    run(&mut w, &[Disconnect, Session(NoNet)]);
    run(
        &mut w,
        &[Advance(Step::Month), Prune(Entry::E1), Rollback(0)],
    );
    let new = w.collect(Proc1, Normal);
    (w, old, new)
}

#[test]
fn a_rolled_back_endpoint_reopening_a_forgotten_stream_starts_it_anew() {
    let (mut w, _, new) = forgotten_stream_reopened();
    w.run(Session(All));
    let trace = finish(w, All);
    let stream = trace.assign_of(0).stream;
    let reopened = trace.events.iter().any(|ev| {
        matches!(ev, Ev::Deliver {
            msg: TelemetryMessage::OpenStream(OpenStream { stream: s }),
            output: ReceiverOutput::Reply(replies),
            ..
        } if *s == stream && matches!(replies.as_slice(),
            [TelemetryMessage::ResumeInfo(info)] if info.a == 0 && info.last_stored.is_none())
            && trace.events.iter().any(|e| matches!(e, Ev::Pruned)))
    });
    assert!(reopened);
    let old_loss = trace.commits.iter().find(|c| match &c.item {
        CommitItem::Dropped { key, range, .. } => key.stream == stream && range.from == 1,
        _ => false,
    });
    let commits = record_commits(&trace, new);
    assert_eq!((commits[0].2, commits[0].3), (stream, 1));
    let new_lt = trace
        .commits
        .iter()
        .find(|c| matches!(&c.item, CommitItem::Record { mark: Some(m), .. } if *m == new))
        .unwrap()
        .lt;
    assert_ne!(old_loss.unwrap().lt, new_lt);
}

/// Shared by a mutation test: a body the endpoint lists for a new stream
/// expires before its `resume_info`, and goes out as a dropped number.
pub fn expired_between_transition_and_resume() -> (World, Mark) {
    let mut w = world(SHORT);
    w.run(Session(All));
    w.collect(Net, Normal);
    let p = w.collect(Proc1, Normal);
    w.run(Disconnect);
    reconnect(&mut w, NoNet);
    run(
        &mut w,
        &[Advance(Step::Retention), ToEntry(2), ToEndpoint(1)],
    );
    (w, p)
}

#[test]
fn a_listed_body_expiring_before_it_is_sent_goes_out_as_a_dropped_number() {
    let (w, _) = expired_between_transition_and_resume();
    let trace = finish(w, All);
    let (_, r) = recoveries(&trace, Some(Reset::Same))[0];
    let dropped = trace.events.iter().any(|ev| {
        matches!(ev, Ev::Emit { msg: TelemetryMessage::DroppedRange(d), .. }
            if d.stream == r.stream && d.from == 1 && d.reason == DropReason::RetentionExpired)
    });
    assert!(dropped);
    assert!(matches!(r.list.as_slice(), [Item::Record { .. }]));
}

#[test]
fn step_6_clears_dropped_numbers_a_new_stream_then_does_not_carry() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Huge);
    w.collect(Net, Normal);
    run(&mut w, &[ToEntry(1), LoseReply, Disconnect, Session(NoNet)]);
    let trace = finish(w, All);
    let same = recoveries(&trace, Some(Reset::Same));
    assert_eq!(same.len(), 1);
    assert!(same[0].1.list.is_empty());
}

#[test]
fn a_dropped_range_already_covered_changes_nothing_and_acknowledges_a() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Huge);
    w.collect(Proc1, Normal);
    w.run(ToEntry(1));
    w.deliver_again();
    let trace = finish(w, All);
    let again: Vec<_> = trace
        .events
        .iter()
        .filter_map(|ev| match ev {
            Ev::Deliver {
                msg: TelemetryMessage::DroppedRange(d),
                before: Some((_, state)),
                output,
                ..
            } if state.a >= d.to => Some(output.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(again.len(), 1);
    assert!(matches!(&again[0], ReceiverOutput::Reply(r)
        if matches!(r.as_slice(), [TelemetryMessage::Ack(ack)] if ack.a == 1)));
}

#[test]
fn a_dropped_range_whose_write_fails_is_sent_again() {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Huge);
    run(
        &mut w,
        &[FailEntryWrite(Entry::E1), ToEntry(1), Session(All)],
    );
    let trace = finish(w, All);
    let failed = trace.events.iter().any(|ev| {
        matches!(
            ev,
            Ev::Deliver {
                msg: TelemetryMessage::DroppedRange(_),
                injected: true,
                output: ReceiverOutput::Disconnect,
                ..
            }
        )
    });
    assert!(failed);
    let stored = trace
        .commits
        .iter()
        .filter(|c| matches!(&c.item, CommitItem::Dropped { range, .. } if range.from == 1))
        .count();
    assert_eq!(stored, 1);
}

/// Shared by mutation tests: the entry goes back to a point at `A = K`
/// after storing a record whose `ack` was lost, and gets it again.
pub fn entry_restored_at_k() -> (World, Mark) {
    let mut w = world(Setup::default());
    w.run(Session(All));
    w.collect(Proc1, Normal);
    run(&mut w, &[Exchange, EntrySnapshot(Entry::E1)]);
    let r2 = w.collect(Proc1, Normal);
    run(&mut w, &[ToEntry(1), LoseReply, EntryRestore(Entry::E1, 0)]);
    (w, r2)
}

#[test]
fn an_entry_restored_to_a_at_or_above_k_gets_the_rest_again() {
    let (mut w, r2) = entry_restored_at_k();
    w.run(Session(All));
    let trace = finish(w, All);
    let resumed: Vec<_> = recoveries(&trace, None)
        .into_iter()
        .filter(|(_, r)| r.allowed)
        .collect();
    assert_eq!(resumed.len(), 1);
    assert_eq!(marks(&resumed[0].1.list), [Some(r2)]);
    assert_eq!(record_commits(&trace, r2).len(), 2);
}

/// Shared by a mutation test: the notices of an `A < K` transition fail
/// to be stored twice, the entry going back between the two tries.
pub fn notices_failing_twice() -> World {
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    w.collect(Proc1, Normal);
    run(
        &mut w,
        &[
            Exchange,
            Advance(Step::Day),
            Tick,
            EntryRestore(Entry::E1, 0),
        ],
    );
    reconnect(&mut w, All);
    // lost_on_reset fails.
    run(&mut w, &[FailEntryWrite(Entry::E1), ToEntry(1)]);
    // lost_on_reset is stored, close_stream fails.
    reconnect_notices(&mut w);
    run(&mut w, &[ToEntry(1), FailEntryWrite(Entry::E1), ToEntry(1)]);
    // The entry goes back again, and the notices then go through.
    run(&mut w, &[EntryRestore(Entry::E1, 0), Session(All)]);
    w
}

fn reconnect_notices(world: &mut World) {
    run(world, &[Connect, Hello(All)]);
}

#[test]
fn notices_failing_to_be_stored_go_again_before_the_open_stream() {
    let w = notices_failing_twice();
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    assert_eq!(r.notices.as_ref().unwrap().lost, [(1, 1)]);
    // Stored before the second restore and again after it.
    assert_eq!(lor_commits(&trace), [(1, 1), (1, 1)]);
    let failures: Vec<&str> = trace
        .events
        .iter()
        .filter_map(|ev| match ev {
            Ev::Deliver {
                msg,
                injected: true,
                ..
            } => Some(msg.t()),
            _ => None,
        })
        .collect();
    assert_eq!(failures, ["lost_on_reset", "close_stream"]);
    let groups = trace
        .events
        .iter()
        .filter(|ev| {
            matches!(
                ev,
                Ev::Emit {
                    msg: TelemetryMessage::CloseStream(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(groups, 3);
}

/// A run whose `A < K` transition reports ranges past what one frame
/// holds: an old stream with an announced loss after every record.
/// `entry_changes` drops the notices after the first is stored;
/// otherwise they go through after a failed write.
fn a_lost_on_reset_past_64_kib(entry_changes: bool) -> Trace {
    const PAIRS: u64 = 4_400;
    let mut w = world(Setup::default());
    run(&mut w, &[Session(All), EntrySnapshot(Entry::E1)]);
    for _ in 0..PAIRS {
        w.collect(Proc1, Normal);
        w.collect(Proc1, Huge);
    }
    run(
        &mut w,
        &[
            Exchange,
            Advance(Step::Day),
            Tick,
            EntryRestore(Entry::E1, 0),
        ],
    );
    reconnect(&mut w, All);
    run(&mut w, &[ToEntry(1), FailEntryWrite(Entry::E1), ToEntry(1)]);
    if entry_changes {
        run(&mut w, &[SetEntries(List::E2), Session(All)]);
    } else {
        w.run(Session(All));
    }
    let trace = finish(w, All);
    let (_, r) = lost_recovery(&trace);
    let expected: Vec<(u64, u64)> = (0..PAIRS).map(|i| (2 * i + 1, 2 * i + 1)).collect();
    assert_eq!(r.notices.as_ref().unwrap().lost, expected);
    // One message would be past the frame limit.
    let one = TelemetryMessage::LostOnReset(senta_protocol::telemetry::LostOnReset {
        old_stream: r.old_stream.unwrap(),
        ranges: crate::fixture::seq_ranges(&expected),
    });
    assert!(wire(&one).1 > 65_536);
    let messages = trace
        .events
        .iter()
        .filter(|ev| {
            matches!(
                ev,
                Ev::Emit {
                    msg: TelemetryMessage::LostOnReset(_),
                    ..
                }
            )
        })
        .count();
    assert!(messages >= 3, "the ranges went out in several messages");
    trace
}

#[test]
fn a_lost_on_reset_past_64_kib_finishes_at_the_same_entry() {
    let trace = a_lost_on_reset_past_64_kib(false);
    assert_eq!(lor_commits(&trace).len(), 4_400);
}

#[test]
fn a_lost_on_reset_past_64_kib_is_dropped_when_the_entry_changes() {
    let trace = a_lost_on_reset_past_64_kib(true);
    let stored = lor_commits(&trace).len();
    assert!(stored > 0 && stored < 4_400);
    assert!(trace.events.iter().any(|ev| matches!(
        ev,
        Ev::NoticesDropped {
            entry_changed: true,
            ..
        }
    )));
}

/// Adds `key` with an unknown value to a CBOR map.
fn with_unknown(map: ciborium::Value, key: &str) -> ciborium::Value {
    let ciborium::Value::Map(mut entries) = map else {
        panic!("not a map");
    };
    entries.push((
        ciborium::Value::Text(key.to_owned()),
        ciborium::Value::Array(vec![
            ciborium::Value::Integer(7.into()),
            ciborium::Value::Text("from a later version".to_owned()),
        ]),
    ));
    ciborium::Value::Map(entries)
}

#[test]
fn a_receiver_stores_unknown_fields_as_sent_and_hashes_those_bytes() {
    let stream = Uuid::from_u128(0x77);
    let mut record = make_record(1, Proc1, Normal);
    record.header.endpoint_id = ENDPOINT;
    record.header.stream = stream;
    record.header.seq = 1;
    let known = record.to_bytes().unwrap();
    let value: ciborium::Value = ciborium::from_reader(known.as_slice()).unwrap();
    let ciborium::Value::Map(entries) = value else {
        panic!("a record is a map");
    };
    let entries = entries
        .into_iter()
        .map(|(key, value)| {
            if key == ciborium::Value::Text("header".to_owned()) {
                (key, with_unknown(value, "x-header-field"))
            } else {
                (key, value)
            }
        })
        .collect();
    let value = with_unknown(ciborium::Value::Map(entries), "x-top-field");
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    assert_ne!(bytes, known);

    let store = TestStore::new(E1);
    let mut machine = ReceiverStream::restore(E1, store.clone()).unwrap();
    let now = crate::fixture::base_time();
    let mut conn = ReceiverConnection::new(ENDPOINT, All.list());
    let open = TelemetryMessage::OpenStream(OpenStream { stream });
    let opened = machine.receive(&mut conn, wire(&open).0, now);
    assert!(matches!(opened, ReceiverOutput::Reply(ref r) if r.len() == 1));
    let batch =
        TelemetryMessage::RecordBatch(RecordBatch::new(stream, vec![bytes.clone()]).unwrap());
    let answer = machine.receive(&mut conn, wire(&batch).0, now);
    assert!(matches!(answer, ReceiverOutput::Reply(ref r) if r.len() == 1));
    assert_eq!(store.contents().records[0].bytes, bytes);

    let mut conn = ReceiverConnection::new(ENDPOINT, All.list());
    let answer = machine.receive(&mut conn, wire(&open).0, now);
    let expected = LastStored {
        seq: 1,
        hash: expected_hash(&bytes),
    };
    assert_eq!(
        answer,
        ReceiverOutput::Reply(vec![TelemetryMessage::ResumeInfo(
            senta_protocol::telemetry::ResumeInfo {
                stream,
                a: 1,
                last_stored: Some(expected),
            }
        )])
    );
}

/// The defect the pull request reports: after the endpoint goes back to a
/// snapshot, a sequence number dropped before is assigned to another
/// record that is dropped too, and the entry's `A`, which covers the first
/// loss, makes step 5 and 6 acknowledge the second without it ever being
/// sent: that record is neither stored nor reported lost.
///
/// The sender does what the SenderStream issue's reconnection judgment
/// says: step 5 lets dropped numbers through, step 6 clears them, and
/// that issue's acceptance criteria name this very input (a snapshot with
/// `K = S = 0` and dropped numbers 1 and 2, answered with `A = 2` and no
/// `last_stored`) as one that goes on at step 6. What it breaks is the
/// guarantee this test holds the pair to — every loss reported, by the
/// assignment that carried it — so the fix is a decision on that
/// contract, not on the code alone. Until it is made, `judge::judge`
/// excuses exactly this fate (`Fate::ConfirmedUnsent`) in the property
/// test, and this case runs the strict judge.
#[test]
#[ignore = "결함: 되돌린 엔드포인트가 다시 할당한 버린 순번을 보내지 않은 채 6단계로 확인해 그 레코드의 손실이 보고되지 않음"]
fn defect_a_number_dropped_again_after_a_rollback_is_acknowledged_unreported() {
    let mut w = world(Setup {
        list: List::E1,
        ..Setup::default()
    });
    run(&mut w, &[Session(All), Snapshot]);
    w.collect(Proc1, Huge);
    run(&mut w, &[Exchange, Rollback(0)]);
    w.collect(Proc1, Huge);
    w.run(Session(All));
    let trace = w.finish(All);
    if let Err(failures) = judge::judge_strict(&trace) {
        panic!("{failures}");
    }
}

#[test]
fn the_defect_case_fails_only_by_the_unreported_loss() {
    let mut w = world(Setup {
        list: List::E1,
        ..Setup::default()
    });
    run(&mut w, &[Session(All), Snapshot]);
    w.collect(Proc1, Huge);
    run(&mut w, &[Exchange, Rollback(0)]);
    let lost = w.collect(Proc1, Huge);
    w.run(Session(All));
    let trace = w.finish(All);
    judge::judge(&trace).unwrap();
    let failures = judge::judge_strict(&trace).unwrap_err();
    assert!(failures.starts_with("1 failures"), "{failures}");
    assert!(
        failures.contains(&format!("omission: record {lost} ")),
        "{failures}"
    );
}
