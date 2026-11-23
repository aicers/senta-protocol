//! Each misbehaviour the issue names, made on the test's side alone (by
//! changing a run's trace, or by having the test's store or delivery
//! change bytes, writes or `ack`s), is caught by a judge.

use senta_protocol::telemetry::{RecordBatch, SeqRange, TelemetryMessage};

use crate::cases::{
    a_below_k_with_no_copy, copy_deleted_by_a_full_buffer_with_a_waiting_record,
    entry_changed_after_a_rollback_then_resumed, entry_restored_at_k,
    expired_between_transition_and_resume, forgotten_stream_reopened, notices_failing_twice,
    record_recovered_after_a_rollback, same_stream_with_dropped_and_records,
    stored_record_waiting_again_after_a_rollback,
};
use crate::fixture::{
    E1, E2,
    Kinds::{All, Proc1Only},
};
use crate::judge;
use crate::ops::Op::Session;
use crate::trace::{CommitItem, Ev, Item, Reset, SentRecord, Trace};

/// Checks that the run passes as it is, then that `misbehave` makes the
/// judgment named fail.
fn caught(trace: Trace, judgment: &str, misbehave: impl FnOnce(&mut Trace)) {
    if let Err(failures) = judge::judge(&trace) {
        panic!("the run fails before the mutation: {failures}");
    }
    let mut trace = trace;
    misbehave(&mut trace);
    let failures = judge::judge(&trace).expect_err("the judges miss the misbehaviour");
    assert!(failures.contains(judgment), "{failures}");
}

/// Checks that a run made to misbehave as it goes fails the judgment.
fn caught_live(trace: &Trace, judgment: &str) {
    let failures = judge::judge(trace).expect_err("the judges miss the misbehaviour");
    assert!(failures.contains(judgment), "{failures}");
}

fn resumed_at_2(trace: &mut Trace) -> &mut Vec<Item> {
    let recovery = trace
        .recoveries
        .iter_mut()
        .find(|r| r.reset.is_none() && r.start == 2)
        .unwrap();
    &mut recovery.list
}

#[test]
fn an_item_added_to_the_expected_list_is_caught() {
    let (w, _) = same_stream_with_dropped_and_records();
    caught(w.finish(All), "list:", |trace| {
        let list = resumed_at_2(trace);
        let extra = list[1].clone();
        list.insert(0, extra);
    });
}

#[test]
fn an_item_taken_from_the_expected_list_is_caught() {
    let (w, _) = same_stream_with_dropped_and_records();
    caught(w.finish(All), "list:", |trace| {
        resumed_at_2(trace).remove(0);
    });
}

#[test]
fn items_of_the_expected_list_out_of_order_are_caught() {
    let (w, _) = same_stream_with_dropped_and_records();
    caught(w.finish(All), "list:", |trace| {
        resumed_at_2(trace).swap(0, 1);
    });
}

#[test]
fn bytes_changed_in_a_resend_and_stored_are_caught() {
    let (mut w, _) = entry_restored_at_k();
    w.tamper.alter_resent = true;
    w.run(Session(All));
    caught_live(&w.finish(All), "bytes:");
}

#[test]
fn a_copy_deleted_by_the_buffer_counted_unsupported_instead_of_lost_is_caught() {
    let w = copy_deleted_by_a_full_buffer_with_a_waiting_record();
    caught(w.finish(Proc1Only), "unsupported:", |trace| {
        for ev in &mut trace.events {
            if let Ev::Emit {
                msg: TelemetryMessage::LostOnReset(lost),
                ..
            } = ev
            {
                lost.ranges.retain(|range| range.from != 1);
            }
        }
        for recovery in &mut trace.recoveries {
            if matches!(recovery.reset, Some(Reset::Lost { .. })) {
                recovery.unsupported_observed += 1;
            }
        }
    });
}

#[test]
fn a_body_sent_as_a_record_after_it_should_have_expired_is_caught() {
    let (w, p) = expired_between_transition_and_resume();
    caught(w.finish(All), "list:", |trace| {
        for ev in &mut trace.events {
            if let Ev::Emit { msg, records, .. } = ev
                && let TelemetryMessage::DroppedRange(dropped) = msg
                && dropped.from == 1
            {
                let bytes = crate::fixture::make_record(
                    p,
                    crate::fixture::Kind::Proc1,
                    crate::fixture::Size::Normal,
                )
                .to_bytes()
                .unwrap();
                *records = vec![SentRecord {
                    seq: 1,
                    mark: Some(p),
                    bytes: bytes.clone(),
                    assign: None,
                }];
                *msg = TelemetryMessage::RecordBatch(
                    RecordBatch::new(dropped.stream, vec![bytes]).unwrap(),
                );
                break;
            }
        }
    });
}

#[test]
fn a_commit_without_an_allowed_recovery_is_caught() {
    let (w, _) = same_stream_with_dropped_and_records();
    caught(w.finish(All), "duplicates:", |trace| {
        let commit = trace
            .commits
            .iter()
            .find(|c| matches!(c.item, CommitItem::Record { .. }))
            .unwrap()
            .clone();
        let mut again = commit;
        again.ev = trace.events.len() - 1;
        again.lt = None;
        trace.commits.push(again);
    });
}

#[test]
fn an_entry_acknowledging_without_storing_after_its_state_was_lost_is_caught() {
    let (mut w, _) = entry_restored_at_k();
    w.drop_records_at(E1);
    w.run(Session(All));
    caught_live(&w.finish(All), "ack:");
}

#[test]
fn a_loss_of_another_assignment_counted_for_a_record_is_caught() {
    let (mut w, _, new) = forgotten_stream_reopened();
    w.run(Session(All));
    caught(w.finish(All), "omission:", |trace| {
        // The old lifetime's loss of 1 stays; the new record at 1 was
        // never stored.
        assert!(
            trace
                .commits
                .iter()
                .any(|c| matches!(&c.item, CommitItem::Dropped { range, .. } if range.from == 1))
        );
        trace
            .commits
            .retain(|c| !matches!(&c.item, CommitItem::Record { mark: Some(m), .. } if *m == new));
    });
}

#[test]
fn an_ack_resting_on_a_loss_of_the_stream_ids_earlier_lifetime_is_caught() {
    let (mut w, _, _) = forgotten_stream_reopened();
    w.tamper.forge_ack = Some(1);
    w.run(Session(All));
    caught_live(&w.finish(All), "ack:");
}

#[test]
fn a_retry_leaving_out_the_close_stream_whose_write_failed_is_caught() {
    let w = notices_failing_twice();
    caught(w.finish(All), "notices:", |trace| {
        let closes: Vec<usize> = trace
            .events
            .iter()
            .enumerate()
            .filter(|(_, ev)| {
                matches!(
                    ev,
                    Ev::Emit {
                        msg: TelemetryMessage::CloseStream(_),
                        ..
                    }
                )
            })
            .map(|(i, _)| i)
            .collect();
        trace.events[closes[2]] = Ev::Removed;
    });
}

#[test]
fn overlapping_lost_on_reset_ranges_are_caught() {
    caught(a_below_k_with_no_copy().finish(All), "notices:", |trace| {
        for ev in &mut trace.events {
            if let Ev::Emit {
                msg: TelemetryMessage::LostOnReset(lost),
                ..
            } = ev
            {
                lost.ranges = vec![SeqRange { from: 1, to: 2 }, SeqRange { from: 2, to: 3 }];
            }
        }
    });
}

#[test]
fn a_number_left_out_of_the_expected_losses_is_caught() {
    caught(a_below_k_with_no_copy().finish(All), "notices:", |trace| {
        for recovery in &mut trace.recoveries {
            if let (Some(Reset::Lost { .. }), Some(notices)) =
                (recovery.reset, recovery.notices.as_mut())
            {
                notices.lost = vec![(1, 1), (3, 3)];
            }
        }
    });
}

/// The second commit of `mark`, copied to the event just before
/// `before`: a commit no recovery since the one before allows.
fn commit_again_before(trace: &mut Trace, mark: crate::fixture::Mark, before: usize) {
    let commit = trace
        .commits
        .iter()
        .find(|c| matches!(&c.item, CommitItem::Record { mark: Some(m), .. } if *m == mark))
        .unwrap()
        .clone();
    let mut again = commit;
    again.ev = before - 1;
    again.lt = None;
    trace.commits.push(again);
    // Stable: the commits of one event keep their order.
    trace.commits.sort_by_key(|c| c.ev);
}

#[test]
fn a_record_recovered_after_a_rollback_and_not_stored_again_is_caught() {
    let (w, p) = record_recovered_after_a_rollback();
    caught(w.finish(All), "omission:", |trace| {
        let last = trace
            .recoveries
            .iter()
            .filter(|r| r.reset == Some(Reset::Fresh))
            .map(|r| r.ev)
            .max()
            .unwrap();
        trace.commits.retain(|c| {
            !(c.ev > last && matches!(&c.item, CommitItem::Record { mark: Some(m), .. } if *m == p))
        });
    });
}

#[test]
fn a_commit_resting_on_a_rollback_an_earlier_reconnection_used_up_is_caught() {
    let (w, r) = entry_changed_after_a_rollback_then_resumed();
    caught(w.finish(All), "duplicates:", |trace| {
        let resumed = trace
            .recoveries
            .iter()
            .filter(|x| x.reset.is_none() && x.entry == E2)
            .map(|x| x.ev)
            .min()
            .unwrap();
        commit_again_before(trace, r, resumed);
    });
}

#[test]
fn a_third_commit_of_a_record_a_rollback_put_back_to_wait_is_caught() {
    let (w, p) = stored_record_waiting_again_after_a_rollback();
    caught(w.finish(All), "duplicates:", |trace| {
        let commit = trace
            .commits
            .iter()
            .rev()
            .find(|c| matches!(&c.item, CommitItem::Record { mark: Some(m), .. } if *m == p))
            .unwrap()
            .clone();
        let mut again = commit;
        again.ev = trace.events.len() - 1;
        again.lt = None;
        trace.commits.push(again);
    });
}
