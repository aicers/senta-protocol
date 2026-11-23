//! The judgments, read from a run's trace alone.

use std::collections::{BTreeMap, BTreeSet};

use senta_protocol::connection::SERVER_OTHER_RECEIVE_LIMIT;
use senta_protocol::telemetry::{ReceiverOutput, TelemetryMessage};
use senta_protocol::telemetry_codes::{DropReason, TelemetryError};
use uuid::Uuid;

use crate::fixture::{Mark, Ranges};
use crate::trace::{CommitItem, Ev, Fate, Item, Lt, RecoveryId, Reset, Trace};

/// Judges a run: every judgment, every failure found.
pub fn judge(trace: &Trace) -> Result<(), String> {
    let mut failures = Vec::new();
    for ev in &trace.events {
        if let Ev::Violation(text) = ev {
            failures.push(format!("model: {text}"));
        }
    }
    failures.extend(lists(trace));
    failures.extend(bytes(trace));
    failures.extend(acks(trace));
    failures.extend(monotonic(trace));
    failures.extend(dropped_ranges(trace));
    failures.extend(errors(trace));
    failures.extend(notices(trace));
    failures.extend(unsupported(trace));
    failures.extend(duplicates(trace));
    failures.extend(omissions(trace));
    if failures.is_empty() {
        Ok(())
    } else {
        let total = failures.len();
        failures.truncate(12);
        Err(format!("{total} failures:\n{}", failures.join("\n")))
    }
}

/// What was sent at one sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    Record(Option<Mark>),
    Dropped(DropReason),
}

fn matches(sent: &Sent, item: &Item) -> bool {
    match (sent, item) {
        (Sent::Record(mark), Item::Record { mark: expected, .. }) => *mark == Some(*expected),
        (
            Sent::Dropped(reason),
            Item::Dropped {
                reason: expected, ..
            },
        ) => reason == expected,
        _ => false,
    }
}

fn units(ev: &Ev) -> Option<(Uuid, Vec<(u64, Sent)>)> {
    let Ev::Emit { msg, records, .. } = ev else {
        return None;
    };
    match msg {
        TelemetryMessage::RecordBatch(batch) => Some((
            batch.stream(),
            records
                .iter()
                .map(|r| (r.seq, Sent::Record(r.mark)))
                .collect(),
        )),
        TelemetryMessage::DroppedRange(range) => Some((
            range.stream,
            (range.from..=range.to)
                .map(|seq| (seq, Sent::Dropped(range.reason.clone())))
                .collect(),
        )),
        _ => None,
    }
}

struct Window {
    recovery: RecoveryId,
    stream: Uuid,
    start: u64,
    list: Vec<Item>,
    pre_queue: BTreeSet<Mark>,
    erased: BTreeMap<u64, DropReason>,
    next: u64,
    emitted: usize,
}

impl Window {
    fn expected(&self, seq: u64) -> Option<Item> {
        let index = usize::try_from(seq.checked_sub(self.start)?).ok()?;
        let item = self.list.get(index)?;
        Some(match self.erased.get(&seq) {
            Some(reason) => Item::Dropped {
                reason: reason.clone(),
                assign: match item {
                    Item::Record { assign, .. } | Item::Dropped { assign, .. } => *assign,
                },
            },
            None => item.clone(),
        })
    }
}

/// On every reconnection, what is sent from `A + 1` (or from 1 on a new
/// stream) is the expected list, item for item, in order, with each body
/// deleted since by retention or overflow sent as its dropped sequence
/// number; past the list come only records the queue did not hold before.
fn lists(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let mut window: Option<Window> = None;
    for (index, ev) in trace.events.iter().enumerate() {
        match ev {
            Ev::Recovery(id) => {
                let r = &trace.recoveries[*id];
                let continues = r.reset.is_none()
                    && window.as_ref().is_some_and(|w| {
                        w.stream == r.stream && w.emitted == 0 && w.start == r.start
                    });
                if continues {
                    // The first resume_info of a new stream: what the
                    // transition listed comes first, then what was moved
                    // since.
                    let w = window.as_mut().unwrap();
                    for i in 0..w.list.len().max(r.list.len()) {
                        let seq = w.start + u64::try_from(i).unwrap();
                        let expected = w.expected(seq);
                        let held = r.list.get(i);
                        let fine = match (&expected, held) {
                            (Some(expected), Some(held)) => same_item(expected, held),
                            (None, Some(_)) => true,
                            _ => false,
                        };
                        if !fine {
                            failures.push(format!(
                                "list: recovery {id} holds {held:?} at {seq} where the transition \
                                 {} listed {expected:?}",
                                w.recovery
                            ));
                        }
                    }
                    w.list.clone_from(&r.list);
                    w.erased.clear();
                    w.pre_queue.clone_from(&r.pre_queue);
                } else {
                    window = Some(Window {
                        recovery: *id,
                        stream: r.stream,
                        start: r.start,
                        list: r.list.clone(),
                        pre_queue: r.pre_queue.clone(),
                        erased: BTreeMap::new(),
                        next: r.start,
                        emitted: 0,
                    });
                }
            }
            Ev::Erase {
                stream,
                seq,
                reason,
            } => {
                if let Some(w) = window.as_mut()
                    && w.stream == *stream
                {
                    w.erased.insert(*seq, reason.clone());
                }
            }
            Ev::EndpointLoss => window = None,
            Ev::Emit { model, .. } => {
                let Some((stream, units)) = units(ev) else {
                    continue;
                };
                let Some(w) = window.as_mut() else {
                    failures.push(format!("list: event {index} sent data before any recovery"));
                    continue;
                };
                if w.stream != stream {
                    failures.push(format!(
                        "list: event {index} sent data of {stream} while {} is resumed",
                        w.stream
                    ));
                    continue;
                }
                for (i, (seq, sent)) in units.iter().enumerate() {
                    if *seq != w.next {
                        failures.push(format!(
                            "list: event {index} sent {seq} of {stream} where {} is next \
                             (recovery {})",
                            w.next, w.recovery
                        ));
                    }
                    match w.expected(*seq) {
                        Some(expected) => {
                            if !matches(sent, &expected) {
                                failures.push(format!(
                                    "list: event {index} sent {sent:?} at {seq} where recovery {} \
                                     lists {expected:?}",
                                    w.recovery
                                ));
                            }
                        }
                        None => {
                            let current = model.get(i).cloned().flatten();
                            if !current.as_ref().is_some_and(|item| matches(sent, item)) {
                                failures.push(format!(
                                    "list: event {index} sent {sent:?} at {seq} past the list of \
                                     recovery {} where the model holds {current:?}",
                                    w.recovery
                                ));
                            }
                            if let Sent::Record(Some(mark)) = sent
                                && w.pre_queue.contains(mark)
                            {
                                failures.push(format!(
                                    "list: event {index} sent record {mark} past the list of \
                                     recovery {}, though the queue held it before",
                                    w.recovery
                                ));
                            }
                        }
                    }
                    w.next = seq + 1;
                    w.emitted += 1;
                }
            }
            _ => {}
        }
    }
    // With no reconnection after it, the last list went out whole.
    if let Some(w) = &window {
        let end = w.start + u64::try_from(w.list.len()).unwrap();
        if w.next < end {
            failures.push(format!(
                "list: the list of recovery {} went out only up to {} of {}",
                w.recovery,
                w.next - 1,
                end - 1
            ));
        }
    }
    // Records sent back to the collection buffer get no new sequence
    // number on the stream that returned them.
    for r in &trace.recoveries {
        if r.returned.is_empty() {
            continue;
        }
        let end = next_recovery_ev(trace, r.ev);
        for ev in &trace.events[r.ev..end] {
            if let Some((stream, units)) = units(ev)
                && stream == r.stream
            {
                for (_, sent) in units {
                    if let Sent::Record(Some(mark)) = sent
                        && r.returned.contains(&mark)
                    {
                        failures.push(format!(
                            "list: record {mark}, sent back to the collection buffer, went out on \
                             the new stream {stream}"
                        ));
                    }
                }
            }
        }
    }
    failures
}

fn same_item(a: &Item, b: &Item) -> bool {
    match (a, b) {
        (Item::Record { mark: x, .. }, Item::Record { mark: y, .. }) => x == y,
        (Item::Dropped { reason: x, .. }, Item::Dropped { reason: y, .. }) => x == y,
        _ => false,
    }
}

fn next_recovery_ev(trace: &Trace, after: usize) -> usize {
    trace.events[after + 1..]
        .iter()
        .position(|ev| matches!(ev, Ev::Recovery(_) | Ev::EndpointLoss))
        .map_or(trace.events.len(), |i| after + 1 + i)
}

/// An assignment sent again goes out bit for bit as it first did, the
/// entry stores those bytes, and the `last_stored` hash of a
/// `resume_info` is the hash the test computes of them.
fn bytes(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let mut first: BTreeMap<u64, &[u8]> = BTreeMap::new();
    for (index, ev) in trace.events.iter().enumerate() {
        match ev {
            Ev::Emit { records, .. } => {
                for record in records {
                    let Some(assign) = record.assign else {
                        continue;
                    };
                    match first.get(&assign) {
                        Some(bytes) if *bytes != record.bytes.as_slice() => {
                            failures.push(format!(
                                "bytes: event {index} sent assignment {assign} (record {:?}) with \
                                 other bytes than it first went out with",
                                record.mark
                            ));
                        }
                        Some(_) => {}
                        None => {
                            first.insert(assign, &record.bytes);
                        }
                    }
                }
            }
            Ev::Deliver {
                resume: Some(resume),
                ..
            } => {
                if let Some((seq, hash)) = resume.last {
                    match resume.expected_hash {
                        Some(expected) if expected == hash => {}
                        Some(_) => failures.push(format!(
                            "bytes: event {index}: the entry's H of {seq} (A = {}) is not the \
                             hash of the bytes first sent",
                            resume.a
                        )),
                        None => failures.push(format!(
                            "bytes: event {index}: the entry's L = {seq} names no record \
                             lifetime {:?} holds",
                            resume.lt
                        )),
                    }
                }
            }
            _ => {}
        }
    }
    for commit in &trace.commits {
        if let CommitItem::Record {
            seq,
            bytes,
            assign: Some(assign),
            mark,
            ..
        } = &commit.item
            && first.get(assign).is_some_and(|f| *f != bytes.as_slice())
        {
            failures.push(format!(
                "bytes: the entry stored record {mark:?} at {seq} with other bytes than its \
                 assignment {assign} first went out with"
            ));
        }
    }
    failures
}

/// Every `ack` covers only what the lifetime of its stream's state holds:
/// a record or a dropped range committed in it, or held by the snapshot it
/// was restored from.
fn acks(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    for (index, ev) in trace.events.iter().enumerate() {
        if let Ev::Deliver { acks, .. } = ev {
            for ack in acks {
                if ack.a > ack.covered {
                    failures.push(format!(
                        "ack: event {index} acknowledged {} where the lifetime {:?} holds 1..={}",
                        ack.a, ack.lt, ack.covered
                    ));
                }
            }
        }
    }
    failures
}

/// `A` never goes back within a lifetime, from the `A` a restored one
/// starts at on.
fn monotonic(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let mut last: BTreeMap<Lt, u64> = trace.starts.clone();
    for commit in &trace.commits {
        if let (Some(lt), CommitItem::Flow { key, state }) = (commit.lt, &commit.item) {
            if let Some(previous) = last.get(&lt)
                && state.a < *previous
            {
                failures.push(format!(
                    "monotonic: A of {} went from {previous} back to {} within lifetime {lt}",
                    key.stream, state.a
                ));
            }
            last.insert(lt, state.a);
        }
    }
    failures
}

fn ack_reply(output: &ReceiverOutput, stream: Uuid, a: u64) -> bool {
    *output
        == ReceiverOutput::Reply(vec![TelemetryMessage::Ack(
            senta_protocol::telemetry::Ack { stream, a },
        )])
}

/// A `dropped_range` the entry takes adds the one tail `(A, to]` and
/// acknowledges `to`; one already covered changes nothing and acknowledges
/// `A`; one whose write fails changes nothing and closes the connection.
fn dropped_ranges(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let mut by_ev: BTreeMap<usize, Vec<&CommitItem>> = BTreeMap::new();
    for commit in &trace.commits {
        by_ev.entry(commit.ev).or_default().push(&commit.item);
    }
    for (index, ev) in trace.events.iter().enumerate() {
        let Ev::Deliver {
            msg: TelemetryMessage::DroppedRange(range),
            before: Some((_, state)),
            injected,
            halted: false,
            output,
            ..
        } = ev
        else {
            continue;
        };
        if !state.is_open() || range.from > range.to || range.from > state.a + 1 {
            continue;
        }
        let commits = by_ev.get(&index).cloned().unwrap_or_default();
        let fine = if *injected {
            commits.is_empty() && *output == ReceiverOutput::Disconnect
        } else if range.to > state.a {
            let tail = matches!(
                commits.as_slice(),
                [CommitItem::Dropped { range: r, reason, .. }, CommitItem::Flow { state: s, .. }]
                    if r.from == state.a + 1 && r.to == range.to && *reason == range.reason
                        && s.a == range.to
            );
            tail && ack_reply(output, range.stream, range.to)
        } else {
            commits.is_empty() && ack_reply(output, range.stream, state.a)
        };
        if !fine {
            failures.push(format!(
                "dropped range: event {index}: {range:?} at A = {} (failure injected: {injected}) \
                 committed {commits:?} and answered {output:?}",
                state.a
            ));
        }
    }
    failures
}

/// The entry refuses nothing the endpoint sends: no batch fails to decode
/// or names another endpoint or stream, no `too_large`, `gap` or
/// `unsupported_kind`; it closes a connection only after a write it was
/// made to fail, and a halted connection gets no answer at all.
fn errors(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    for (index, ev) in trace.events.iter().enumerate() {
        let Ev::Deliver {
            entry,
            link,
            msg,
            injected,
            halted,
            output,
            ..
        } = ev
        else {
            continue;
        };
        match output {
            ReceiverOutput::Disconnect if *halted || *injected => {}
            ReceiverOutput::Disconnect => failures.push(format!(
                "errors: event {index}: {entry} closed connection {link} on {msg:?}"
            )),
            ReceiverOutput::Reply(replies) => {
                if *halted {
                    failures.push(format!(
                        "errors: event {index}: a halted connection answered {replies:?}"
                    ));
                }
                if *injected {
                    failures.push(format!(
                        "errors: event {index}: a failed write answered {replies:?}"
                    ));
                }
                for reply in replies {
                    if let TelemetryMessage::ErrorMessage(error) = reply {
                        let closed_open = error.error == TelemetryError::Closed
                            && matches!(msg, TelemetryMessage::OpenStream(_));
                        if !closed_open {
                            failures.push(format!(
                                "errors: event {index}: the entry answered {msg:?} with {error:?}"
                            ));
                        }
                    }
                }
            }
        }
    }
    failures
}

/// The notices of every new stream: before each of its `open_stream`s, on
/// every connection, the expected `lost_on_reset`s, then the
/// `close_stream`, always the same messages in the same order, and nothing
/// of the kind where none is expected. The entry's loss records follow
/// them.
#[allow(clippy::too_many_lines)] // The notice rules, each a few lines.
fn notices(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let limit = usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap();
    // Segments: from a recovery or its revival to its end.
    let mut segments: Vec<(RecoveryId, usize, usize, bool)> = Vec::new();
    for (id, r) in trace.recoveries.iter().enumerate() {
        if r.notices.is_none() {
            continue;
        }
        let mut starts = vec![r.ev];
        starts.extend(
            trace
                .events
                .iter()
                .enumerate()
                .filter_map(|(i, ev)| match ev {
                    Ev::Revived { recovery } if *recovery == id => Some(i),
                    _ => None,
                }),
        );
        for start in starts {
            let mut end = trace.events.len();
            let mut done = false;
            for (i, ev) in trace.events.iter().enumerate().skip(start + 1) {
                let stop = match ev {
                    Ev::NoticesDone { recovery } if *recovery == id => {
                        done = true;
                        true
                    }
                    Ev::NoticesDropped { recovery, .. } if *recovery == id => true,
                    Ev::Recovery(_) | Ev::EndpointLoss | Ev::Revived { .. } => true,
                    _ => false,
                };
                if stop {
                    end = i;
                    break;
                }
            }
            segments.push((id, start, end, done));
        }
    }
    let mut commits_at: BTreeMap<usize, Vec<&crate::trace::Commit>> = BTreeMap::new();
    for commit in &trace.commits {
        commits_at.entry(commit.ev).or_default().push(commit);
    }
    let mut groups: BTreeMap<RecoveryId, Vec<TelemetryMessage>> = BTreeMap::new();
    for &(id, start, end, done) in &segments {
        let r = &trace.recoveries[id];
        let expected = r.notices.as_ref().unwrap();
        let mut current: BTreeMap<u64, Vec<(TelemetryMessage, usize)>> = BTreeMap::new();
        for (index, ev) in trace.events.iter().enumerate().take(end).skip(start + 1) {
            let Ev::Emit {
                link,
                msg,
                payload_len,
                ..
            } = ev
            else {
                continue;
            };
            match msg {
                TelemetryMessage::LostOnReset(_) | TelemetryMessage::CloseStream(_) => {
                    current
                        .entry(*link)
                        .or_default()
                        .push((msg.clone(), *payload_len));
                }
                TelemetryMessage::OpenStream(open) if open.stream == r.stream => {
                    let group = current.remove(link).unwrap_or_default();
                    let messages: Vec<TelemetryMessage> =
                        group.iter().map(|(m, _)| m.clone()).collect();
                    let mut lost = Vec::new();
                    let mut close = None;
                    for (message, payload_len) in &group {
                        if *payload_len > limit {
                            failures.push(format!(
                                "notices: event {index}: a notice of {payload_len} bytes is past \
                                 the {limit} an entry receives"
                            ));
                        }
                        match message {
                            TelemetryMessage::LostOnReset(l) => {
                                if close.is_some() || Some(l.old_stream) != r.old_stream {
                                    failures.push(format!(
                                        "notices: event {index}: {l:?} after the close_stream or \
                                         of another stream"
                                    ));
                                }
                                lost.extend(l.ranges.iter().map(|x| (x.from, x.to)));
                            }
                            TelemetryMessage::CloseStream(c) => close = Some(c.stream),
                            _ => {}
                        }
                    }
                    for pair in lost.windows(2) {
                        if pair[0].0 > pair[0].1 || pair[0].1.saturating_add(1) >= pair[1].0 {
                            failures.push(format!(
                                "notices: event {index}: the lost_on_reset ranges {:?} and {:?} \
                                 overlap, touch or are out of order",
                                pair[0], pair[1]
                            ));
                        }
                    }
                    if lost != expected.lost {
                        failures.push(format!(
                            "notices: event {index}: lost_on_reset {lost:?} where recovery {id} \
                             expects {:?}",
                            expected.lost
                        ));
                    }
                    let expected_close = r.old_stream.filter(|_| expected.close);
                    if close != expected_close {
                        failures.push(format!(
                            "notices: event {index}: close_stream {close:?} where recovery {id} \
                             expects {expected_close:?}"
                        ));
                    }
                    match groups.get(&id) {
                        Some(first) if *first != messages => failures.push(format!(
                            "notices: event {index}: the notices of recovery {id} went out \
                             otherwise than the first time"
                        )),
                        Some(_) => {}
                        None => {
                            groups.insert(id, messages);
                        }
                    }
                }
                TelemetryMessage::OpenStream(_) => {
                    current.remove(link);
                }
                _ => {
                    if let Some(group) = current.remove(link) {
                        failures.push(format!(
                            "notices: event {index}: notices {group:?} not followed by the \
                             open_stream of recovery {id}"
                        ));
                    }
                }
            }
        }
        // The first message after a transition is on its connection.
        if start == r.ev {
            let first = trace.events[start + 1..end].iter().find_map(|ev| match ev {
                Ev::Emit {
                    link, entry, msg, ..
                } => Some((*link, *entry, msg.clone())),
                _ => None,
            });
            if let Some((link, entry, msg)) = first
                && (Some(link) != r.link
                    || entry != r.entry
                    || !matches!(
                        msg,
                        TelemetryMessage::LostOnReset(_)
                            | TelemetryMessage::CloseStream(_)
                            | TelemetryMessage::OpenStream(_)
                    ))
            {
                failures.push(format!(
                    "notices: the first message after recovery {id} is {msg:?} on link {link}"
                ));
            }
        }
        // The entry's loss records.
        let (Some(Reset::Lost { .. }), Some(old)) = (r.reset, r.old_stream) else {
            continue;
        };
        let expected_set = {
            let mut set = Ranges::new();
            for (from, to) in &expected.lost {
                set.insert(*from, *to);
            }
            set
        };
        let mut baseline: Option<(usize, Vec<(u64, u64)>)> = None;
        let mut new: Vec<(u64, u64)> = Vec::new();
        let mut held = None;
        for (index, ev) in trace.events.iter().enumerate().take(end + 1).skip(start) {
            match ev {
                Ev::Baseline { recovery, ranges } if *recovery == id => {
                    baseline = Some((index, ranges.clone()));
                    new.clear();
                }
                Ev::Held { recovery, ranges } if *recovery == id => held = Some(ranges.clone()),
                _ => {}
            }
            for commit in commits_at.get(&index).into_iter().flatten() {
                let CommitItem::Lor { key, range, .. } = &commit.item else {
                    continue;
                };
                if commit.entry != r.entry || key.stream != old || baseline.is_none() {
                    continue;
                }
                let pair = (range.from, range.to);
                if !expected.lost.contains(&pair) {
                    failures.push(format!(
                        "notices: the entry recorded the loss {pair:?} of {old}, which recovery \
                         {id} does not report"
                    ));
                }
                let base = &baseline.as_ref().unwrap().1;
                if base.contains(&pair) || new.contains(&pair) {
                    failures.push(format!(
                        "notices: the entry recorded the loss {pair:?} of {old} again"
                    ));
                }
                new.push(pair);
            }
        }
        // Held is pushed after the call that ended the segment.
        if done {
            for ev in &trace.events[end..] {
                if let Ev::Held { recovery, ranges } = ev
                    && *recovery == id
                {
                    held = Some(ranges.clone());
                    break;
                }
            }
            let Some((_, base)) = &baseline else {
                failures.push(format!("notices: recovery {id} has no baseline"));
                continue;
            };
            let mut stored = Ranges::new();
            for (from, to) in base.iter().chain(&new) {
                stored.insert(*from, *to);
            }
            if !stored.covers(&expected_set) {
                failures.push(format!(
                    "notices: recovery {id} ended with the entry holding {:?} of the losses {:?}",
                    stored.ranges(),
                    expected.lost
                ));
            }
            if let Some(held) = held
                && !base.iter().all(|range| held.contains(range))
            {
                failures.push(format!(
                    "notices: the baseline loss records {base:?} of recovery {id} are not all \
                     held at its end: {held:?}"
                ));
            }
        }
    }
    // No notice goes out outside its group.
    let mut pending: BTreeMap<u64, usize> = BTreeMap::new();
    for (index, ev) in trace.events.iter().enumerate() {
        if let Ev::Emit { link, msg, .. } = ev {
            match msg {
                TelemetryMessage::LostOnReset(_) | TelemetryMessage::CloseStream(_) => {
                    pending.entry(*link).or_insert(index);
                }
                TelemetryMessage::OpenStream(_) => {
                    pending.remove(link);
                }
                _ => {
                    if let Some(at) = pending.remove(link) {
                        failures.push(format!(
                            "notices: event {at}: a notice not followed by an open_stream"
                        ));
                    }
                }
            }
        }
    }
    failures
}

/// A transition adds to the `unsupported` count only the collected records
/// it deleted, never a copy it sent back.
fn unsupported(trace: &Trace) -> Vec<String> {
    trace
        .recoveries
        .iter()
        .enumerate()
        .filter(|(_, r)| r.reset.is_some() && r.unsupported_expected != r.unsupported_observed)
        .map(|(id, r)| {
            format!(
                "unsupported: recovery {id} added {} where {} were expected",
                r.unsupported_observed, r.unsupported_expected
            )
        })
        .collect()
}

/// Every commit of a record at an entry after its first has its own
/// allowed recovery since the one before; a lifetime stores a sequence
/// number once.
fn duplicates(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let mut by_record: BTreeMap<(Uuid, Mark), Vec<usize>> = BTreeMap::new();
    let mut by_seq: BTreeMap<(Lt, u64), usize> = BTreeMap::new();
    for commit in &trace.commits {
        if let CommitItem::Record { mark, seq, .. } = &commit.item {
            if let Some(mark) = mark {
                by_record
                    .entry((commit.entry, *mark))
                    .or_default()
                    .push(commit.ev);
            }
            if let Some(lt) = commit.lt {
                *by_seq.entry((lt, *seq)).or_default() += 1;
            }
        }
    }
    for ((lt, seq), count) in by_seq {
        if count > 1 {
            failures.push(format!(
                "duplicates: lifetime {lt} stored {seq} {count} times"
            ));
        }
    }
    for ((entry, mark), evs) in by_record {
        for pair in evs.windows(2) {
            let (before, at) = (pair[0], pair[1]);
            let allowed = trace.recoveries.iter().any(|r| {
                r.allowed
                    && r.entry == entry
                    && r.ev > before
                    && r.ev < at
                    // Waiting records too, which the issue leaves out:
                    // see `Recovery::waiting`.
                    && (r.targets.contains(&mark) || r.waiting.contains(&mark))
            });
            if !allowed {
                failures.push(format!(
                    "duplicates: record {mark} committed again at {entry} (event {at}) with no \
                     allowed recovery of it since event {before}"
                ));
            }
        }
    }
    failures
}

/// After the drain, every record the endpoint ever held is stored, or
/// reported lost, or still waits, or was dropped where the rules let it go.
fn omissions(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    let fin = &trace.final_state;
    let mut commits: BTreeMap<Mark, Vec<(Uuid, usize)>> = BTreeMap::new();
    let mut reported: BTreeSet<Mark> = BTreeSet::new();
    for commit in &trace.commits {
        match &commit.item {
            CommitItem::Record {
                mark: Some(mark), ..
            } => commits
                .entry(*mark)
                .or_default()
                .push((commit.entry, commit.ev)),
            CommitItem::Dropped { assigns, .. } | CommitItem::Lor { assigns, .. } => {
                reported.extend(assigns.iter().map(|a| trace.assign_of(*a).mark));
            }
            _ => {}
        }
    }
    // How each record was let go, in the final state's history.
    let mut fates: BTreeMap<Mark, Vec<Fate>> = BTreeMap::new();
    for (mark, fate) in &fin.fates {
        fates.entry(*mark).or_default().push(*fate);
    }
    // The last recovery of each record, whether or not the final state
    // went through it, and the last one the final state went through.
    let mut last_recovery: BTreeMap<Mark, RecoveryId> = BTreeMap::new();
    let mut last_in_lineage: BTreeMap<Mark, RecoveryId> = BTreeMap::new();
    for (id, r) in trace.recoveries.iter().enumerate() {
        for mark in &r.targets {
            last_recovery.insert(*mark, id);
            if fin.lineage.contains(&id) {
                last_in_lineage.insert(*mark, id);
            }
        }
    }
    let dropped_by_entry_change: BTreeSet<RecoveryId> = trace
        .events
        .iter()
        .filter_map(|ev| match ev {
            Ev::NoticesDropped {
                recovery,
                entry_changed: true,
            } => Some(*recovery),
            _ => None,
        })
        .collect();
    for mark in &trace.marks {
        // Only in a state the endpoint lost, or taken away with every
        // copy and all that could report it by a state loss: no longer
        // the endpoint's to send or report.
        if !fin.known.contains(mark) || fin.erased.contains(mark) {
            continue;
        }
        let committed = commits.get(mark).cloned().unwrap_or_default();
        let after = |id: Option<&RecoveryId>| -> Vec<(Uuid, usize)> {
            match id {
                None => committed.clone(),
                Some(id) => {
                    let r = &trace.recoveries[*id];
                    committed
                        .iter()
                        .filter(|(entry, ev)| *entry == r.entry && *ev > r.ev)
                        .copied()
                        .collect()
                }
            }
        };
        let last = last_recovery.get(mark);
        let lineage_last = last_in_lineage.get(mark);
        // A recovery the endpoint undid by going back to a snapshot leaves
        // the record to the recoveries of the state gone back to. Where
        // that state reopens a stream the undone recovery closed and gets
        // `closed`, the stream it opens then resends every copy it still
        // holds, and that recovery targets the record, so the record must
        // be stored after it; a copy no longer held is neither resent nor
        // reported, as the rule for `closed` says.
        let relied = after(lineage_last);
        let stored = !relied.is_empty() || !after(last).is_empty();
        let let_go = fates.get(mark).map(Vec::as_slice).unwrap_or_default();
        let lor_abandoned = let_go.iter().any(|fate| {
            matches!(fate, Fate::LostOnResetOnly(id)
                if lineage_last == Some(id) && dropped_by_entry_change.contains(id))
        });
        let fine = stored
            || reported.contains(mark)
            || fin.collected.contains(mark)
            || let_go.contains(&Fate::Unsupported)
            || let_go.contains(&Fate::Abandoned)
            || lor_abandoned;
        if !fine {
            failures.push(format!(
                "omission: record {mark} is neither stored after its last recovery {:?}, nor \
                 reported lost, nor waiting, nor dropped by the rules (commits {committed:?})",
                last_recovery.get(mark)
            ));
        }
    }
    failures
}
