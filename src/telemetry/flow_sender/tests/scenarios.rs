//! The sender's rules, scenario by scenario, with the entry's answers made
//! by hand.

use super::*;

// ----- Registration and the collection buffer -----

#[test]
fn records_wait_for_registration_then_move_in_collection_order() {
    let mut h = H::big();
    h.entries(&[E1]);
    let actions = h.establish(E1, K1);
    assert!(actions.is_empty());
    let stream = h.flow().stream;
    assert!(sent(&h.collect_n(1, 1..=3)).is_empty());
    assert_eq!(h.stream.status().collected_records, 3);

    let actions = h.stream.register(EP).unwrap();
    let records = sent(&actions);
    assert_eq!(seqs(&records), [1, 2, 3]);
    assert_eq!(ns(&records), [1, 2, 3]);
    for record in &records {
        assert_eq!(record.endpoint_id, EP);
        assert_eq!(record.stream, stream);
    }
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.queued_records), (0, 3));
    assert_eq!(h.flow().assigned, 3);
    h.check_invariants();
}

#[test]
fn registration_without_a_stream_moves_nothing_until_one_opens() {
    let mut h = H::big();
    h.entries(&[E1]);
    h.collect_n(1, 1..=2);
    assert!(h.stream.register(EP).unwrap().is_empty());
    assert_eq!(h.stream.status().collected_records, 2);
    assert_eq!(h.stream.endpoint_id(), Some(EP));

    let records = sent(&h.establish(E1, K1));
    assert_eq!(seqs(&records), [1, 2]);
    assert_eq!(ns(&records), [1, 2]);
    assert!(records.iter().all(|record| record.endpoint_id == EP));
}

#[test]
fn another_endpoint_id_is_refused_and_the_same_one_changes_nothing() {
    let mut h = registered();
    h.collect(record(1, 1));
    let store = h.stream.store().clone();
    let core = format!("{:?}", h.stream.core);

    let error = h.stream.register(Uuid::from_u128(0xe1)).unwrap_err();
    assert!(matches!(
        error,
        SenderError::EndpointIdMismatch { registered, given }
            if registered == EP && given == Uuid::from_u128(0xe1)
    ));
    assert_eq!(h.stream.store(), &store);
    assert_eq!(format!("{:?}", h.stream.core), core);

    assert!(h.stream.register(EP).unwrap().is_empty());
    assert_eq!(h.stream.store(), &store);
    assert_eq!(h.stream.endpoint_id(), Some(EP));
}

#[test]
fn records_of_kinds_not_accepted_wait_without_blocking_later_ones() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    assert!(sent(&h.collect(record(2, 1))).is_empty());
    let records = sent(&h.collect(record(1, 2)));
    assert_eq!((seqs(&records), ns(&records)), (vec![1], vec![2]));
    assert_eq!(h.stream.status().collected_records, 1);

    // A wider list moves the waiting record at the next hello_ack.
    h.close();
    h.connect();
    let opened = h.hello(E1, K12);
    assert_eq!(kinds_sent(&opened), ["open_stream"]);
    assert_eq!(open_of(&opened), Some(stream));
    assert_eq!(h.stream.status().collected_records, 0);
    let hash = h.hash_of(1);
    let records = sent(&h.resume(stream, 1, Some((1, hash))));
    assert_eq!((seqs(&records), ns(&records)), (vec![2], vec![1]));
}

#[test]
fn a_record_breaking_a_rule_is_refused_at_collection() {
    let mut h = registered();
    h.establish(E1, K1);
    let store = h.stream.store().clone();
    let mut bad = record(1, 1);
    bad.header.net_state_source = NetStateSource::Unknown;
    let error = h.stream.collect(bad, h.wall, h.now).unwrap_err();
    assert!(matches!(
        error,
        SenderError::Record(crate::telemetry::RecordEncodeError::UnknownNetStateWithAddresses)
    ));
    assert_eq!(h.stream.store(), &store);
    assert_eq!(h.stream.status().collected_records, 0);
    assert_eq!(h.flow().assigned, 0);
}

#[test]
fn moved_records_are_numbered_from_one_without_gaps() {
    let mut h = registered();
    h.establish(E1, K12);
    let stream = h.flow().stream;
    let mut all = Vec::new();
    for n in 1..=20 {
        all.extend(sent(&h.collect(record(if n % 3 == 0 { 2 } else { 1 }, n))));
    }
    assert_eq!(seqs(&all), (1..=20).collect::<Vec<_>>());
    for record in &all {
        assert_eq!(record.seq, record.n);
        assert_eq!((record.endpoint_id, record.stream), (EP, stream));
    }
}

#[test]
fn resent_records_are_the_same_bytes_and_hash() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    let first = sent(&h.collect_n(1, 1..=3));
    h.close();
    h.connect();
    assert_eq!(open_of(&h.hello(E1, K1)), Some(stream));
    let again = sent(&h.resume(stream, 0, None));
    assert_eq!(first, again);
    for record in &again {
        assert_eq!(h.hash_of(record.seq), record_hash(&record.bytes));
    }
}

#[test]
fn the_collection_buffer_limit_deletes_the_oldest_without_a_dropped_range() {
    let mut h = H::new(SenderConfig::new(2, 1 << 40));
    h.entries(&[E1]);
    h.collect_n(1, 1..=3);
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (2, 1));
    h.stream.register(EP).unwrap();
    let actions = h.establish(E1, K1);
    assert_eq!(ns(&sent(&actions)), [2, 3]);
    assert!(drops(&actions).is_empty());
    assert_eq!(h.stream.status().dropped_ranges, 0);
}

#[test]
fn the_collection_buffer_retention_counts_unsupported_at_its_exact_end() {
    let retention = SignedDuration::from_secs(10);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.collect(record(1, 1));
    let just_before = wall(10).checked_sub(SignedDuration::from_nanos(1)).unwrap();
    h.stream.tick(just_before, h.now).unwrap();
    assert_eq!(h.stream.status().collected_records, 1);
    h.stream.tick(wall(10), h.now).unwrap();
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (0, 1));
    assert_eq!(status.dropped_ranges, 0);
}

// ----- Dropped sequence numbers -----

#[test]
fn a_record_past_256_kib_is_dropped_as_too_large() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    let actions = h.collect(record_of_len(1, 1, MAX_RECORD_LEN, stream, 1));
    let records = sent(&actions);
    assert_eq!(seqs(&records), [1]);
    assert_eq!(records[0].bytes.len(), MAX_RECORD_LEN);

    let actions = h.collect(record_of_len(1, 2, MAX_RECORD_LEN + 1, stream, 2));
    assert!(sent(&actions).is_empty());
    assert_eq!(drops(&actions), [(2, 2, DropReason::TooLarge)]);
    assert_eq!(h.stream.status().dropped_ranges, 1);
    // The next record follows it.
    assert_eq!(seqs(&sent(&h.collect(record(1, 3)))), [3]);
    h.check_invariants();
}

#[test]
fn queue_overflow_deletes_acknowledged_copies_first() {
    let len = len_of(record(1, 1));
    let mut h = H::new(SenderConfig::new(100, 3 * len));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.collect_n(1, 1..=3);
    h.ack(stream, 2);

    h.collect(record(1, 4));
    assert!(
        h.stream.core.state.queue.get(&1).is_none(),
        "the oldest copy goes first"
    );
    h.collect(record(1, 5));
    assert!(h.stream.core.state.queue.get(&2).is_none());
    assert_eq!(h.stream.status().dropped_ranges, 0);
    // No copy is left: the lowest unacknowledged record goes.
    h.collect(record(1, 6));
    assert_eq!(h.stream.status().dropped_ranges, 1);
    assert_eq!(h.stream.status().queued_bytes, 3 * len);

    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 2, None);
    assert_eq!(drops(&actions), [(3, 3, DropReason::BufferOverflow)]);
    assert_eq!(seqs(&sent(&actions)), [4, 5, 6]);
    h.check_invariants();
}

/// The byte length of `record` as the first record of a stream.
fn len_of(record: Record) -> u64 {
    let mut record = record;
    record.header.endpoint_id = EP;
    record.header.seq = 1;
    u64::try_from(record.to_bytes().unwrap().len()).unwrap()
}

#[test]
fn an_unacknowledged_record_expires_at_the_exact_end_of_its_retention() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect(record(1, 1));
    assert_eq!(h.flow().assigned, 1, "moved while disconnected");

    let just_before = wall(100)
        .checked_sub(SignedDuration::from_nanos(1))
        .unwrap();
    h.stream.tick(just_before, h.now).unwrap();
    assert!(h.stream.core.state.queue.get(&1).is_some());
    h.stream.tick(wall(100), h.now).unwrap();
    assert!(h.stream.core.state.queue.get(&1).is_none());

    h.wall = wall(100);
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 0, None);
    assert_eq!(drops(&actions), [(1, 1, DropReason::RetentionExpired)]);
    assert!(sent(&actions).is_empty());
}

#[test]
fn an_acknowledged_copy_is_kept_24_hours_from_its_first_acknowledgement() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.collect_n(1, 1..=2);
    h.ack(stream, 1);
    h.advance(3600);
    h.ack(stream, 2);
    // A later acknowledgement, and a resume_info at step 6, extend nothing.
    h.advance(3600);
    h.close();
    h.connect();
    h.hello(E1, K1);
    h.resume(stream, 2, None);
    assert!(h.ack(stream, 2).is_empty());

    let day = SignedDuration::from_hours(24);
    let at = |hours: i64, nanos: i64| {
        wall(0)
            .checked_add(day)
            .unwrap()
            .checked_add(SignedDuration::from_hours(hours))
            .unwrap()
            .checked_sub(SignedDuration::from_nanos(nanos))
            .unwrap()
    };
    let now = h.now;
    h.stream.tick(at(0, 1), now).unwrap();
    assert_eq!(h.stream.status().queued_records, 2);
    h.stream.tick(at(0, 0), now).unwrap();
    assert_eq!(h.stream.status().queued_records, 1);
    h.stream.tick(at(1, 1), now).unwrap();
    assert_eq!(h.stream.status().queued_records, 1);
    h.stream.tick(at(1, 0), now).unwrap();
    assert_eq!(h.stream.status().queued_records, 0);
}

#[test]
fn each_copy_expires_from_its_own_acknowledgement_when_the_wall_clock_goes_back() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.collect_n(1, 1..=2);
    h.wall = wall(10 * 3600);
    h.ack(stream, 1);
    // The wall clock steps back: copy 2 is first acknowledged before
    // copy 1 was.
    h.wall = wall(5 * 3600);
    h.ack(stream, 2);

    let day = 24 * 3600;
    let now = h.now;
    h.stream.tick(wall(5 * 3600 + day), now).unwrap();
    let queue = &h.stream.core.state.queue;
    assert!(queue.get(&1).is_some(), "copy 1 is kept to its own end");
    assert!(queue.get(&2).is_none());
    h.stream
        .tick(
            wall(10 * 3600 + day)
                .checked_sub(SignedDuration::from_nanos(1))
                .unwrap(),
            now,
        )
        .unwrap();
    assert_eq!(h.stream.status().queued_records, 1);
    h.stream.tick(wall(10 * 3600 + day), now).unwrap();
    assert_eq!(h.stream.status().queued_records, 0);
    assert!(h.stream.core.state.acked.map().is_empty());
}

// ----- Sending -----

#[test]
fn batches_hold_consecutive_records_of_the_stream_within_1_mib() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    for n in 1..=5 {
        h.collect(record_of_len(1, n, 250_000, stream, n));
    }
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 0, None);
    assert_eq!(kinds_sent(&actions), ["record_batch", "record_batch"]);
    assert_eq!(seqs(&sent(&actions)), [1, 2, 3, 4, 5]);
}

#[test]
fn dropped_sequence_numbers_go_in_their_place() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect(record(1, 1));
    h.wall = wall(50);
    h.collect_n(1, 2..=3);
    h.wall = wall(60);
    h.collect(record_of_len(1, 4, MAX_RECORD_LEN + 1, stream, 4));
    h.collect(record(1, 5));
    h.wall = wall(100);
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 0, None);
    let order: Vec<String> = messages(&actions)
        .into_iter()
        .map(|message| match message {
            TelemetryMessage::DroppedRange(range) => format!("drop {}-{}", range.from, range.to),
            TelemetryMessage::RecordBatch(batch) => format!("batch of {}", batch.records().len()),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(order, ["drop 1-1", "batch of 2", "drop 4-4", "batch of 1"]);
}

// ----- The window and the ledger -----

#[test]
fn the_window_stops_new_records_at_10000_past_k() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=10_005);
    assert_eq!(
        h.stream.core.state.ledger.len(),
        0,
        "no hash before sending"
    );
    h.connect();
    h.hello(E1, K1);
    let records = sent(&h.resume(stream, 0, None));
    assert_eq!(records.len(), 10_000);
    assert_eq!(h.flow().sent, 10_000);
    assert_eq!(h.stream.core.state.ledger.len(), 10_000);
    h.check_invariants();

    let records = sent(&h.ack(stream, 5));
    assert_eq!(seqs(&records), [10_001, 10_002, 10_003, 10_004, 10_005]);
    h.check_invariants();
}

#[test]
fn a_full_window_is_resent_on_the_next_connection() {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=10_002);
    h.connect();
    h.hello(E1, K1);
    assert_eq!(sent(&h.resume(stream, 0, None)).len(), 10_000);
    h.close();
    h.connect();
    h.hello(E1, K1);
    let records = sent(&h.resume(stream, 0, None));
    assert_eq!(seqs(&records), (1..=10_000).collect::<Vec<_>>());
    h.check_invariants();
}

#[test]
fn a_dropped_range_longer_than_the_window_goes_in_parts() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=10_001);
    h.wall = wall(100);
    h.stream.tick(h.wall, h.now).unwrap();
    assert_eq!(h.stream.status().dropped_ranges, 1);
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 0, None);
    assert_eq!(drops(&actions), [(1, 10_000, DropReason::RetentionExpired)]);
    h.check_invariants();
    let actions = h.ack(stream, 10_000);
    assert_eq!(
        drops(&actions),
        [(10_001, 10_001, DropReason::RetentionExpired)]
    );
    h.ack(stream, 10_001);
    assert_eq!(h.flow().acknowledged, 10_001);
    h.check_invariants();
}

#[test]
fn a_snapshot_with_k_and_s_at_zero_resumes_over_dropped_sequence_numbers() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=2);
    h.wall = wall(100);
    h.stream.tick(h.wall, h.now).unwrap();
    let position = h.flow();
    assert_eq!((position.acknowledged, position.sent), (0, 0));

    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 2, None);
    assert!(actions.is_empty());
    let position = h.flow();
    assert_eq!(position.stream, stream);
    assert_eq!((position.acknowledged, position.sent), (2, 2));
    h.check_invariants();
}

// ----- Acknowledgements -----

#[test]
fn an_ack_raises_k_only_with_the_right_to_acknowledge_and_within_c() {
    let mut h = registered();
    h.connect();
    let stream = open_of(&h.hello(E1, K1)).unwrap();
    h.collect_n(1, 1..=3);
    // No right yet: an ack past K disconnects and changes nothing.
    let store = h.stream.store().clone();
    assert_eq!(h.ack(stream, 1), [SenderAction::Disconnect]);
    assert_eq!(h.stream.store(), &store);
    assert_eq!(h.flow().acknowledged, 0);
    assert_eq!(h.stream.connection(), None);

    h.connect();
    h.hello(E1, K1);
    h.resume(stream, 0, None);
    // C is 3: past it disconnects.
    assert_eq!(h.ack(stream, 4), [SenderAction::Disconnect]);
    assert_eq!(h.flow().acknowledged, 0);

    h.connect();
    h.hello(E1, K1);
    h.resume(stream, 0, None);
    assert!(h.ack(stream, 2).is_empty());
    assert_eq!(h.flow().acknowledged, 2);
    assert_eq!(h.stream.status().entries[0].last_success, Some(h.wall));
    // Not past K, or of another stream: ignored, the connection stays.
    assert!(h.ack(stream, 2).is_empty());
    assert!(h.ack(stream, 1).is_empty());
    assert!(h.ack(Uuid::from_u128(0x99), 3).is_empty());
    assert!(h.stream.connection().is_some());
    assert_eq!(h.flow().acknowledged, 2);
    assert!(h.ack(stream, 3).is_empty());
    assert_eq!(h.flow().acknowledged, 3);
}

#[test]
fn an_ignored_ack_still_handles_the_deadlines() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.connect();
    let stream = open_of(&h.hello(E1, K1)).unwrap();
    h.collect(record(1, 1));
    h.wall = wall(100);
    // Of another stream, without the right to acknowledge: ignored, and
    // the collected record expires in the same call.
    assert!(h.ack(Uuid::from_u128(0x99), 5).is_empty());
    assert_eq!(h.stream.status().unsupported, 1);
    assert!(h.ack(stream, 0).is_empty());
    assert!(h.stream.connection().is_some());
}

#[test]
fn after_a_new_stream_on_the_same_connection_its_acks_wait_for_its_resume_info() {
    let mut h = registered();
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.collect(record(2, 1));
    h.collect(record(1, 2));
    h.close();
    h.connect();
    assert_eq!(open_of(&h.hello(E1, K1)), Some(old));
    // Step 6, then decision ②: the first record is no longer accepted.
    let actions = h.resume(old, 0, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_ne!(new, old);
    assert_eq!(h.stream.status().collected_records, 1);

    // The old stream's ack is ignored.
    assert!(h.ack(old, 2).is_empty());
    assert!(h.stream.connection().is_some());
    // The new stream's, before its resume_info, disconnects.
    let store = h.stream.store().clone();
    assert_eq!(h.ack(new, 1), [SenderAction::Disconnect]);
    assert_eq!(h.stream.store(), &store);
    assert_eq!(h.flow().acknowledged, 0);
}

#[test]
fn decision_2_sends_the_rest_from_one_on_a_new_stream() {
    let mut h = registered();
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.collect(record(2, 1));
    h.collect_n(1, 2..=3);
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    let new = open_of(&actions).unwrap();
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(seqs(&records), [1, 2]);
    assert_eq!(ns(&records), [2, 3]);
    assert!(records.iter().all(|record| record.stream == new));
    assert_eq!(h.stream.status().collected_records, 1);
}

// ----- The reconnection judgment -----

/// A sender at `E1` that sent records 1 to 3 of kind 1 on a stream and
/// is reconnected, its `open_stream` awaiting the answer.
fn three_sent() -> (H, Uuid, Vec<Sent>) {
    let mut h = registered();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    let records = sent(&h.collect_n(1, 1..=3));
    h.close();
    h.connect();
    assert_eq!(open_of(&h.hello(E1, K1)), Some(stream));
    (h, stream, records)
}

/// Answers the awaited `open_stream` with everything stored.
fn resume_all(h: &mut H, stream: Uuid, records: &[Sent]) -> Vec<SenderAction> {
    let last = records.last().unwrap();
    h.resume(stream, last.seq, Some((last.seq, record_hash(&last.bytes))))
}

/// Reconnects at `E1` with kind 1, awaiting the `open_stream`'s answer.
fn reconnect(h: &mut H) -> Vec<SenderAction> {
    h.close();
    h.connect();
    h.hello(E1, K1)
}

#[test]
fn step_2_opens_a_new_stream_when_the_entry_acknowledged_less() {
    let (mut h, stream, records) = three_sent();
    assert!(resume_all(&mut h, stream, &records).is_empty());
    assert_eq!(h.flow().acknowledged, 3);
    reconnect(&mut h);
    // A = K is no reset.
    assert!(h.resume(stream, 3, None).is_empty());
    assert_eq!(h.flow().stream, stream);
    reconnect(&mut h);
    let actions = h.resume(stream, 2, None);
    // Copy 3 is renumbered, so nothing is lost.
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let new = open_of(&actions).unwrap();
    let records = sent(&h.resume(new, 0, None));
    assert_eq!((seqs(&records), ns(&records)), (vec![1], vec![3]));
}

#[test]
fn step_3_opens_a_new_stream_when_the_entry_acknowledged_more_than_m() {
    let (mut h, stream, _) = three_sent();
    let actions = h.resume(stream, 4, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let new = open_of(&actions).unwrap();
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(
        (seqs(&records), ns(&records)),
        (vec![1, 2, 3], vec![1, 2, 3])
    );
}

#[test]
fn step_3_boundary_a_equal_to_m_resumes() {
    let (mut h, stream, records) = three_sent();
    let hash = record_hash(&records[2].bytes);
    assert!(h.resume(stream, 3, Some((3, hash))).is_empty());
    assert_eq!(h.flow().stream, stream);
    assert_eq!(h.flow().acknowledged, 3);
}

#[test]
fn step_4_compares_the_last_stored_hash_when_l_is_past_k() {
    let (mut h, stream, records) = three_sent();
    let wrong = record_hash(&records[0].bytes);
    let actions = h.resume(stream, 2, Some((2, wrong)));
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);

    // L = K skips the comparison.
    let (mut h, stream, records) = three_sent();
    let hash = record_hash(&records[0].bytes);
    h.resume(stream, 1, Some((1, hash)));
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(stream, 1, Some((1, wrong_hash())));
    assert_eq!(seqs(&sent(&actions)), [2, 3]);
    assert_eq!(h.flow().stream, stream);
}

fn wrong_hash() -> [u8; 16] {
    [0x55; 16]
}

#[test]
fn step_4_finds_the_hash_of_a_sent_record_whose_body_expired() {
    let retention = SignedDuration::from_secs(100);
    let setup = || {
        let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
        h.entries(&[E1]);
        h.stream.register(EP).unwrap();
        h.establish(E1, K1);
        let stream = h.flow().stream;
        let records = sent(&h.collect_n(1, 1..=3));
        h.close();
        h.wall = wall(100);
        h.stream.tick(h.wall, h.now).unwrap();
        assert_eq!(h.stream.status().queued_records, 0);
        assert_eq!(h.stream.core.state.ledger.len(), 3);
        h.connect();
        h.hello(E1, K1);
        (h, stream, records)
    };
    let (mut h, stream, records) = setup();
    let hash = record_hash(&records[2].bytes);
    assert!(h.resume(stream, 3, Some((3, hash))).is_empty());
    assert_eq!(h.flow().stream, stream);
    assert_eq!(h.flow().acknowledged, 3);

    let (mut h, stream, _) = setup();
    let actions = h.resume(stream, 3, Some((3, wrong_hash())));
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
}

#[test]
fn step_5_requires_every_sequence_number_after_max_l_k_to_be_dropped() {
    let (mut h, stream, _) = three_sent();
    let actions = h.resume(stream, 2, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);

    let (mut h, stream, records) = three_sent();
    let hash = record_hash(&records[0].bytes);
    let actions = h.resume(stream, 2, Some((1, hash)));
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);

    let (mut h, stream, records) = three_sent();
    let hash = record_hash(&records[1].bytes);
    let actions = h.resume(stream, 2, Some((2, hash)));
    assert_eq!(seqs(&sent(&actions)), [3]);
    assert_eq!(h.flow().stream, stream);
}

#[test]
fn step_6_resumes_from_a_plus_one() {
    let (mut h, stream, records) = three_sent();
    let hash = record_hash(&records[0].bytes);
    let actions = h.resume(stream, 1, Some((1, hash)));
    let again = sent(&actions);
    assert_eq!(seqs(&again), [2, 3]);
    assert_eq!(again, records[1..]);
    let position = h.flow();
    assert_eq!((position.acknowledged, position.sent), (1, 3));
}

#[test]
fn an_invalid_resume_info_only_disconnects_even_with_a_matching_hash() {
    for case in 0..4 {
        let (mut h, stream, records) = three_sent();
        let hash = record_hash(&records[2].bytes);
        if case == 2 {
            h.resume(stream, 0, None);
        }
        let store = h.stream.store().clone();
        let message = match case {
            // L past A.
            0 => resume_info(stream, 2, Some((3, hash))),
            // Another stream.
            1 => resume_info(Uuid::from_u128(0x77), 3, Some((3, hash))),
            // Nothing awaiting: its resume_info already arrived.
            2 => resume_info(stream, 3, Some((3, hash))),
            // Before the hello_ack.
            _ => {
                h.close();
                h.connect();
                resume_info(stream, 3, Some((3, hash)))
            }
        };
        assert_eq!(h.recv(message), [SenderAction::Disconnect], "case {case}");
        assert_eq!(h.stream.store(), &store, "case {case}");
        assert_eq!(h.flow().acknowledged, 0, "case {case}");
    }
}

// ----- Connections and the order of a call -----

#[test]
fn inputs_of_another_connection_and_invalid_messages_handle_no_deadline() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1, E2]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let stream = h.flow().stream;
    let old = h.conn();
    h.close();
    h.collect(record(1, 1));
    h.connect();
    let store = h.stream.store().clone();
    let late = wall(200);
    let now = MIN30 * 2;

    // A late answer on the connection that ended.
    let id = h.fresh_id();
    let actions = h
        .stream
        .receive(old, &resume_info(stream, 0, None), id, late, now)
        .unwrap();
    assert!(actions.is_empty());
    let actions = h
        .stream
        .hello_ack(old, &entry(E1, K1), id, late, now)
        .unwrap();
    assert!(actions.is_empty());
    assert!(h.stream.disconnected(old, late, now).unwrap().is_empty());
    assert_eq!(h.stream.store(), &store);
    assert!(h.stream.connection().is_some());

    // An invalid message on the current one: a resume_info before the
    // hello_ack.
    let conn = h.conn();
    let actions = h
        .stream
        .receive(conn, &resume_info(stream, 0, None), id, late, now)
        .unwrap();
    assert_eq!(actions, [SenderAction::Disconnect]);
    assert_eq!(h.stream.store(), &store);
    assert!(h.stream.core.state.queue.get(&1).is_some(), "not expired");
    assert_eq!(h.stream.target(), Some(E1), "not moved");

    // A hello_ack of another entry is invalid too.
    h.connect();
    let conn = h.conn();
    let actions = h
        .stream
        .hello_ack(conn, &entry(E2, K1), id, late, now)
        .unwrap();
    assert_eq!(actions, [SenderAction::Disconnect]);
    assert_eq!(h.stream.target(), Some(E1));
    assert!(h.stream.core.state.queue.get(&1).is_some());
}

#[test]
fn a_hello_ack_at_the_30_minute_mark_keeps_the_entry() {
    let mut h = H::big();
    h.entries(&[E1, E2]);
    h.connect();
    h.now = MIN30;
    let actions = h.hello(E1, K1);
    assert_eq!(h.stream.target(), Some(E1));
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    assert!(!disconnects(&actions));
}

// ----- New streams -----

#[test]
fn renumbering_keeps_the_order_and_changes_only_stream_and_seq() {
    let mut h = registered();
    h.establish(E1, K12);
    let old = h.flow().stream;
    let mut first = Vec::new();
    for (n, kind) in [(1, 1), (2, 2), (3, 1), (4, 2), (5, 1)] {
        first.extend(sent(&h.collect(record(kind, n))));
    }
    h.close();
    h.connect();
    h.hello(E1, K1);
    // Step 3: the entry claims more than M.
    let actions = h.resume(old, 9, None);
    let new = open_of(&actions).unwrap();
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(
        (seqs(&records), ns(&records)),
        (vec![1, 2, 3], vec![1, 3, 5])
    );
    for record in &records {
        let before = first.iter().find(|old| old.n == record.n).unwrap();
        let mut a = Record::from_bytes(&before.bytes).unwrap();
        let b = Record::from_bytes(&record.bytes).unwrap();
        assert_eq!(b.header.stream, new);
        a.header.stream = new;
        a.header.seq = record.seq;
        assert_eq!(a, b, "only stream and seq differ");
        assert_ne!(before.bytes, record.bytes);
        assert_eq!(
            h.stream.core.state.queue.get(&record.seq).unwrap().hash,
            record_hash(&record.bytes)
        );
    }
    assert_eq!(h.stream.status().collected_records, 2);
}

#[test]
fn a_reset_with_narrower_kinds_returns_copies_and_keeps_them_past_their_retention() {
    let hours = 240;
    let retention = SignedDuration::from_hours(hours);
    let end = hours * 3600;
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.close();
    // Collected offline, sent and acknowledged just before the end of
    // their retention.
    for (n, kind) in [(1, 2), (2, 1), (3, 2), (4, 1)] {
        h.collect(record(kind, n));
    }
    h.wall = wall(end - 10);
    h.connect();
    h.hello(E1, K12);
    assert_eq!(seqs(&sent(&h.resume(old, 0, None))), [1, 2, 3, 4]);
    h.ack(old, 4);
    // The entry loses everything; it now accepts kind 1 only.
    h.wall = wall(end - 5);
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_eq!(h.stream.status().collected_records, 2);

    // Past the retention from collection, nothing resent expires: its
    // retention started again at the reset.
    h.wall = wall(end + 1);
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(ns(&records), [2, 4]);
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (2, 0));
    assert!(h.stream.core.state.dropped.map().is_empty());

    // The list widens: the returned copies are sent.
    h.close();
    h.connect();
    h.hello(E1, K12);
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(ns(&records), [2, 4, 1, 3]);
}

#[test]
fn copies_returned_to_a_full_collection_buffer_and_deleted_there_are_lost_on_reset() {
    let mut h = H::new(SenderConfig::new(2, 1 << 40));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.collect(record(2, 1));
    h.collect(record(1, 2));
    h.ack(old, 2);
    h.close();
    h.collect(record(3, 10));
    h.collect(record(3, 11));
    assert_eq!(h.stream.status().collected_records, 2);
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    // Copy 1 went back to the full buffer, oldest there, and was deleted.
    assert_eq!(
        kinds_sent(&actions),
        ["lost_on_reset", "close_stream", "open_stream"]
    );
    assert_eq!(lost_ranges(&actions), [(1, 1)]);
    assert_eq!(lost(&actions)[0].old_stream, old);
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (2, 0));
}

#[test]
fn collected_records_moved_on_reset_make_room_for_returned_copies_before_the_limit() {
    /// Kinds 1 and 3.
    const K13: &[(u16, u16, u16)] = &[(1, 1, 1), (3, 1, 1)];
    let mut h = H::new(SenderConfig::new(2, 1 << 40));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.collect(record(2, 1));
    h.collect(record(1, 2));
    h.ack(old, 2);
    h.close();
    h.collect(record(3, 10));
    h.collect(record(3, 11));
    assert_eq!(h.stream.status().collected_records, 2);
    h.connect();
    h.hello(E1, K1);
    assert_eq!(h.stream.status().collected_records, 2);
    // No input lets the reset's call move a record already collected: the
    // hello_ack just before moves it under the old stream with the same
    // list. So the list the reset moves with is put in place here, after
    // the hello_ack's move and before the resume_info.
    h.stream
        .core
        .state
        .meta
        .accepted
        .iter_mut()
        .find(|kinds| kinds.entry == E1)
        .unwrap()
        .kinds = kinds(K13);
    let actions = h.resume(old, 0, None);
    // Copy 2 was renumbered 1 and copy 1 went back to the full buffer,
    // oldest there. Records 10 and 11 moved out first, so the limit
    // deleted nothing: copy 1 is not lost.
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    assert!(lost_ranges(&actions).is_empty());
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (1, 0));
    let collected: Vec<u64> = h
        .stream
        .core
        .state
        .collect
        .map()
        .values()
        .map(|collected| {
            let record = Record::from_bytes(&collected.bytes).unwrap();
            record.body.decode::<Body>().unwrap().n
        })
        .collect();
    assert_eq!(collected, [1]);
    let new = open_of(&actions).unwrap();
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(
        (seqs(&records), ns(&records)),
        (vec![1, 2, 3], vec![2, 10, 11])
    );
    assert!(records.iter().all(|record| record.stream == new));
    h.check_invariants();

    // The list widens: the copy kept in the buffer is sent next.
    h.close();
    h.connect();
    h.hello(E1, &[(1, 1, 1), (2, 1, 1), (3, 1, 1)]);
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(
        (seqs(&records), ns(&records)),
        (vec![1, 2, 3, 4], vec![2, 10, 11, 1])
    );
}

#[test]
fn a_returned_copy_kept_by_the_collection_buffer_is_not_lost_on_reset() {
    let mut h = H::new(SenderConfig::new(2, 1 << 40));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.collect(record(3, 10));
    h.establish(E1, K12);
    let old = h.flow().stream;
    h.collect(record(2, 1));
    h.collect(record(1, 2));
    h.ack(old, 2);
    h.close();
    h.collect(record(3, 11));
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    // The older record 10 was deleted instead, as unsupported.
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let status = h.stream.status();
    assert_eq!((status.collected_records, status.unsupported), (2, 1));
}

#[test]
fn a_renumbered_copy_dropped_by_the_queue_limit_is_reported_once() {
    let len = len_of(record(1, 1));
    let mut h = H::new(SenderConfig::new(100, 1 << 40));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let old = h.flow().stream;
    h.collect_n(1, 1..=3);
    h.ack(old, 3);
    h.close();
    // Restarted with room for two records: the copies stay until the
    // queue next fills.
    let mut h = H {
        stream: SenderStream::open(
            h.stream.store().clone(),
            SenderConfig::new(100, 2 * len),
            h.now,
        )
        .unwrap(),
        ..h.restart()
    };
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    // The three copies were renumbered 1 to 3, and 1 was dropped for the
    // limit: reported by the new stream alone.
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
    let new = open_of(&actions).unwrap();
    let actions = h.resume(new, 0, None);
    assert_eq!(drops(&actions), [(1, 1, DropReason::BufferOverflow)]);
    assert_eq!(ns(&sent(&actions)), [2, 3]);
}

#[test]
fn a_record_stored_then_expired_and_acknowledged_at_step_6_is_lost_without_a_copy() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let old = h.flow().stream;
    let records = sent(&h.collect_n(1, 1..=3));
    h.close();
    h.wall = wall(100);
    h.stream.tick(h.wall, h.now).unwrap();
    h.connect();
    h.hello(E1, K1);
    let hash = record_hash(&records[2].bytes);
    assert!(h.resume(old, 3, Some((3, hash))).is_empty());
    assert!(h.stream.core.state.dropped.map().is_empty());
    assert!(h.stream.core.state.announced.map().is_empty());
    h.collect(record(1, 4));
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 1, None);
    assert_eq!(lost_ranges(&actions), [(2, 3)]);
    let new = open_of(&actions).unwrap();
    assert_eq!(ns(&sent(&h.resume(new, 0, None))), [4]);
}

#[test]
fn announced_losses_are_left_out_of_lost_on_reset() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let old = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=2);
    h.wall = wall(50);
    h.collect(record(1, 3));
    h.wall = wall(100);
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    assert_eq!(drops(&actions), [(1, 2, DropReason::RetentionExpired)]);
    h.ack(old, 3);
    h.close();
    h.connect();
    h.hello(E1, K1);
    // Copy 3 is renumbered and 1-2 were announced: nothing is lost.
    let actions = h.resume(old, 0, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);

    // Everything announced: nothing is lost either.
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let old = h.flow().stream;
    h.close();
    h.collect_n(1, 1..=3);
    h.wall = wall(100);
    h.connect();
    h.hello(E1, K1);
    h.resume(old, 0, None);
    h.ack(old, 3);
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    assert_eq!(kinds_sent(&actions), ["close_stream", "open_stream"]);
}

#[test]
fn many_lost_ranges_split_into_frames_within_64_kib_the_same_every_time() {
    let retention = SignedDuration::from_secs(100);
    let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
    h.entries(&[E1]);
    h.stream.register(EP).unwrap();
    h.establish(E1, K1);
    let old = h.flow().stream;
    h.close();
    // Odd records expire and are announced; even ones are acknowledged,
    // and their copies expire too.
    let total: u64 = 30_000;
    for n in 1..=total {
        h.wall = if n % 2 == 1 { wall(0) } else { wall(50) };
        h.collect(record(1, n));
    }
    h.wall = wall(100);
    h.connect();
    h.hello(E1, K1);
    h.resume(old, 0, None);
    let mut k = 0;
    while k < total {
        k = (k + engine::WINDOW).min(total);
        h.ack(old, k);
    }
    assert_eq!(h.flow().acknowledged, total);
    h.advance(24 * 3600);
    h.close();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 0, None);
    let notices = lost(&actions);
    assert_eq!(notices.len(), 8);
    let ranges = lost_ranges(&actions);
    let expected: Vec<(u64, u64)> = (1..=total / 2).map(|i| (2 * i, 2 * i)).collect();
    assert_eq!(ranges, expected);
    for message in &notices {
        let frame = TelemetryMessage::LostOnReset(message.clone())
            .to_frame()
            .unwrap();
        assert!(frame.payload().len() <= usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap());
    }

    // The same messages on the next connection, and after a restart.
    let before: Vec<TelemetryMessage> = messages(&actions);
    h.close();
    h.connect();
    assert_eq!(messages(&h.hello(E1, K1)), before);
    let mut restarted = h.restart();
    restarted.connect();
    assert_eq!(messages(&restarted.hello(E1, K1)), before);
}

#[test]
fn the_widest_lost_on_reset_fits_a_frame() {
    let ranges = vec![
        SeqRange {
            from: u64::MAX,
            to: u64::MAX
        };
        engine::LOST_RANGES_PER_MESSAGE
    ];
    let message = TelemetryMessage::LostOnReset(LostOnReset {
        old_stream: Uuid::from_u128(u128::MAX),
        ranges,
    });
    let frame = message.to_frame().unwrap();
    assert!(frame.payload().len() <= usize::try_from(SERVER_OTHER_RECEIVE_LIMIT).unwrap());
}

#[test]
fn a_reset_at_the_same_entry_carries_dropped_sequence_numbers_past_k() {
    let retention = SignedDuration::from_secs(100);
    let setup = || {
        let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
        h.entries(&[E1, E2]);
        h.stream.register(EP).unwrap();
        h.establish(E1, K1);
        let old = h.flow().stream;
        h.close();
        h.collect(record(1, 1));
        h.wall = wall(50);
        h.collect(record(1, 2));
        h.wall = wall(100);
        h.stream.tick(h.wall, h.now).unwrap();
        assert_eq!(h.stream.status().dropped_ranges, 1);
        (h, old)
    };
    let (mut h, old) = setup();
    h.connect();
    h.hello(E1, K1);
    let actions = h.resume(old, 5, None);
    assert_eq!(
        messages(&actions)[0],
        TelemetryMessage::CloseStream(CloseStream { stream: old })
    );
    let new = open_of(&actions).unwrap();
    let actions = h.resume(new, 0, None);
    assert_eq!(drops(&actions), [(1, 1, DropReason::RetentionExpired)]);
    assert_eq!(ns(&sent(&actions)), [2]);
    assert_eq!(h.stream.status().dropped_ranges, 1, "not counted again");

    // At another entry, neither.
    let (mut h, old) = setup();
    h.entries(&[E2]);
    h.connect();
    let actions = h.hello(E2, K1);
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_ne!(new, old);
    let actions = h.resume(new, 0, None);
    assert!(drops(&actions).is_empty());
    assert_eq!(
        (seqs(&sent(&actions)), ns(&sent(&actions))),
        (vec![1], vec![2])
    );
}

#[test]
fn closed_answers_open_a_new_stream_with_only_its_open_stream() {
    let (mut h, stream, _) = three_sent();
    let actions = h.recv(TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: Some(stream),
        error: TelemetryError::Closed,
    }));
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_ne!(new, stream);
    // The next connection retries with the open_stream alone.
    h.close();
    h.connect();
    let actions = h.hello(E1, K1);
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    assert_eq!(open_of(&actions), Some(new));
    let records = sent(&h.resume(new, 0, None));
    assert_eq!(
        (seqs(&records), ns(&records)),
        (vec![1, 2, 3], vec![1, 2, 3])
    );
}

#[test]
fn other_errors_only_disconnect() {
    let errors = [
        (true, None, TelemetryError::Closed),
        (true, Some(Uuid::from_u128(0x77)), TelemetryError::Closed),
        (false, Some(Uuid::nil()), TelemetryError::Closed),
        (true, Some(Uuid::nil()), TelemetryError::Gap { expected: 1 }),
        (true, Some(Uuid::nil()), TelemetryError::BadRange),
        (true, Some(Uuid::nil()), TelemetryError::UnknownStream),
        (true, None, TelemetryError::NotListed),
    ];
    for (awaiting, stream_of, error) in errors {
        let (mut h, stream, _) = three_sent();
        if !awaiting {
            h.resume(stream, 0, None);
        }
        let store = h.stream.store().clone();
        let stream_of = stream_of.map(|id| if id.is_nil() { stream } else { id });
        let actions = h.recv(TelemetryMessage::ErrorMessage(ErrorMessage {
            stream: stream_of,
            error: error.clone(),
        }));
        assert_eq!(actions, [SenderAction::Disconnect], "{error:?}");
        assert_eq!(h.stream.store(), &store);
        assert_eq!(h.flow().stream, stream);
    }
}

#[test]
fn notices_go_before_every_open_stream_until_its_resume_info() {
    let (mut h, old, records) = three_sent();
    resume_all(&mut h, old, &records);
    // The copies expire before the reset.
    h.advance(24 * 3600);
    reconnect(&mut h);
    let actions = h.resume(old, 1, None);
    assert_eq!(
        kinds_sent(&actions),
        ["lost_on_reset", "close_stream", "open_stream"]
    );
    assert_eq!(lost_ranges(&actions), [(2, 3)]);
    let notices = messages(&actions);
    let new = open_of(&actions).unwrap();
    for _ in 0..2 {
        assert_eq!(messages(&reconnect(&mut h)), notices);
    }
    h.resume(new, 0, None);
    assert_eq!(kinds_sent(&reconnect(&mut h)), ["open_stream"]);
}

// ----- Node moves and entries -----

#[test]
fn the_target_moves_after_30_minutes_without_a_hello_ack() {
    let mut h = H::big();
    assert_eq!(
        h.entries(&[E1, E2, E3]),
        [SenderAction::Connect { entry_id: E1 }]
    );
    // Failed attempts do not restart the 30 minutes.
    for minute in [0, 10, 20] {
        h.now = Duration::from_secs(minute * 60);
        h.connect();
        h.close();
    }
    h.connect();
    let now = MIN30 - Duration::from_nanos(1);
    assert!(h.stream.tick(h.wall, now).unwrap().is_empty());
    assert_eq!(h.stream.target(), Some(E1));
    let actions = h.stream.tick(h.wall, MIN30).unwrap();
    assert_eq!(
        actions,
        [
            SenderAction::Disconnect,
            SenderAction::Connect { entry_id: E2 }
        ]
    );
    assert_eq!(h.stream.target(), Some(E2));
    h.stream.tick(h.wall, MIN30 * 2).unwrap();
    assert_eq!(h.stream.target(), Some(E3));
    // After the last comes the first.
    let actions = h.stream.tick(h.wall, MIN30 * 3).unwrap();
    assert_eq!(actions, [SenderAction::Connect { entry_id: E1 }]);
}

#[test]
fn a_connection_with_a_hello_ack_keeps_the_target_until_it_ends() {
    let mut h = H::big();
    h.entries(&[E1, E2]);
    h.connect();
    h.hello(E1, K1);
    let two_hours = Duration::from_secs(7200);
    assert!(h.stream.tick(h.wall, two_hours).unwrap().is_empty());
    h.now = two_hours;
    h.close();
    h.stream
        .tick(h.wall, two_hours + MIN30 - Duration::from_nanos(1))
        .unwrap();
    assert_eq!(h.stream.target(), Some(E1));
    h.stream.tick(h.wall, two_hours + MIN30).unwrap();
    assert_eq!(h.stream.target(), Some(E2));
}

#[test]
fn a_new_list_without_the_target_moves_to_its_first_entry() {
    let mut h = H::big();
    h.entries(&[E1, E2]);
    h.connect();
    assert!(h.entries(&[E3, E1]).is_empty());
    assert_eq!(h.stream.target(), Some(E1));
    assert!(h.stream.connection().is_some());
    let actions = h.entries(&[E2, E3]);
    assert_eq!(
        actions,
        [
            SenderAction::Disconnect,
            SenderAction::Connect { entry_id: E2 }
        ]
    );
    assert_eq!(h.stream.target(), Some(E2));
    assert!(h.entries(&[]).is_empty());
    assert_eq!(h.stream.target(), None);
    assert_eq!(h.stream.connect(h.wall, h.now).unwrap().connection, None);
}

#[test]
fn a_new_entry_identity_opens_a_new_stream_with_the_unacknowledged_records_only() {
    let mut h = registered();
    h.entries(&[E1, E2]);
    h.establish(E1, K1);
    let old = h.flow().stream;
    h.collect_n(1, 1..=3);
    h.ack(old, 1);
    h.entries(&[E2]);
    h.connect();
    let actions = h.hello(E2, K1);
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_eq!(h.stream.status().queued_records, 2, "the copy is gone");
    let actions = h.resume(new, 0, None);
    let records = sent(&actions);
    assert_eq!((seqs(&records), ns(&records)), (vec![1, 2], vec![2, 3]));
    assert!(records.iter().all(|record| record.stream == new));
    let position = h.flow();
    assert_eq!((position.stream, position.entry_id), (new, E2));
}

#[test]
fn back_at_the_first_entry_before_the_other_hello_ack_the_stream_carries_on() {
    let mut h = registered();
    h.entries(&[E1, E2]);
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.close();
    h.now = MIN30;
    h.stream.tick(h.wall, h.now).unwrap();
    assert_eq!(h.stream.target(), Some(E2));
    // Not moved while the target is another entry.
    h.collect(record(1, 1));
    assert_eq!(h.stream.status().collected_records, 1);
    h.connect();
    h.close();
    h.now = MIN30 * 2;
    h.stream.tick(h.wall, h.now).unwrap();
    assert_eq!(h.stream.target(), Some(E1));
    assert_eq!(h.stream.status().collected_records, 0, "moved again");
    h.connect();
    let actions = h.hello(E1, K1);
    assert_eq!(open_of(&actions), Some(stream));
    assert_eq!(seqs(&sent(&h.resume(stream, 0, None))), [1]);
}

#[test]
fn back_at_the_first_entry_after_the_other_hello_ack_a_new_stream_opens() {
    let mut h = registered();
    h.entries(&[E1, E2]);
    h.establish(E1, K1);
    let first = h.flow().stream;
    h.collect_n(1, 1..=2);
    h.close();
    h.now = MIN30;
    h.stream.tick(h.wall, h.now).unwrap();
    h.connect();
    let second = open_of(&h.hello(E2, K1)).unwrap();
    assert_eq!(h.flow().entry_id, E2);
    h.close();
    h.now = MIN30 * 2;
    h.stream.tick(h.wall, h.now).unwrap();
    assert_eq!(h.stream.target(), Some(E1));
    h.connect();
    let third = open_of(&h.hello(E1, K1)).unwrap();
    assert!(third != first && third != second);
    let records = sent(&h.resume(third, 0, None));
    assert_eq!((seqs(&records), ns(&records)), (vec![1, 2], vec![1, 2]));
}

// ----- Status -----

#[test]
fn the_status_reports_the_last_success_per_entry_and_the_counts() {
    let mut h = registered();
    h.entries(&[E1, E2]);
    h.establish(E1, K1);
    let stream = h.flow().stream;
    h.collect_n(1, 1..=2);
    h.collect(record(2, 3));
    h.ack(stream, 1);
    let at = h.wall;
    let status = h.stream.status();
    assert_eq!(
        status.entries,
        [
            SenderEntryStatus {
                entry_id: E1,
                last_success: Some(at)
            },
            SenderEntryStatus {
                entry_id: E2,
                last_success: None
            }
        ]
    );
    let len = len_of(record(1, 1));
    assert_eq!(status.collected_records, 1);
    assert_eq!(status.queued_records, 2);
    assert_eq!(status.queued_bytes, 2 * len);
    assert_eq!((status.dropped_ranges, status.unsupported), (0, 0));

    // It outlives a change of entry identity.
    h.entries(&[E2, E1]);
    h.close();
    h.now = MIN30;
    h.stream.tick(h.wall, h.now).unwrap();
    assert_eq!(h.stream.target(), Some(E2));
    h.connect();
    h.hello(E2, K1);
    assert_eq!(h.flow().entry_id, E2);
    let status = h.stream.status();
    assert_eq!(status.entries[0].last_success, None);
    assert_eq!(status.entries[1].last_success, Some(at));
}

// ----- Persistence -----

#[test]
fn a_restarted_sender_keeps_its_target_id_and_stream_and_moves_with_the_last_list() {
    let mut h = registered();
    h.entries(&[E1, E2]);
    h.establish(E1, K12);
    let stream = h.flow().stream;
    h.collect_n(1, 1..=2);
    let mut h = h.restart();
    assert_eq!(h.stream.target(), Some(E1));
    assert_eq!(h.stream.endpoint_id(), Some(EP));
    assert_eq!(h.stream.connection(), None);
    h.collect(record(2, 3));
    assert_eq!(h.flow().assigned, 3, "moved with the last verified list");
    h.connect();
    assert_eq!(open_of(&h.hello(E1, K12)), Some(stream));
    let records = sent(&h.resume(stream, 0, None));
    assert_eq!(ns(&records), [1, 2, 3]);
}

#[test]
fn a_restarted_sender_decides_as_before() {
    let (mut h, old, records) = three_sent();
    resume_all(&mut h, old, &records);
    h.advance(24 * 3600);
    h.close();
    let mut restarted = h.restart();
    for h in [&mut h, &mut restarted] {
        h.connect();
        h.hello(E1, K1);
    }
    let a = h.resume(old, 1, None);
    let b = restarted.resume(old, 1, None);
    assert_eq!(a, b);
    assert_eq!(lost_ranges(&a), [(2, 3)]);
    assert_eq!(h.stream.store(), restarted.stream.store());
}

#[test]
fn an_empty_store_opens_a_new_stream_at_the_first_hello_ack() {
    let mut h = registered();
    h.connect();
    let actions = h.hello(E1, K1);
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    assert_eq!(h.flow().assigned, 0);
}

#[test]
fn records_left_without_sequence_state_are_renumbered_by_the_next_stream() {
    let mut h = registered();
    h.establish(E1, K12);
    let old = h.flow().stream;
    let first = sent(&h.collect(record(1, 1)));
    let second = sent(&h.collect(record(2, 2)));
    let third = sent(&h.collect(record(1, 3)));
    h.close();
    let leftovers: Vec<SenderRecovered> = [&first, &second, &third]
        .into_iter()
        .map(|records| SenderRecovered {
            bytes: records[0].bytes.clone(),
            retained_since: wall(0),
        })
        .collect();
    let stream = SenderStream::recover(
        h.stream.store().clone(),
        SenderConfig::new(100, 1 << 40),
        leftovers,
        h.now,
    )
    .unwrap();
    let mut h = H {
        stream,
        ..h.restart()
    };
    assert_eq!(h.stream.position(), None);
    assert_eq!(h.stream.endpoint_id(), Some(EP));
    h.connect();
    let actions = h.hello(E1, K1);
    assert_eq!(kinds_sent(&actions), ["open_stream"]);
    let new = open_of(&actions).unwrap();
    assert_ne!(new, old);
    let records = sent(&h.resume(new, 0, None));
    assert_eq!((seqs(&records), ns(&records)), (vec![1, 2], vec![1, 3]));
    assert_eq!(h.stream.status().collected_records, 1);
}

#[test]
fn the_stored_entries_round_trip_through_cbor() {
    let (mut h, old, _) = three_sent();
    h.collect(record(2, 9));
    let actions = h.resume(old, 1, None);
    let new = open_of(&actions).unwrap();
    h.resume(new, 0, None);
    h.ack(new, 2);
    let mut kinds: Vec<_> = h
        .stream
        .store()
        .entries()
        .keys()
        .map(|key| std::mem::discriminant(&key.0))
        .collect();
    kinds.dedup();
    assert!(kinds.len() >= 5, "{kinds:?}");
    for (key, entry) in h.stream.store().entries() {
        let key_bytes = cbor::to_vec(key).unwrap();
        let entry_bytes = cbor::to_vec(entry).unwrap();
        assert_eq!(
            &cbor::from_slice::<SenderStateKey>(&key_bytes).unwrap(),
            key
        );
        assert_eq!(
            &cbor::from_slice::<SenderStateEntry>(&entry_bytes).unwrap(),
            entry
        );
    }
}

#[test]
fn a_commit_writes_only_what_the_call_changed() {
    let (mut h, stream, _) = three_sent();
    h.resume(stream, 0, None);
    let mut recorder = Recorder::default();
    std::mem::swap(&mut recorder.inner, h.stream.store_mut());
    let mut stream =
        SenderStream::open(recorder, SenderConfig::new(100_000, 1 << 40), h.now).unwrap();
    stream.collect(record(1, 4), h.wall, h.now).unwrap();
    let change = stream.store().last.clone().unwrap();
    let queued = change
        .puts()
        .iter()
        .filter(|(key, _)| matches!(key.0, store::Key::Queued(_)))
        .count();
    assert_eq!(queued, 1, "only the new record's bytes");
}

#[derive(Default)]
struct Recorder {
    inner: MemorySenderStore,
    last: Option<SenderStateChange>,
}

impl SenderStore for Recorder {
    fn load(&self) -> Result<Vec<(SenderStateKey, SenderStateEntry)>, SenderStoreError> {
        self.inner.load()
    }

    fn commit(&mut self, change: &SenderStateChange) -> Result<(), SenderStoreError> {
        self.last = Some(change.clone());
        self.inner.commit(change)
    }
}

/// Runs `call` once as reference, and once after a failed attempt.
fn check_atomic(
    setup: impl Fn() -> H,
    call: impl Fn(&mut H) -> Result<Vec<SenderAction>, SenderError>,
) {
    let mut reference = setup();
    let expected = call(&mut reference).unwrap();

    let mut h = setup();
    let core = format!("{:?}", h.stream.core);
    let entries = h.stream.store().entries().clone();
    h.stream.store_mut().fail_next_commits(1);
    let error = call(&mut h).unwrap_err();
    assert!(matches!(error, SenderError::Store(_)), "{error:?}");
    assert_eq!(format!("{:?}", h.stream.core), core);
    assert_eq!(h.stream.store().entries(), &entries);

    assert_eq!(call(&mut h).unwrap(), expected);
    assert_eq!(
        format!("{:?}", h.stream.core),
        format!("{:?}", reference.stream.core)
    );
    assert_eq!(
        h.stream.store().entries(),
        reference.stream.store().entries()
    );
}

const NEW: Uuid = Uuid::from_u128(0x7777);

#[test]
fn every_state_changing_call_is_undone_when_its_write_fails() {
    let retention = SignedDuration::from_secs(100);
    // Sent 1-3 at E1, acknowledged 1, one record waiting offline with its
    // retention due at 100 s, and reconnected awaiting resume_info.
    let base = || {
        let mut h = H::new(SenderConfig::new(100, 1 << 40).with_retention(retention));
        h.entries(&[E1, E2]);
        h.stream.register(EP).unwrap();
        h.establish(E1, K1);
        let stream = h.flow().stream;
        h.collect_n(1, 1..=3);
        h.ack(stream, 1);
        h.close();
        h.collect(record(1, 4));
        h.collect(record(2, 5));
        h.connect();
        h
    };
    let late = wall(100);
    let stream = base().flow().stream;
    let hello = |h: &mut H| {
        let conn = h.conn();
        h.stream.hello_ack(conn, &entry(E1, K1), NEW, late, h.now)
    };

    check_atomic(base, |h| h.stream.collect(record(1, 6), late, h.now));
    check_atomic(base, |h| h.stream.tick(late, h.now));
    check_atomic(base, |h| h.stream.tick(h.wall, MIN30));
    check_atomic(base, |h| h.stream.set_entries(vec![E2], late, h.now));
    check_atomic(base, |h| {
        h.stream
            .connect(late, MIN30)
            .map(|connected| connected.actions)
    });
    check_atomic(base, |h| {
        let conn = h.conn();
        h.stream.disconnected(conn, late, h.now)
    });
    check_atomic(base, hello);
    check_atomic(base, |h| {
        let conn = h.conn();
        h.stream
            .hello_ack(conn, &entry(E1, K12), NEW, h.wall, h.now)
    });
    let greeted = || {
        let mut h = base();
        hello(&mut h).unwrap();
        h
    };
    let receive = |message: TelemetryMessage| {
        move |h: &mut H| {
            let conn = h.conn();
            h.stream.receive(conn, &message, NEW, late, h.now)
        }
    };
    check_atomic(greeted, receive(resume_info(stream, 1, None)));
    check_atomic(greeted, receive(resume_info(stream, 0, None)));
    check_atomic(greeted, receive(resume_info(stream, 9, None)));
    check_atomic(
        greeted,
        receive(TelemetryMessage::ErrorMessage(ErrorMessage {
            stream: Some(stream),
            error: TelemetryError::Closed,
        })),
    );
    let resumed = || {
        let mut h = greeted();
        let conn = h.conn();
        h.stream
            .receive(conn, &resume_info(stream, 1, None), NEW, h.wall, h.now)
            .unwrap();
        h
    };
    check_atomic(
        resumed,
        receive(TelemetryMessage::Ack(Ack { stream, a: 3 })),
    );

    // Registration moving records, and a new entry identity.
    let unregistered = || {
        let mut h = H::big();
        h.entries(&[E1]);
        h.establish(E1, K1);
        h.collect_n(1, 1..=2);
        h
    };
    check_atomic(unregistered, |h| h.stream.register(EP));
    let moved = || {
        let mut h = base();
        h.entries(&[E2]);
        h.connect();
        h
    };
    check_atomic(moved, |h| {
        let conn = h.conn();
        h.stream.hello_ack(conn, &entry(E2, K1), NEW, h.wall, h.now)
    });
}

#[test]
fn a_failed_recovery_writes_nothing() {
    let mut store = MemorySenderStore::new();
    store.fail_next_commits(1);
    let leftovers = vec![SenderRecovered {
        bytes: record(1, 1).to_bytes().unwrap(),
        retained_since: wall(0),
    }];
    let error = SenderStream::recover(
        &mut store,
        SenderConfig::new(10, 1 << 20),
        leftovers,
        Duration::ZERO,
    )
    .unwrap_err();
    assert!(matches!(error, SenderError::Store(_)));
    assert!(store.entries().is_empty());
    let garbage = vec![SenderRecovered {
        bytes: vec![0xff],
        retained_since: wall(0),
    }];
    let error = SenderStream::recover(
        &mut store,
        SenderConfig::new(10, 1 << 20),
        garbage,
        Duration::ZERO,
    )
    .unwrap_err();
    assert!(matches!(error, SenderError::Recovered { index: 0, .. }));
}

#[test]
fn a_store_holding_something_else_is_refused() {
    let mut store = MemorySenderStore::new();
    let change = SenderStateChange {
        puts: vec![(
            SenderStateKey(store::Key::Queued(1)),
            SenderStateEntry(store::Entry::Announced(3)),
        )],
        removes: Vec::new(),
    };
    store.commit(&change).unwrap();
    let error = SenderStream::open(store, SenderConfig::new(10, 10), Duration::ZERO).unwrap_err();
    assert!(matches!(error, SenderError::Corrupt { .. }));
}
