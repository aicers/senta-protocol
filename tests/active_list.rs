//! The active list, its lease and the standing it gives endpoints, driven
//! through the public API.
#![cfg(feature = "auth")]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ciborium::Value;
use senta_protocol::auth::active_list::{
    ActiveList, Admission, ApplyError, ConnectionChange, ConnectionId, DEFAULT_LEASE_LENGTH,
    EndpointIdentity, EntryState, Lease, LicenseRestriction, ListEntry, ListUpdate, OperatorStatus,
    Standing, allowed,
};
use senta_protocol::connection::{ConnectionKind, DecodeErrorKind, cbor};
use senta_protocol::standing::SuspendReason;
use senta_protocol::telemetry_codes::TelemetryError;
use uuid::Uuid;

const MINUTE: Duration = Duration::from_secs(60);
const NANO: Duration = Duration::from_nanos(1);

fn spki(n: u8) -> [u8; 32] {
    [n; 32]
}

fn endpoint_id(n: u8) -> Uuid {
    Uuid::from_u128(u128::from(n))
}

fn customer_id(n: u8) -> Uuid {
    Uuid::from_u128(0x1000 + u128::from(n))
}

fn identity(n: u8) -> Option<EndpointIdentity> {
    Some(EndpointIdentity {
        endpoint_id: endpoint_id(n),
        customer_endpoint_id: customer_id(n),
    })
}

/// The entry of endpoint `n`, whose key is `spki(n)`.
fn entry(n: u8, state: EntryState) -> ListEntry {
    ListEntry {
        endpoint_id: endpoint_id(n),
        spki_sha256: spki(n),
        customer_endpoint_id: customer_id(n),
        state,
    }
}

fn active(n: u8) -> ListEntry {
    entry(n, EntryState::Active)
}

fn suspended(reason: SuspendReason) -> EntryState {
    EntryState::Suspended { reason }
}

fn full(version: u64, entries: Vec<ListEntry>) -> ListUpdate {
    ListUpdate::Full { version, entries }
}

fn diff(base_version: u64, version: u64, upserts: Vec<ListEntry>, removals: &[u8]) -> ListUpdate {
    ListUpdate::Diff {
        base_version,
        version,
        upserts,
        removals: removals.iter().map(|n| endpoint_id(*n)).collect(),
    }
}

fn conn(n: u64) -> ConnectionId {
    ConnectionId(n)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn at(minutes: u64) -> Duration {
    MINUTE * u32::try_from(minutes).unwrap()
}

/// Everything a refused update must leave as it was.
#[derive(Debug, PartialEq)]
struct Snapshot {
    version: Option<u64>,
    deadline: Option<Duration>,
    entries: Vec<ListEntry>,
    connections: Vec<ConnectionId>,
}

fn snapshot(list: &ActiveList) -> Snapshot {
    let mut entries: Vec<ListEntry> = list.entries().cloned().collect();
    entries.sort_unstable_by_key(|entry| entry.endpoint_id);
    let mut connections: Vec<ConnectionId> = list.connections().collect();
    connections.sort_unstable();
    Snapshot {
        version: list.version(),
        deadline: list.lease_deadline(),
        entries,
        connections,
    }
}

fn standing(list: &ActiveList, n: u8, now: Duration) -> Standing {
    list.standing(&spki(n), now).standing
}

/// Registers connection `n` from key `spki(n)`, expecting nothing back.
fn register(list: &mut ActiveList, n: u8, now: Duration) {
    let outcome = list.register(conn(u64::from(n)), &spki(n), ip("192.0.2.1"), now);
    assert_eq!(outcome.expired, None);
    assert_eq!(outcome.replaced, None);
}

/// A list leased for the default length, with `entries` applied at zero as
/// version 1.
fn leased(entries: Vec<ListEntry>) -> ActiveList {
    let mut list = ActiveList::new(Some(Lease::default()));
    list.apply(full(1, entries), Duration::ZERO).result.unwrap();
    list
}

fn unleased(entries: Vec<ListEntry>) -> ActiveList {
    let mut list = ActiveList::new(None);
    list.apply(full(1, entries), Duration::ZERO).result.unwrap();
    list
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

fn uuid_value(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

fn entry_value(n: u8, state: Value) -> Value {
    map(vec![
        ("endpoint_id", uuid_value(endpoint_id(n))),
        ("spki_sha256", Value::Bytes(spki(n).to_vec())),
        ("customer_endpoint_id", uuid_value(customer_id(n))),
        ("state", state),
    ])
}

fn to_value(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

// ---- Combining the operator's and the license's say ----

#[test]
fn combine_orders_by_strength() {
    use LicenseRestriction as L;
    use OperatorStatus as O;

    let revoked = suspended(SuspendReason::Revoked);
    let operator = suspended(SuspendReason::Operator);
    for (op, license, expected) in [
        (O::Revoked, L::None, revoked.clone()),
        (O::Revoked, L::Pending, revoked.clone()),
        (O::Revoked, L::Suspended, revoked),
        (O::Suspended, L::None, operator.clone()),
        (O::Suspended, L::Pending, operator.clone()),
        (O::Suspended, L::Suspended, operator),
        (O::Active, L::None, EntryState::Active),
        (O::Active, L::Pending, EntryState::LicensePending),
        (O::Active, L::Suspended, suspended(SuspendReason::License)),
    ] {
        assert_eq!(
            EntryState::combine(op, license),
            expected,
            "{op:?} + {license:?}"
        );
    }
}

// ---- The CBOR shape ----

#[test]
fn entries_round_trip_with_each_state() {
    for (state, value) in [
        (EntryState::Active, text("active")),
        (EntryState::LicensePending, text("license_pending")),
        (
            suspended(SuspendReason::Revoked),
            map(vec![("suspended", map(vec![("reason", text("revoked"))]))]),
        ),
        (
            suspended(SuspendReason::Operator),
            map(vec![("suspended", map(vec![("reason", text("operator"))]))]),
        ),
        (
            suspended(SuspendReason::License),
            map(vec![("suspended", map(vec![("reason", text("license"))]))]),
        ),
    ] {
        let entry = entry(3, state);
        let bytes = cbor::to_vec(&entry).unwrap();
        assert_eq!(to_value(&bytes), entry_value(3, value));
        assert_eq!(cbor::from_slice::<ListEntry>(&bytes).unwrap(), entry);
    }
}

#[test]
fn full_and_diff_round_trip() {
    let update = full(
        7,
        vec![active(1), entry(2, suspended(SuspendReason::Operator))],
    );
    let bytes = update.encode().unwrap();
    assert_eq!(
        to_value(&bytes),
        map(vec![(
            "full",
            map(vec![
                ("version", Value::from(7)),
                (
                    "entries",
                    Value::Array(vec![
                        entry_value(1, text("active")),
                        entry_value(
                            2,
                            map(vec![("suspended", map(vec![("reason", text("operator"))]))])
                        ),
                    ])
                ),
            ])
        )])
    );
    assert_eq!(ListUpdate::decode(&bytes).unwrap(), update);

    let update = diff(7, 8, vec![entry(3, EntryState::LicensePending)], &[1, 2]);
    let bytes = update.encode().unwrap();
    assert_eq!(
        to_value(&bytes),
        map(vec![(
            "diff",
            map(vec![
                ("base_version", Value::from(7)),
                ("version", Value::from(8)),
                (
                    "upserts",
                    Value::Array(vec![entry_value(3, text("license_pending"))])
                ),
                (
                    "removals",
                    Value::Array(vec![uuid_value(endpoint_id(1)), uuid_value(endpoint_id(2))])
                ),
            ])
        )])
    );
    assert_eq!(ListUpdate::decode(&bytes).unwrap(), update);
}

#[test]
fn unknown_fields_are_ignored() {
    let mut entry = entry_value(
        1,
        map(vec![(
            "suspended",
            map(vec![("reason", text("license")), ("since", Value::from(5))]),
        )]),
    );
    if let Value::Map(fields) = &mut entry {
        fields.push((text("hostname"), text("host-1")));
    }
    let value = map(vec![(
        "diff",
        map(vec![
            ("base_version", Value::from(1)),
            ("version", Value::from(2)),
            ("upserts", Value::Array(vec![entry])),
            ("removals", Value::Array(vec![])),
            ("pushed_by", text("review")),
        ]),
    )]);
    assert_eq!(
        ListUpdate::decode(&encode(&value)).unwrap(),
        diff(
            1,
            2,
            vec![self::entry(1, suspended(SuspendReason::License))],
            &[]
        )
    );
}

#[test]
fn an_unknown_reason_decodes_as_other() {
    let value = entry_value(
        1,
        map(vec![(
            "suspended",
            map(vec![("reason", text("quarantine"))]),
        )]),
    );
    assert_eq!(
        cbor::from_slice::<ListEntry>(&encode(&value)).unwrap(),
        entry(1, suspended(SuspendReason::Other("quarantine".to_owned())))
    );
}

#[test]
fn malformed_updates_fail_to_decode() {
    let with_spki = |bytes: Vec<u8>| {
        map(vec![(
            "full",
            map(vec![
                ("version", Value::from(1)),
                (
                    "entries",
                    Value::Array(vec![map(vec![
                        ("endpoint_id", uuid_value(endpoint_id(1))),
                        ("spki_sha256", Value::Bytes(bytes)),
                        ("customer_endpoint_id", uuid_value(customer_id(1))),
                        ("state", text("active")),
                    ])]),
                ),
            ]),
        )])
    };
    assert!(ListUpdate::decode(&encode(&with_spki(vec![1; 32]))).is_ok());
    for len in [31, 33] {
        assert_eq!(
            ListUpdate::decode(&encode(&with_spki(vec![1; len])))
                .unwrap_err()
                .kind(),
            DecodeErrorKind::Invalid,
            "{len} bytes"
        );
    }

    let duplicate = Value::Map(vec![(
        text("full"),
        Value::Map(vec![
            (text("version"), Value::from(1)),
            (text("version"), Value::from(2)),
            (text("entries"), Value::Array(vec![])),
        ]),
    )]);
    assert_eq!(
        ListUpdate::decode(&encode(&duplicate)).unwrap_err().kind(),
        DecodeErrorKind::DuplicateKey
    );

    for state in [text("quarantined"), map(vec![("quarantined", map(vec![]))])] {
        let value = map(vec![(
            "full",
            map(vec![
                ("version", Value::from(1)),
                ("entries", Value::Array(vec![entry_value(1, state.clone())])),
            ]),
        )]);
        assert_eq!(
            ListUpdate::decode(&encode(&value)).unwrap_err().kind(),
            DecodeErrorKind::Invalid,
            "{state:?}"
        );
    }
}

// ---- Applying updates ----

#[test]
fn a_new_list_is_unready_until_a_full_list() {
    let mut list = ActiveList::new(Some(Lease::default()));
    assert!(!list.is_ready());
    assert_eq!(list.version(), None);
    for n in [1, 2, 3] {
        let judged = list.standing(&spki(n), Duration::ZERO);
        assert_eq!(judged.standing, Standing::Unready);
        assert_eq!(judged.identity, None);
    }

    let applied = list
        .apply(
            full(
                4,
                vec![
                    active(1),
                    entry(2, EntryState::LicensePending),
                    entry(3, suspended(SuspendReason::Revoked)),
                ],
            ),
            MINUTE,
        )
        .result
        .unwrap();
    assert_eq!(applied.version, 4);
    assert!(list.is_ready());
    assert_eq!(list.version(), Some(4));
    assert_eq!(standing(&list, 1, MINUTE), Standing::Active);
    assert_eq!(standing(&list, 2, MINUTE), Standing::LicensePending);
    assert_eq!(
        standing(&list, 3, MINUTE),
        Standing::Suspended {
            reason: SuspendReason::Revoked
        }
    );
    assert_eq!(standing(&list, 4, MINUTE), Standing::NotListed);
}

#[test]
fn a_diff_needs_the_version_applied() {
    let mut list = ActiveList::new(Some(Lease::default()));
    register(&mut list, 1, Duration::ZERO);
    let before = snapshot(&list);
    let outcome = list.apply(diff(0, 1, vec![active(1)], &[]), MINUTE);
    assert_eq!(outcome.expired, None);
    assert_eq!(
        outcome.result,
        Err(ApplyError::VersionMismatch {
            base_version: 0,
            current: None
        })
    );
    assert_eq!(snapshot(&list), before);
    assert_eq!(standing(&list, 1, MINUTE), Standing::Unready);

    list.apply(full(5, vec![active(1)]), MINUTE).result.unwrap();
    let before = snapshot(&list);
    for base in [4, 6] {
        let outcome = list.apply(diff(base, 9, vec![active(2)], &[1]), at(2));
        assert_eq!(outcome.expired, None);
        assert_eq!(
            outcome.result,
            Err(ApplyError::VersionMismatch {
                base_version: base,
                current: Some(5)
            })
        );
        assert_eq!(snapshot(&list), before);
    }

    let applied = list
        .apply(diff(5, 9, vec![active(2)], &[1]), at(2))
        .result
        .unwrap();
    assert_eq!(applied.version, 9);
    assert_eq!(list.version(), Some(9));
    assert_eq!(standing(&list, 1, at(2)), Standing::NotListed);
    assert_eq!(standing(&list, 2, at(2)), Standing::Active);
}

#[test]
fn a_diff_out_of_step_reports_the_version_however_malformed() {
    let other = || entry(1, suspended(SuspendReason::Other("quarantine".to_owned())));
    let malformed = |base| {
        [
            diff(base, base, vec![active(3)], &[]),
            diff(base, base.saturating_sub(1), vec![active(3)], &[]),
            diff(base, 9, vec![other()], &[]),
            diff(base, 9, vec![active(3), active(3)], &[]),
            diff(base, 9, vec![active(3)], &[3]),
        ]
    };

    let mut list = ActiveList::new(Some(Lease::default()));
    register(&mut list, 1, Duration::ZERO);
    let before = snapshot(&list);
    for update in malformed(0) {
        let ListUpdate::Diff { base_version, .. } = update else {
            unreachable!("every case is a diff");
        };
        let outcome = list.apply(update.clone(), MINUTE);
        assert_eq!(outcome.expired, None, "{update:?}");
        assert_eq!(
            outcome.result,
            Err(ApplyError::VersionMismatch {
                base_version,
                current: None
            }),
            "{update:?}"
        );
        assert_eq!(snapshot(&list), before, "{update:?}");
    }

    list.apply(full(5, vec![active(1), active(2)]), MINUTE)
        .result
        .unwrap();
    let before = snapshot(&list);
    for update in malformed(4).into_iter().chain(malformed(7)) {
        let ListUpdate::Diff { base_version, .. } = update else {
            unreachable!("every case is a diff");
        };
        let outcome = list.apply(update.clone(), at(2));
        assert_eq!(outcome.expired, None, "{update:?}");
        assert_eq!(
            outcome.result,
            Err(ApplyError::VersionMismatch {
                base_version,
                current: Some(5)
            }),
            "{update:?}"
        );
        assert_eq!(snapshot(&list), before, "{update:?}");
    }
}

#[test]
fn a_full_list_applies_whatever_its_version() {
    let mut list = leased(vec![active(1)]);
    list.apply(full(10, vec![active(1)]), MINUTE)
        .result
        .unwrap();
    let applied = list.apply(full(3, vec![active(2)]), at(2)).result.unwrap();
    assert_eq!(applied.version, 3);
    assert_eq!(list.version(), Some(3));
    assert_eq!(standing(&list, 1, at(2)), Standing::NotListed);
    assert_eq!(standing(&list, 2, at(2)), Standing::Active);
}

#[test]
fn malformed_updates_change_nothing() {
    let other = || entry(9, suspended(SuspendReason::Other("quarantine".to_owned())));
    let other_one = || entry(1, suspended(SuspendReason::Other("quarantine".to_owned())));
    let mut moved = active(4);
    moved.spki_sha256 = spki(2);
    let mut twice = active(3);
    twice.spki_sha256 = spki(4);
    let cases = [
        (
            full(9, vec![active(1), other()]),
            ApplyError::UnknownReason {
                endpoint_id: endpoint_id(9),
            },
        ),
        (
            diff(1, 2, vec![other_one()], &[]),
            ApplyError::UnknownReason {
                endpoint_id: endpoint_id(1),
            },
        ),
        (
            full(9, vec![active(1), active(1)]),
            ApplyError::RepeatedEndpoint {
                endpoint_id: endpoint_id(1),
            },
        ),
        (
            full(9, {
                let mut same_id = active(2);
                same_id.endpoint_id = endpoint_id(1);
                vec![active(1), same_id]
            }),
            ApplyError::RepeatedEndpoint {
                endpoint_id: endpoint_id(1),
            },
        ),
        (
            full(9, vec![active(2), moved.clone()]),
            ApplyError::DuplicateSpki {
                first: endpoint_id(2),
                second: endpoint_id(4),
            },
        ),
        // An upsert taking the key of an entry the diff leaves alone.
        (
            diff(1, 2, vec![moved], &[]),
            ApplyError::DuplicateSpki {
                first: endpoint_id(2),
                second: endpoint_id(4),
            },
        ),
        // Two upserts with one key.
        (
            diff(1, 2, vec![active(4), twice], &[]),
            ApplyError::DuplicateSpki {
                first: endpoint_id(4),
                second: endpoint_id(3),
            },
        ),
        (
            diff(1, 1, vec![active(3)], &[]),
            ApplyError::VersionNotAdvanced {
                base_version: 1,
                version: 1,
            },
        ),
        (
            diff(1, 0, vec![active(3)], &[]),
            ApplyError::VersionNotAdvanced {
                base_version: 1,
                version: 0,
            },
        ),
        (
            diff(1, 2, vec![active(3), active(3)], &[]),
            ApplyError::RepeatedEndpoint {
                endpoint_id: endpoint_id(3),
            },
        ),
        (
            diff(1, 2, vec![active(3)], &[3]),
            ApplyError::RepeatedEndpoint {
                endpoint_id: endpoint_id(3),
            },
        ),
    ];
    for (update, error) in cases {
        let mut list = leased(vec![active(1), active(2)]);
        register(&mut list, 1, Duration::ZERO);
        register(&mut list, 2, Duration::ZERO);
        let before = snapshot(&list);
        let outcome = list.apply(update.clone(), MINUTE);
        assert_eq!(outcome.expired, None, "{update:?}");
        assert_eq!(outcome.result, Err(error), "{update:?}");
        assert_eq!(snapshot(&list), before, "{update:?}");
        assert_eq!(standing(&list, 1, MINUTE), Standing::Active);
    }
}

#[test]
fn a_diff_may_hand_a_released_key_on() {
    // Entry 2 is removed and entry 4 takes its key; entry 1 moves to a new
    // key and entry 3 takes its old one.
    let mut list = unleased(vec![active(1), active(2)]);
    let mut takes_two = active(4);
    takes_two.spki_sha256 = spki(2);
    let mut one_moves = active(1);
    one_moves.spki_sha256 = spki(5);
    let mut takes_one = active(3);
    takes_one.spki_sha256 = spki(1);
    list.apply(
        diff(1, 2, vec![takes_two, one_moves, takes_one], &[2]),
        MINUTE,
    )
    .result
    .unwrap();
    assert_eq!(list.standing(&spki(2), MINUTE).identity, identity(4));
    assert_eq!(
        list.standing(&spki(5), MINUTE)
            .identity
            .map(|id| id.endpoint_id),
        Some(endpoint_id(1))
    );
    assert_eq!(
        list.standing(&spki(1), MINUTE)
            .identity
            .map(|id| id.endpoint_id),
        Some(endpoint_id(3))
    );
}

#[test]
fn removing_an_unknown_endpoint_is_ignored() {
    let mut list = unleased(vec![active(1), active(2)]);
    let applied = list
        .apply(diff(1, 2, vec![active(3)], &[2, 8]), MINUTE)
        .result
        .unwrap();
    assert_eq!(applied.version, 2);
    assert_eq!(standing(&list, 1, MINUTE), Standing::Active);
    assert_eq!(standing(&list, 2, MINUTE), Standing::NotListed);
    assert_eq!(standing(&list, 3, MINUTE), Standing::Active);
}

#[test]
fn applied_updates_return_the_connections_they_change() {
    let mut list = leased(vec![
        active(1),
        active(2),
        active(3),
        entry(4, EntryState::LicensePending),
    ]);
    for n in 1..=5 {
        register(&mut list, n, Duration::ZERO);
    }
    let applied = list
        .apply(
            diff(
                1,
                2,
                vec![entry(1, suspended(SuspendReason::Operator)), active(5)],
                &[2],
            ),
            MINUTE,
        )
        .result
        .unwrap();
    assert_eq!(
        applied.changes,
        vec![
            ConnectionChange {
                connection: conn(1),
                standing: Standing::Suspended {
                    reason: SuspendReason::Operator
                },
                identity: identity(1),
                close: false,
            },
            ConnectionChange {
                connection: conn(2),
                standing: Standing::NotListed,
                identity: None,
                close: true,
            },
            ConnectionChange {
                connection: conn(5),
                standing: Standing::Active,
                identity: identity(5),
                close: false,
            },
        ]
    );

    // A full list judges every connection the same way.
    let applied = list
        .apply(
            full(3, vec![active(1), active(3), entry(4, EntryState::Active)]),
            at(2),
        )
        .result
        .unwrap();
    assert_eq!(
        applied.changes,
        vec![
            ConnectionChange {
                connection: conn(1),
                standing: Standing::Active,
                identity: identity(1),
                close: false,
            },
            ConnectionChange {
                connection: conn(4),
                standing: Standing::Active,
                identity: identity(4),
                close: false,
            },
            ConnectionChange {
                connection: conn(5),
                standing: Standing::NotListed,
                identity: None,
                close: true,
            },
        ]
    );
}

#[test]
fn the_first_full_list_reports_every_connection_it_lists() {
    let mut list = ActiveList::new(None);
    register(&mut list, 1, Duration::ZERO);
    register(&mut list, 2, Duration::ZERO);
    let applied = list.apply(full(1, vec![active(1)]), MINUTE).result.unwrap();
    assert_eq!(
        applied.changes,
        vec![
            ConnectionChange {
                connection: conn(1),
                standing: Standing::Active,
                identity: identity(1),
                close: false,
            },
            ConnectionChange {
                connection: conn(2),
                standing: Standing::NotListed,
                identity: None,
                close: false,
            },
        ]
    );
}

#[test]
fn a_key_change_closes_the_old_key_connection() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, Duration::ZERO);
    register(&mut list, 2, Duration::ZERO);
    let mut rekeyed = active(1);
    rekeyed.spki_sha256 = spki(2);
    let applied = list
        .apply(diff(1, 2, vec![rekeyed], &[]), MINUTE)
        .result
        .unwrap();
    assert_eq!(
        applied.changes,
        vec![
            ConnectionChange {
                connection: conn(1),
                standing: Standing::NotListed,
                identity: None,
                close: true,
            },
            ConnectionChange {
                connection: conn(2),
                standing: Standing::Active,
                identity: identity(1),
                close: false,
            },
        ]
    );
}

#[test]
fn a_key_moving_to_another_endpoint_closes_its_connection() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, Duration::ZERO);
    let mut other = active(2);
    other.spki_sha256 = spki(1);
    let applied = list.apply(full(2, vec![other]), MINUTE).result.unwrap();
    assert_eq!(
        applied.changes,
        vec![ConnectionChange {
            connection: conn(1),
            standing: Standing::Active,
            identity: identity(2),
            close: true,
        }]
    );

    let outcome = list.register(conn(10), &spki(1), ip("192.0.2.1"), at(2));
    assert_eq!(outcome.replaced, Some(conn(1)));
    assert_eq!(list.standing(&spki(1), at(2)).identity, identity(2));
}

#[test]
fn a_customer_id_change_closes_the_connection() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, Duration::ZERO);
    let mut renamed = active(1);
    renamed.customer_endpoint_id = customer_id(9);
    let applied = list
        .apply(diff(1, 2, vec![renamed], &[]), MINUTE)
        .result
        .unwrap();
    assert_eq!(
        applied.changes,
        vec![ConnectionChange {
            connection: conn(1),
            standing: Standing::Active,
            identity: Some(EndpointIdentity {
                endpoint_id: endpoint_id(1),
                customer_endpoint_id: customer_id(9),
            }),
            close: true,
        }]
    );
}

#[test]
fn the_standing_carries_the_matched_ids() {
    let mut list = ActiveList::new(Some(Lease::default()));
    assert_eq!(list.standing(&spki(1), Duration::ZERO).identity, None);
    list.apply(
        full(
            1,
            vec![active(1), entry(2, suspended(SuspendReason::License))],
        ),
        Duration::ZERO,
    )
    .result
    .unwrap();
    assert_eq!(list.standing(&spki(1), MINUTE).identity, identity(1));
    assert_eq!(list.standing(&spki(2), MINUTE).identity, identity(2));
    assert_eq!(list.standing(&spki(3), MINUTE).identity, None);
    // An expired lease hides the standing, not the ids.
    let expired = list.standing(&spki(1), DEFAULT_LEASE_LENGTH);
    assert_eq!(expired.standing, Standing::LeaseExpired);
    assert_eq!(expired.identity, identity(1));
}

// ---- Connections with the same key ----

#[test]
fn a_connection_with_the_same_key_replaces_the_open_one() {
    let mut list = unleased(vec![active(1)]);
    // Listed and unlisted keys alike.
    for key in [1, 2] {
        let first = conn(u64::from(key) * 10);
        let second = conn(u64::from(key) * 10 + 1);
        let third = conn(u64::from(key) * 10 + 2);
        let outcome = list.register(first, &spki(key), ip("192.0.2.1"), MINUTE);
        assert_eq!(outcome.replaced, None);
        let outcome = list.register(second, &spki(key), ip("192.0.2.1"), MINUTE);
        assert_eq!(outcome.replaced, Some(first));
        assert_eq!(outcome.duplicate_key, None);

        assert!(!list.remove(first), "the replaced connection is forgotten");
        assert!(list.connections().any(|id| id == second));
        let outcome = list.register(third, &spki(key), ip("192.0.2.1"), at(2));
        assert_eq!(outcome.replaced, Some(second));
        assert!(list.remove(third));
        assert!(!list.connections().any(|id| id == third));
    }
}

/// Registers connections 1, 2, ... from one key at the given times and
/// addresses, and returns each registration's duplicate key report.
fn replace(
    list: &mut ActiveList,
    key: u8,
    registrations: &[(Duration, IpAddr)],
) -> Vec<Option<senta_protocol::auth::active_list::DuplicateKey>> {
    registrations
        .iter()
        .zip(1..)
        .map(|((now, address), n)| {
            list.register(conn(n), &spki(key), *address, *now)
                .duplicate_key
        })
        .collect()
}

#[test]
fn three_replacements_from_two_addresses_are_a_duplicate_key() {
    let a = ip("192.0.2.1");
    let b = ip("198.51.100.7");
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(1), b), (at(2), a), (at(9), b)],
    );
    assert_eq!(reports[..3], [None, None, None]);
    let report = reports[3].clone().unwrap();
    assert_eq!(report.spki_sha256, spki(1));
    assert_eq!(report.endpoint_id, Some(endpoint_id(1)));
    assert_eq!(report.addresses, vec![a, b]);
    assert_eq!(report.replacements, 3);

    // An unlisted key carries no endpoint id.
    let mut list = unleased(vec![]);
    let reports = replace(
        &mut list,
        2,
        &[(at(0), a), (at(1), b), (at(2), a), (at(3), a)],
    );
    assert_eq!(reports[3].as_ref().unwrap().endpoint_id, None);
}

#[test]
fn fewer_replacements_or_one_address_are_no_duplicate_key() {
    let a = ip("192.0.2.1");
    let b = ip("198.51.100.7");

    let mut list = unleased(vec![active(1)]);
    let reports = replace(&mut list, 1, &[(at(0), a), (at(1), b), (at(2), a)]);
    assert!(reports.iter().all(Option::is_none), "two replacements");

    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(1), a), (at(2), a), (at(3), a)],
    );
    assert!(reports.iter().all(Option::is_none), "one address");

    // The first replacement, at one minute, is exactly ten minutes before
    // the third.
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(1), b), (at(5), a), (at(11), b)],
    );
    assert!(reports.iter().all(Option::is_none), "ten minutes apart");
    // A nanosecond less, and it counts.
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(1), b), (at(5), a), (at(11) - NANO, b)],
    );
    assert_eq!(reports[3].as_ref().unwrap().replacements, 3);
}

#[test]
fn only_the_port_differing_is_one_address() {
    let first: SocketAddr = "192.0.2.1:50000".parse().unwrap();
    let second: SocketAddr = "192.0.2.1:50001".parse().unwrap();
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[
            (at(0), first.ip()),
            (at(1), second.ip()),
            (at(2), first.ip()),
            (at(3), second.ip()),
        ],
    );
    assert!(reports.iter().all(Option::is_none));

    // An IPv4 address mapped into IPv6 is that IPv4 address.
    let mapped = ip("::ffff:192.0.2.1");
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[
            (at(0), first.ip()),
            (at(1), mapped),
            (at(2), mapped),
            (at(3), mapped),
        ],
    );
    assert!(reports.iter().all(Option::is_none));
}

#[test]
fn later_replacements_count_only_the_last_ten_minutes() {
    let a = ip("192.0.2.1");
    let b = ip("198.51.100.7");

    // The fourth replacement, at eleven minutes, counts only the third and
    // itself.
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(0), b), (at(1), a), (at(2), b), (at(11), a)],
    );
    assert!(reports[3].is_some());
    assert_eq!(reports[4], None);

    // The other address was only in the first replacement; the three left
    // are from one address.
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), b), (at(1), a), (at(2), a), (at(3), a), (at(11), a)],
    );
    assert_eq!(reports[3].as_ref().unwrap().addresses, vec![a, b]);
    assert_eq!(reports[4], None);

    // Three within the window from two addresses report again.
    let mut list = unleased(vec![active(1)]);
    let reports = replace(
        &mut list,
        1,
        &[(at(0), a), (at(1), b), (at(2), a), (at(3), b), (at(4), a)],
    );
    assert_eq!(reports[3].as_ref().unwrap().replacements, 3);
    assert_eq!(reports[4].as_ref().unwrap().replacements, 4);
}

// ---- The lease ----

#[test]
fn only_a_confirmation_of_the_version_applied_extends_the_lease() {
    let mut list = ActiveList::new(Some(Lease::default()));
    let outcome = list.confirm(0, MINUTE);
    assert!(!outcome.extended);
    assert_eq!(outcome.expired, None);
    assert_eq!(list.lease_deadline(), None);

    list.apply(full(4, vec![active(1)]), Duration::ZERO)
        .result
        .unwrap();
    assert_eq!(list.lease_deadline(), Some(DEFAULT_LEASE_LENGTH));
    for version in [3, 5] {
        let outcome = list.confirm(version, at(10));
        assert!(!outcome.extended);
        assert_eq!(list.lease_deadline(), Some(DEFAULT_LEASE_LENGTH));
    }
    let outcome = list.confirm(4, at(10));
    assert!(outcome.extended);
    assert_eq!(outcome.expired, None);
    assert_eq!(list.lease_deadline(), Some(at(10) + DEFAULT_LEASE_LENGTH));
}

#[test]
fn a_full_list_starts_the_lease_and_a_diff_does_not_extend_it() {
    let mut list = ActiveList::new(Some(Lease::default()));
    list.apply(full(1, vec![active(1)]), at(5)).result.unwrap();
    assert_eq!(list.lease_deadline(), Some(at(35)));
    list.apply(diff(1, 2, vec![active(2)], &[]), at(20))
        .result
        .unwrap();
    assert_eq!(list.lease_deadline(), Some(at(35)));
    assert_eq!(standing(&list, 2, at(35) - NANO), Standing::Active);
    assert_eq!(standing(&list, 2, at(35)), Standing::LeaseExpired);
    list.apply(full(1, vec![active(1)]), at(40)).result.unwrap();
    assert_eq!(list.lease_deadline(), Some(at(70)));
}

#[test]
fn the_lease_expires_at_its_length_once() {
    for length in [DEFAULT_LEASE_LENGTH, at(45)] {
        let mut list = ActiveList::new(Some(Lease::new(length)));
        list.apply(full(1, vec![active(1), active(2)]), Duration::ZERO)
            .result
            .unwrap();
        register(&mut list, 1, MINUTE);
        register(&mut list, 3, MINUTE);
        assert_eq!(list.check_lease(length - NANO), None);
        assert_eq!(standing(&list, 1, length - NANO), Standing::Active);
        assert_eq!(list.check_lease(length), Some(vec![conn(1), conn(3)]));
        assert_eq!(list.check_lease(length), None);
        assert_eq!(list.check_lease(length + MINUTE), None);
        // Expired connections stay registered until the caller removes
        // them.
        let mut open: Vec<_> = list.connections().collect();
        open.sort_unstable();
        assert_eq!(open, vec![conn(1), conn(3)]);
    }
}

#[test]
fn extending_just_before_the_deadline_keeps_connections_open() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    let outcome = list.confirm(1, DEFAULT_LEASE_LENGTH - NANO);
    assert!(outcome.extended);
    assert_eq!(outcome.expired, None);
    assert_eq!(list.check_lease(DEFAULT_LEASE_LENGTH), None);
    assert_eq!(standing(&list, 1, DEFAULT_LEASE_LENGTH), Standing::Active);
}

#[test]
fn a_confirmation_after_the_deadline_delivers_the_expiry_first() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    register(&mut list, 2, MINUTE);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    let outcome = list.confirm(1, late);
    assert_eq!(outcome.expired, Some(vec![conn(1), conn(2)]));
    assert!(outcome.extended);
    assert_eq!(list.lease_deadline(), Some(late + DEFAULT_LEASE_LENGTH));
    assert_eq!(list.check_lease(late), None);

    let outcome = list.register(conn(3), &spki(1), ip("192.0.2.1"), late);
    assert_eq!(outcome.expired, None);
    assert_eq!(standing(&list, 1, late), Standing::Active);
}

#[test]
fn a_confirmation_of_another_version_after_the_deadline_delivers_the_expiry() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    let before = snapshot(&list);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    let outcome = list.confirm(2, late);
    assert_eq!(outcome.expired, Some(vec![conn(1)]));
    assert!(!outcome.extended);
    assert_eq!(snapshot(&list), before);
    assert_eq!(standing(&list, 1, late), Standing::LeaseExpired);
    assert_eq!(list.check_lease(late), None);
}

#[test]
fn a_full_list_after_the_deadline_delivers_the_expiry_first() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    register(&mut list, 2, MINUTE);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    let outcome = list.apply(full(2, vec![active(2)]), late);
    assert_eq!(outcome.expired, Some(vec![conn(1), conn(2)]));
    let applied = outcome.result.unwrap();
    assert_eq!(applied.changes, vec![]);
    assert_eq!(list.lease_deadline(), Some(late + DEFAULT_LEASE_LENGTH));
    assert_eq!(list.check_lease(late), None);

    register(&mut list, 4, late);
    assert_eq!(standing(&list, 2, late), Standing::Active);
    assert_eq!(standing(&list, 4, late), Standing::NotListed);
}

#[test]
fn a_refused_full_list_after_the_deadline_delivers_the_expiry() {
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    let before = snapshot(&list);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    let outcome = list.apply(full(2, vec![active(2), active(2)]), late);
    assert_eq!(outcome.expired, Some(vec![conn(1)]));
    assert!(outcome.result.is_err());
    assert_eq!(snapshot(&list), before);
    assert_eq!(standing(&list, 1, late), Standing::LeaseExpired);
    assert_eq!(list.check_lease(late), None);
}

#[test]
fn a_diff_after_the_deadline_delivers_the_expiry_and_leaves_the_lease() {
    let late = DEFAULT_LEASE_LENGTH + MINUTE;

    // Applied: the diff changes connection 1's entry, and still connection
    // 1 is only in the expiry.
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    register(&mut list, 2, MINUTE);
    let outcome = list.apply(diff(1, 2, vec![active(2)], &[1]), late);
    assert_eq!(outcome.expired, Some(vec![conn(1), conn(2)]));
    assert_eq!(outcome.result.unwrap().changes, vec![]);
    assert_eq!(list.version(), Some(2));
    assert_eq!(list.lease_deadline(), Some(DEFAULT_LEASE_LENGTH));
    assert_eq!(standing(&list, 2, late), Standing::LeaseExpired);

    // Refused for its base version.
    let mut list = leased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    let before = snapshot(&list);
    let outcome = list.apply(diff(7, 8, vec![active(2)], &[]), late);
    assert_eq!(outcome.expired, Some(vec![conn(1)]));
    assert!(matches!(
        outcome.result,
        Err(ApplyError::VersionMismatch { .. })
    ));
    assert_eq!(snapshot(&list), before);
    assert_eq!(standing(&list, 1, late), Standing::LeaseExpired);
}

#[test]
fn a_registration_after_the_deadline_delivers_the_connections_before_it() {
    let mut list = leased(vec![active(1), active(2)]);
    register(&mut list, 1, MINUTE);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    let outcome = list.register(conn(2), &spki(2), ip("192.0.2.1"), late);
    assert_eq!(outcome.expired, Some(vec![conn(1)]));
    assert_eq!(standing(&list, 2, late), Standing::LeaseExpired);
    assert_eq!(list.check_lease(late + MINUTE), None);

    assert!(list.confirm(1, late + MINUTE).extended);
    assert_eq!(standing(&list, 2, late + MINUTE), Standing::Active);
}

#[test]
fn an_expired_lease_refuses_active_endpoints_until_extended() {
    let mut list = leased(vec![active(1)]);
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    assert_eq!(list.check_lease(DEFAULT_LEASE_LENGTH), Some(vec![]));
    assert_eq!(standing(&list, 1, late), Standing::LeaseExpired);
    assert_eq!(standing(&list, 2, late), Standing::LeaseExpired);
    assert!(list.confirm(1, late).extended);
    assert_eq!(standing(&list, 1, late), Standing::Active);
    assert_eq!(standing(&list, 2, late), Standing::NotListed);
}

#[test]
fn a_full_list_renewing_the_lease_reports_connections_opened_while_expired() {
    let mut list = leased(vec![active(1), active(2)]);
    register(&mut list, 1, MINUTE);
    assert_eq!(list.check_lease(DEFAULT_LEASE_LENGTH), Some(vec![conn(1)]));
    let late = DEFAULT_LEASE_LENGTH + MINUTE;
    register(&mut list, 2, late);
    assert_eq!(standing(&list, 2, late), Standing::LeaseExpired);

    // Connection 1 was returned by the expiry and is in no change;
    // connection 2, opened while expired, is taken again.
    let outcome = list.apply(full(2, vec![active(1), active(2)]), late);
    assert_eq!(outcome.expired, None);
    assert_eq!(
        outcome.result.unwrap().changes,
        vec![ConnectionChange {
            connection: conn(2),
            standing: Standing::Active,
            identity: identity(2),
            close: false,
        }]
    );
    assert_eq!(standing(&list, 2, late), Standing::Active);
}

#[test]
fn a_second_expiry_returns_only_connections_not_already_returned() {
    let mut list = leased(vec![active(1), active(2)]);
    register(&mut list, 1, MINUTE);
    assert_eq!(list.check_lease(DEFAULT_LEASE_LENGTH), Some(vec![conn(1)]));
    let renewed = DEFAULT_LEASE_LENGTH + MINUTE;
    assert!(list.confirm(1, renewed).extended);
    register(&mut list, 2, renewed);
    assert_eq!(
        list.check_lease(renewed + DEFAULT_LEASE_LENGTH),
        Some(vec![conn(2)])
    );
}

#[test]
fn without_a_lease_the_list_never_expires() {
    let mut list = unleased(vec![active(1)]);
    register(&mut list, 1, MINUTE);
    let much_later = Duration::from_secs(10 * 365 * 24 * 60 * 60);
    assert_eq!(list.lease_deadline(), None);
    assert_eq!(list.check_lease(much_later), None);
    assert!(!list.confirm(1, much_later).extended);
    assert_eq!(standing(&list, 1, much_later), Standing::Active);
    assert_eq!(standing(&list, 2, much_later), Standing::NotListed);
}

// ---- What a standing lets an endpoint send ----

const CONTROL_KINDS: [&str; 15] = [
    "hello",
    "hello_ack",
    "ping",
    "pong",
    "unsupported",
    "enroll_request",
    "enroll_result_poll",
    "unenroll",
    "enroll_result",
    "status_report",
    "documents",
    "document_ack",
    "command",
    "command_result",
    "suspend_notice",
];

const OTHER_KINDS: [&str; 4] = ["record_batch", "open_stream", "error", "no_such_message"];

fn standings() -> [Standing; 6] {
    [
        Standing::Unready,
        Standing::LeaseExpired,
        Standing::NotListed,
        Standing::LicensePending,
        Standing::Suspended {
            reason: SuspendReason::Revoked,
        },
        Standing::Active,
    ]
}

#[test]
fn allowed_follows_the_table() {
    for standing in standings() {
        let permitted: Option<&[&str]> = match standing {
            Standing::NotListed => Some(&[
                "hello",
                "ping",
                "pong",
                "enroll_request",
                "enroll_result_poll",
            ]),
            Standing::LicensePending => Some(&[
                "hello",
                "ping",
                "pong",
                "status_report",
                "enroll_result_poll",
                "unenroll",
            ]),
            Standing::Suspended { .. } => {
                Some(&["hello", "ping", "pong", "status_report", "unenroll"])
            }
            _ => None,
        };
        let telemetry = match standing {
            Standing::Unready => Admission::Close,
            Standing::LeaseExpired => Admission::ErrorThenClose(TelemetryError::LeaseExpired),
            Standing::NotListed | Standing::LicensePending => {
                Admission::ErrorThenClose(TelemetryError::NotListed)
            }
            Standing::Suspended { .. } => Admission::ErrorThenClose(TelemetryError::Suspended),
            Standing::Active => Admission::Accept,
        };
        for t in CONTROL_KINDS.iter().chain(&OTHER_KINDS) {
            let control = match (&standing, permitted) {
                (Standing::Active, _) => Admission::Accept,
                (Standing::Unready | Standing::LeaseExpired, _) => Admission::Close,
                (_, Some(permitted)) if permitted.contains(t) => Admission::Accept,
                _ => Admission::Unsupported,
            };
            assert_eq!(
                allowed(&standing, ConnectionKind::Control, t),
                control,
                "{standing:?} control {t}"
            );
            assert_eq!(
                allowed(&standing, ConnectionKind::Telemetry, t),
                telemetry,
                "{standing:?} telemetry {t}"
            );
        }
    }
}

#[test]
fn only_a_suspended_control_endpoint_is_sent_a_notice() {
    for standing in standings() {
        let expected = match &standing {
            Standing::Suspended { reason } => Some(reason),
            _ => None,
        };
        assert_eq!(
            standing.suspend_notice(ConnectionKind::Control),
            expected,
            "{standing:?}"
        );
        assert_eq!(standing.suspend_notice(ConnectionKind::Telemetry), None);
    }
    let operator = Standing::Suspended {
        reason: SuspendReason::Operator,
    };
    assert_eq!(
        operator.suspend_notice(ConnectionKind::Control),
        Some(&SuspendReason::Operator)
    );
}

#[test]
fn only_an_active_endpoint_may_send_large_frames() {
    for standing in standings() {
        let expected = if standing == Standing::Active {
            4_194_304
        } else {
            65_536
        };
        assert_eq!(standing.receive_limit(), expected, "{standing:?}");
    }
}

// ---- On the server connection helper ----

#[cfg(feature = "telemetry")]
mod on_the_connection_helper {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ciborium::Value;
    use jiff::Timestamp;
    use senta_protocol::auth::active_list::{ActiveList, EntryState, Lease, allowed};
    use senta_protocol::connection::{
        CloseReason, ConnectionKind, Envelope, Frame, Hello, HelloAck, Message,
        SERVER_OTHER_RECEIVE_LIMIT, ServerAction, ServerChannel, ServerConfig, ServerConnection,
        Unsupported, VersionRange,
    };
    use senta_protocol::standing::SuspendReason;
    use senta_protocol::telemetry::{ErrorMessage, TELEMETRY_MESSAGE_KINDS};
    use senta_protocol::telemetry_codes::TelemetryError;
    use uuid::Uuid;

    use super::{DEFAULT_LEASE_LENGTH, MINUTE, active, diff, entry, full, ip, spki};

    const CONTROL_KINDS: [&str; 4] = [
        "enroll_request",
        "enroll_result_poll",
        "status_report",
        "unenroll",
    ];

    fn wall() -> Timestamp {
        Timestamp::from_second(1_700_000_000).unwrap()
    }

    fn hello() -> Frame {
        Frame::from_message(&Hello {
            crate_version: "0.1.0".to_owned(),
            versions: VersionRange::default(),
            sent_at: wall(),
        })
        .unwrap()
    }

    fn message(t: &str) -> Frame {
        Frame::new(t, &Value::Map(vec![])).unwrap()
    }

    /// The list shared between the test and the standing check, with the
    /// monotonic time the check judges at.
    #[derive(Clone)]
    struct Shared {
        list: Arc<Mutex<ActiveList>>,
        now: Arc<Mutex<Duration>>,
    }

    impl Shared {
        fn new(list: ActiveList) -> Self {
            Self {
                list: Arc::new(Mutex::new(list)),
                now: Arc::new(Mutex::new(MINUTE)),
            }
        }

        fn set_now(&self, now: Duration) {
            *self.now.lock().unwrap() = now;
        }

        fn server(&self, port: ConnectionKind, key: u8) -> ServerConnection {
            let channel = match port {
                ConnectionKind::Control => ServerChannel::Control,
                ConnectionKind::Telemetry => ServerChannel::Telemetry {
                    entry_id: Uuid::from_u128(0xe),
                    accepted_kinds: vec![],
                },
            };
            let known: Vec<&str> = match port {
                ConnectionKind::Control => CONTROL_KINDS.to_vec(),
                ConnectionKind::Telemetry => TELEMETRY_MESSAGE_KINDS.to_vec(),
            };
            let shared = self.clone();
            let config = ServerConfig::new(channel, SERVER_OTHER_RECEIVE_LIMIT)
                .with_known_kinds(known)
                .with_standing(move |t| {
                    let now = *shared.now.lock().unwrap();
                    let standing = shared.list.lock().unwrap().standing(&spki(key), now);
                    allowed(&standing.standing, port, t).to_standing_verdict()
                });
            ServerConnection::new(config, Duration::ZERO)
        }
    }

    fn receive(server: &mut ServerConnection, frame: &Frame) -> Vec<ServerAction> {
        server.receive(frame.as_bytes(), wall(), MINUTE)
    }

    /// Asserts that `actions` send the telemetry `error { error }`,
    /// without `stream`, and close.
    fn assert_error_then_close(actions: &[ServerAction], error: &TelemetryError) {
        let [ServerAction::SendThenClose { frame, .. }] = actions else {
            panic!("expected an error and a close, got {actions:?}");
        };
        let envelope = Envelope::parse(frame.payload()).unwrap();
        assert_eq!(envelope.t(), ErrorMessage::T);
        let body: Value = envelope.body().decode().unwrap();
        let Value::Map(fields) = body else {
            panic!("expected a map, got {body:?}");
        };
        let keys: Vec<&Value> = fields.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, [&Value::Text("error".to_owned())], "no stream");
        let decoded: ErrorMessage = envelope.body().decode().unwrap();
        assert_eq!(decoded.stream, None);
        assert_eq!(&decoded.error, error);
    }

    fn established(server: &mut ServerConnection) {
        let actions = receive(server, &hello());
        let Some(ServerAction::Send(ack)) = actions.first() else {
            panic!("expected a hello_ack, got {actions:?}");
        };
        let envelope = Envelope::parse(ack.payload()).unwrap();
        assert_eq!(envelope.t(), HelloAck::T);
        assert!(matches!(actions.get(1), Some(ServerAction::Handshake(_))));
        assert!(server.is_established());
    }

    fn sample_list() -> ActiveList {
        let mut list = ActiveList::new(Some(Lease::default()));
        list.apply(
            full(
                1,
                vec![
                    active(1),
                    entry(2, EntryState::LicensePending),
                    entry(
                        3,
                        EntryState::Suspended {
                            reason: SuspendReason::Operator,
                        },
                    ),
                ],
            ),
            Duration::ZERO,
        )
        .result
        .unwrap();
        list
    }

    #[test]
    fn a_refused_telemetry_hello_gets_its_error_and_no_ack() {
        let shared = Shared::new(sample_list());
        for (key, error) in [
            (4, TelemetryError::NotListed),
            (2, TelemetryError::NotListed),
            (3, TelemetryError::Suspended),
        ] {
            let mut server = shared.server(ConnectionKind::Telemetry, key);
            let actions = receive(&mut server, &hello());
            assert_error_then_close(&actions, &error);
            assert!(server.is_closed());
        }

        let mut server = shared.server(ConnectionKind::Telemetry, 1);
        established(&mut server);

        shared.set_now(DEFAULT_LEASE_LENGTH);
        let mut server = shared.server(ConnectionKind::Telemetry, 1);
        let actions = receive(&mut server, &hello());
        assert_error_then_close(&actions, &TelemetryError::LeaseExpired);
    }

    #[test]
    fn an_unready_list_closes_without_a_word() {
        let shared = Shared::new(ActiveList::new(Some(Lease::default())));
        for port in [ConnectionKind::Telemetry, ConnectionKind::Control] {
            let mut server = shared.server(port, 1);
            let actions = receive(&mut server, &hello());
            assert!(
                matches!(
                    actions.as_slice(),
                    [ServerAction::Close(CloseReason::Standing { .. })]
                ),
                "{port:?}: {actions:?}"
            );
        }
    }

    #[test]
    fn a_first_message_other_than_hello_closes_without_a_word() {
        let shared = Shared::new(sample_list());
        let mut server = shared.server(ConnectionKind::Telemetry, 4);
        let actions = receive(&mut server, &message("open_stream"));
        assert!(
            matches!(
                actions.as_slice(),
                [ServerAction::Close(CloseReason::ExpectedHello { .. })]
            ),
            "{actions:?}"
        );
    }

    #[test]
    fn a_connection_suspended_after_its_handshake_is_refused_its_next_message() {
        let shared = Shared::new(sample_list());
        let mut server = shared.server(ConnectionKind::Telemetry, 1);
        established(&mut server);
        let applied = shared
            .list
            .lock()
            .unwrap()
            .apply(
                diff(
                    1,
                    2,
                    vec![entry(
                        1,
                        EntryState::Suspended {
                            reason: SuspendReason::License,
                        },
                    )],
                    &[],
                ),
                MINUTE,
            )
            .result
            .unwrap();
        assert_eq!(applied.version, 2);
        let actions = receive(&mut server, &message("record_batch"));
        assert_error_then_close(&actions, &TelemetryError::Suspended);
    }

    #[test]
    fn an_expired_lease_refuses_open_and_new_connections() {
        let shared = Shared::new(sample_list());
        let mut open = shared.server(ConnectionKind::Telemetry, 1);
        established(&mut open);
        {
            let mut list = shared.list.lock().unwrap();
            let _ = list.register(super::conn(1), &spki(1), ip("192.0.2.1"), MINUTE);
            assert_eq!(
                list.check_lease(DEFAULT_LEASE_LENGTH),
                Some(vec![super::conn(1)])
            );
        }
        shared.set_now(DEFAULT_LEASE_LENGTH);
        let actions = receive(&mut open, &message("record_batch"));
        assert_error_then_close(&actions, &TelemetryError::LeaseExpired);

        let mut new = shared.server(ConnectionKind::Telemetry, 1);
        let actions = receive(&mut new, &hello());
        assert_error_then_close(&actions, &TelemetryError::LeaseExpired);

        assert!(
            shared
                .list
                .lock()
                .unwrap()
                .confirm(1, DEFAULT_LEASE_LENGTH)
                .extended
        );
        let mut renewed = shared.server(ConnectionKind::Telemetry, 1);
        established(&mut renewed);
    }

    #[test]
    fn a_control_message_the_standing_does_not_permit_is_unsupported() {
        let shared = Shared::new(sample_list());
        for (key, t) in [
            (4, "status_report"),
            (3, "enroll_request"),
            (2, "enroll_request"),
        ] {
            let mut server = shared.server(ConnectionKind::Control, key);
            established(&mut server);
            let actions = receive(&mut server, &message(t));
            let [ServerAction::Send(frame)] = actions.as_slice() else {
                panic!("expected an unsupported, got {actions:?}");
            };
            let envelope = Envelope::parse(frame.payload()).unwrap();
            assert_eq!(envelope.t(), Unsupported::T);
            let unsupported: Unsupported = envelope.body().decode().unwrap();
            assert_eq!(unsupported.kind, t);
            assert!(server.is_established(), "key {key}: {t}");
        }

        // What the standing permits reaches the caller.
        let mut server = shared.server(ConnectionKind::Control, 4);
        established(&mut server);
        let actions = receive(&mut server, &message("enroll_request"));
        assert!(
            matches!(actions.as_slice(), [ServerAction::Deliver(envelope)] if envelope.t() == "enroll_request"),
            "{actions:?}"
        );
    }
}
