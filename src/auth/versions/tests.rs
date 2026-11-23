//! Tests of the document version state machine and of receiving a
//! `Documents` list.
//!
//! Every document is signed with the deterministic test keys of
//! `test_util`, and every trust state and recovery epoch change comes from
//! the key set state machine's public API. A crash is a write the store
//! refuses, or a copy of what the store held at some point, from which a
//! new state machine is made as a restarted endpoint makes it.

use std::cell::RefCell;
use std::rc::Rc;

use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};

use super::*;
use crate::auth::documents::{
    Hash32, InstallId, PositiveInteger, SemVer, verify_addresses, verify_keyset,
};
use crate::auth::jws::test_util::TestKey;
use crate::auth::jws::{KeyKind, KeyLookup, KeySource, Kid, PublicKey};
use crate::auth::keyset::EpochChange;
use crate::results::DocumentResult;

const INSTALL: &str = "install-a";
const CUSTOMER: &str = "c0000000-0000-4000-8000-000000000001";
/// Customer key names, one per recovery epoch of the tests.
const NAME_A: &str = "a0000000-0000-4000-8000-00000000000a";
const NAME_B: &str = "b0000000-0000-4000-8000-00000000000b";
const ENDPOINT: &str = "e0000000-0000-4000-8000-0000000000e1";
const OTHER_ENDPOINT: &str = "e0000000-0000-4000-8000-0000000000e2";
const GROUP_A: &str = "9a000000-0000-4000-8000-00000000000a";
const GROUP_B: &str = "9b000000-0000-4000-8000-00000000000b";
const NOW: &str = "2026-11-23T00:00:00Z";
const SENTA: &str = "1.5.0";
const REASON: &str = "disk full";
const PEM: &str = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";

// --- keys ---------------------------------------------------------------

fn seed(class: u8, tag: u8, version: u64) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[0] = class;
    seed[1] = tag;
    seed[2..10].copy_from_slice(&version.to_be_bytes());
    seed
}

/// The customer key of version `version` under the key name `name`.
fn ck(name: &str, version: u64) -> TestKey {
    TestKey::from_seed(&seed(1, name.as_bytes()[0], version))
}

fn ckid(name: &str, version: u64) -> String {
    format!("endpoint-{name}:{version}")
}

/// The recovery key of version `version`.
fn rk(version: u64) -> TestKey {
    TestKey::from_seed(&seed(2, 0, version))
}

fn rkid(version: u64) -> String {
    format!("recovery-{INSTALL}:{version}")
}

fn id(text: &str) -> LowerUuid {
    LowerUuid::parse(text).unwrap()
}

fn now() -> Timestamp {
    NOW.parse().unwrap()
}

fn at(offset: SignedDuration) -> String {
    (now() + offset).to_string()
}

fn hours(count: i64) -> SignedDuration {
    SignedDuration::from_hours(count)
}

fn semver(text: &str) -> SemVer {
    SemVer::parse(text).unwrap()
}

// --- key documents --------------------------------------------------------

/// The key set `version` of `name` in `epoch`: its keys are the previous
/// and the new version (only 1 for version 1), the new one is current, and
/// older versions are revoked.
fn keyset_payload(epoch: u64, name: &str, version: u64) -> Vec<u8> {
    let versions: Vec<u64> = if version == 1 {
        vec![1]
    } else {
        vec![version - 1, version]
    };
    let keys: Vec<Value> = versions
        .iter()
        .map(|&v| json!({"kid": ckid(name, v), "key": ck(name, v).jwk()}))
        .collect();
    let revoked: Vec<String> = (1..version.saturating_sub(1))
        .map(|v| ckid(name, v))
        .collect();
    serde_json::to_vec(&json!({
        "customer_endpoint_id": CUSTOMER,
        "customer_key_name": format!("endpoint-{name}"),
        "recovery_epoch": epoch,
        "keyset_version": version,
        "keys": keys,
        "current_kid": ckid(name, version),
        "revoked_kids": revoked,
    }))
    .unwrap()
}

/// The ordinary rotation to `version` of `name`, signed by the version
/// before.
fn rotation(epoch: u64, name: &str, version: u64) -> String {
    ck(name, version - 1).sign(
        Typ::Keyset,
        &ckid(name, version - 1),
        &keyset_payload(epoch, name, version),
    )
}

/// The version 1 of `epoch` under `name`, signed by the recovery key of
/// version `signer`.
fn recovery(epoch: u64, name: &str, signer: u64) -> String {
    rk(signer).sign(Typ::Keyset, &rkid(signer), &keyset_payload(epoch, name, 1))
}

/// The recovery key replacement to `version`, signed by the version before.
fn recovery_key(version: u64) -> String {
    let payload = serde_json::to_vec(&json!({
        "install_id": INSTALL,
        "recovery_key_version": version,
        "recovery_key": rk(version).jwk(),
    }))
    .unwrap();
    rk(version - 1).sign(Typ::RecoveryKey, &rkid(version - 1), &payload)
}

struct OneKey {
    kid: String,
    key: PublicKey,
}

impl KeySource for OneKey {
    fn find_key(&self, kid: &Kid, _: &[KeyKind]) -> KeyLookup {
        if kid.as_str() == self.kid {
            KeyLookup::Found {
                key: self.key,
                kind: kid.kind(),
            }
        } else {
            KeyLookup::Unknown
        }
    }
}

/// The trust state of an endpoint that has just installed: key set (1, 1)
/// of `NAME_A`, recovery key 1.
fn installed() -> TrustState {
    let jws = ck(NAME_A, 1).sign(Typ::Keyset, &ckid(NAME_A, 1), &keyset_payload(1, NAME_A, 1));
    let source = OneKey {
        kid: ckid(NAME_A, 1),
        key: ck(NAME_A, 1).public_key(),
    };
    TrustState::new(
        verify_keyset(&jws, &source).unwrap(),
        InstallId::parse(INSTALL).unwrap(),
        rk(1).jwk(),
        PositiveInteger::new(1).unwrap(),
    )
}

/// Takes `chain` into `trust`, which must apply it whole, and returns the
/// epoch changes it brought.
fn take_chain(trust: &mut TrustState, chain: &[String]) -> Vec<EpochChange> {
    let outcome = trust.receive_chain(chain);
    assert!(!outcome.is_stopped(), "{outcome:?}");
    outcome.epoch_changes().to_vec()
}

// --- versioned documents ----------------------------------------------------

#[derive(Clone)]
struct Doc {
    typ: Typ,
    payload: Value,
}

impl Doc {
    fn with(mut self, key: &str, value: Value) -> Self {
        self.payload[key] = value;
        self
    }

    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.payload).unwrap()
    }

    /// Signed by the customer key `NAME_A:1`.
    fn jws(&self) -> String {
        self.by(NAME_A, 1)
    }

    fn by(&self, name: &str, version: u64) -> String {
        ck(name, version).sign(self.typ, &ckid(name, version), &self.bytes())
    }

    /// Signed under `NAME_A:1` by a key that is not that kid's.
    fn forged(&self) -> String {
        TestKey::from_seed(&[9; 32]).sign(self.typ, &ckid(NAME_A, 1), &self.bytes())
    }
}

fn policy(epoch: u64, group: &str, version: u64) -> Doc {
    Doc {
        typ: Typ::Policy,
        payload: json!({
            "recovery_epoch": epoch,
            "group_id": group,
            "version": version,
            "collection_mode": "extended",
            "sysmon_config": {
                "sha256": Hash32::from([1; 32]),
                "sources": ["https://example.com/sysmon.xml"],
            },
            "field_exclusions": {},
            "audit_settings": {"windows_local_apply": true, "linux_auditd_rules": false},
            "event_log_channels": {},
            "status_ui": "tray",
        }),
    }
}

fn assign(epoch: u64, endpoint: &str, version: u64, group: &str) -> Doc {
    Doc {
        typ: Typ::Assign,
        payload: json!({
            "recovery_epoch": epoch,
            "endpoint_id": endpoint,
            "version": version,
            "group_id": group,
            "uninstall_token_sha256": Hash32::from([5; 32]),
        }),
    }
}

fn addresses(epoch: u64, version: u64) -> Doc {
    Doc {
        typ: Typ::Addresses,
        payload: json!({
            "recovery_epoch": epoch,
            "version": version,
            "control_entries": [],
            "telemetry_entries": [],
            "trust_roots": [PEM],
            "distribution_points": [],
        }),
    }
}

/// An update for `(field, id)`, `group_id` or `endpoint_id`, issued a day
/// before `NOW` and expiring a day after.
fn update(epoch: u64, target: (&str, &str), version: u64, target_version: Option<&str>) -> Doc {
    let mut payload = json!({
        "recovery_epoch": epoch,
        "version": version,
        "target_version": target_version,
        "rollback": false,
        "issued_at": at(hours(-24)),
        "expires_at": at(hours(24)),
    });
    payload[target.0] = json!(target.1);
    if target_version.is_some() {
        payload["package_sha256"] = json!(Hash32::from([3; 32]));
        payload["package_size"] = json!(1024);
        payload["sources"] = json!(["https://example.com/senta.pkg"]);
    }
    Doc {
        typ: Typ::Update,
        payload,
    }
}

fn to_group(group: &str) -> (&'static str, &str) {
    ("group_id", group)
}

fn to_endpoint(endpoint: &str) -> (&'static str, &str) {
    ("endpoint_id", endpoint)
}

// --- stores and applier -------------------------------------------------------

#[derive(Debug, Default)]
struct Shared {
    json: Option<String>,
    writes: usize,
    writes_left: Option<usize>,
}

/// A version store that keeps the state as JSON, shared between its
/// clones, and that can be told to refuse writes.
#[derive(Clone, Debug, Default)]
struct SharedStore(Rc<RefCell<Shared>>);

impl SharedStore {
    fn holding(json: Option<String>) -> Self {
        Self(Rc::new(RefCell::new(Shared {
            json,
            ..Shared::default()
        })))
    }

    fn json(&self) -> Option<String> {
        self.0.borrow().json.clone()
    }

    fn writes(&self) -> usize {
        self.0.borrow().writes
    }

    /// Lets `count` more writes through and refuses every one after.
    fn fail_after(&self, count: usize) {
        self.0.borrow_mut().writes_left = Some(count);
    }

    fn heal(&self) {
        self.0.borrow_mut().writes_left = None;
    }

    /// A store holding what this one holds, as a restarted endpoint reads
    /// it.
    fn reopen(&self) -> Self {
        Self::holding(self.json())
    }
}

impl VersionStore for SharedStore {
    fn load(&self) -> Result<Option<VersionState>, StoreError> {
        self.0
            .borrow()
            .json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(StoreError::new)
    }

    fn save(&mut self, state: &VersionState) -> Result<(), StoreError> {
        let mut shared = self.0.borrow_mut();
        if let Some(left) = shared.writes_left {
            if left == 0 {
                return Err(StoreError::new("the write was refused"));
            }
            shared.writes_left = Some(left - 1);
        }
        shared.json = Some(serde_json::to_string(state).map_err(StoreError::new)?);
        shared.writes += 1;
        Ok(())
    }
}

/// A trust store in memory that can be told to refuse writes.
#[derive(Default)]
struct FlakyTrustStore {
    inner: MemoryTrustStore,
    fail: bool,
}

impl TrustStore for FlakyTrustStore {
    fn load(&self) -> Result<Option<TrustState>, StoreError> {
        self.inner.load()
    }

    fn save(&mut self, state: &TrustState) -> Result<(), StoreError> {
        if self.fail {
            return Err(StoreError::new("the write was refused"));
        }
        self.inner.save(state)
    }
}

/// An applier that records what it applies, fails for the slots it is
/// told to, and records what a watched store held at each call.
#[derive(Default)]
struct Recorder {
    calls: Vec<(Slot, u64)>,
    fail_all: bool,
    failing: Vec<Slot>,
    watch: Option<SharedStore>,
    seen: Vec<Option<String>>,
}

impl DocumentApplier for Recorder {
    fn apply(&mut self, content: &DocumentContent) -> Result<(), String> {
        let slot = content.slot();
        self.calls.push((slot, content.version()));
        if let Some(watch) = &self.watch {
            self.seen.push(watch.json());
        }
        if self.fail_all || self.failing.contains(&slot) {
            Err(REASON.to_owned())
        } else {
            Ok(())
        }
    }
}

/// An enrolled endpoint at the trust state `installed()`.
struct Endpoint {
    trust: TrustState,
    trust_store: FlakyTrustStore,
    store: SharedStore,
    versions: DocumentVersions<SharedStore>,
    applier: Recorder,
    now: Timestamp,
    senta: SemVer,
}

impl Endpoint {
    fn new() -> Self {
        let trust = installed();
        let store = SharedStore::default();
        let mut versions = DocumentVersions::create(store.clone(), &trust).unwrap();
        versions.set_endpoint_id(id(ENDPOINT)).unwrap();
        Self {
            trust_store: FlakyTrustStore {
                inner: MemoryTrustStore::with_state(trust.clone()),
                fail: false,
            },
            trust,
            store,
            versions,
            applier: Recorder::default(),
            now: now(),
            senta: semver(SENTA),
        }
    }

    /// An endpoint assigned to `group` by the assignment of version 1.
    fn assigned(group: &str) -> Self {
        let mut endpoint = Self::new();
        endpoint.applied(&assign(1, ENDPOINT, 1, group).jws());
        endpoint
    }

    fn receive(&mut self, jws: &str) -> Receipt {
        self.try_receive(jws).unwrap()
    }

    fn try_receive(&mut self, jws: &str) -> Result<Receipt, VersionsError> {
        self.versions
            .receive(jws, &self.trust, self.now, &self.senta, &mut self.applier)
    }

    fn result(&mut self, jws: &str) -> DocumentResult {
        self.receive(jws).result().clone()
    }

    fn applied(&mut self, jws: &str) {
        assert_eq!(self.result(jws), DocumentResult::Applied);
    }

    fn resume(&mut self) -> Vec<(Slot, DocumentResult)> {
        self.versions
            .resume(&self.trust, &mut self.applier)
            .unwrap()
    }

    fn receive_list(&mut self, list: &[String]) -> Result<DocumentsOutcome, DocumentsError> {
        receive_documents(
            list,
            &mut self.trust,
            &mut self.trust_store,
            &mut self.versions,
            self.now,
            &self.senta,
            &mut self.applier,
        )
    }

    /// Starts again from what the stores hold.
    fn restart(&mut self) {
        self.restart_from(self.store.json());
    }

    /// Starts again from the document version state `json` and the stored
    /// trust state.
    fn restart_from(&mut self, json: Option<String>) {
        self.store = SharedStore::holding(json);
        self.versions = DocumentVersions::restore(self.store.clone()).unwrap();
        self.trust = self.trust_store.load().unwrap().unwrap();
    }

    /// Takes `chain` into the trust state and stores it, without telling
    /// the document versions; returns the epoch changes.
    fn take_chain(&mut self, chain: &[String]) -> Vec<EpochChange> {
        let changes = take_chain(&mut self.trust, chain);
        self.trust_store.save(&self.trust).unwrap();
        changes
    }

    /// Recovers to epoch 2 under `NAME_B`, telling the document versions.
    fn recover(&mut self) {
        for change in self.take_chain(&[recovery(2, NAME_B, 1)]) {
            assert!(self.versions.epoch_changed(change).unwrap());
        }
    }

    fn report(&self, slot: Slot) -> SlotReport {
        self.versions.report(slot)
    }
}

fn versions_of(report: &SlotReport) -> (Option<u64>, Option<u64>) {
    (report.verified_version, report.applied_version)
}

fn halted() -> SlotStatus {
    SlotStatus::Halted {
        reason: REASON.to_owned(),
    }
}

fn apply_failed() -> DocumentResult {
    DocumentResult::ApplyFailed {
        reason: REASON.to_owned(),
    }
}

fn processed(outcome: &DocumentsOutcome) -> Vec<Option<DocumentResult>> {
    outcome
        .entries()
        .iter()
        .map(|entry| match entry.outcome() {
            EntryOutcome::Processed(result) => Some(result.clone()),
            EntryOutcome::NotProcessed => None,
        })
        .collect()
}

// --- receiving one document -----------------------------------------------------

#[test]
fn each_typ_applies_once_into_an_empty_slot() {
    let mut endpoint = Endpoint::new();
    let cases = [
        (assign(1, ENDPOINT, 10, GROUP_A), Slot::Assign, 10),
        (policy(1, GROUP_A, 20), Slot::Policy(id(GROUP_A)), 20),
        (addresses(1, 30), Slot::Addresses, 30),
        (
            update(1, to_group(GROUP_A), 40, Some("2.0.0")),
            Slot::GroupUpdate(id(GROUP_A)),
            40,
        ),
        (
            update(1, to_endpoint(ENDPOINT), 50, Some("2.0.0")),
            Slot::EndpointUpdate,
            50,
        ),
    ];
    for (doc, slot, version) in &cases {
        let receipt = endpoint.receive(&doc.jws());
        assert_eq!(receipt.result(), &DocumentResult::Applied, "{slot:?}");
        assert!(!receipt.epoch_aligned());
        assert_eq!(receipt.conflict(), None);
        let report = endpoint.report(*slot);
        assert_eq!(versions_of(&report), (Some(*version), Some(*version)));
        assert_eq!(report.status, SlotStatus::Normal);
        assert_eq!(report.current, Some((1, *version)));
        assert!(!report.untrusted);
        assert_eq!(
            endpoint
                .versions
                .current_content(*slot)
                .map(DocumentContent::version),
            Some(*version)
        );
    }
    let expected: Vec<(Slot, u64)> = cases.iter().map(|(_, slot, v)| (*slot, *v)).collect();
    assert_eq!(endpoint.applier.calls, expected);
    let listed: Vec<Slot> = endpoint.versions.reports().iter().map(|r| r.slot).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    assert_eq!(listed, sorted);
    assert_eq!(listed.len(), 5);
}

#[test]
fn the_first_rule_broken_decides_the_result() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&update(1, to_group(GROUP_A), 40, Some("2.0.0")).jws());
    let expired = |doc: Doc| {
        doc.with("issued_at", json!(at(hours(-72))))
            .with("expires_at", json!(at(hours(-48))))
    };
    let mut broken_policy = policy(2, GROUP_B, 1);
    broken_policy
        .payload
        .as_object_mut()
        .unwrap()
        .remove("status_ui");
    let command = Doc {
        typ: Typ::Command,
        payload: json!({}),
    };
    let cases = [
        // Not one of the four `typ`s.
        (command.jws(), DocumentResult::SchemaError),
        ("not a jws".to_owned(), DocumentResult::SchemaError),
        // 1 before 2: a bad signature and a wrong epoch.
        (policy(2, GROUP_A, 1).forged(), DocumentResult::BadSignature),
        // 1 before 2: a schema error and a wrong epoch.
        (broken_policy.jws(), DocumentResult::SchemaError),
        // 2 before 3: a wrong epoch and a wrong group.
        (policy(2, GROUP_B, 1).jws(), DocumentResult::EpochMismatch),
        // 3 before 4: another endpoint, at a version below the verified one.
        (
            assign(1, OTHER_ENDPOINT, 0, GROUP_A).jws(),
            DocumentResult::WrongTarget,
        ),
        // 3 before 5: another group, expired.
        (
            expired(update(1, to_group(GROUP_B), 50, Some("2.0.0"))).jws(),
            DocumentResult::WrongTarget,
        ),
        // 4 before 5: stale and expired.
        (
            expired(update(1, to_group(GROUP_A), 39, Some("2.0.0"))).jws(),
            DocumentResult::Stale,
        ),
        // 4 before 5: the verified version with other content, expired.
        (
            expired(update(1, to_group(GROUP_A), 40, Some("2.0.0"))).jws(),
            DocumentResult::Conflict,
        ),
        // 4 before 5: a rollback without the flag, at the verified version.
        (
            update(1, to_group(GROUP_A), 40, Some("1.0.0")).jws(),
            DocumentResult::Conflict,
        ),
        // 5: a new version, expired.
        (
            expired(update(1, to_group(GROUP_A), 41, Some("2.0.0"))).jws(),
            DocumentResult::Expired,
        ),
        // 5: a new version, a rollback without the flag.
        (
            update(1, to_group(GROUP_A), 41, Some("1.0.0")).jws(),
            DocumentResult::SchemaError,
        ),
    ];
    for (jws, expected) in cases {
        let before = endpoint.store.json();
        let writes = endpoint.store.writes();
        let calls = endpoint.applier.calls.len();
        let receipt = endpoint.receive(&jws);
        assert_eq!(receipt.result(), &expected, "{jws}");
        assert_eq!(
            receipt.conflict().is_some(),
            expected == DocumentResult::Conflict
        );
        assert_eq!(endpoint.store.json(), before);
        assert_eq!(endpoint.store.writes(), writes);
        assert_eq!(endpoint.applier.calls.len(), calls);
    }
}

#[test]
fn a_policy_needs_the_group_of_the_current_assignment() {
    let mut endpoint = Endpoint::new();
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 1).jws()),
        DocumentResult::WrongTarget
    );
    endpoint.applied(&assign(1, ENDPOINT, 1, GROUP_A).jws());
    assert_eq!(endpoint.versions.current_group(), Some(id(GROUP_A)));
    endpoint.applied(&policy(1, GROUP_A, 1).jws());
    endpoint.applied(&assign(1, ENDPOINT, 2, GROUP_B).jws());
    endpoint.applied(&policy(1, GROUP_B, 1).jws());
    let before = endpoint.store.json();
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 2).jws()),
        DocumentResult::WrongTarget
    );
    assert_eq!(
        endpoint.result(&update(1, to_group(GROUP_A), 2, Some("2.0.0")).jws()),
        DocumentResult::WrongTarget
    );
    assert_eq!(endpoint.store.json(), before);
}

#[test]
fn the_same_version_and_hash_is_a_duplicate_a_retry_or_halted() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let applied = policy(1, GROUP_A, 5).jws();
    endpoint.applied(&applied);
    let calls = endpoint.applier.calls.len();
    assert_eq!(endpoint.result(&applied), DocumentResult::Duplicate);
    endpoint.restart();
    assert_eq!(endpoint.result(&applied), DocumentResult::Duplicate);
    assert_eq!(endpoint.applier.calls.len(), calls);

    // Pending: the same document again is applied again.
    let pending = policy(1, GROUP_A, 6).jws();
    endpoint.applier.fail_all = true;
    assert_eq!(endpoint.result(&pending), apply_failed());
    assert_eq!(
        endpoint.report(Slot::Policy(id(GROUP_A))).status,
        SlotStatus::Pending
    );
    endpoint.applier.fail_all = false;
    endpoint.applied(&pending);
    assert_eq!(endpoint.applier.calls.len(), calls + 2);
    let report = endpoint.report(Slot::Policy(id(GROUP_A)));
    assert_eq!(versions_of(&report), (Some(6), Some(6)));
    assert_eq!(report.status, SlotStatus::Normal);
}

#[test]
fn a_version_received_again_is_verified_again() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let pending = policy(1, GROUP_A, 5).jws();
    endpoint.applier.fail_all = true;
    assert_eq!(endpoint.result(&pending), apply_failed());
    endpoint.applier.fail_all = false;

    // `NAME_A:1` is revoked by the key set (1, 3).
    endpoint.take_chain(&[rotation(1, NAME_A, 2), rotation(1, NAME_A, 3)]);
    let before = endpoint.store.json();
    let calls = endpoint.applier.calls.len();
    assert_eq!(endpoint.result(&pending), DocumentResult::RevokedKid);
    assert_eq!(endpoint.store.json(), before);
    assert_eq!(endpoint.applier.calls.len(), calls);
    assert_eq!(
        endpoint.report(Slot::Policy(id(GROUP_A))).status,
        SlotStatus::Pending
    );
}

#[test]
fn other_content_at_the_verified_version_is_a_conflict() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 5).jws());
    let other = policy(1, GROUP_A, 5)
        .with("collection_mode", json!("essential"))
        .jws();
    let alarm = ConflictAlarm {
        slot: Slot::Policy(id(GROUP_A)),
        version: 5,
    };
    for restart in [false, true] {
        if restart {
            endpoint.restart();
        }
        let before = endpoint.store.json();
        let receipt = endpoint.receive(&other);
        assert_eq!(receipt.result(), &DocumentResult::Conflict);
        assert_eq!(receipt.conflict(), Some(alarm));
        assert_eq!(endpoint.store.json(), before);
    }
}

#[test]
fn the_third_failure_halts_the_version() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let slot = Slot::Policy(id(GROUP_A));
    endpoint.applied(&policy(1, GROUP_A, 4).jws());
    let failing = policy(1, GROUP_A, 5).jws();
    let calls = endpoint.applier.calls.len() + 3;
    endpoint.applier.fail_all = true;
    for attempt in 1..=3 {
        assert_eq!(endpoint.result(&failing), apply_failed(), "{attempt}");
        // The count of failures survives a restart.
        endpoint.restart();
    }
    let report = endpoint.report(slot);
    assert_eq!(report.status, halted());
    assert_eq!(versions_of(&report), (Some(5), Some(4)));
    assert_eq!(endpoint.applier.calls.len(), calls);

    // A halted version is neither applied again nor resumed.
    endpoint.applier.fail_all = false;
    let before = endpoint.store.json();
    assert_eq!(endpoint.result(&failing), apply_failed());
    assert_eq!(endpoint.resume(), []);
    assert_eq!(endpoint.applier.calls.len(), calls);
    assert_eq!(endpoint.store.json(), before);

    // The current document stays the one applied last.
    assert_eq!(
        endpoint
            .versions
            .current_content(slot)
            .map(DocumentContent::version),
        Some(4)
    );
    assert_eq!(report.current, Some((1, 4)));

    // A higher version is taken and lifts the halt.
    endpoint.applied(&policy(1, GROUP_A, 6).jws());
    let report = endpoint.report(slot);
    assert_eq!(report.status, SlotStatus::Normal);
    assert_eq!(versions_of(&report), (Some(6), Some(6)));
}

// --- crashes and resuming ------------------------------------------------------

#[test]
fn a_pending_document_is_applied_after_a_restart() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let slot = Slot::Policy(id(GROUP_A));
    endpoint.applied(&policy(1, GROUP_A, 4).jws());
    endpoint.applier.watch = Some(endpoint.store.clone());
    endpoint.applied(&policy(1, GROUP_A, 5).jws());
    // What the store held when the policy was about to be applied.
    let crashed = endpoint.applier.seen.pop().unwrap();

    // The key that signed it is revoked meanwhile.
    endpoint.take_chain(&[rotation(1, NAME_A, 2), rotation(1, NAME_A, 3)]);
    endpoint.restart_from(crashed);
    let report = endpoint.report(slot);
    assert_eq!(versions_of(&report), (Some(5), Some(4)));
    assert_eq!(report.status, SlotStatus::Pending);

    assert_eq!(endpoint.resume(), [(slot, DocumentResult::Applied)]);
    let report = endpoint.report(slot);
    assert_eq!(versions_of(&report), (Some(5), Some(5)));
    assert_eq!(report.current, Some((1, 5)));
    assert_eq!(endpoint.resume(), []);
}

#[test]
fn a_crash_after_applying_applies_again() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let slot = Slot::Policy(id(GROUP_A));
    let calls = endpoint.applier.calls.len();
    endpoint.store.fail_after(1);
    let error = endpoint
        .try_receive(&policy(1, GROUP_A, 5).jws())
        .unwrap_err();
    assert!(matches!(error, VersionsError::Store(_)), "{error:?}");
    assert_eq!(endpoint.applier.calls.len(), calls + 1);

    endpoint.restart();
    assert_eq!(endpoint.report(slot).status, SlotStatus::Pending);
    assert_eq!(endpoint.resume(), [(slot, DocumentResult::Applied)]);
    assert_eq!(endpoint.applier.calls.len(), calls + 2);
    assert_eq!(versions_of(&endpoint.report(slot)), (Some(5), Some(5)));
}

#[test]
fn a_failed_completion_write_leaves_the_document_pending() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let slot = Slot::Policy(id(GROUP_A));
    endpoint.store.fail_after(1);
    let error = endpoint
        .try_receive(&policy(1, GROUP_A, 5).jws())
        .unwrap_err();
    assert!(matches!(error, VersionsError::Store(_)), "{error:?}");
    endpoint.store.heal();
    // The state in memory is the stored one.
    let stored: VersionState = serde_json::from_str(&endpoint.store.json().unwrap()).unwrap();
    assert_eq!(endpoint.versions.state(), &stored);
    let report = endpoint.report(slot);
    assert_eq!(versions_of(&report), (Some(5), None));
    assert_eq!(report.status, SlotStatus::Pending);
    assert_eq!(endpoint.resume(), [(slot, DocumentResult::Applied)]);
    assert_eq!(versions_of(&endpoint.report(slot)), (Some(5), Some(5)));
}

#[test]
fn a_failed_pending_write_applies_nothing() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 4).jws());
    let before = endpoint.store.json();
    let state = endpoint.versions.state().clone();
    let calls = endpoint.applier.calls.len();
    endpoint.store.fail_after(0);
    let error = endpoint
        .try_receive(&policy(1, GROUP_A, 5).jws())
        .unwrap_err();
    assert!(matches!(error, VersionsError::Store(_)), "{error:?}");
    assert_eq!(endpoint.applier.calls.len(), calls);
    assert_eq!(endpoint.store.json(), before);
    assert_eq!(endpoint.versions.state(), &state);
}

#[test]
fn a_pending_document_of_another_group_waits() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let slot = Slot::Policy(id(GROUP_A));
    endpoint.applier.fail_all = true;
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 5).jws()),
        apply_failed()
    );
    endpoint.applier.fail_all = false;
    endpoint.applied(&assign(1, ENDPOINT, 2, GROUP_B).jws());

    let calls = endpoint.applier.calls.len();
    assert_eq!(endpoint.resume(), []);
    assert_eq!(endpoint.applier.calls.len(), calls);
    let report = endpoint.report(slot);
    assert_eq!(report.status, SlotStatus::PendingOutOfTarget);
    assert_eq!(versions_of(&report), (Some(5), None));

    endpoint.applied(&assign(1, ENDPOINT, 3, GROUP_A).jws());
    assert_eq!(endpoint.report(slot).status, SlotStatus::Pending);
    assert_eq!(endpoint.resume(), [(slot, DocumentResult::Applied)]);
    assert_eq!(versions_of(&endpoint.report(slot)), (Some(5), Some(5)));
}

#[test]
fn resuming_follows_the_assignment_it_resumes() {
    let policy_a = Slot::Policy(id(GROUP_A));
    let policy_b = Slot::Policy(id(GROUP_B));
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applier.failing = vec![policy_a, policy_b];
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 1).jws()),
        apply_failed()
    );
    endpoint.applied(&assign(1, ENDPOINT, 2, GROUP_B).jws());
    assert_eq!(
        endpoint.result(&policy(1, GROUP_B, 1).jws()),
        apply_failed()
    );
    endpoint.applied(&assign(1, ENDPOINT, 3, GROUP_A).jws());
    endpoint.applier.failing = vec![Slot::Assign];
    assert_eq!(
        endpoint.result(&assign(1, ENDPOINT, 4, GROUP_B).jws()),
        apply_failed()
    );
    // Group A is applied, and an assignment to B and both policies pending.
    let stored = endpoint.store.json();

    // The assignment applies: only B's policy follows.
    endpoint.restart_from(stored.clone());
    endpoint.applier.failing = vec![];
    assert_eq!(
        endpoint.resume(),
        [
            (Slot::Assign, DocumentResult::Applied),
            (policy_b, DocumentResult::Applied)
        ]
    );
    assert_eq!(
        endpoint.report(policy_a).status,
        SlotStatus::PendingOutOfTarget
    );
    assert_eq!(versions_of(&endpoint.report(policy_b)), (Some(1), Some(1)));

    // The assignment fails: only A's policy follows.
    endpoint.restart_from(stored);
    endpoint.applier.failing = vec![Slot::Assign];
    assert_eq!(
        endpoint.resume(),
        [
            (Slot::Assign, apply_failed()),
            (policy_a, DocumentResult::Applied)
        ]
    );
    assert_eq!(
        endpoint.report(policy_b).status,
        SlotStatus::PendingOutOfTarget
    );
    assert_eq!(versions_of(&endpoint.report(policy_a)), (Some(1), Some(1)));
}

// --- updates ---------------------------------------------------------------------

#[test]
fn a_new_update_is_held_to_its_validity_window() {
    for (target, null_version) in [(to_group(GROUP_A), false), (to_endpoint(ENDPOINT), true)] {
        let mut endpoint = Endpoint::assigned(GROUP_A);
        let target_version = if null_version { None } else { Some("2.0.0") };
        let doc = |version: u64, issued: i64, expires: i64| {
            update(1, target, version, target_version)
                .with("issued_at", json!(at(hours(issued))))
                .with("expires_at", json!(at(hours(expires))))
        };
        let second = SignedDuration::from_secs(1);
        let cases = [
            // Issued more than an hour ahead.
            (
                doc(1, 0, 48).with("issued_at", json!((now() + hours(1) + second).to_string())),
                DocumentResult::NotYetValid,
            ),
            // Issued exactly an hour ahead.
            (doc(2, 1, 48), DocumentResult::Applied),
            // Expired more than an hour ago.
            (
                doc(3, -48, 0).with("expires_at", json!((now() - hours(1) - second).to_string())),
                DocumentResult::Expired,
            ),
            // Expired exactly an hour ago.
            (doc(4, -48, -1), DocumentResult::Applied),
            // A lifetime of more than 30 days.
            (
                doc(5, -24, 0).with(
                    "expires_at",
                    json!((now() + hours(30 * 24 - 24) + second).to_string()),
                ),
                DocumentResult::Expired,
            ),
            // A lifetime of exactly 30 days.
            (doc(6, -24, 30 * 24 - 24), DocumentResult::Applied),
        ];
        for (doc, expected) in cases {
            let before = endpoint.store.json();
            let result = endpoint.result(&doc.jws());
            assert_eq!(result, expected, "{target:?} {}", doc.payload);
            if expected != DocumentResult::Applied {
                assert_eq!(endpoint.store.json(), before);
            }
        }
    }
}

#[test]
fn an_accepted_update_is_applied_whatever_the_time_and_version() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let group_update = update(1, to_group(GROUP_A), 5, Some("2.0.0")).jws();
    let endpoint_update = update(1, to_endpoint(ENDPOINT), 6, Some("2.0.0")).jws();
    endpoint.applier.fail_all = true;
    assert_eq!(endpoint.result(&group_update), apply_failed());
    assert_eq!(endpoint.result(&endpoint_update), apply_failed());
    endpoint.applier.fail_all = false;

    // Both expired, and the installed senta is now above their target.
    endpoint.now = now() + hours(24 * 3);
    endpoint.senta = semver("3.0.0");
    endpoint.applied(&group_update);
    endpoint.restart();
    assert_eq!(
        endpoint.resume(),
        [(Slot::EndpointUpdate, DocumentResult::Applied)]
    );
    assert_eq!(endpoint.result(&group_update), DocumentResult::Duplicate);
    assert_eq!(endpoint.result(&endpoint_update), DocumentResult::Duplicate);
}

#[test]
fn a_rollback_needs_the_flag() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let down = update(1, to_group(GROUP_A), 1, Some("1.0.0"));
    assert_eq!(endpoint.result(&down.jws()), DocumentResult::SchemaError);
    endpoint.applied(&down.with("rollback", json!(true)).jws());
    endpoint.applied(&update(1, to_group(GROUP_A), 2, Some(SENTA)).jws());
    // A `null` target version has nothing to roll back.
    endpoint.applied(&update(1, to_endpoint(ENDPOINT), 1, None).jws());
}

#[test]
fn an_update_to_the_endpoint_comes_first() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    assert_eq!(endpoint.versions.current_update(), None);
    endpoint.applied(&update(1, to_group(GROUP_A), 1, Some("2.0.0")).jws());
    let current = endpoint.versions.current_update().unwrap();
    assert_eq!(current.slot, Slot::GroupUpdate(id(GROUP_A)));
    assert!(!current.untrusted);

    endpoint.applied(&update(1, to_endpoint(ENDPOINT), 1, Some("3.0.0")).jws());
    let current = endpoint.versions.current_update().unwrap();
    assert_eq!(current.slot, Slot::EndpointUpdate);
    assert_eq!(current.content.target_version(), Some(&semver("3.0.0")));

    // A `null` target version releases the endpoint to its group's.
    endpoint.applied(&update(1, to_endpoint(ENDPOINT), 2, None).jws());
    let current = endpoint.versions.current_update().unwrap();
    assert_eq!(current.slot, Slot::GroupUpdate(id(GROUP_A)));
    assert_eq!(current.content.target_version(), Some(&semver("2.0.0")));
}

// --- recovery epochs ---------------------------------------------------------------

#[test]
fn a_new_epoch_starts_the_versions_over() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 100).jws());
    endpoint.applier.fail_all = true;
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 101).jws()),
        apply_failed()
    );
    endpoint.applier.fail_all = false;

    endpoint.recover();
    let calls = endpoint.applier.calls.len();
    // The pending document of the earlier epoch is gone.
    assert_eq!(endpoint.resume(), []);
    assert_eq!(endpoint.applier.calls.len(), calls);
    endpoint.applied(&assign(2, ENDPOINT, 1, GROUP_A).by(NAME_B, 1));
    endpoint.applied(&policy(2, GROUP_A, 5).by(NAME_B, 1));
    let report = endpoint.report(Slot::Policy(id(GROUP_A)));
    assert_eq!(versions_of(&report), (Some(5), Some(5)));
    assert_eq!(report.current, Some((2, 5)));
}

#[test]
fn what_an_earlier_epoch_applied_is_used_and_not_trusted() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let policy_a = Slot::Policy(id(GROUP_A));
    endpoint.applied(&policy(1, GROUP_A, 100).jws());
    endpoint.applied(&update(1, to_group(GROUP_A), 7, Some("2.0.0")).jws());
    assert!(!endpoint.versions.has_untrusted());

    endpoint.recover();
    assert_eq!(endpoint.versions.recovery_epoch(), 2);
    assert!(endpoint.versions.has_untrusted());
    let report = endpoint.report(policy_a);
    assert_eq!(versions_of(&report), (None, None));
    assert_eq!(report.current, Some((1, 100)));
    assert!(report.untrusted);
    assert_eq!(
        endpoint
            .versions
            .current_content(policy_a)
            .map(DocumentContent::version),
        Some(100)
    );
    assert_eq!(endpoint.versions.current_group(), None);

    // No assignment of the new epoch yet.
    assert_eq!(
        endpoint.result(&policy(2, GROUP_A, 1).by(NAME_B, 1)),
        DocumentResult::WrongTarget
    );
    let current = endpoint.versions.current_update().unwrap();
    assert_eq!(current.slot, Slot::GroupUpdate(id(GROUP_A)));
    assert!(current.untrusted);

    endpoint.applied(&assign(2, ENDPOINT, 1, GROUP_A).by(NAME_B, 1));
    assert!(!endpoint.report(Slot::Assign).untrusted);
    assert!(endpoint.report(policy_a).untrusted);
    endpoint.applied(&policy(2, GROUP_A, 1).by(NAME_B, 1));
    assert!(!endpoint.report(policy_a).untrusted);
    endpoint.applied(&update(2, to_group(GROUP_A), 1, Some("2.0.0")).by(NAME_B, 1));
    assert!(!endpoint.versions.has_untrusted());
}

#[test]
fn starting_an_epoch_over_is_one_write() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 100).jws());
    endpoint.applier.fail_all = true;
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 101).jws()),
        apply_failed()
    );

    let changes = endpoint.take_chain(&[recovery(2, NAME_B, 1)]);
    let [change] = changes[..] else {
        panic!("{changes:?}")
    };
    // The write fails: nothing changes.
    let before = endpoint.store.json();
    let state = endpoint.versions.state().clone();
    endpoint.store.fail_after(0);
    let error = endpoint.versions.epoch_changed(change).unwrap_err();
    assert!(matches!(error, VersionsError::Store(_)), "{error:?}");
    assert_eq!(endpoint.store.json(), before);
    assert_eq!(endpoint.versions.state(), &state);

    endpoint.store.heal();
    let writes = endpoint.store.writes();
    assert!(endpoint.versions.epoch_changed(change).unwrap());
    assert_eq!(endpoint.store.writes(), writes + 1);
    endpoint.restart();
    assert_eq!(endpoint.versions.recovery_epoch(), 2);
    for report in endpoint.versions.reports() {
        assert_eq!(versions_of(&report), (None, None), "{report:?}");
        assert_eq!(report.status, SlotStatus::Normal);
        assert!(report.untrusted);
    }
}

#[test]
fn a_trust_state_ahead_starts_the_epoch_over_first() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 100).jws());
    let mut told = Endpoint::assigned(GROUP_A);
    told.applied(&policy(1, GROUP_A, 100).jws());
    told.recover();

    // The epoch change is never passed on.
    endpoint.take_chain(&[recovery(2, NAME_B, 1)]);
    let receipt = endpoint.receive(&policy(1, GROUP_A, 101).by(NAME_B, 1));
    assert_eq!(receipt.result(), &DocumentResult::EpochMismatch);
    assert!(receipt.epoch_aligned());
    // Only the epoch was started over.
    assert_eq!(endpoint.store.json(), told.store.json());
    assert_eq!(endpoint.store.writes(), told.store.writes());
}

#[test]
fn an_epoch_does_not_go_back() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let writes = endpoint.store.writes();
    let late = EpochChange {
        old_epoch: 0,
        new_epoch: 1,
    };
    assert!(!endpoint.versions.epoch_changed(late).unwrap());
    assert_eq!(endpoint.store.writes(), writes);

    let old_trust = endpoint.trust.clone();
    endpoint.recover();
    endpoint.applier.fail_all = true;
    assert_eq!(
        endpoint.result(&assign(2, ENDPOINT, 1, GROUP_B).by(NAME_B, 1)),
        apply_failed()
    );
    endpoint.applier.fail_all = false;
    let before = endpoint.store.json();
    let same = EpochChange {
        old_epoch: 1,
        new_epoch: 2,
    };
    assert!(!endpoint.versions.epoch_changed(same).unwrap());
    assert!(!endpoint.versions.epoch_changed(late).unwrap());
    assert_eq!(endpoint.store.json(), before);

    // A trust state behind the stored epoch.
    let calls = endpoint.applier.calls.len();
    let error = endpoint
        .versions
        .receive(
            &policy(1, GROUP_A, 1).jws(),
            &old_trust,
            endpoint.now,
            &endpoint.senta,
            &mut endpoint.applier,
        )
        .unwrap_err();
    assert!(
        matches!(
            error,
            VersionsError::TrustBehind {
                stored_epoch: 2,
                trust_epoch: 1
            }
        ),
        "{error:?}"
    );
    let error = endpoint
        .versions
        .resume(&old_trust, &mut endpoint.applier)
        .unwrap_err();
    assert!(
        matches!(error, VersionsError::TrustBehind { .. }),
        "{error:?}"
    );
    assert_eq!(endpoint.applier.calls.len(), calls);
    assert_eq!(endpoint.store.json(), before);
}

#[test]
fn a_leaked_key_cannot_hold_back_the_next_epoch() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    // `NAME_A:1`, still in `keys`, is the leaked key.
    endpoint.take_chain(&[rotation(1, NAME_A, 2)]);
    assert_eq!(
        endpoint.result(&policy(9_007_199_254_740_991, GROUP_A, 1).jws()),
        DocumentResult::EpochMismatch
    );
    endpoint.applied(&policy(1, GROUP_A, 9_007_199_254_740_991).jws());
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 5).by(NAME_A, 2)),
        DocumentResult::Stale
    );

    for change in endpoint.take_chain(&[recovery(2, NAME_B, 1)]) {
        endpoint.versions.epoch_changed(change).unwrap();
    }
    endpoint.applied(&assign(2, ENDPOINT, 1, GROUP_A).by(NAME_B, 1));
    endpoint.applied(&policy(2, GROUP_A, 5).by(NAME_B, 1));
}

// --- creating the state, addresses and the endpoint id ------------------------------

#[test]
fn the_install_addresses_are_applied_without_the_applier() {
    let trust = installed();
    let store = SharedStore::default();
    let mut versions = DocumentVersions::create(store.clone(), &trust).unwrap();
    assert_eq!(versions.endpoint_id(), None);
    let jws = addresses(1, 7).jws();
    let verified = verify_addresses(&jws, &trust).unwrap();
    assert_eq!(
        versions.install_addresses(verified).unwrap(),
        DocumentResult::Applied
    );
    versions.set_endpoint_id(id(ENDPOINT)).unwrap();

    let mut calls = 0;
    let mut applier = |_: &DocumentContent| -> Result<(), String> {
        calls += 1;
        Ok(())
    };
    let mut versions = DocumentVersions::restore(store.reopen()).unwrap();
    let report = versions.report(Slot::Addresses);
    assert_eq!(versions_of(&report), (Some(7), Some(7)));
    assert_eq!(report.current, Some((1, 7)));
    assert_eq!(report.status, SlotStatus::Normal);
    let receipt = versions
        .receive(&jws, &trust, now(), &semver(SENTA), &mut applier)
        .unwrap();
    assert_eq!(receipt.result(), &DocumentResult::Duplicate);
    assert_eq!(calls, 0);

    // Another address document is not put over it.
    let state = versions.state().clone();
    let other = verify_addresses(&addresses(1, 8).jws(), &trust).unwrap();
    let error = versions.install_addresses(other).unwrap_err();
    assert!(
        matches!(error, VersionsError::AddressesAlreadyVerified),
        "{error:?}"
    );
    assert_eq!(versions.state(), &state);
}

#[test]
fn the_install_addresses_must_be_of_the_epoch() {
    let trust = installed();
    let mut store = MemoryVersionStore::new();
    let mut versions = DocumentVersions::create(&mut store, &trust).unwrap();
    let verified = verify_addresses(&addresses(2, 7).jws(), &trust).unwrap();
    assert_eq!(
        versions.install_addresses(verified).unwrap(),
        DocumentResult::EpochMismatch
    );
    assert_eq!(versions.report(Slot::Addresses).verified_version, None);
    drop(versions);
    assert_eq!(store.state().cloned(), Some(VersionState::new(1)));
}

#[test]
fn the_endpoint_id_is_set_once() {
    let trust = installed();
    let store = SharedStore::default();
    let mut versions = DocumentVersions::create(store.clone(), &trust).unwrap();
    let mut applier = Recorder::default();
    let result = versions
        .receive(
            &assign(1, ENDPOINT, 1, GROUP_A).jws(),
            &trust,
            now(),
            &semver(SENTA),
            &mut applier,
        )
        .unwrap();
    assert_eq!(result.result(), &DocumentResult::WrongTarget);
    assert_eq!(
        result.identity().target(),
        Some(&DocumentTarget::Endpoint(id(ENDPOINT)))
    );

    versions.set_endpoint_id(id(ENDPOINT)).unwrap();
    let writes = store.writes();
    versions.set_endpoint_id(id(ENDPOINT)).unwrap();
    assert_eq!(store.writes(), writes);
    let error = versions.set_endpoint_id(id(OTHER_ENDPOINT)).unwrap_err();
    assert!(
        matches!(error, VersionsError::EndpointIdMismatch { .. }),
        "{error:?}"
    );
    assert_eq!(store.writes(), writes);
    assert_eq!(versions.endpoint_id(), Some(id(ENDPOINT)));
}

#[test]
fn a_state_is_created_once_and_restored_only_once_created() {
    let trust = installed();
    let store = SharedStore::default();
    let error = DocumentVersions::restore(store.clone()).unwrap_err();
    assert!(matches!(error, VersionsError::NotCreated), "{error:?}");

    // A failed write makes no state machine.
    store.fail_after(0);
    let error = DocumentVersions::create(store.clone(), &trust).unwrap_err();
    assert!(matches!(error, VersionsError::Store(_)), "{error:?}");
    assert_eq!(store.json(), None);
    store.heal();

    DocumentVersions::create(store.clone(), &trust).unwrap();
    let before = store.json();
    let error = DocumentVersions::create(store.clone(), &trust).unwrap_err();
    assert!(matches!(error, VersionsError::AlreadyCreated), "{error:?}");
    assert_eq!(store.json(), before);
    assert_eq!(
        DocumentVersions::restore(store).unwrap().recovery_epoch(),
        1
    );
}

#[test]
fn the_state_reads_back_as_written() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&addresses(1, 3).jws());
    endpoint.applied(&policy(1, GROUP_A, 4).jws());
    endpoint.applied(&update(1, to_endpoint(ENDPOINT), 1, None).jws());
    endpoint.applier.fail_all = true;
    for _ in 0..3 {
        assert_eq!(
            endpoint.result(&update(1, to_group(GROUP_A), 5, Some("2.0.0")).jws()),
            apply_failed()
        );
    }
    assert_eq!(
        endpoint.result(&policy(1, GROUP_A, 5).jws()),
        apply_failed()
    );
    let state = endpoint.versions.state().clone();
    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(serde_json::from_str::<VersionState>(&json).unwrap(), state);
    let reports = endpoint.versions.reports();
    endpoint.restart();
    assert_eq!(endpoint.versions.reports(), reports);
    assert_eq!(
        endpoint.report(Slot::GroupUpdate(id(GROUP_A))).status,
        halted()
    );
}

// --- receiving a `Documents` list ----------------------------------------------------

#[test]
fn a_list_takes_the_chain_then_the_documents_of_the_new_epoch() {
    let mut endpoint = Endpoint::new();
    let list = [
        policy(2, GROUP_A, 5).by(NAME_B, 1),
        rotation(1, NAME_A, 2),
        recovery_key(2),
        recovery(2, NAME_B, 2),
        assign(2, ENDPOINT, 1, GROUP_A).by(NAME_B, 1),
        addresses(2, 3).by(NAME_B, 1),
    ];
    let outcome = endpoint.receive_list(&list).unwrap();
    assert_eq!(
        processed(&outcome),
        vec![Some(DocumentResult::Applied); list.len()]
    );
    assert_eq!(
        outcome.epoch_changes(),
        [EpochChange {
            old_epoch: 1,
            new_epoch: 2
        }]
    );
    assert_eq!(
        (
            endpoint.trust.recovery_epoch(),
            endpoint.trust.keyset_version(),
            endpoint.trust.recovery_key_version()
        ),
        (2, 1, 2)
    );
    assert_eq!(
        endpoint.trust_store.load().unwrap().as_ref(),
        Some(&endpoint.trust)
    );
    assert_eq!(endpoint.versions.recovery_epoch(), 2);
    assert_eq!(
        endpoint.applier.calls,
        [
            (Slot::Assign, 1),
            (Slot::Policy(id(GROUP_A)), 5),
            (Slot::Addresses, 3)
        ]
    );
}

#[test]
fn a_list_whose_chain_stops_takes_the_documents_with_what_it_reached() {
    let mut endpoint = Endpoint::new();
    let list = [
        rotation(1, NAME_A, 2),
        rotation(1, NAME_A, 4),
        rotation(1, NAME_A, 3),
        assign(1, ENDPOINT, 1, GROUP_A).by(NAME_A, 2),
        policy(1, GROUP_A, 1).by(NAME_A, 2),
    ];
    let outcome = endpoint.receive_list(&list).unwrap();
    assert_eq!(
        processed(&outcome),
        [
            Some(DocumentResult::Applied),
            Some(DocumentResult::KeysetGap {
                have_epoch: 1,
                have_version: 2
            }),
            None,
            Some(DocumentResult::Applied),
            Some(DocumentResult::Applied),
        ]
    );
    let skipped = outcome.entries()[2].identity();
    assert_eq!(skipped.typ(), Some("senta-keyset"));
    assert_eq!(
        skipped.target(),
        Some(&DocumentTarget::Customer(id(CUSTOMER)))
    );
    assert_eq!(
        (skipped.recovery_epoch(), skipped.version()),
        (Some(1), Some(3))
    );
    assert_eq!(endpoint.trust.keyset_version(), 2);
}

#[test]
fn a_policy_before_its_assignment_in_a_list_is_taken() {
    let mut endpoint = Endpoint::new();
    let list = [
        policy(1, GROUP_A, 1).jws(),
        assign(1, ENDPOINT, 1, GROUP_A).jws(),
        Doc {
            typ: Typ::Command,
            payload: json!({}),
        }
        .jws(),
    ];
    let outcome = endpoint.receive_list(&list).unwrap();
    assert_eq!(
        processed(&outcome),
        [
            Some(DocumentResult::Applied),
            Some(DocumentResult::Applied),
            Some(DocumentResult::SchemaError),
        ]
    );
}

/// The lists of the two ways the trust state changes, each with the
/// documents signed by the new keys.
fn trust_changing_lists() -> [Vec<String>; 2] {
    [
        vec![
            rotation(1, NAME_A, 2),
            assign(1, ENDPOINT, 1, GROUP_A).by(NAME_A, 2),
            policy(1, GROUP_A, 1).by(NAME_A, 2),
        ],
        vec![
            recovery(2, NAME_B, 1),
            assign(2, ENDPOINT, 1, GROUP_A).by(NAME_B, 1),
            policy(2, GROUP_A, 1).by(NAME_B, 1),
        ],
    ]
}

#[test]
fn a_trust_state_not_stored_changes_nothing() {
    for list in trust_changing_lists() {
        let mut endpoint = Endpoint::new();
        let trust = endpoint.trust.clone();
        let before = endpoint.store.json();
        endpoint.trust_store.fail = true;
        let error = endpoint.receive_list(&list).unwrap_err();
        let DocumentsError::TrustStore { chain, .. } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(chain.results(), [DocumentResult::Applied]);
        assert_eq!(endpoint.trust, trust);
        assert_eq!(endpoint.store.json(), before);
        assert!(endpoint.applier.calls.is_empty());

        // Again without a restart: the chain is taken again.
        endpoint.trust_store.fail = false;
        let outcome = endpoint.receive_list(&list).unwrap();
        assert_eq!(processed(&outcome), vec![Some(DocumentResult::Applied); 3]);
        assert_eq!(
            endpoint.trust_store.load().unwrap().as_ref(),
            Some(&endpoint.trust)
        );
    }
}

#[test]
fn a_crash_before_the_trust_state_is_stored_keeps_the_versions() {
    for list in trust_changing_lists() {
        let mut endpoint = Endpoint::new();
        let before = endpoint.store.json();
        endpoint.trust_store.fail = true;
        endpoint.receive_list(&list).unwrap_err();
        endpoint.restart();
        assert_eq!(endpoint.trust, installed());
        assert_eq!(endpoint.store.json(), before);

        endpoint.trust_store.fail = false;
        let outcome = endpoint.receive_list(&list).unwrap();
        assert_eq!(processed(&outcome), vec![Some(DocumentResult::Applied); 3]);
    }
}

#[test]
fn a_crash_after_the_trust_state_is_stored_takes_the_documents_again() {
    for list in trust_changing_lists() {
        let mut endpoint = Endpoint::new();
        let before = endpoint.store.json();
        endpoint.store.fail_after(0);
        let error = endpoint.receive_list(&list).unwrap_err();
        assert!(
            matches!(error, DocumentsError::Versions(VersionsError::Store(_))),
            "{error:?}"
        );
        assert_eq!(
            endpoint.trust_store.load().unwrap().as_ref(),
            Some(&endpoint.trust)
        );
        assert_eq!(endpoint.store.json(), before);

        endpoint.restart();
        assert_ne!(endpoint.trust, installed());
        let outcome = endpoint.receive_list(&list).unwrap();
        assert_eq!(
            processed(&outcome),
            [
                Some(DocumentResult::Duplicate),
                Some(DocumentResult::Applied),
                Some(DocumentResult::Applied),
            ]
        );
    }
}

#[test]
fn each_entry_carries_what_was_read_of_it() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    let shared = OTHER_ENDPOINT;
    let list = [
        policy(1, GROUP_A, 2).forged(),
        addresses(1, 3).jws(),
        update(1, to_group(shared), 7, Some("2.0.0")).jws(),
        update(1, to_endpoint(shared), 7, Some("2.0.0")).jws(),
        // The chain stops at the first, which keeps what it read.
        ck(NAME_B, 1).sign(Typ::Keyset, &ckid(NAME_A, 1), &keyset_payload(1, NAME_A, 2)),
        recovery_key(2),
        rotation(1, NAME_A, 3),
        Doc {
            typ: Typ::Command,
            payload: json!({}),
        }
        .jws(),
        "not a jws".to_owned(),
    ];
    let outcome = endpoint.receive_list(&list).unwrap();
    assert_eq!(
        processed(&outcome),
        [
            Some(DocumentResult::BadSignature),
            Some(DocumentResult::Applied),
            Some(DocumentResult::WrongTarget),
            Some(DocumentResult::WrongTarget),
            Some(DocumentResult::BadSignature),
            None,
            None,
            Some(DocumentResult::SchemaError),
            Some(DocumentResult::SchemaError),
        ]
    );
    let identities: Vec<_> = outcome
        .entries()
        .iter()
        .map(|entry| {
            let identity = entry.identity();
            (
                identity.typ(),
                identity.target().cloned(),
                identity.recovery_epoch(),
                identity.version(),
            )
        })
        .collect();
    assert_eq!(
        identities,
        [
            (Some("senta-policy"), None, None, None),
            (Some("senta-addresses"), None, None, Some(3)),
            (
                Some("senta-update"),
                Some(DocumentTarget::Group(id(shared))),
                None,
                Some(7)
            ),
            (
                Some("senta-update"),
                Some(DocumentTarget::Endpoint(id(shared))),
                None,
                Some(7)
            ),
            (
                Some("senta-keyset"),
                Some(DocumentTarget::Customer(id(CUSTOMER))),
                Some(1),
                Some(2)
            ),
            (
                Some("senta-recovery-key"),
                Some(DocumentTarget::Install(InstallId::parse(INSTALL).unwrap())),
                None,
                Some(2)
            ),
            (
                Some("senta-keyset"),
                Some(DocumentTarget::Customer(id(CUSTOMER))),
                Some(1),
                Some(3)
            ),
            (Some("senta-command"), None, None, None),
            (None, None, None, None),
        ]
    );
}

#[test]
fn a_conflict_in_a_list_raises_an_alarm() {
    let mut endpoint = Endpoint::assigned(GROUP_A);
    endpoint.applied(&policy(1, GROUP_A, 5).jws());
    let list = [policy(1, GROUP_A, 5)
        .with("status_ui", json!("hidden"))
        .jws()];
    let outcome = endpoint.receive_list(&list).unwrap();
    assert_eq!(processed(&outcome), [Some(DocumentResult::Conflict)]);
    assert_eq!(
        outcome.conflicts(),
        [ConflictAlarm {
            slot: Slot::Policy(id(GROUP_A)),
            version: 5
        }]
    );
}
