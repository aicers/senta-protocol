//! Tests of the key set state machine, the catch-up chain and enrollment.
//!
//! Every document is signed with the deterministic test keys of
//! `test_util` and goes through the public API.

use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::auth::documents::{Hash32, verify_enroll_result, verify_keyset};
use crate::auth::jws::PublicKey;
use crate::auth::jws::test_util::TestKey;

const INSTALL: &str = "install-a";
const OTHER_INSTALL: &str = "install-b";
const CUSTOMER: &str = "c0000000-0000-4000-8000-000000000001";
const OTHER_CUSTOMER: &str = "c0000000-0000-4000-8000-000000000002";
/// Customer key names, one per recovery epoch of the tests.
const NAME_A: &str = "a0000000-0000-4000-8000-00000000000a";
const NAME_B: &str = "b0000000-0000-4000-8000-00000000000b";
const NAME_C: &str = "d0000000-0000-4000-8000-00000000000d";
const ENDPOINT: &str = "e0000000-0000-4000-8000-0000000000e1";
const TOKEN: &str = "f0000000-0000-4000-8000-0000000000f1";
const ATTEMPT: &str = "f0000000-0000-4000-8000-0000000000f2";
const OTHER_ID: &str = "f0000000-0000-4000-8000-0000000000ff";
const SPKI: [u8; 32] = [7; 32];

// --- keys -------------------------------------------------------------------

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

fn rkid(install: &str, version: u64) -> String {
    format!("recovery-{install}:{version}")
}

/// A key no test trusts, to make bad signatures with.
fn stranger() -> TestKey {
    TestKey::from_seed(&[9; 32])
}

fn install_id() -> InstallId {
    InstallId::parse(INSTALL).unwrap()
}

fn uuid(text: &str) -> Uuid {
    Uuid::parse_str(text).unwrap()
}

// --- documents --------------------------------------------------------------

/// A key set of the customer key name `name`, whose keys are versions of
/// that name.
#[derive(Clone)]
struct Ks {
    customer: &'static str,
    name: &'static str,
    epoch: u64,
    version: u64,
    keys: Vec<u64>,
    current: u64,
    revoked: Vec<String>,
}

impl Ks {
    /// The rotation `version` of `name`: its keys are the previous and the
    /// new version, the new one is current, and older versions of the name
    /// are revoked.
    fn rotation(epoch: u64, name: &'static str, version: u64) -> Self {
        let keys = if version == 1 {
            vec![1]
        } else {
            vec![version - 1, version]
        };
        Self {
            customer: CUSTOMER,
            name,
            epoch,
            version,
            keys,
            current: version,
            revoked: (1..version.saturating_sub(1))
                .map(|v| ckid(name, v))
                .collect(),
        }
    }

    fn revoking(mut self, kids: impl IntoIterator<Item = String>) -> Self {
        self.revoked.extend(kids);
        self
    }

    fn payload(&self) -> Vec<u8> {
        let keys: Vec<_> = self
            .keys
            .iter()
            .map(|&v| json!({"kid": ckid(self.name, v), "key": ck(self.name, v).jwk()}))
            .collect();
        serde_json::to_vec(&json!({
            "customer_endpoint_id": self.customer,
            "customer_key_name": format!("endpoint-{}", self.name),
            "recovery_epoch": self.epoch,
            "keyset_version": self.version,
            "keys": keys,
            "current_kid": ckid(self.name, self.current),
            "revoked_kids": self.revoked,
        }))
        .unwrap()
    }

    /// Signed by the customer key `name:version`.
    fn signed_by(&self, name: &str, version: u64) -> String {
        ck(name, version).sign(Typ::Keyset, &ckid(name, version), &self.payload())
    }

    /// Signed by the previous version of its own key name, as a rotation is.
    fn rotated(&self) -> String {
        self.signed_by(self.name, self.version - 1)
    }

    /// Signed by its own `current_kid`.
    fn resigned(&self) -> String {
        self.signed_by(self.name, self.current)
    }

    /// Signed by the recovery key of version `version` of this install.
    fn recovery_signed(&self, version: u64) -> String {
        rk(version).sign(Typ::Keyset, &rkid(INSTALL, version), &self.payload())
    }

    /// Signed by a key that is not the kid's.
    fn forged(&self, kid: &str) -> String {
        stranger().sign(Typ::Keyset, kid, &self.payload())
    }
}

fn recovery_payload(install: &str, version: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "install_id": install,
        "recovery_key_version": version,
        "recovery_key": rk(version).jwk(),
    }))
    .unwrap()
}

/// The recovery key replacement to `version`, signed by the version before.
fn rk_doc(version: u64) -> String {
    rk(version - 1).sign(
        Typ::RecoveryKey,
        &rkid(INSTALL, version - 1),
        &recovery_payload(INSTALL, version),
    )
}

fn enroll_payload(epoch: u64, spki: [u8; 32], token: &str, attempt: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "recovery_epoch": epoch,
        "endpoint_id": ENDPOINT,
        "spki_sha256": Hash32::from(spki),
        "token_id": token,
        "attempt_id": attempt,
    }))
    .unwrap()
}

fn enroll_result(name: &str, version: u64, epoch: u64) -> String {
    ck(name, version).sign(
        Typ::EnrollResult,
        &ckid(name, version),
        &enroll_payload(epoch, SPKI, TOKEN, ATTEMPT),
    )
}

fn attempt() -> EnrollAttempt {
    EnrollAttempt {
        spki_sha256: SPKI,
        attempt_id: uuid(ATTEMPT),
        token_id: uuid(TOKEN),
    }
}

// --- states -------------------------------------------------------------------

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

/// The state of an endpoint that trusts `ks`, signed by its own current key,
/// and the recovery key of version `recovery_version`.
fn state_at(ks: &Ks, recovery_version: u64) -> TrustState {
    let source = OneKey {
        kid: ckid(ks.name, ks.current),
        key: ck(ks.name, ks.current).public_key(),
    };
    let verified = verify_keyset(&ks.resigned(), &source).unwrap();
    TrustState::new(
        verified,
        install_id(),
        rk(recovery_version).jwk(),
        PositiveInteger::new(recovery_version).unwrap(),
    )
}

/// The state of an endpoint that has just installed: (1, 1) of `NAME_A`,
/// recovery key 1.
fn installed() -> TrustState {
    state_at(&Ks::rotation(1, NAME_A, 1), 1)
}

fn snapshot(state: &TrustState) -> String {
    serde_json::to_string(state).unwrap()
}

fn kids(entries: &[KeysetEntry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.kid.as_str()).collect()
}

fn strs(kids: &[CustomerKid]) -> Vec<&str> {
    kids.iter().map(CustomerKid::as_str).collect()
}

fn position(state: &TrustState) -> (u64, u64, u64) {
    (
        state.recovery_epoch(),
        state.keyset_version(),
        state.recovery_key_version(),
    )
}

/// Asserts that receiving `jws` as a key set gives `expected`, no epoch
/// change, and leaves the state as it was.
#[track_caller]
fn assert_keyset_rejected(state: &mut TrustState, jws: &str, expected: &DocumentResult) {
    let before = snapshot(state);
    let receipt = state.receive_keyset(jws);
    assert_eq!(receipt.result(), expected);
    assert_eq!(receipt.epoch_change(), None);
    assert_eq!(snapshot(state), before);
}

#[track_caller]
fn assert_recovery_rejected(state: &mut TrustState, jws: &str, expected: &DocumentResult) {
    let before = snapshot(state);
    assert_eq!(&state.receive_recovery_key(jws), expected);
    assert_eq!(snapshot(state), before);
}

#[track_caller]
fn assert_applied(state: &mut TrustState, jws: &str) -> Option<EpochChange> {
    let receipt = state.receive_keyset(jws);
    assert_eq!(receipt.result(), &DocumentResult::Applied);
    receipt.epoch_change()
}

fn gap(have_epoch: u64, have_version: u64) -> DocumentResult {
    DocumentResult::KeysetGap {
        have_epoch,
        have_version,
    }
}

// --- trust state --------------------------------------------------------------

#[test]
fn state_reports_what_it_trusts() {
    let state = installed();
    assert_eq!(state.install_id().as_str(), INSTALL);
    assert_eq!(state.customer_endpoint_id().get(), uuid(CUSTOMER));
    assert_eq!(
        state.customer_key_name().to_string(),
        format!("endpoint-{NAME_A}")
    );
    assert_eq!(position(&state), (1, 1, 1));
    assert_eq!(kids(state.keys()), [ckid(NAME_A, 1)]);
    assert_eq!(state.current_kid().as_str(), ckid(NAME_A, 1));
    assert!(state.revoked_kids().is_empty());
    assert_eq!(state.recovery_key(), &rk(1).jwk());
}

#[test]
fn rotations_apply_in_order() {
    let mut state = installed();
    for version in 2..=3 {
        let ks = Ks::rotation(1, NAME_A, version);
        assert_eq!(assert_applied(&mut state, &ks.rotated()), None);
        assert_eq!(position(&state), (1, version, 1));
        let expected_keys: Vec<_> = ks.keys.iter().map(|&v| ckid(NAME_A, v)).collect();
        assert_eq!(kids(state.keys()), expected_keys);
        assert_eq!(state.current_kid().as_str(), ckid(NAME_A, version));
        assert_eq!(strs(state.revoked_kids()), ks.revoked);
    }
    assert_eq!(strs(state.revoked_kids()), [ckid(NAME_A, 1)]);
}

#[test]
fn next_version_must_be_signed_by_current_kid() {
    let mut state = installed();
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated());
    // Now keys A1, A2 with A2 current.
    let v3 = Ks::rotation(1, NAME_A, 3);
    // Another kid of `keys`.
    assert_keyset_rejected(
        &mut state,
        &v3.signed_by(NAME_A, 1),
        &DocumentResult::UnknownKid,
    );
    // The recovery key, at the same epoch.
    assert_keyset_rejected(
        &mut state,
        &v3.recovery_signed(1),
        &DocumentResult::UnknownKid,
    );
    // A kid the state does not know at all.
    assert_keyset_rejected(
        &mut state,
        &v3.signed_by(NAME_C, 1),
        &DocumentResult::UnknownKid,
    );
    // The current kid, with a signature that does not verify.
    assert_keyset_rejected(
        &mut state,
        &v3.forged(&ckid(NAME_A, 2)),
        &DocumentResult::BadSignature,
    );
    assert_applied(&mut state, &v3.rotated());

    // A1 is revoked by v3.
    assert_keyset_rejected(
        &mut state,
        &Ks::rotation(1, NAME_A, 4).signed_by(NAME_A, 1),
        &DocumentResult::RevokedKid,
    );
}

#[test]
fn version_gap_in_the_same_epoch() {
    let mut state = installed();
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated());
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 3).rotated());
    let v5 = Ks::rotation(1, NAME_A, 5);
    assert_keyset_rejected(&mut state, &v5.rotated(), &gap(1, 3));
    // No signature is checked for a gap.
    assert_keyset_rejected(&mut state, &v5.forged(&ckid(NAME_A, 4)), &gap(1, 3));
    // N + 1 still applies.
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 4).rotated());
}

#[test]
fn recovery_raises_the_epoch() {
    for epoch in [2, 3] {
        let mut state = installed();
        let ks = Ks::rotation(epoch, NAME_B, 1).revoking([ckid(NAME_A, 1)]);
        let change = assert_applied(&mut state, &ks.recovery_signed(1));
        assert_eq!(
            change,
            Some(EpochChange {
                old_epoch: 1,
                new_epoch: epoch
            })
        );
        assert_eq!(position(&state), (epoch, 1, 1));
        assert_eq!(
            state.customer_key_name().to_string(),
            format!("endpoint-{NAME_B}")
        );
        assert_eq!(kids(state.keys()), [ckid(NAME_B, 1)]);
        assert_eq!(state.current_kid().as_str(), ckid(NAME_B, 1));
        assert_eq!(strs(state.revoked_kids()), [ckid(NAME_A, 1)]);
    }
}

#[test]
fn recovery_document_checks_its_signer() {
    let mut state = installed();
    assert_eq!(
        state.receive_recovery_key(&rk_doc(2)),
        DocumentResult::Applied
    );
    assert_eq!(state.recovery_key_version(), 2);

    // A version other than 1 is a schema error before anything else.
    for signer in [1, 2, 3] {
        assert_keyset_rejected(
            &mut state,
            &Ks::rotation(2, NAME_B, 2).recovery_signed(signer),
            &DocumentResult::SchemaError,
        );
    }

    let ks = Ks::rotation(2, NAME_B, 1);
    // V - 1.
    assert_keyset_rejected(
        &mut state,
        &ks.recovery_signed(1),
        &DocumentResult::UnknownKid,
    );
    // V + 1.
    assert_keyset_rejected(
        &mut state,
        &ks.recovery_signed(3),
        &DocumentResult::RecoveryKeyGap { have: 2 },
    );
    // Another install's recovery key of version V.
    assert_keyset_rejected(
        &mut state,
        &rk(2).sign(Typ::Keyset, &rkid(OTHER_INSTALL, 2), &ks.payload()),
        &DocumentResult::UnknownKid,
    );
    // The kid of V with a signature that does not verify.
    assert_keyset_rejected(
        &mut state,
        &ks.forged(&rkid(INSTALL, 2)),
        &DocumentResult::BadSignature,
    );
    // A customer kid on a later epoch: the recovery key set was missed.
    assert_keyset_rejected(&mut state, &ks.resigned(), &gap(1, 1));
    assert_keyset_rejected(
        &mut state,
        &Ks::rotation(2, NAME_B, 2).rotated(),
        &gap(1, 1),
    );
    // V.
    assert_applied(&mut state, &ks.recovery_signed(2));
}

#[test]
fn held_versions_are_duplicates_whoever_signed_them() {
    let mut state = installed();
    let v2 = Ks::rotation(1, NAME_A, 2);
    assert_applied(&mut state, &v2.rotated());
    // v3 drops A2 from `keys` without revoking it, and v4 revokes A3.
    let mut v3 = Ks::rotation(1, NAME_A, 3);
    v3.keys = vec![3];
    v3.revoked = vec![];
    assert_applied(&mut state, &v3.rotated());
    let mut v4 = Ks::rotation(1, NAME_A, 4);
    v4.keys = vec![4];
    v4.revoked = vec![ckid(NAME_A, 3)];
    assert_applied(&mut state, &v4.signed_by(NAME_A, 3));

    let duplicate = DocumentResult::Duplicate;
    // Signed by a key since removed from `keys`.
    assert_keyset_rejected(&mut state, &v3.rotated(), &duplicate);
    // Signed by a key since revoked.
    assert_keyset_rejected(&mut state, &v4.signed_by(NAME_A, 3), &duplicate);
    // A bad signature.
    assert_keyset_rejected(&mut state, &v4.forged(&ckid(NAME_A, 4)), &duplicate);
    // A copy signed by the recovery key.
    assert_keyset_rejected(&mut state, &v4.recovery_signed(1), &duplicate);
    // Lower versions.
    assert_keyset_rejected(&mut state, &v2.rotated(), &duplicate);
    assert_keyset_rejected(
        &mut state,
        &Ks::rotation(1, NAME_A, 1).resigned(),
        &duplicate,
    );

    // After a recovery, a lower epoch at any version is a duplicate too.
    let recovered = Ks::rotation(2, NAME_B, 1);
    assert_applied(&mut state, &recovered.recovery_signed(1));
    assert_keyset_rejected(
        &mut state,
        &Ks::rotation(1, NAME_A, 9).rotated(),
        &duplicate,
    );
    // The re-signed copy of the recovery key set.
    assert_keyset_rejected(&mut state, &recovered.resigned(), &duplicate);
}

#[test]
fn another_customer_is_wrong_target_even_when_older() {
    let mut state = installed();
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated());
    for version in [1, 2, 3] {
        let mut ks = Ks::rotation(1, NAME_A, version);
        ks.customer = OTHER_CUSTOMER;
        assert_keyset_rejected(&mut state, &ks.resigned(), &DocumentResult::WrongTarget);
    }
    let mut recovery = Ks::rotation(2, NAME_B, 1);
    recovery.customer = OTHER_CUSTOMER;
    assert_keyset_rejected(
        &mut state,
        &recovery.recovery_signed(1),
        &DocumentResult::WrongTarget,
    );
}

#[test]
fn unreadable_key_sets_are_schema_errors() {
    let mut state = installed();
    let schema = DocumentResult::SchemaError;
    assert_keyset_rejected(&mut state, "not a jws", &schema);
    assert_keyset_rejected(&mut state, &rk_doc(2), &schema);
    let policy = ck(NAME_A, 1).sign(Typ::Policy, &ckid(NAME_A, 1), b"{}");
    assert_keyset_rejected(&mut state, &policy, &schema);
    let broken = ck(NAME_A, 1).sign(Typ::Keyset, &ckid(NAME_A, 1), b"{}");
    assert_keyset_rejected(&mut state, &broken, &schema);
}

#[test]
fn recovery_key_replacement() {
    let mut state = installed();
    assert_eq!(
        state.receive_recovery_key(&rk_doc(2)),
        DocumentResult::Applied
    );
    assert_eq!(state.recovery_key_version(), 2);
    assert_eq!(state.recovery_key(), &rk(2).jwk());

    // V + 2 or more.
    assert_recovery_rejected(
        &mut state,
        &rk_doc(4),
        &DocumentResult::RecoveryKeyGap { have: 2 },
    );
    // V or below, whatever the signature.
    assert_recovery_rejected(&mut state, &rk_doc(2), &DocumentResult::Duplicate);
    assert_recovery_rejected(
        &mut state,
        &stranger().sign(
            Typ::RecoveryKey,
            &rkid(INSTALL, 7),
            &recovery_payload(INSTALL, 1),
        ),
        &DocumentResult::Duplicate,
    );
    // Another install, even at a lower version.
    for version in [1, 3] {
        assert_recovery_rejected(
            &mut state,
            &rk(2).sign(
                Typ::RecoveryKey,
                &rkid(OTHER_INSTALL, 2),
                &recovery_payload(OTHER_INSTALL, version),
            ),
            &DocumentResult::WrongTarget,
        );
    }
    // V + 1 signed by a kid other than `recovery-<install>:<V>`.
    let v3 = recovery_payload(INSTALL, 3);
    for (key, kid) in [
        (rk(1), rkid(INSTALL, 1)),
        (rk(3), rkid(INSTALL, 3)),
        (rk(2), rkid(OTHER_INSTALL, 2)),
    ] {
        assert_recovery_rejected(
            &mut state,
            &key.sign(Typ::RecoveryKey, &kid, &v3),
            &DocumentResult::UnknownKid,
        );
    }
    // V + 1 with a bad signature.
    assert_recovery_rejected(
        &mut state,
        &stranger().sign(Typ::RecoveryKey, &rkid(INSTALL, 2), &v3),
        &DocumentResult::BadSignature,
    );
    // A customer key may not sign one at all.
    assert_recovery_rejected(
        &mut state,
        &ck(NAME_A, 1).sign(Typ::RecoveryKey, &ckid(NAME_A, 1), &v3),
        &DocumentResult::WrongKeyClass,
    );
    assert_recovery_rejected(
        &mut state,
        &Ks::rotation(1, NAME_A, 2).rotated(),
        &DocumentResult::SchemaError,
    );

    assert_eq!(
        state.receive_recovery_key(&rk_doc(3)),
        DocumentResult::Applied
    );
    assert_eq!(state.recovery_key_version(), 3);
    assert_eq!(state.recovery_key(), &rk(3).jwk());
}

#[test]
fn only_a_recovery_brings_an_epoch_change() {
    let mut state = installed();
    // An ordinary rotation.
    assert_eq!(
        assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated()),
        None
    );
    // A duplicate and a rejection.
    assert_eq!(
        state
            .receive_keyset(&Ks::rotation(1, NAME_A, 2).rotated())
            .epoch_change(),
        None
    );
    assert_eq!(
        state
            .receive_keyset(&Ks::rotation(2, NAME_B, 1).recovery_signed(2))
            .epoch_change(),
        None
    );
    // A recovery key replacement.
    let outcome = state.receive_chain(&[rk_doc(2)]);
    assert_eq!(outcome.results(), [DocumentResult::Applied]);
    assert!(outcome.epoch_changes().is_empty());
    // A recovery.
    let outcome = state.receive_chain(&[Ks::rotation(4, NAME_B, 1).recovery_signed(2)]);
    assert_eq!(
        outcome.epoch_changes(),
        [EpochChange {
            old_epoch: 1,
            new_epoch: 4
        }]
    );
}

#[test]
fn state_is_a_key_source_for_customer_documents() {
    let mut state = installed();
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated());
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 3).rotated());
    // keys A2, A3; revoked A1.
    let customer = [KeyKind::Customer];
    for version in [2, 3] {
        let kid = Kid::parse(&ckid(NAME_A, version)).unwrap();
        assert_eq!(
            state.find_key(&kid, &customer),
            KeyLookup::Found {
                key: ck(NAME_A, version).public_key(),
                kind: KeyKind::Customer,
            }
        );
        assert_eq!(
            state.find_key(&kid, &[KeyKind::Recovery]),
            KeyLookup::Unknown
        );
    }
    let revoked = Kid::parse(&ckid(NAME_A, 1)).unwrap();
    assert_eq!(state.find_key(&revoked, &customer), KeyLookup::Revoked);
    for unknown in [ckid(NAME_A, 4), ckid(NAME_B, 2), rkid(INSTALL, 1)] {
        let kid = Kid::parse(&unknown).unwrap();
        assert_eq!(
            state.find_key(&kid, &[KeyKind::Customer, KeyKind::Recovery]),
            KeyLookup::Unknown,
            "{unknown}"
        );
    }

    let result = enroll_result(NAME_A, 3, 1);
    assert!(verify_enroll_result(&result, &state).is_ok());
    let revoked_result = enroll_result(NAME_A, 1, 1);
    assert_eq!(
        verify_enroll_result(&revoked_result, &state)
            .unwrap_err()
            .result(),
        DocumentResult::RevokedKid
    );
}

#[test]
fn state_read_back_gives_the_same_verdicts() {
    let mut state = installed();
    assert_applied(&mut state, &Ks::rotation(1, NAME_A, 2).rotated());
    assert_eq!(
        state.receive_recovery_key(&rk_doc(2)),
        DocumentResult::Applied
    );

    let json = serde_json::to_string(&state).unwrap();
    let from_json: TrustState = serde_json::from_str(&json).unwrap();
    let mut cbor = Vec::new();
    ciborium::into_writer(&state, &mut cbor).unwrap();
    let from_cbor: TrustState = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert_eq!(from_json, state);
    assert_eq!(from_cbor, state);

    let documents = [
        Ks::rotation(1, NAME_A, 4).rotated(),
        Ks::rotation(1, NAME_A, 3).signed_by(NAME_A, 1),
        Ks::rotation(1, NAME_A, 2).forged(&ckid(NAME_A, 2)),
        Ks::rotation(2, NAME_B, 1).recovery_signed(1),
        Ks::rotation(1, NAME_A, 3).rotated(),
        rk_doc(4),
        rk_doc(3),
        Ks::rotation(2, NAME_B, 1).recovery_signed(3),
    ];
    for mut copy in [from_json, from_cbor] {
        let mut original = state.clone();
        for jws in &documents {
            let expected = original.receive_chain(std::slice::from_ref(jws));
            let actual = copy.receive_chain(std::slice::from_ref(jws));
            assert_eq!(actual, expected);
            assert_eq!(copy, original);
        }
        assert_eq!(position(&copy), (2, 1, 3));
    }
    // A state in which `current_kid` is not among `keys` does not read.
    let current = format!(r#""current_kid":"{}""#, ckid(NAME_A, 2));
    assert!(json.contains(&current));
    let broken = json.replace(&current, &format!(r#""current_kid":"{}""#, ckid(NAME_A, 9)));
    assert!(serde_json::from_str::<TrustState>(&broken).is_err());
}

// --- receiving a chain ----------------------------------------------------------

#[test]
fn chain_stops_at_the_first_rejection() {
    let mut state = installed();
    let chain = [
        Ks::rotation(1, NAME_A, 2).rotated(),
        Ks::rotation(1, NAME_A, 2).rotated(),
        Ks::rotation(1, NAME_A, 4).rotated(),
        Ks::rotation(1, NAME_A, 3).rotated(),
    ];
    let outcome = state.receive_chain(&chain);
    assert_eq!(
        outcome.results(),
        [
            DocumentResult::Applied,
            DocumentResult::Duplicate,
            gap(1, 2)
        ]
    );
    assert!(outcome.is_stopped());
    assert_eq!(outcome.stopped_at(), Some((2, &gap(1, 2))));
    // v2 stays applied, and v3, after the stop, was not processed.
    assert_eq!(position(&state), (1, 2, 1));

    let outcome = state.receive_chain(&[Ks::rotation(1, NAME_A, 3).rotated()]);
    assert!(!outcome.is_stopped());
    assert_eq!(outcome.stopped_at(), None);
    assert_eq!(position(&state), (1, 3, 1));
}

#[test]
fn chain_stops_at_another_typ() {
    let mut state = installed();
    let policy = ck(NAME_A, 2).sign(Typ::Policy, &ckid(NAME_A, 2), b"{}");
    let chain = [
        Ks::rotation(1, NAME_A, 2).rotated(),
        policy,
        Ks::rotation(1, NAME_A, 3).rotated(),
    ];
    let outcome = state.receive_chain(&chain);
    assert_eq!(
        outcome.results(),
        [DocumentResult::Applied, DocumentResult::SchemaError]
    );
    assert!(outcome.is_stopped());
    assert_eq!(position(&state), (1, 2, 1));
}

#[test]
fn chain_stops_at_a_recovery_key_rejection() {
    let mut state = installed();
    let chain = [
        rk_doc(2),
        rk_doc(4),
        Ks::rotation(2, NAME_B, 1).recovery_signed(2),
    ];
    let outcome = state.receive_chain(&chain);
    assert_eq!(
        outcome.results(),
        [
            DocumentResult::Applied,
            DocumentResult::RecoveryKeyGap { have: 2 }
        ]
    );
    assert!(outcome.epoch_changes().is_empty());
    assert_eq!(position(&state), (1, 1, 2));
}

// --- building a chain -------------------------------------------------------------

/// A history and the chain it must give from its baseline.
struct Case {
    name: &'static str,
    baseline_keyset: Ks,
    baseline: CatchUpBaseline,
    keysets: Vec<String>,
    recovery_keys: Vec<String>,
    expected: Vec<String>,
    latest: (u64, u64, u64),
}

fn baseline(
    recovery_epoch: u64,
    keyset_version: u64,
    recovery_key_version: u64,
) -> CatchUpBaseline {
    CatchUpBaseline {
        recovery_epoch,
        keyset_version,
        recovery_key_version,
    }
}

fn build(
    keysets: &[String],
    recovery_keys: &[String],
    baseline: CatchUpBaseline,
) -> Result<Vec<String>, CatchUpError> {
    build_catch_up_chain(
        uuid(CUSTOMER),
        &install_id(),
        keysets,
        recovery_keys,
        baseline,
    )
    .map(|chain| chain.into_iter().map(str::to_owned).collect())
}

fn rotations(
    epoch: u64,
    name: &'static str,
    versions: std::ops::RangeInclusive<u64>,
) -> Vec<String> {
    versions
        .map(|version| Ks::rotation(epoch, name, version).rotated())
        .collect()
}

fn cases() -> Vec<Case> {
    let a1 = Ks::rotation(1, NAME_A, 1);
    let b1 = Ks::rotation(2, NAME_B, 1).revoking([ckid(NAME_A, 1), ckid(NAME_A, 2)]);
    let c1 = Ks::rotation(3, NAME_C, 1);
    vec![
        // No epoch change.
        Case {
            name: "no epoch change",
            baseline_keyset: a1.clone(),
            baseline: baseline(1, 1, 1),
            keysets: [vec![a1.resigned()], rotations(1, NAME_A, 2..=4)].concat(),
            recovery_keys: vec![],
            expected: rotations(1, NAME_A, 2..=4),
            latest: (1, 4, 1),
        },
        // One epoch change, signed by the baseline's recovery key, with no
        // replacement history at all; the re-signed copy stays out.
        Case {
            name: "one epoch change, no replacements",
            baseline_keyset: a1.clone(),
            baseline: baseline(1, 1, 1),
            keysets: [
                vec![a1.resigned(), b1.resigned(), b1.recovery_signed(1)],
                rotations(1, NAME_A, 2..=2),
                rotations(2, NAME_B, 2..=3),
            ]
            .concat(),
            recovery_keys: vec![],
            expected: [
                rotations(1, NAME_A, 2..=2),
                vec![b1.recovery_signed(1)],
                rotations(2, NAME_B, 2..=3),
            ]
            .concat(),
            latest: (2, 3, 1),
        },
        // Two epoch changes, with replacements before each recovery key set
        // and one after the last.
        Case {
            name: "two epoch changes",
            baseline_keyset: a1.clone(),
            baseline: baseline(1, 1, 1),
            keysets: [
                rotations(1, NAME_A, 2..=2),
                vec![b1.recovery_signed(2), b1.resigned()],
                rotations(2, NAME_B, 2..=2),
                vec![c1.recovery_signed(3), c1.resigned()],
                rotations(3, NAME_C, 2..=2),
            ]
            .concat(),
            recovery_keys: vec![rk_doc(2), rk_doc(3), rk_doc(4)],
            expected: [
                rotations(1, NAME_A, 2..=2),
                vec![rk_doc(2), b1.recovery_signed(2)],
                rotations(2, NAME_B, 2..=2),
                vec![rk_doc(3), c1.recovery_signed(3)],
                rotations(3, NAME_C, 2..=2),
                vec![rk_doc(4)],
            ]
            .concat(),
            latest: (3, 2, 4),
        },
        // R1 trusted, R2 and R3 missed, the recovery key set signed by R3.
        Case {
            name: "replacements missed before a recovery",
            baseline_keyset: Ks::rotation(1, NAME_A, 2),
            baseline: baseline(1, 2, 1),
            keysets: [
                rotations(1, NAME_A, 2..=2),
                vec![b1.recovery_signed(3)],
                rotations(2, NAME_B, 2..=3),
            ]
            .concat(),
            recovery_keys: vec![rk_doc(3), rk_doc(2)],
            expected: [
                vec![rk_doc(2), rk_doc(3), b1.recovery_signed(3)],
                rotations(2, NAME_B, 2..=3),
            ]
            .concat(),
            latest: (2, 3, 3),
        },
        // Only replacements at or below the baseline's, the recovery key set
        // signed by the baseline's recovery key, and an epoch skipped.
        Case {
            name: "replacements only below the baseline",
            baseline_keyset: Ks::rotation(1, NAME_A, 2),
            baseline: baseline(1, 2, 3),
            keysets: [
                rotations(1, NAME_A, 2..=2),
                vec![c1.recovery_signed(3)],
                rotations(3, NAME_C, 2..=2),
            ]
            .concat(),
            recovery_keys: vec![rk_doc(2), rk_doc(3)],
            expected: [vec![c1.recovery_signed(3)], rotations(3, NAME_C, 2..=2)].concat(),
            latest: (3, 2, 3),
        },
        // A baseline epoch whose version 1 the history has only re-signed, as
        // the install configuration carries it.
        Case {
            name: "baseline epoch re-signed only",
            baseline_keyset: Ks::rotation(2, NAME_B, 1),
            baseline: baseline(2, 1, 2),
            keysets: [
                vec![Ks::rotation(2, NAME_B, 1).resigned()],
                rotations(2, NAME_B, 2..=3),
            ]
            .concat(),
            recovery_keys: vec![rk_doc(2)],
            expected: rotations(2, NAME_B, 2..=3),
            latest: (2, 3, 2),
        },
        // Only a replacement after the baseline.
        Case {
            name: "replacement only",
            baseline_keyset: Ks::rotation(1, NAME_A, 2),
            baseline: baseline(1, 2, 1),
            keysets: rotations(1, NAME_A, 2..=2),
            recovery_keys: vec![rk_doc(2), rk_doc(2)],
            expected: vec![rk_doc(2)],
            latest: (1, 2, 2),
        },
        // A baseline at the latest documents.
        Case {
            name: "up to date",
            baseline_keyset: Ks::rotation(1, NAME_A, 3),
            baseline: baseline(1, 3, 2),
            keysets: rotations(1, NAME_A, 2..=3),
            recovery_keys: vec![rk_doc(2)],
            expected: vec![],
            latest: (1, 3, 2),
        },
    ]
}

/// Orders of the same input: as given, reversed, rotated, and interleaved.
fn orders(documents: &[String]) -> Vec<Vec<String>> {
    let mut orders = vec![documents.to_vec()];
    let mut reversed = documents.to_vec();
    reversed.reverse();
    orders.push(reversed);
    for shift in 1..documents.len() {
        let mut rotated = documents.to_vec();
        rotated.rotate_left(shift);
        orders.push(rotated);
    }
    let (even, odd): (Vec<_>, Vec<_>) = documents
        .iter()
        .enumerate()
        .partition(|(index, _)| index % 2 == 0);
    orders.push(
        odd.into_iter()
            .chain(even)
            .map(|(_, jws)| jws.clone())
            .collect(),
    );
    orders
}

#[test]
fn chain_order_is_fixed_whatever_the_input_order() {
    for case in cases() {
        for keysets in orders(&case.keysets) {
            for recovery_keys in orders(&case.recovery_keys) {
                let chain = build(&keysets, &recovery_keys, case.baseline)
                    .unwrap_or_else(|error| panic!("{}: {error}", case.name));
                assert_eq!(chain, case.expected, "{}", case.name);
            }
        }
    }
}

#[test]
fn built_chains_apply_from_the_baseline() {
    for case in cases() {
        let chain = build(&case.keysets, &case.recovery_keys, case.baseline).unwrap();
        let mut state = state_at(&case.baseline_keyset, case.baseline.recovery_key_version);
        assert_eq!(
            position(&state),
            (
                case.baseline.recovery_epoch,
                case.baseline.keyset_version,
                case.baseline.recovery_key_version
            ),
            "{}",
            case.name
        );
        let outcome = state.receive_chain(&chain);
        assert!(!outcome.is_stopped(), "{}", case.name);
        assert!(
            outcome
                .results()
                .iter()
                .all(|result| *result == DocumentResult::Applied),
            "{}: {:?}",
            case.name,
            outcome.results()
        );
        assert_eq!(outcome.results().len(), chain.len(), "{}", case.name);
        assert_eq!(position(&state), case.latest, "{}", case.name);

        // The same chain again: every document a duplicate, even though the
        // keys that signed the early ones have since been revoked.
        let before = snapshot(&state);
        let again = state.receive_chain(&chain);
        assert!(
            again
                .results()
                .iter()
                .all(|result| *result == DocumentResult::Duplicate),
            "{}",
            case.name
        );
        assert!(again.epoch_changes().is_empty());
        assert_eq!(snapshot(&state), before, "{}", case.name);
    }
}

#[test]
fn rereceived_chain_with_a_new_version_applies_only_that() {
    let case = cases().into_iter().nth(2).unwrap();
    let chain = build(&case.keysets, &case.recovery_keys, case.baseline).unwrap();
    let mut state = state_at(&case.baseline_keyset, case.baseline.recovery_key_version);
    let outcome = state.receive_chain(&chain);
    assert_eq!(
        outcome.epoch_changes(),
        [
            EpochChange {
                old_epoch: 1,
                new_epoch: 2
            },
            EpochChange {
                old_epoch: 2,
                new_epoch: 3
            }
        ]
    );
    // The earliest signers, A1 and B1, are out of the key set by now.
    assert!(
        !kids(state.keys()).contains(&ckid(NAME_A, 1).as_str())
            && !kids(state.keys()).contains(&ckid(NAME_B, 1).as_str())
    );

    let mut longer = chain.clone();
    longer.push(Ks::rotation(3, NAME_C, 3).rotated());
    let outcome = state.receive_chain(&longer);
    let mut expected = vec![DocumentResult::Duplicate; chain.len()];
    expected.push(DocumentResult::Applied);
    assert_eq!(outcome.results(), expected);
    assert_eq!(position(&state), (3, 3, 4));
}

#[test]
fn recovery_signed_version_one_is_required_after_the_baseline() {
    let b1 = Ks::rotation(2, NAME_B, 1);
    let keysets = [
        rotations(1, NAME_A, 2..=2),
        vec![b1.resigned()],
        rotations(2, NAME_B, 2..=2),
    ]
    .concat();
    assert!(matches!(
        build(&keysets, &[], baseline(1, 2, 1)),
        Err(CatchUpError::MissingRecoverySigned { epoch: 2 })
    ));
}

#[test]
fn chain_building_rejects_bad_histories() {
    let a1 = Ks::rotation(1, NAME_A, 1);
    let b1 = Ks::rotation(2, NAME_B, 1);
    let base = baseline(1, 1, 1);
    let no_rk: [String; 0] = [];

    // Unreadable documents.
    assert!(matches!(
        build(&["x".to_owned()], &no_rk, base),
        Err(CatchUpError::UnreadableKeyset { index: 0, .. })
    ));
    assert!(matches!(
        build(&[a1.resigned(), rk_doc(2)], &no_rk, base),
        Err(CatchUpError::UnreadableKeyset { index: 1, .. })
    ));
    assert!(matches!(
        build(&[], &[a1.resigned()], base),
        Err(CatchUpError::UnreadableRecoveryKey { index: 0, .. })
    ));

    // A recovery key not signed by the version before it, at or below the
    // baseline too.
    let skipped = rk(1).sign(
        Typ::RecoveryKey,
        &rkid(INSTALL, 1),
        &recovery_payload(INSTALL, 3),
    );
    assert!(matches!(
        build(&[], &[rk_doc(2), skipped], base),
        Err(CatchUpError::RecoveryKeyWrongSigner {
            index: 1,
            version: 3
        })
    ));
    let self_signed = rk(2).sign(
        Typ::RecoveryKey,
        &rkid(INSTALL, 2),
        &recovery_payload(INSTALL, 2),
    );
    assert!(matches!(
        build(&[], &[self_signed], baseline(1, 1, 5)),
        Err(CatchUpError::RecoveryKeyWrongSigner {
            index: 0,
            version: 2
        })
    ));
    let first = rk(1).sign(
        Typ::RecoveryKey,
        &rkid(INSTALL, 1),
        &recovery_payload(INSTALL, 1),
    );
    assert!(matches!(
        build(&[], &[first], base),
        Err(CatchUpError::RecoveryKeyWrongSigner { version: 1, .. })
    ));

    // Another customer, another install, another install's recovery key.
    let mut other = Ks::rotation(1, NAME_A, 1);
    other.customer = OTHER_CUSTOMER;
    assert!(matches!(
        build(&[other.resigned()], &no_rk, baseline(1, 5, 1)),
        Err(CatchUpError::KeysetWrongCustomer { index: 0 })
    ));
    let foreign = rk(1).sign(
        Typ::RecoveryKey,
        &rkid(OTHER_INSTALL, 1),
        &recovery_payload(OTHER_INSTALL, 2),
    );
    assert!(matches!(
        build(&[], &[rk_doc(2), foreign], base),
        Err(CatchUpError::RecoveryKeyWrongInstall { index: 1 })
    ));
    let foreign_signed = rk(1).sign(Typ::Keyset, &rkid(OTHER_INSTALL, 1), &b1.payload());
    assert!(matches!(
        build(&[foreign_signed], &no_rk, base),
        Err(CatchUpError::KeysetForeignRecoveryKey { index: 0 })
    ));

    // The same version with different content, below the baseline too.
    let mut changed = Ks::rotation(1, NAME_A, 2);
    changed.keys = vec![2];
    assert!(matches!(
        build(
            &[Ks::rotation(1, NAME_A, 2).rotated(), changed.rotated()],
            &no_rk,
            baseline(1, 5, 1)
        ),
        Err(CatchUpError::KeysetConflict {
            epoch: 1,
            version: 2
        })
    ));
    let changed_rk = rk(1).sign(
        Typ::RecoveryKey,
        &rkid(INSTALL, 1),
        &serde_json::to_vec(&json!({
            "install_id": INSTALL,
            "recovery_key_version": 2,
            "recovery_key": stranger().jwk(),
        }))
        .unwrap(),
    );
    assert!(matches!(
        build(&[], &[rk_doc(2), changed_rk], baseline(1, 1, 9)),
        Err(CatchUpError::RecoveryKeyConflict { version: 2 })
    ));

    // Missing versions.
    assert!(matches!(
        build(&rotations(1, NAME_A, 3..=3), &no_rk, base),
        Err(CatchUpError::MissingKeyset {
            epoch: 1,
            version: 2
        })
    ));
    assert!(matches!(
        build(&rotations(2, NAME_B, 2..=2), &no_rk, base),
        Err(CatchUpError::MissingKeyset {
            epoch: 2,
            version: 1
        })
    ));
    assert!(matches!(
        build(
            &[vec![b1.recovery_signed(1)], rotations(2, NAME_B, 3..=3)].concat(),
            &no_rk,
            base
        ),
        Err(CatchUpError::MissingKeyset {
            epoch: 2,
            version: 2
        })
    ));
    assert!(matches!(
        build(&[], &[rk_doc(3)], base),
        Err(CatchUpError::MissingRecoveryKey { version: 2 })
    ));
    assert!(matches!(
        build(&[b1.recovery_signed(3)], &[rk_doc(3)], base),
        Err(CatchUpError::MissingRecoveryKey { version: 2 })
    ));

    // A recovery key set signed by a recovery key out of reach.
    assert!(matches!(
        build(&[b1.recovery_signed(1)], &no_rk, baseline(1, 1, 2)),
        Err(CatchUpError::RecoverySignerBehind {
            epoch: 2,
            signer: 1,
            trusted: 2
        })
    ));
    let c1 = Ks::rotation(3, NAME_C, 1);
    assert!(matches!(
        build(
            &[b1.recovery_signed(3), c1.recovery_signed(2)],
            &[rk_doc(2), rk_doc(3)],
            base
        ),
        Err(CatchUpError::RecoverySignerBehind {
            epoch: 3,
            signer: 2,
            trusted: 3
        })
    ));
    assert!(matches!(
        build(&[b1.recovery_signed(2)], &no_rk, base),
        Err(CatchUpError::RecoverySignerAhead {
            epoch: 2,
            signer: 2,
            reachable: 1
        })
    ));
    assert!(matches!(
        build(&[b1.recovery_signed(4)], &[rk_doc(2), rk_doc(3)], base),
        Err(CatchUpError::RecoverySignerAhead {
            epoch: 2,
            signer: 4,
            reachable: 3
        })
    ));
}

// --- enrollment -------------------------------------------------------------------

/// The history an enrollment catches up on, from the installed state:
/// (1, 2), (1, 3), recovery key 2, then epoch 2 through (2, 3), where `NAME_B`
/// replaces `NAME_A` and revokes its keys.
fn enroll_history() -> Vec<String> {
    let revoked_a = || (1..=3).map(|v| ckid(NAME_A, v));
    let b1 = Ks::rotation(2, NAME_B, 1).revoking(revoked_a());
    let b2 = Ks::rotation(2, NAME_B, 2).revoking(revoked_a());
    let b3 = Ks::rotation(2, NAME_B, 3).revoking(revoked_a());
    vec![
        Ks::rotation(1, NAME_A, 2).rotated(),
        Ks::rotation(1, NAME_A, 3).rotated(),
        rk_doc(2),
        b1.recovery_signed(2),
        b2.rotated(),
        b3.rotated(),
    ]
}

#[test]
fn enrollment_succeeds_after_the_chain() {
    let state = installed();
    let result = enroll_result(NAME_B, 3, 2);
    // Before the chain, the result's signer is unknown.
    assert_eq!(
        verify_enroll_result(&result, &state).unwrap_err().result(),
        DocumentResult::UnknownKid
    );
    let history = enroll_history();
    let keysets: Vec<String> = std::iter::once(Ks::rotation(1, NAME_A, 1).resigned())
        .chain(history.iter().filter(|jws| **jws != rk_doc(2)).cloned())
        .collect();
    let chain = build(&keysets, &[rk_doc(2)], baseline(1, 1, 1)).unwrap();
    assert_eq!(chain, history);

    let outcome = receive_enroll_result(state, &chain, &result, &attempt());
    assert_eq!(outcome.endpoint_id(), Some(uuid(ENDPOINT)));
    assert_eq!(outcome.result(), Ok(uuid(ENDPOINT)));
    assert_eq!(outcome.failure(), None);
    assert_eq!(
        outcome.epoch_changes(),
        [EpochChange {
            old_epoch: 1,
            new_epoch: 2
        }]
    );
    assert!(
        outcome
            .chain()
            .results()
            .iter()
            .all(|result| *result == DocumentResult::Applied)
    );
    assert_eq!(position(outcome.state()), (2, 3, 2));

    // The same chain and result again.
    let state = outcome.into_state();
    let before = snapshot(&state);
    let again = receive_enroll_result(state, &chain, &result, &attempt());
    assert_eq!(again.endpoint_id(), Some(uuid(ENDPOINT)));
    assert!(
        again
            .chain()
            .results()
            .iter()
            .all(|result| *result == DocumentResult::Duplicate)
    );
    assert!(again.epoch_changes().is_empty());
    assert_eq!(snapshot(again.state()), before);
}

#[track_caller]
fn assert_enroll_fails(result: &str, expected: &EnrollFailure) {
    let outcome = receive_enroll_result(installed(), &enroll_history(), result, &attempt());
    assert_eq!(outcome.failure(), Some(expected));
    assert_eq!(outcome.endpoint_id(), None);
    // The chain stays applied.
    assert_eq!(position(outcome.state()), (2, 3, 2));
    assert_eq!(outcome.epoch_changes().len(), 1);
}

#[test]
fn enrollment_result_must_verify_after_the_chain() {
    // A2, revoked by the recovery key set.
    assert_enroll_fails(
        &enroll_result(NAME_A, 2, 2),
        &EnrollFailure::Rejected(DocumentResult::RevokedKid),
    );
    // B1, revoked by (2, 3).
    assert_enroll_fails(
        &enroll_result(NAME_B, 1, 2),
        &EnrollFailure::Rejected(DocumentResult::RevokedKid),
    );
    assert_enroll_fails(
        &enroll_result(NAME_C, 1, 2),
        &EnrollFailure::Rejected(DocumentResult::UnknownKid),
    );
    assert_enroll_fails(
        &ck(NAME_B, 3).sign(Typ::Policy, &ckid(NAME_B, 3), b"{}"),
        &EnrollFailure::Rejected(DocumentResult::SchemaError),
    );
    assert_enroll_fails(
        &stranger().sign(
            Typ::EnrollResult,
            &ckid(NAME_B, 3),
            &enroll_payload(2, SPKI, TOKEN, ATTEMPT),
        ),
        &EnrollFailure::Rejected(DocumentResult::BadSignature),
    );
}

#[test]
fn enrollment_result_must_match_the_attempt() {
    let signed =
        |payload: Vec<u8>| ck(NAME_B, 3).sign(Typ::EnrollResult, &ckid(NAME_B, 3), &payload);
    let mut other_spki = SPKI;
    other_spki[31] ^= 1;
    assert_enroll_fails(
        &signed(enroll_payload(2, other_spki, TOKEN, ATTEMPT)),
        &EnrollFailure::SpkiMismatch,
    );
    assert_enroll_fails(
        &signed(enroll_payload(2, SPKI, OTHER_ID, ATTEMPT)),
        &EnrollFailure::TokenIdMismatch,
    );
    assert_enroll_fails(
        &signed(enroll_payload(2, SPKI, TOKEN, OTHER_ID)),
        &EnrollFailure::AttemptIdMismatch,
    );
    for epoch in [1, 3] {
        assert_enroll_fails(
            &signed(enroll_payload(epoch, SPKI, TOKEN, ATTEMPT)),
            &EnrollFailure::EpochMismatch {
                result: epoch,
                current: 2,
            },
        );
    }
}

#[test]
fn enrollment_fails_when_the_chain_stops() {
    let history = enroll_history();
    // A result the installed state already trusts the signer of.
    let trusted_result = enroll_result(NAME_A, 1, 1);
    assert!(verify_enroll_result(&trusted_result, &installed()).is_ok());

    let forged_v3 = Ks::rotation(1, NAME_A, 3).forged(&ckid(NAME_A, 2));
    let cases = [
        // (2, 2) missing: (2, 3) is a gap, and (2, 2) after it is not
        // processed.
        (
            vec![
                history[0].clone(),
                history[1].clone(),
                history[2].clone(),
                history[3].clone(),
                history[5].clone(),
                history[4].clone(),
            ],
            4,
            gap(2, 1),
            (2, 1, 2),
            1,
        ),
        // (1, 3) with a bad signature.
        (
            [vec![history[0].clone(), forged_v3], history[1..].to_vec()].concat(),
            1,
            DocumentResult::BadSignature,
            (1, 2, 1),
            0,
        ),
        // The replacement to recovery key 2 missing.
        (
            [history[..2].to_vec(), history[3..].to_vec()].concat(),
            2,
            DocumentResult::RecoveryKeyGap { have: 1 },
            (1, 3, 1),
            0,
        ),
    ];
    for (chain, index, result, at, epoch_changes) in cases {
        for enroll in [&trusted_result, &enroll_result(NAME_B, 3, 2)] {
            let outcome = receive_enroll_result(installed(), &chain, enroll, &attempt());
            assert_eq!(
                outcome.failure(),
                Some(&EnrollFailure::Chain {
                    index,
                    result: result.clone()
                })
            );
            assert_eq!(outcome.endpoint_id(), None);
            assert_eq!(outcome.chain().results().len(), index + 1);
            assert_eq!(position(outcome.state()), at);
            assert_eq!(outcome.epoch_changes().len(), epoch_changes);
        }
    }
}
