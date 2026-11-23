//! Tests of the install configuration trust chain.
//!
//! Every document is signed with the deterministic test keys of
//! `test_util` and goes through the public API. Each failure case breaks
//! one rule and keeps everything else valid; only the step order cases
//! break two.

use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde_json::{Value, json};

use super::*;
use crate::auth::documents::SemVer;
use crate::auth::jws::VerifyError;
use crate::auth::jws::test_util::TestKey;
use crate::auth::versions::{
    DocumentContent, MemoryTrustStore, Slot, SlotStatus, StoreError, TrustStore, VersionState,
};

const INSTALL: &str = "install-a";
const OTHER_INSTALL: &str = "install-b";
const INSTALL_NAME: &str = "Head office";
const OTHER_INSTALL_NAME: &str = "Branch office";
const CUSTOMER: &str = "c0000000-0000-4000-8000-000000000001";
const OTHER_CUSTOMER: &str = "c0000000-0000-4000-8000-000000000002";
/// Customer key names, one per recovery epoch of the tests.
const NAME_A: &str = "a0000000-0000-4000-8000-00000000000a";
const NAME_B: &str = "b0000000-0000-4000-8000-00000000000b";
const TOKEN: &str = "f0000000-0000-4000-8000-0000000000f1";
const EXPIRES_AT: &str = "2026-12-31T00:00:00Z";
const ISSUED_AT: &str = "2026-01-01T00:00:00Z";
const NOW: &str = "2026-11-23T00:00:00Z";
const SENTA: &str = "1.5.0";
const PEM: &str = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
const HW_SALT: [u8; 32] = [5; 32];
/// The recovery epoch of the key set of a plain install configuration.
const EPOCH: u64 = 3;
/// The version of the address document of an install configuration.
const ADDRESSES_VERSION: u64 = 7;
const RELEASE_KID: &str = "vendor-release-1";
const TEST_KID: &str = "vendor-test-1";

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

fn rkid(version: u64) -> String {
    format!("recovery-{INSTALL}:{version}")
}

/// The install signing key of `install`, version 1.
fn isk(install: &str) -> TestKey {
    TestKey::from_seed(&seed(3, install.as_bytes()[install.len() - 1], 1))
}

fn iskid(install: &str) -> String {
    format!("install-{install}:1")
}

/// The vendor key under `kid`, a different one for each kid.
fn vk(kid: &str) -> TestKey {
    let mut seed = [4; 32];
    for (byte, kid_byte) in seed.iter_mut().skip(1).zip(kid.bytes()) {
        *byte = kid_byte;
    }
    TestKey::from_seed(&seed)
}

/// A key nobody trusts, to make bad signatures with.
fn stranger() -> TestKey {
    TestKey::from_seed(&[9; 32])
}

/// The vendor keys of the tests: one release key and one test key.
fn vendor_keys() -> VendorKeys {
    VendorKeys::new([
        (RELEASE_KID, vk(RELEASE_KID).jwk()),
        (TEST_KID, vk(TEST_KID).jwk()),
    ])
    .unwrap()
}

/// Flips the lowest bit of the first byte of the JWS's signature.
fn flip_signature_bit(jws: &str) -> String {
    let (input, signature) = jws.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
    bytes[0] ^= 1;
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// `jws` with its payload replaced by `payload` and its signature kept.
fn with_payload(jws: &str, payload: &[u8]) -> String {
    let mut parts = jws.split('.');
    let header = parts.next().unwrap();
    parts.next().unwrap();
    let signature = parts.next().unwrap();
    format!("{header}.{}.{signature}", URL_SAFE_NO_PAD.encode(payload))
}

fn id(text: &str) -> LowerUuid {
    LowerUuid::parse(text).unwrap()
}

// --- documents --------------------------------------------------------------

/// A key set of `name`, whose keys are versions of that name.
#[derive(Clone)]
struct Ks {
    customer: &'static str,
    name: &'static str,
    epoch: u64,
    version: u64,
    keys: Vec<u64>,
    current: u64,
    revoked: Vec<u64>,
}

impl Ks {
    /// The rotation `version` of `name` in `epoch`: its keys are the
    /// previous and the new version, the new one is current, and older
    /// versions of the name are revoked.
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
            revoked: (1..version.saturating_sub(1)).collect(),
        }
    }

    fn payload(&self) -> Vec<u8> {
        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|&v| json!({"kid": ckid(self.name, v), "key": ck(self.name, v).jwk()}))
            .collect();
        let revoked: Vec<String> = self.revoked.iter().map(|&v| ckid(self.name, v)).collect();
        serde_json::to_vec(&json!({
            "customer_endpoint_id": self.customer,
            "customer_key_name": format!("endpoint-{}", self.name),
            "recovery_epoch": self.epoch,
            "keyset_version": self.version,
            "keys": keys,
            "current_kid": ckid(self.name, self.current),
            "revoked_kids": revoked,
        }))
        .unwrap()
    }

    fn signed_by(&self, version: u64) -> String {
        ck(self.name, version).sign(Typ::Keyset, &ckid(self.name, version), &self.payload())
    }

    /// Signed by its own `current_kid`.
    fn resigned(&self) -> String {
        self.signed_by(self.current)
    }

    /// Signed by the recovery key of version `version`.
    fn recovery_signed(&self, version: u64) -> String {
        rk(version).sign(Typ::Keyset, &rkid(version), &self.payload())
    }
}

fn addresses_payload(epoch: u64, version: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "recovery_epoch": epoch,
        "version": version,
        "control_entries": [],
        "telemetry_entries": [],
        "trust_roots": [PEM],
        "distribution_points": [],
    }))
    .unwrap()
}

fn addresses(epoch: u64, name: &str, signer: u64) -> String {
    ck(name, signer).sign(
        Typ::Addresses,
        &ckid(name, signer),
        &addresses_payload(epoch, ADDRESSES_VERSION),
    )
}

fn enroll_payload() -> Vec<u8> {
    serde_json::to_vec(&json!({"token_id": TOKEN, "expires_at": EXPIRES_AT})).unwrap()
}

fn enroll(name: &str, signer: u64) -> String {
    ck(name, signer).sign(Typ::Enroll, &ckid(name, signer), &enroll_payload())
}

fn cert_payload(install: &str, name: &str) -> Value {
    json!({
        "install_id": install,
        "install_name": name,
        "install_signing_key": isk(install).jwk(),
        "install_signing_kid": iskid(install),
        "issued_at": ISSUED_AT,
    })
}

fn sign_cert(payload: &Value, key: &TestKey, kid: &str) -> String {
    key.sign(
        Typ::DeploymentCert,
        kid,
        &serde_json::to_vec(payload).unwrap(),
    )
}

/// The deployment certificate of `install`, signed by the release key.
fn cert(install: &str, name: &str) -> String {
    sign_cert(&cert_payload(install, name), &vk(RELEASE_KID), RELEASE_KID)
}

/// An install configuration, each field of which a test may replace.
#[derive(Clone)]
struct Config {
    payload: Value,
    signer: String,
    signing_kid: String,
}

impl Config {
    /// A valid install configuration of `INSTALL`, with the key set
    /// (`EPOCH`, 1) of `NAME_A`, the recovery key 2, and documents signed
    /// by `NAME_A:1`.
    fn new() -> Self {
        Self::with_keyset(&Ks::rotation(EPOCH, NAME_A, 1))
    }

    /// A valid install configuration whose key set is `ks`, signed by its
    /// `current_kid`, with the address document and the enrollment token
    /// signed by that kid too.
    fn with_keyset(ks: &Ks) -> Self {
        Self {
            payload: json!({
                "install_id": INSTALL,
                "customer_endpoint_id": ks.customer,
                "customer_key_name": format!("endpoint-{}", ks.name),
                "keyset": ks.resigned(),
                "recovery_key": rk(2).jwk(),
                "recovery_key_version": 2,
                "addresses": addresses(ks.epoch, ks.name, ks.current),
                "enroll_token": enroll(ks.name, ks.current),
                "hw_salt": Hash32::from(HW_SALT),
                "vdi_mode": true,
                "deployment_cert": cert(INSTALL, INSTALL_NAME),
            }),
            signer: INSTALL.to_owned(),
            signing_kid: iskid(INSTALL),
        }
    }

    fn set(mut self, field: &str, value: impl Into<Value>) -> Self {
        self.payload[field] = value.into();
        self
    }

    fn remove(mut self, field: &str) -> Self {
        self.payload.as_object_mut().unwrap().remove(field);
        self
    }

    /// Signed by the install signing key of `install`, under its kid.
    fn signed_by(mut self, install: &str) -> Self {
        install.clone_into(&mut self.signer);
        self.signing_kid = iskid(install);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.payload).unwrap()
    }

    fn jws(&self) -> String {
        isk(&self.signer).sign(Typ::InstallConfig, &self.signing_kid, &self.bytes())
    }
}

fn check(jws: &str) -> Result<VerifiedInstall, TrustChainError> {
    verify(jws, &vendor_keys(), false)
}

// --- failure checks ---------------------------------------------------------

/// Asserts the step, document and failure of `error`.
fn assert_at(
    error: &TrustChainError,
    step: Step,
    document: ChainDocument,
    failure: &InstallConfigFailure,
) {
    assert_eq!(error.step(), step, "{error}");
    assert_eq!(error.document(), document, "{error}");
    assert_eq!(error.failure(), failure, "{error}");
}

/// Asserts that `jws` fails at `step` on `document` with `failure`, caused
/// by a verification function or a reading that gave `result`, and returns
/// that function's error.
fn fails_with_document(
    jws: &str,
    trust_test_keys: bool,
    step: Step,
    document: ChainDocument,
    failure: &InstallConfigFailure,
    result: &DocumentResult,
) -> DocumentError {
    let error = verify(jws, &vendor_keys(), trust_test_keys).unwrap_err();
    assert_at(&error, step, document, failure);
    assert_eq!(
        error.cause().document_result().as_ref(),
        Some(result),
        "{error}"
    );
    match error.cause() {
        FailureCause::Document(inner) => inner.clone(),
        other => panic!("not a document cause: {other:?}"),
    }
}

fn fails_on_cert(jws: &str, trust_test_keys: bool, result: &DocumentResult) -> DocumentError {
    fails_with_document(
        jws,
        trust_test_keys,
        Step::DeploymentCert,
        ChainDocument::DeploymentCert,
        &InstallConfigFailure::DeploymentCertInvalid,
        result,
    )
}

fn fails_on_config(jws: &str, step: Step, result: &DocumentResult) -> DocumentError {
    fails_with_document(
        jws,
        false,
        step,
        ChainDocument::InstallConfig,
        &InstallConfigFailure::InstallConfigInvalid,
        result,
    )
}

fn fails_on_keyset(jws: &str, result: &DocumentResult) -> DocumentError {
    fails_with_document(
        jws,
        false,
        Step::Keyset,
        ChainDocument::Keyset,
        &InstallConfigFailure::KeysetInvalid,
        result,
    )
}

fn fails_on_addresses(jws: &str, result: &DocumentResult) -> DocumentError {
    fails_with_document(
        jws,
        false,
        Step::SignedDocuments,
        ChainDocument::Addresses,
        &InstallConfigFailure::AddressesInvalid,
        result,
    )
}

fn fails_on_enroll(jws: &str, result: &DocumentResult) -> DocumentError {
    fails_with_document(
        jws,
        false,
        Step::SignedDocuments,
        ChainDocument::EnrollToken,
        &InstallConfigFailure::EnrollTokenInvalid,
        result,
    )
}

fn assert_untrusted(error: &TrustChainError, kid: &str) {
    assert_at(
        error,
        Step::DeploymentCert,
        ChainDocument::DeploymentCert,
        &InstallConfigFailure::UntrustedVendorKey,
    );
    match error.cause() {
        FailureCause::UntrustedVendorKey { kid: rejected } => assert_eq!(rejected.as_str(), kid),
        other => panic!("not an untrusted vendor key: {other:?}"),
    }
    assert_eq!(error.cause().document_result(), None);
}

/// An install configuration whose deployment certificate is `cert`.
fn with_cert(cert: String) -> String {
    Config::new().set("deployment_cert", cert).jws()
}

// --- passing chains -----------------------------------------------------------

#[test]
fn a_valid_install_config_passes() {
    let ks = Ks::rotation(EPOCH, NAME_A, 1);
    let config = Config::with_keyset(&ks);
    let install = check(&config.jws()).unwrap();

    let trust = install.trust_state();
    assert_eq!((trust.recovery_epoch(), trust.keyset_version()), (EPOCH, 1));
    let kids: Vec<&str> = trust.keys().iter().map(|e| e.kid.as_str()).collect();
    assert_eq!(kids, [ckid(NAME_A, 1)]);
    assert_eq!(trust.keys()[0].key, ck(NAME_A, 1).jwk());
    assert_eq!(trust.current_kid().as_str(), ckid(NAME_A, 1));
    assert!(trust.revoked_kids().is_empty());
    assert_eq!(trust.recovery_key(), &rk(2).jwk());
    assert_eq!(trust.recovery_key_version(), 2);
    assert_eq!(trust.install_id().as_str(), INSTALL);
    assert_eq!(trust.customer_endpoint_id(), id(CUSTOMER));

    assert_eq!(install.install_id().as_str(), INSTALL);
    assert_eq!(install.install_name().as_str(), INSTALL_NAME);
    assert_eq!(install.customer_endpoint_id(), id(CUSTOMER));
    assert_eq!(
        install.customer_key_name().to_string(),
        format!("endpoint-{NAME_A}")
    );
    assert_eq!(install.hw_salt().get(), &HW_SALT);
    assert!(install.vdi_mode());
    assert_eq!(install.enroll_token(), enroll(NAME_A, 1));
    assert_eq!(install.token_id(), id(TOKEN));
    assert_eq!(
        install.expires_at(),
        Some(EXPIRES_AT.parse::<Timestamp>().unwrap())
    );
    let addresses = install.addresses();
    assert_eq!(addresses.content().recovery_epoch().get(), EPOCH);
    assert_eq!(addresses.content().version().get(), ADDRESSES_VERSION);
    assert_eq!(addresses.kid().as_str(), ckid(NAME_A, 1));
    assert_eq!(
        addresses.payload(),
        addresses_payload(EPOCH, ADDRESSES_VERSION)
    );

    // A configuration with `vdi_mode` false and a token without expiry.
    let token = ck(NAME_A, 1).sign(
        Typ::Enroll,
        &ckid(NAME_A, 1),
        &serde_json::to_vec(&json!({"token_id": TOKEN})).unwrap(),
    );
    let install = check(
        &Config::new()
            .set("vdi_mode", false)
            .set("enroll_token", token.clone())
            .jws(),
    )
    .unwrap();
    assert!(!install.vdi_mode());
    assert_eq!(install.enroll_token(), token);
    assert_eq!(install.expires_at(), None);
}

#[test]
fn a_keyset_after_rotations_passes() {
    let ks = Ks::rotation(EPOCH, NAME_A, 3);
    let install = check(&Config::with_keyset(&ks).jws()).unwrap();
    let trust = install.trust_state();
    assert_eq!((trust.recovery_epoch(), trust.keyset_version()), (EPOCH, 3));
    let kids: Vec<&str> = trust.keys().iter().map(|e| e.kid.as_str()).collect();
    assert_eq!(kids, [ckid(NAME_A, 2), ckid(NAME_A, 3)]);
    assert_eq!(trust.current_kid().as_str(), ckid(NAME_A, 3));
    let revoked: Vec<&str> = trust.revoked_kids().iter().map(|k| k.as_str()).collect();
    assert_eq!(revoked, [ckid(NAME_A, 1)]);
}

#[test]
fn a_recovery_keyset_signed_again_by_its_current_kid_passes() {
    // (e + 1, 1) after a recovery, the same content the recovery key
    // signed, signed again by its own `current_kid`.
    let ks = Ks::rotation(EPOCH + 1, NAME_B, 1);
    let recovery_signed = ks.recovery_signed(2);
    let resigned = ks.resigned();
    assert_eq!(
        recovery_signed.split('.').nth(1),
        resigned.split('.').nth(1),
        "the same content bytes"
    );
    let install = check(&Config::with_keyset(&ks).jws()).unwrap();
    let trust = install.trust_state();
    assert_eq!(
        (trust.recovery_epoch(), trust.keyset_version()),
        (EPOCH + 1, 1)
    );
    assert_eq!(trust.current_kid().as_str(), ckid(NAME_B, 1));
    assert_eq!(
        trust.customer_key_name().to_string(),
        format!("endpoint-{NAME_B}")
    );
}

#[test]
fn a_recovery_keyset_signed_by_the_recovery_key_is_invalid() {
    let ks = Ks::rotation(EPOCH + 1, NAME_B, 1);
    let jws = Config::with_keyset(&ks)
        .set("keyset", ks.recovery_signed(2))
        .jws();
    fails_on_keyset(&jws, &DocumentResult::UnknownKid);
}

#[test]
fn a_keyset_signed_by_another_key_of_its_keys_is_invalid() {
    let ks = Ks::rotation(EPOCH, NAME_A, 2);
    let jws = Config::with_keyset(&ks)
        .set("keyset", ks.signed_by(1))
        .jws();
    fails_on_keyset(&jws, &DocumentResult::UnknownKid);

    // Under its `current_kid`, but not that key's signature.
    let forged = stranger().sign(Typ::Keyset, &ckid(NAME_A, 2), &ks.payload());
    let jws = Config::with_keyset(&ks).set("keyset", forged).jws();
    fails_on_keyset(&jws, &DocumentResult::BadSignature);
}

#[test]
fn a_keyset_of_another_customer_is_invalid() {
    let mut ks = Ks::rotation(EPOCH, NAME_A, 1);
    ks.customer = OTHER_CUSTOMER;
    let jws = Config::new().set("keyset", ks.resigned()).jws();
    let error = check(&jws).unwrap_err();
    assert_at(
        &error,
        Step::Keyset,
        ChainDocument::Keyset,
        &InstallConfigFailure::KeysetInvalid,
    );
    assert_eq!(
        error.cause(),
        &FailureCause::CustomerMismatch {
            field: CustomerField::CustomerEndpointId
        }
    );

    // The install configuration names another customer key name than the
    // key set's.
    let jws = Config::new()
        .set("customer_key_name", format!("endpoint-{NAME_B}"))
        .jws();
    let error = check(&jws).unwrap_err();
    assert_at(
        &error,
        Step::Keyset,
        ChainDocument::Keyset,
        &InstallConfigFailure::KeysetInvalid,
    );
    assert_eq!(
        error.cause(),
        &FailureCause::CustomerMismatch {
            field: CustomerField::CustomerKeyName
        }
    );
    assert_eq!(error.cause().document_result(), None);
}

#[test]
fn a_keyset_that_does_not_read_is_invalid() {
    let jws = Config::new().set("keyset", "not a jws").jws();
    fails_on_keyset(&jws, &DocumentResult::SchemaError);
    let jws = Config::new()
        .set("keyset", addresses(EPOCH, NAME_A, 1))
        .jws();
    fails_on_keyset(&jws, &DocumentResult::SchemaError);
}

// --- the document version state ------------------------------------------------

/// Counts the applications, and fails none.
#[derive(Default)]
struct Counter {
    calls: usize,
}

impl crate::auth::versions::DocumentApplier for Counter {
    fn apply(&mut self, _: &DocumentContent) -> Result<(), String> {
        self.calls += 1;
        Ok(())
    }
}

/// Asserts that `versions` is the first state of `install`: at `epoch`,
/// without an endpoint id, with the address document applied, and that the
/// same address document received again is a duplicate the applier never
/// sees.
fn assert_first_state<S: VersionStore>(
    versions: &mut DocumentVersions<S>,
    install: &VerifiedInstall,
    addresses_jws: &str,
    epoch: u64,
) {
    assert_eq!(versions.recovery_epoch(), epoch);
    assert_eq!(versions.endpoint_id(), None);
    let report = versions.report(Slot::Addresses);
    assert_eq!(report.verified_version, Some(ADDRESSES_VERSION));
    assert_eq!(report.applied_version, Some(ADDRESSES_VERSION));
    assert_eq!(report.current, Some((epoch, ADDRESSES_VERSION)));
    assert_eq!(report.status, SlotStatus::Normal);
    assert!(!report.untrusted);
    assert_eq!(versions.reports().len(), 1);
    assert_eq!(
        versions.current_content(Slot::Addresses),
        Some(&DocumentContent::Addresses(
            install.addresses().content().clone()
        ))
    );

    // The trust state is stored before the versions use it.
    let trust_store = MemoryTrustStore::with_state(install.trust_state().clone());
    let trust = trust_store.load().unwrap().unwrap();
    let mut counter = Counter::default();
    let receipt = versions
        .receive(
            addresses_jws,
            &trust,
            NOW.parse().unwrap(),
            &SemVer::parse(SENTA).unwrap(),
            &mut counter,
        )
        .unwrap();
    assert_eq!(receipt.result(), &DocumentResult::Duplicate);
    assert!(!receipt.epoch_aligned());
    assert_eq!(counter.calls, 0);
}

#[test]
fn the_first_document_versions_hold_the_install_addresses() {
    let install = check(&Config::new().jws()).unwrap();
    let mut store = MemoryVersionStore::new();
    let mut versions = install.create_document_versions(&mut store).unwrap();
    assert_first_state(&mut versions, &install, &addresses(EPOCH, NAME_A, 1), EPOCH);
    drop(versions);

    // What was stored is the same state, and a state machine restored from
    // it is the same.
    let stored = store.state().cloned().unwrap();
    let mut restored = DocumentVersions::restore(store).unwrap();
    assert_eq!(restored.state(), &stored);
    assert_first_state(&mut restored, &install, &addresses(EPOCH, NAME_A, 1), EPOCH);
}

#[test]
fn the_first_document_versions_after_a_recovery_are_at_its_epoch() {
    let ks = Ks::rotation(EPOCH + 1, NAME_B, 1);
    let install = check(&Config::with_keyset(&ks).jws()).unwrap();
    let mut versions = install
        .create_document_versions(MemoryVersionStore::new())
        .unwrap();
    assert_first_state(
        &mut versions,
        &install,
        &addresses(EPOCH + 1, NAME_B, 1),
        EPOCH + 1,
    );
}

#[derive(Default)]
struct Shared {
    state: Option<VersionState>,
    loads: usize,
    saves: usize,
    /// The number of the load (1 for the first) that fails.
    fail_load: Option<usize>,
    fail_save: bool,
}

/// A store whose loads and saves a test can make fail, shared with the test
/// that looks into it.
#[derive(Clone, Default)]
struct FlakyStore(Rc<RefCell<Shared>>);

impl FlakyStore {
    fn state(&self) -> Option<VersionState> {
        self.0.borrow().state.clone()
    }

    fn saves(&self) -> usize {
        self.0.borrow().saves
    }

    fn heal(&self) {
        let mut shared = self.0.borrow_mut();
        shared.fail_load = None;
        shared.fail_save = false;
    }
}

impl VersionStore for FlakyStore {
    fn load(&self) -> Result<Option<VersionState>, StoreError> {
        let mut shared = self.0.borrow_mut();
        shared.loads += 1;
        if shared.fail_load == Some(shared.loads) {
            return Err(StoreError::new("load refused"));
        }
        Ok(shared.state.clone())
    }

    fn save(&mut self, state: &VersionState) -> Result<(), StoreError> {
        let mut shared = self.0.borrow_mut();
        if shared.fail_save {
            return Err(StoreError::new("save refused"));
        }
        shared.saves += 1;
        shared.state = Some(state.clone());
        Ok(())
    }
}

fn assert_store_error(result: Result<DocumentVersions<FlakyStore>, VersionsError>) {
    match result {
        Err(VersionsError::Store(_)) => {}
        Err(other) => panic!("not a store error: {other:?}"),
        Ok(_) => panic!("a state machine was returned"),
    }
}

#[test]
fn a_failed_first_load_writes_nothing_and_can_be_retried() {
    let install = check(&Config::new().jws()).unwrap();
    let store = FlakyStore::default();
    store.0.borrow_mut().fail_load = Some(1);
    assert_store_error(install.create_document_versions(store.clone()));
    assert_eq!(store.state(), None);
    assert_eq!(store.saves(), 0);

    store.heal();
    let mut versions = install.create_document_versions(store.clone()).unwrap();
    assert_first_state(&mut versions, &install, &addresses(EPOCH, NAME_A, 1), EPOCH);
    assert_eq!(store.saves(), 1);
}

#[test]
fn a_failed_save_writes_nothing_and_can_be_retried() {
    let install = check(&Config::new().jws()).unwrap();
    let store = FlakyStore::default();
    store.0.borrow_mut().fail_save = true;
    assert_store_error(install.create_document_versions(store.clone()));
    assert_eq!(store.state(), None);
    assert_eq!(store.saves(), 0);

    store.heal();
    let mut versions = install.create_document_versions(store.clone()).unwrap();
    assert_first_state(&mut versions, &install, &addresses(EPOCH, NAME_A, 1), EPOCH);
    assert_eq!(store.saves(), 1);
}

#[test]
fn a_failed_load_after_the_save_leaves_the_state_stored() {
    let install = check(&Config::new().jws()).unwrap();
    let store = FlakyStore::default();
    // The first load checks the store is empty; the second, in `restore`,
    // fails.
    store.0.borrow_mut().fail_load = Some(2);
    assert_store_error(install.create_document_versions(store.clone()));
    let stored = store.state().unwrap();
    assert_eq!(store.saves(), 1);

    store.heal();
    let error = install
        .create_document_versions(store.clone())
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, VersionsError::AlreadyCreated), "{error:?}");
    assert_eq!(store.saves(), 1);
    let mut versions = DocumentVersions::restore(store.clone()).unwrap();
    assert_eq!(versions.state(), &stored);
    assert_first_state(&mut versions, &install, &addresses(EPOCH, NAME_A, 1), EPOCH);
}

#[test]
fn a_store_that_holds_a_state_is_left_alone() {
    // A state of another install configuration, at another epoch.
    let ks = Ks::rotation(EPOCH + 1, NAME_B, 1);
    let other = check(&Config::with_keyset(&ks).jws()).unwrap();
    let store = FlakyStore::default();
    drop(other.create_document_versions(store.clone()).unwrap());
    let stored = store.state().unwrap();

    let install = check(&Config::new().jws()).unwrap();
    let error = install
        .create_document_versions(store.clone())
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, VersionsError::AlreadyCreated), "{error:?}");
    assert_eq!(store.state(), Some(stored));
    assert_eq!(store.saves(), 1);
}

// --- the vendor keys and the deployment certificate -----------------------------

#[test]
fn a_vendor_key_list_takes_only_distinct_vendor_kids() {
    let key = vk(RELEASE_KID).jwk();
    let keys = VendorKeys::new([
        ("vendor-release-1", key),
        ("vendor-release-01", key),
        ("vendor-test-1", key),
    ])
    .unwrap();
    assert_eq!(keys.len(), 3);
    assert!(
        VendorKeys::new(Vec::<(String, Jwk)>::new())
            .unwrap()
            .is_empty()
    );

    for bad in [
        "vendor-other-1",
        "vendor-test-",
        "vendor-test-x",
        "vendor-release-",
        "",
    ] {
        let error = VendorKeys::new([(RELEASE_KID, key), (bad, key)]).unwrap_err();
        assert!(
            matches!(&error, VendorKeysError::Kid { kid, .. } if kid == bad),
            "{bad}: {error:?}"
        );
    }
    for (bad, kind) in [
        (iskid(INSTALL), KeyKind::InstallSigning),
        (rkid(1), KeyKind::Recovery),
        (ckid(NAME_A, 1), KeyKind::Customer),
    ] {
        let error = VendorKeys::new([(bad.as_str(), key)]).unwrap_err();
        assert_eq!(
            error,
            VendorKeysError::NotVendorKid {
                kid: bad.clone(),
                kind
            }
        );
    }
    let error = VendorKeys::new([
        (TEST_KID, key),
        (RELEASE_KID, key),
        (TEST_KID, vk(TEST_KID).jwk()),
    ])
    .unwrap_err();
    assert_eq!(
        error,
        VendorKeysError::DuplicateKid {
            kid: TEST_KID.to_owned()
        }
    );
}

#[test]
fn an_untrusted_test_key_is_rejected_whatever_its_signature() {
    let payload = cert_payload(INSTALL, INSTALL_NAME);
    // In the list and correctly signed.
    let listed = with_cert(sign_cert(&payload, &vk(TEST_KID), TEST_KID));
    // Not in the list.
    let unlisted = with_cert(sign_cert(&payload, &vk("vendor-test-2"), "vendor-test-2"));
    // In the list, with a signature that does not verify.
    let forged = with_cert(sign_cert(&payload, &stranger(), TEST_KID));
    let flipped = with_cert(flip_signature_bit(&sign_cert(
        &payload,
        &vk(TEST_KID),
        TEST_KID,
    )));
    for (jws, kid) in [
        (&listed, TEST_KID),
        (&unlisted, "vendor-test-2"),
        (&forged, TEST_KID),
        (&flipped, TEST_KID),
    ] {
        assert_untrusted(&check(jws).unwrap_err(), kid);
    }

    // Trusted, the listed one passes and the others fail on the certificate.
    let install = verify(&listed, &vendor_keys(), true).unwrap();
    assert_eq!(install.install_id().as_str(), INSTALL);
    fails_on_cert(&unlisted, true, &DocumentResult::UnknownKid);
    fails_on_cert(&forged, true, &DocumentResult::BadSignature);
    fails_on_cert(&flipped, true, &DocumentResult::BadSignature);
}

#[test]
fn a_vendor_kid_out_of_grammar_is_invalid_whether_or_not_test_keys_are_trusted() {
    let payload = cert_payload(INSTALL, INSTALL_NAME);
    for kid in ["vendor-test-", "vendor-test-x", "vendor-other-1"] {
        let jws = with_cert(sign_cert(&payload, &vk(TEST_KID), kid));
        for trusted in [false, true] {
            let error = fails_on_cert(&jws, trusted, &DocumentResult::SchemaError);
            assert!(
                matches!(error, DocumentError::Verify(VerifyError::Kid { .. })),
                "{kid}: {error:?}"
            );
        }
    }
}

#[test]
fn a_certificate_signed_by_another_kind_of_key_is_invalid() {
    let payload = cert_payload(INSTALL, INSTALL_NAME);
    for (key, kid) in [
        (isk(INSTALL), iskid(INSTALL)),
        (ck(NAME_A, 1), ckid(NAME_A, 1)),
        (rk(2), rkid(2)),
    ] {
        let jws = with_cert(sign_cert(&payload, &key, &kid));
        for trusted in [false, true] {
            let error = fails_on_cert(&jws, trusted, &DocumentResult::WrongKeyClass);
            assert!(
                matches!(error, DocumentError::Verify(VerifyError::KeyKind { .. })),
                "{kid}: {error:?}"
            );
        }
    }
}

#[test]
fn a_certificate_that_does_not_verify_is_invalid() {
    let payload = cert_payload(INSTALL, INSTALL_NAME);
    // A release kid not in the list.
    let unlisted = sign_cert(&payload, &vk("vendor-release-2"), "vendor-release-2");
    fails_on_cert(&with_cert(unlisted), false, &DocumentResult::UnknownKid);
    // A kid of the list, signed by another key: the test key's.
    let other_key = sign_cert(&payload, &vk(TEST_KID), RELEASE_KID);
    fails_on_cert(&with_cert(other_key), false, &DocumentResult::BadSignature);
    // One bit of the signature flipped.
    let flipped = flip_signature_bit(&cert(INSTALL, INSTALL_NAME));
    fails_on_cert(&with_cert(flipped), false, &DocumentResult::BadSignature);
    // Not of the certificate's typ.
    let wrong_typ = vk(RELEASE_KID).sign(
        Typ::InstallConfig,
        RELEASE_KID,
        &serde_json::to_vec(&payload).unwrap(),
    );
    fails_on_cert(&with_cert(wrong_typ), false, &DocumentResult::SchemaError);
    fails_on_cert(
        &with_cert("x.y.z".to_owned()),
        false,
        &DocumentResult::SchemaError,
    );

    // Contents that break the schema, correctly signed.
    let mut missing = payload.clone();
    missing.as_object_mut().unwrap().remove("install_name");
    let mut other_install_kid = payload.clone();
    other_install_kid["install_signing_kid"] = iskid(OTHER_INSTALL).into();
    let mut extra = payload;
    extra["note"] = "x".into();
    for bad in [missing, other_install_kid, extra] {
        let error = fails_on_cert(
            &with_cert(sign_cert(&bad, &vk(RELEASE_KID), RELEASE_KID)),
            false,
            &DocumentResult::SchemaError,
        );
        assert!(error.schema_error().is_some(), "{error:?}");
    }

    // A test kid not in the list, with test keys trusted.
    let keys = VendorKeys::new([(RELEASE_KID, vk(RELEASE_KID).jwk())]).unwrap();
    let jws = with_cert(sign_cert(
        &cert_payload(INSTALL, INSTALL_NAME),
        &vk(TEST_KID),
        TEST_KID,
    ));
    let error = verify(&jws, &keys, true).unwrap_err();
    assert_at(
        &error,
        Step::DeploymentCert,
        ChainDocument::DeploymentCert,
        &InstallConfigFailure::DeploymentCertInvalid,
    );
    assert_eq!(
        error.cause().document_result(),
        Some(DocumentResult::UnknownKid)
    );
}

// --- the install configuration --------------------------------------------------

#[test]
fn an_install_config_that_does_not_read_is_invalid_at_the_first_step() {
    for jws in ["", "not a jws", "a.b.c"] {
        fails_on_config(jws, Step::ReadInstallConfig, &DocumentResult::SchemaError);
    }
    for bad in [
        Config::new().remove("hw_salt"),
        Config::new().set("vdi_mode", "yes"),
        Config::new().set("deployment_cert", ""),
        Config::new().set("extra", 1),
    ] {
        let error = fails_on_config(
            &bad.jws(),
            Step::ReadInstallConfig,
            &DocumentResult::SchemaError,
        );
        assert!(error.schema_error().is_some(), "{error:?}");
    }
    // Of another typ.
    let jws = isk(INSTALL).sign(Typ::Keyset, &iskid(INSTALL), &Config::new().bytes());
    fails_on_config(&jws, Step::ReadInstallConfig, &DocumentResult::SchemaError);
    // Signed by a key of a kind that may not sign it.
    let jws = ck(NAME_A, 1).sign(Typ::InstallConfig, &ckid(NAME_A, 1), &Config::new().bytes());
    fails_on_config(
        &jws,
        Step::ReadInstallConfig,
        &DocumentResult::WrongKeyClass,
    );
}

#[test]
fn an_install_config_changed_without_signing_again_is_invalid() {
    let signed = Config::new().jws();
    let changed = [
        Config::new().set("vdi_mode", false),
        Config::new().set("hw_salt", json!(Hash32::from([6; 32]))),
        // One of the JWSs inside swapped for another valid one.
        Config::new().set(
            "addresses",
            ck(NAME_A, 1).sign(
                Typ::Addresses,
                &ckid(NAME_A, 1),
                &addresses_payload(EPOCH, ADDRESSES_VERSION + 1),
            ),
        ),
        Config::new().set(
            "enroll_token",
            ck(NAME_A, 1).sign(
                Typ::Enroll,
                &ckid(NAME_A, 1),
                &serde_json::to_vec(&json!({"token_id": TOKEN})).unwrap(),
            ),
        ),
        Config::new().set("keyset", Ks::rotation(EPOCH, NAME_A, 2).resigned()),
    ];
    for config in changed {
        let tampered = with_payload(&signed, &config.bytes());
        let error = fails_on_config(
            &tampered,
            Step::InstallConfig,
            &DocumentResult::BadSignature,
        );
        assert!(
            matches!(error, DocumentError::Verify(VerifyError::Signature { .. })),
            "{error:?}"
        );
    }
}

#[test]
fn an_install_config_signed_by_another_install_signing_key_is_invalid() {
    // Under the certificate's kid, by another key.
    let config = Config::new();
    let forged = stranger().sign(Typ::InstallConfig, &iskid(INSTALL), &config.bytes());
    fails_on_config(&forged, Step::InstallConfig, &DocumentResult::BadSignature);
    // Under another install signing kid of the same install.
    let other = isk(OTHER_INSTALL).sign(
        Typ::InstallConfig,
        &format!("install-{INSTALL}:2"),
        &config.bytes(),
    );
    fails_on_config(&other, Step::InstallConfig, &DocumentResult::UnknownKid);
    // By another install's signing key, under its own kid.
    fails_on_config(
        &config.signed_by(OTHER_INSTALL).jws(),
        Step::InstallConfig,
        &DocumentResult::UnknownKid,
    );
}

#[test]
fn a_certificate_of_another_install_is_caught() {
    let other_cert = cert(OTHER_INSTALL, OTHER_INSTALL_NAME);
    // Signed by this install's signing key: the certificate does not hold it.
    let jws = Config::new()
        .set("deployment_cert", other_cert.clone())
        .jws();
    fails_on_config(&jws, Step::InstallConfig, &DocumentResult::UnknownKid);

    // Signed by the other install's signing key, with this install's id.
    let jws = Config::new()
        .set("deployment_cert", other_cert)
        .signed_by(OTHER_INSTALL)
        .jws();
    let error = check(&jws).unwrap_err();
    assert_at(
        &error,
        Step::InstallConfig,
        ChainDocument::InstallConfig,
        &InstallConfigFailure::InstallIdMismatch,
    );
    assert_eq!(
        error.cause(),
        &FailureCause::InstallIdMismatch {
            deployment_cert: InstallId::parse(OTHER_INSTALL).unwrap(),
            install_config: InstallId::parse(INSTALL).unwrap(),
        }
    );
    assert_eq!(error.cause().document_result(), None);
}

// --- the address document and the enrollment token ------------------------------

#[test]
fn an_address_document_that_does_not_verify_is_invalid() {
    // A key the key set does not hold.
    let unknown = addresses(EPOCH, NAME_A, 9);
    fails_on_addresses(
        &Config::new().set("addresses", unknown).jws(),
        &DocumentResult::UnknownKid,
    );
    // The key set's kid, another key.
    let forged = stranger().sign(
        Typ::Addresses,
        &ckid(NAME_A, 1),
        &addresses_payload(EPOCH, ADDRESSES_VERSION),
    );
    fails_on_addresses(
        &Config::new().set("addresses", forged).jws(),
        &DocumentResult::BadSignature,
    );
    // One bit of the signature flipped.
    let flipped = flip_signature_bit(&addresses(EPOCH, NAME_A, 1));
    let error = fails_on_addresses(
        &Config::new().set("addresses", flipped).jws(),
        &DocumentResult::BadSignature,
    );
    assert!(
        matches!(error, DocumentError::Verify(VerifyError::Signature { .. })),
        "{error:?}"
    );
    // The recovery key, which may not sign it.
    let recovery = rk(2).sign(
        Typ::Addresses,
        &rkid(2),
        &addresses_payload(EPOCH, ADDRESSES_VERSION),
    );
    fails_on_addresses(
        &Config::new().set("addresses", recovery).jws(),
        &DocumentResult::WrongKeyClass,
    );
}

#[test]
fn an_address_document_of_another_epoch_is_invalid() {
    let jws = Config::new()
        .set("addresses", addresses(EPOCH + 1, NAME_A, 1))
        .jws();
    let error = check(&jws).unwrap_err();
    assert_at(
        &error,
        Step::SignedDocuments,
        ChainDocument::Addresses,
        &InstallConfigFailure::AddressesInvalid,
    );
    assert_eq!(
        error.cause(),
        &FailureCause::EpochMismatch {
            addresses: EPOCH + 1,
            keyset: EPOCH,
        }
    );
    assert_eq!(error.cause().document_result(), None);
}

#[test]
fn an_enrollment_token_that_does_not_verify_is_invalid() {
    let unknown = enroll(NAME_A, 9);
    fails_on_enroll(
        &Config::new().set("enroll_token", unknown).jws(),
        &DocumentResult::UnknownKid,
    );
    let flipped = flip_signature_bit(&enroll(NAME_A, 1));
    fails_on_enroll(
        &Config::new().set("enroll_token", flipped).jws(),
        &DocumentResult::BadSignature,
    );
    let wrong_typ = ck(NAME_A, 1).sign(Typ::EnrollResult, &ckid(NAME_A, 1), &enroll_payload());
    fails_on_enroll(
        &Config::new().set("enroll_token", wrong_typ).jws(),
        &DocumentResult::SchemaError,
    );
    let bad_content = ck(NAME_A, 1).sign(
        Typ::Enroll,
        &ckid(NAME_A, 1),
        &serde_json::to_vec(&json!({"token_id": "not a uuid"})).unwrap(),
    );
    fails_on_enroll(
        &Config::new().set("enroll_token", bad_content).jws(),
        &DocumentResult::SchemaError,
    );
}

#[test]
fn any_key_of_the_keyset_not_revoked_signs_the_documents() {
    // Keys 1 and 2, current 2: documents signed by key 1.
    let ks = Ks::rotation(EPOCH, NAME_A, 2);
    let jws = Config::with_keyset(&ks)
        .set("addresses", addresses(EPOCH, NAME_A, 1))
        .set("enroll_token", enroll(NAME_A, 1))
        .jws();
    let install = check(&jws).unwrap();
    assert_eq!(install.addresses().kid().as_str(), ckid(NAME_A, 1));
    assert_eq!(install.enroll_token(), enroll(NAME_A, 1));
    assert_eq!(
        install.trust_state().current_kid().as_str(),
        ckid(NAME_A, 2)
    );
}

#[test]
fn a_revoked_key_signs_no_document() {
    // Keys 2 and 3, current 3, key 1 revoked.
    let ks = Ks::rotation(EPOCH, NAME_A, 3);
    let jws = Config::with_keyset(&ks)
        .set("addresses", addresses(EPOCH, NAME_A, 1))
        .jws();
    fails_on_addresses(&jws, &DocumentResult::RevokedKid);
    let jws = Config::with_keyset(&ks)
        .set("enroll_token", enroll(NAME_A, 1))
        .jws();
    fails_on_enroll(&jws, &DocumentResult::RevokedKid);
}

// --- the order of the steps -------------------------------------------------------

#[test]
fn the_first_step_broken_decides_the_failure() {
    let untrusted_cert = sign_cert(
        &cert_payload(INSTALL, INSTALL_NAME),
        &vk("vendor-release-2"),
        "vendor-release-2",
    );
    let wrong_keyset = Ks::rotation(EPOCH, NAME_A, 2).signed_by(1);
    let bad_addresses = flip_signature_bit(&addresses(EPOCH, NAME_A, 1));
    let bad_token = flip_signature_bit(&enroll(NAME_A, 1));

    // The certificate and the key set.
    let jws = Config::new()
        .set("deployment_cert", untrusted_cert.clone())
        .set("keyset", wrong_keyset.clone())
        .jws();
    fails_on_cert(&jws, false, &DocumentResult::UnknownKid);

    // The test key policy and the install configuration's signature.
    let test_cert = sign_cert(&cert_payload(INSTALL, INSTALL_NAME), &stranger(), TEST_KID);
    let jws = Config::new()
        .set("deployment_cert", test_cert)
        .signed_by(OTHER_INSTALL)
        .jws();
    assert_untrusted(&check(&jws).unwrap_err(), TEST_KID);

    // The install configuration's signature and the key set.
    let config = Config::new().set("keyset", wrong_keyset.clone());
    let forged = stranger().sign(Typ::InstallConfig, &iskid(INSTALL), &config.bytes());
    fails_on_config(&forged, Step::InstallConfig, &DocumentResult::BadSignature);

    // The install id and the key set.
    let jws = Config::new()
        .set("deployment_cert", cert(OTHER_INSTALL, OTHER_INSTALL_NAME))
        .set("keyset", wrong_keyset.clone())
        .signed_by(OTHER_INSTALL)
        .jws();
    assert_eq!(
        check(&jws).unwrap_err().failure(),
        &InstallConfigFailure::InstallIdMismatch
    );

    // The key set and the address document.
    let jws = Config::new()
        .set("keyset", wrong_keyset)
        .set("addresses", bad_addresses.clone())
        .jws();
    fails_on_keyset(&jws, &DocumentResult::UnknownKid);

    // The address document and the enrollment token.
    let jws = Config::new()
        .set("addresses", bad_addresses)
        .set("enroll_token", bad_token)
        .jws();
    fails_on_addresses(&jws, &DocumentResult::BadSignature);

    // The reading of the install configuration and the certificate.
    let jws = Config::new()
        .set("deployment_cert", untrusted_cert)
        .remove("hw_salt")
        .jws();
    fails_on_config(&jws, Step::ReadInstallConfig, &DocumentResult::SchemaError);
}

#[test]
fn steps_and_documents_are_named() {
    assert_eq!(
        [
            Step::ReadInstallConfig,
            Step::DeploymentCert,
            Step::InstallConfig,
            Step::Keyset,
            Step::SignedDocuments,
        ]
        .map(Step::number),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(ChainDocument::EnrollToken.typ(), Typ::Enroll);
    let error = check(
        &Config::new()
            .set("addresses", addresses(EPOCH + 1, NAME_A, 1))
            .jws(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "install configuration trust chain failed at step 5 on the senta-addresses: the address \
         document's recovery epoch 4 is not the key set's 3"
    );
    assert!(std::error::Error::source(&error).is_none());
    let error = check(&Config::new().set("keyset", "x").jws()).unwrap_err();
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn the_recovery_key_version_comes_from_the_install_config() {
    let install = check(
        &Config::new()
            .set("recovery_key", json!(rk(5).jwk()))
            .set("recovery_key_version", 5)
            .jws(),
    )
    .unwrap();
    assert_eq!(install.trust_state().recovery_key(), &rk(5).jwk());
    assert_eq!(install.trust_state().recovery_key_version(), 5);
}
