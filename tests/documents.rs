//! Tests of `senta_protocol::auth::documents`: the content types of the
//! eleven `typ`s, their verification and pre-verification reading, and the
//! validity window.
#![cfg(all(feature = "auth", feature = "test-util"))]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use jiff::{SignedDuration, Timestamp};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use senta_protocol::auth::documents::{
    AbsoluteUrl, Address, AddressHost, AddressesContent, AssignContent, AuditSettings, CLOCK_SKEW,
    CertificatePem, CommandAction, CommandContent, CommandKind, ContentError, ControlEntry,
    CustomerKeyName, CustomerKid, DeploymentCertContent, DiagnoseArgs, DnsName, DocumentError,
    EnrollContent, EnrollResultContent, ExistingSysmon, InstallConfigContent, InstallId, Integer,
    JwsText, KeysetContent, KeysetEntry, KindNumber, MAX_COMMAND_LIFETIME, MAX_UPDATE_LIFETIME,
    NonEmptyString, PolicyCollectionMode, PolicyContent, PositiveInteger, RecoveryKeyContent,
    SemVer, StatusUi, SysmonConfig, SysmonConfigs, TelemetryEntry, UpdateContent, UpdatePackage,
    UpdateRelease, UpdateTarget, WindowsSysmonPackage, check_validity_window,
    inspect_install_config, inspect_keyset, inspect_recovery_key, verify_addresses, verify_assign,
    verify_command, verify_deployment_cert, verify_enroll, verify_enroll_result,
    verify_install_config, verify_keyset, verify_policy, verify_recovery_key,
    verify_self_signed_keyset, verify_update,
};
use senta_protocol::auth::jws::strict::{
    self, Base64UrlArray, Base64UrlBytes, LowerUuid, UtcTimestamp,
};
use senta_protocol::auth::jws::test_util::TestKey;
use senta_protocol::auth::jws::{
    HeaderDiagnostics, KeyKind, KeyLookup, KeySource, Kid, Typ, VerifyError,
};
use senta_protocol::auth::tls::{
    CONTROL_ALPN, ClientConfigError, endpoint_certificate, endpoint_client_config,
    endpoint_private_key, expected_server_name,
};
use senta_protocol::results::DocumentResult;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::Digest as _;

// ---------------------------------------------------------------------------
// Keys, kids and the key source
// ---------------------------------------------------------------------------

const ENDPOINT: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_ENDPOINT: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const GROUP: &str = "16fd2706-8baf-433b-82eb-8c7fada847da";
const TOKEN: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const ATTEMPT: &str = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
const ENTRY_A: &str = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11";
const ENTRY_B: &str = "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12";
const COMMAND: &str = "c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13";

const VENDOR_KID: &str = "vendor-release-1";
const INSTALL_KID: &str = "install-acme:1";
const RECOVERY_KID: &str = "recovery-acme:4";
const INSTALL_ID: &str = "acme";

const T0: &str = "2026-01-01T00:00:00Z";
const T0_PLUS_HOUR: &str = "2026-01-01T01:00:00Z";
const T0_PLUS_DAY: &str = "2026-01-02T00:00:00Z";
const BEFORE_T0: &str = "2025-12-31T23:59:59.999Z";

fn customer_kid(version: u32) -> String {
    format!("endpoint-{ENDPOINT}:{version}")
}

fn vendor_key() -> TestKey {
    TestKey::from_seed(&[10; 32])
}

fn install_key() -> TestKey {
    TestKey::from_seed(&[11; 32])
}

fn customer_key() -> TestKey {
    TestKey::from_seed(&[12; 32])
}

fn recovery_key() -> TestKey {
    TestKey::from_seed(&[13; 32])
}

fn stranger_key() -> TestKey {
    TestKey::from_seed(&[99; 32])
}

/// A key source over a fixed table.
#[derive(Default)]
struct Source(BTreeMap<String, KeyLookup>);

impl Source {
    fn with(mut self, kid: &str, key: &TestKey, kind: KeyKind) -> Self {
        self.0.insert(
            kid.to_owned(),
            KeyLookup::Found {
                key: key.public_key(),
                kind,
            },
        );
        self
    }

    fn revoked(mut self, kid: &str) -> Self {
        self.0.insert(kid.to_owned(), KeyLookup::Revoked);
        self
    }
}

impl KeySource for Source {
    fn find_key(&self, kid: &Kid, _allowed: &[KeyKind]) -> KeyLookup {
        self.0
            .get(kid.as_str())
            .copied()
            .unwrap_or(KeyLookup::Unknown)
    }
}

/// A source that knows the four signing keys, each under its own kind.
fn source() -> Source {
    Source::default()
        .with(VENDOR_KID, &vendor_key(), KeyKind::Vendor)
        .with(INSTALL_KID, &install_key(), KeyKind::InstallSigning)
        .with(&customer_kid(1), &customer_key(), KeyKind::Customer)
        .with(RECOVERY_KID, &recovery_key(), KeyKind::Recovery)
}

/// The key and kid that sign a document of `typ`.
fn signer(typ: Typ) -> (TestKey, String) {
    match typ {
        Typ::DeploymentCert => (vendor_key(), VENDOR_KID.to_owned()),
        Typ::InstallConfig => (install_key(), INSTALL_KID.to_owned()),
        Typ::RecoveryKey => (recovery_key(), RECOVERY_KID.to_owned()),
        _ => (customer_key(), customer_kid(1)),
    }
}

fn sign(typ: Typ, payload: &[u8]) -> String {
    let (key, kid) = signer(typ);
    key.sign(typ, &kid, payload)
}

fn sign_value(typ: Typ, value: &Value) -> String {
    sign(typ, &serde_json::to_vec(value).unwrap())
}

/// Flips one bit of the signature, which stays well-formed base64url.
fn break_signature(jws: &str) -> String {
    let (signing_input, signature) = jws.rsplit_once('.').unwrap();
    let mut chars: Vec<char> = signature.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    format!("{signing_input}.{}", chars.into_iter().collect::<String>())
}

// ---------------------------------------------------------------------------
// Dispatch over the eleven typs
// ---------------------------------------------------------------------------

/// What a successful verification gives, with the content as JSON.
#[derive(Debug, PartialEq)]
struct Outcome {
    content: Value,
    kid: Kid,
    payload_hash: [u8; 32],
    header: HeaderDiagnostics,
}

macro_rules! outcome {
    ($result:expr) => {
        $result.map(|document| Outcome {
            content: serde_json::to_value(document.content()).unwrap(),
            kid: document.kid().clone(),
            payload_hash: *document.payload_hash(),
            header: document.header().clone(),
        })
    };
}

fn verify_typ(typ: Typ, jws: &str, source: &Source) -> Result<Outcome, DocumentError> {
    match typ {
        Typ::DeploymentCert => outcome!(verify_deployment_cert(jws, source)),
        Typ::InstallConfig => outcome!(verify_install_config(jws, source)),
        Typ::Keyset => outcome!(verify_keyset(jws, source)),
        Typ::RecoveryKey => outcome!(verify_recovery_key(jws, source)),
        Typ::Enroll => outcome!(verify_enroll(jws, source)),
        Typ::EnrollResult => outcome!(verify_enroll_result(jws, source)),
        Typ::Policy => outcome!(verify_policy(jws, source)),
        Typ::Assign => outcome!(verify_assign(jws, source)),
        Typ::Addresses => outcome!(verify_addresses(jws, source)),
        Typ::Update => outcome!(verify_update(jws, source)),
        Typ::Command => outcome!(verify_command(jws, source)),
    }
}

/// The pre-verification reading of `typ`, for the three typs that have one.
fn inspect_typ(typ: Typ, jws: &str) -> Result<Outcome, DocumentError> {
    match typ {
        Typ::Keyset => outcome!(inspect_keyset(jws)),
        Typ::RecoveryKey => outcome!(inspect_recovery_key(jws)),
        Typ::InstallConfig => outcome!(inspect_install_config(jws)),
        other => panic!("{other} has no pre-verification reading"),
    }
}

const INSPECTABLE: [Typ; 3] = [Typ::Keyset, Typ::RecoveryKey, Typ::InstallConfig];

fn verify_value(typ: Typ, value: &Value) -> Result<Outcome, DocumentError> {
    verify_typ(typ, &sign_value(typ, value), &source())
}

fn verify_bytes(typ: Typ, payload: &[u8]) -> Result<Outcome, DocumentError> {
    verify_typ(typ, &sign(typ, payload), &source())
}

// ---------------------------------------------------------------------------
// Valid documents
// ---------------------------------------------------------------------------

fn root_ca_pem(name: &str) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![format!("{name}.example")]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.self_signed(&key).unwrap().pem()
}

/// Two root certificates, made once.
fn roots() -> &'static (String, String) {
    static ROOTS: OnceLock<(String, String)> = OnceLock::new();
    ROOTS.get_or_init(|| (root_ca_pem("root-a"), root_ca_pem("root-b")))
}

fn b64(bytes: &[u8]) -> Value {
    serde_json::to_value(Base64UrlBytes::from(bytes.to_vec())).unwrap()
}

fn jwk_value(key: &TestKey) -> Value {
    serde_json::to_value(key.jwk()).unwrap()
}

/// A valid content of each `typ`, as hand-written JSON following the table
/// of the issue.
fn valid(typ: Typ) -> Value {
    match typ {
        Typ::DeploymentCert => json!({
            "install_id": INSTALL_ID,
            "install_name": "Acme Corp",
            "install_signing_key": jwk_value(&install_key()),
            "install_signing_kid": INSTALL_KID,
            "issued_at": T0,
        }),
        Typ::InstallConfig => json!({
            "install_id": INSTALL_ID,
            "customer_endpoint_id": ENDPOINT,
            "customer_key_name": format!("endpoint-{ENDPOINT}"),
            "keyset": "keyset.jws.here",
            "recovery_key": jwk_value(&recovery_key()),
            "recovery_key_version": 4,
            "addresses": "addresses.jws.here",
            "enroll_token": "enroll.jws.here",
            "hw_salt": b64(&[5; 32]),
            "vdi_mode": false,
            "deployment_cert": "deployment.jws.here",
        }),
        Typ::Keyset => json!({
            "customer_endpoint_id": ENDPOINT,
            "customer_key_name": format!("endpoint-{ENDPOINT}"),
            "recovery_epoch": 0,
            "keyset_version": 3,
            "keys": [
                {"kid": customer_kid(2), "key": jwk_value(&customer_key())},
                {"kid": customer_kid(3), "key": jwk_value(&stranger_key())},
            ],
            "current_kid": customer_kid(3),
            "revoked_kids": [customer_kid(1)],
        }),
        Typ::RecoveryKey => json!({
            "install_id": INSTALL_ID,
            "recovery_key_version": 5,
            "recovery_key": jwk_value(&stranger_key()),
        }),
        Typ::Enroll => json!({
            "token_id": TOKEN,
            "expires_at": T0_PLUS_DAY,
        }),
        Typ::EnrollResult => json!({
            "recovery_epoch": 0,
            "endpoint_id": OTHER_ENDPOINT,
            "spki_sha256": b64(&[6; 32]),
            "token_id": TOKEN,
            "attempt_id": ATTEMPT,
        }),
        Typ::Policy => json!({
            "recovery_epoch": 2,
            "group_id": GROUP,
            "version": 7,
            "collection_mode": "extended",
            "sysmon_configs": [
                {
                    "os": "windows",
                    "sha256": b64(&[7; 32]),
                    "sources": ["https://dist.example/sysmon-windows.xml"],
                },
                {
                    "os": "linux",
                    "sha256": b64(&[17; 32]),
                    "sources": [
                        "https://dist.example/sysmon-linux.xml",
                        "https://mirror.example/sysmon-linux.xml",
                    ],
                },
            ],
            "existing_sysmon": "take_over",
            "windows_sysmon_package": {
                "version": "15.15",
                "sha256": b64(&[27; 32]),
                "size": 4_194_304,
                "sources": ["https://dist.example/sysmon/sysmon.zip"],
            },
            "field_exclusions": {
                "1": ["CommandLine", "ParentCommandLine"],
                "65535": [],
            },
            "audit_settings": {
                "windows_local_apply": true,
                "linux_auditd_rules": false,
            },
            "event_log_channels": {
                "Microsoft-Windows-Sysmon/Operational": [1, 3],
                "Security": [0, 4624, 65535],
            },
            "status_ui": "tray",
        }),
        Typ::Assign => json!({
            "recovery_epoch": 2,
            "endpoint_id": OTHER_ENDPOINT,
            "version": 1,
            "group_id": GROUP,
            "uninstall_token_sha256": b64(&[8; 32]),
        }),
        Typ::Addresses => json!({
            "recovery_epoch": 2,
            "version": 9,
            "control_entries": [
                {"address": "review.example:443", "expected_name": "review.example"},
            ],
            "telemetry_entries": [
                {"entry_id": ENTRY_A, "address": "10.0.0.1:8443", "expected_name": "store-a.example"},
                {"entry_id": ENTRY_B, "address": "[2001:db8::1]:8443", "expected_name": "store-b.example"},
            ],
            "trust_roots": [roots().0.clone()],
            "distribution_points": ["https://dist.example/"],
        }),
        Typ::Update => json!({
            "recovery_epoch": 2,
            "version": 4,
            "group_id": GROUP,
            "target_version": "1.2.3-rc.1+build.5",
            "packages": [
                {
                    "platform": "windows-x86_64-msi",
                    "sha256": b64(&[9; 32]),
                    "size": 1_048_576,
                    "sources": ["https://dist.example/agent-1.2.3.msi"],
                },
                {
                    "platform": "linux-x86_64-deb",
                    "sha256": b64(&[19; 32]),
                    "size": 2_097_152,
                    "sources": [
                        "https://dist.example/agent-1.2.3.deb",
                        "https://mirror.example/agent-1.2.3.deb",
                    ],
                },
            ],
            "rollback": false,
            "issued_at": T0,
            "expires_at": T0_PLUS_DAY,
        }),
        Typ::Command => json!({
            "command_id": COMMAND,
            "endpoint_id": OTHER_ENDPOINT,
            "seq": 12,
            "issued_at": T0,
            "expires_at": T0_PLUS_HOUR,
            "recovery_epoch": 2,
            "kind": "diagnose",
            "args": {},
        }),
    }
}

/// A valid `senta-update` that releases one endpoint from a pinned version.
fn valid_null_update() -> Value {
    json!({
        "recovery_epoch": 2,
        "version": 5,
        "endpoint_id": OTHER_ENDPOINT,
        "target_version": null,
        "rollback": true,
        "issued_at": T0,
        "expires_at": T0_PLUS_DAY,
    })
}

fn uuid(text: &str) -> LowerUuid {
    LowerUuid::parse(text).unwrap()
}

fn time(text: &str) -> UtcTimestamp {
    UtcTimestamp::parse(text).unwrap()
}

fn int(value: u32) -> Integer {
    Integer::from(value)
}

fn positive(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).unwrap()
}

fn text(value: &str) -> NonEmptyString {
    NonEmptyString::new(value).unwrap()
}

fn jws_text(value: &str) -> JwsText {
    JwsText::new(value).unwrap()
}

fn url(value: &str) -> AbsoluteUrl {
    AbsoluteUrl::parse(value).unwrap()
}

fn ckid(version: u32) -> CustomerKid {
    CustomerKid::parse(&customer_kid(version)).unwrap()
}

fn key_name() -> CustomerKeyName {
    CustomerKeyName::parse(&format!("endpoint-{ENDPOINT}")).unwrap()
}

fn install_id() -> InstallId {
    InstallId::parse(INSTALL_ID).unwrap()
}

fn dns(value: &str) -> DnsName {
    DnsName::parse(value).unwrap()
}

fn deployment_cert_content() -> DeploymentCertContent {
    DeploymentCertContent::new(
        install_id(),
        text("Acme Corp"),
        install_key().jwk(),
        Kid::parse(INSTALL_KID).unwrap(),
        time(T0),
    )
    .unwrap()
}

fn install_config_content() -> InstallConfigContent {
    InstallConfigContent {
        install_id: install_id(),
        customer_endpoint_id: uuid(ENDPOINT),
        customer_key_name: key_name(),
        keyset: jws_text("keyset.jws.here"),
        recovery_key: recovery_key().jwk(),
        recovery_key_version: positive(4),
        addresses: jws_text("addresses.jws.here"),
        enroll_token: jws_text("enroll.jws.here"),
        hw_salt: Base64UrlArray::from([5; 32]),
        vdi_mode: false,
        deployment_cert: jws_text("deployment.jws.here"),
    }
}

fn keyset_content() -> KeysetContent {
    KeysetContent::new(
        uuid(ENDPOINT),
        key_name(),
        int(0),
        positive(3),
        vec![
            KeysetEntry {
                kid: ckid(2),
                key: customer_key().jwk(),
            },
            KeysetEntry {
                kid: ckid(3),
                key: stranger_key().jwk(),
            },
        ],
        ckid(3),
        vec![ckid(1)],
    )
    .unwrap()
}

fn recovery_key_content() -> RecoveryKeyContent {
    RecoveryKeyContent {
        install_id: install_id(),
        recovery_key_version: positive(5),
        recovery_key: stranger_key().jwk(),
    }
}

fn enroll_content() -> EnrollContent {
    EnrollContent {
        token_id: uuid(TOKEN),
        expires_at: Some(time(T0_PLUS_DAY)),
    }
}

fn enroll_result_content() -> EnrollResultContent {
    EnrollResultContent {
        recovery_epoch: int(0),
        endpoint_id: uuid(OTHER_ENDPOINT),
        spki_sha256: Base64UrlArray::from([6; 32]),
        token_id: uuid(TOKEN),
        attempt_id: uuid(ATTEMPT),
    }
}

fn policy_content() -> PolicyContent {
    PolicyContent {
        recovery_epoch: int(2),
        group_id: uuid(GROUP),
        version: int(7),
        collection_mode: PolicyCollectionMode::Extended,
        sysmon_configs: SysmonConfigs::new(vec![
            SysmonConfig::new(
                text("windows"),
                Base64UrlArray::from([7; 32]),
                vec![url("https://dist.example/sysmon-windows.xml")],
            )
            .unwrap(),
            SysmonConfig::new(
                text("linux"),
                Base64UrlArray::from([17; 32]),
                vec![
                    url("https://dist.example/sysmon-linux.xml"),
                    url("https://mirror.example/sysmon-linux.xml"),
                ],
            )
            .unwrap(),
        ])
        .unwrap(),
        existing_sysmon: ExistingSysmon::TakeOver,
        windows_sysmon_package: Some(
            WindowsSysmonPackage::new(
                text("15.15"),
                Base64UrlArray::from([27; 32]),
                positive(4_194_304),
                vec![url("https://dist.example/sysmon/sysmon.zip")],
            )
            .unwrap(),
        ),
        field_exclusions: BTreeMap::from([
            (
                KindNumber::new(1).unwrap(),
                vec![text("CommandLine"), text("ParentCommandLine")],
            ),
            (KindNumber::new(65535).unwrap(), vec![]),
        ]),
        audit_settings: AuditSettings {
            windows_local_apply: true,
            linux_auditd_rules: false,
        },
        event_log_channels: BTreeMap::from([
            (text("Microsoft-Windows-Sysmon/Operational"), vec![1, 3]),
            (text("Security"), vec![0, 4624, 65535]),
        ]),
        status_ui: StatusUi::Tray,
    }
}

fn assign_content() -> AssignContent {
    AssignContent {
        recovery_epoch: int(2),
        endpoint_id: uuid(OTHER_ENDPOINT),
        version: int(1),
        group_id: uuid(GROUP),
        uninstall_token_sha256: Base64UrlArray::from([8; 32]),
    }
}

fn addresses_content() -> AddressesContent {
    AddressesContent::new(
        int(2),
        int(9),
        vec![ControlEntry {
            address: Address::parse("review.example:443").unwrap(),
            expected_name: dns("review.example"),
        }],
        vec![
            TelemetryEntry {
                entry_id: uuid(ENTRY_A),
                address: Address::new(AddressHost::Ipv4([10, 0, 0, 1].into()), 8443).unwrap(),
                expected_name: dns("store-a.example"),
            },
            TelemetryEntry {
                entry_id: uuid(ENTRY_B),
                address: Address::parse("[2001:db8::1]:8443").unwrap(),
                expected_name: dns("store-b.example"),
            },
        ],
        vec![CertificatePem::parse(&roots().0).unwrap()],
        vec![url("https://dist.example/")],
    )
    .unwrap()
}

fn update_packages() -> Vec<UpdatePackage> {
    vec![
        UpdatePackage::new(
            text("windows-x86_64-msi"),
            Base64UrlArray::from([9; 32]),
            positive(1_048_576),
            vec![url("https://dist.example/agent-1.2.3.msi")],
        )
        .unwrap(),
        UpdatePackage::new(
            text("linux-x86_64-deb"),
            Base64UrlArray::from([19; 32]),
            positive(2_097_152),
            vec![
                url("https://dist.example/agent-1.2.3.deb"),
                url("https://mirror.example/agent-1.2.3.deb"),
            ],
        )
        .unwrap(),
    ]
}

fn update_release() -> UpdateRelease {
    UpdateRelease::new(
        SemVer::parse("1.2.3-rc.1+build.5").unwrap(),
        update_packages(),
    )
    .unwrap()
}

fn update_content() -> UpdateContent {
    UpdateContent::new(
        int(2),
        int(4),
        UpdateTarget::Group(uuid(GROUP)),
        Some(update_release()),
        false,
        time(T0),
        time(T0_PLUS_DAY),
    )
    .unwrap()
}

fn null_update_content() -> UpdateContent {
    UpdateContent::new(
        int(2),
        int(5),
        UpdateTarget::Endpoint(uuid(OTHER_ENDPOINT)),
        None,
        true,
        time(T0),
        time(T0_PLUS_DAY),
    )
    .unwrap()
}

fn command_content() -> CommandContent {
    CommandContent::new(
        uuid(COMMAND),
        uuid(OTHER_ENDPOINT),
        int(12),
        time(T0),
        time(T0_PLUS_HOUR),
        int(2),
        CommandAction::Diagnose(DiagnoseArgs {}),
    )
    .unwrap()
}

/// The typed content of [`valid`] for `typ`, built outside the crate, as
/// JSON.
fn typed(typ: Typ) -> Value {
    fn to_value<T: Serialize>(content: &T) -> Value {
        serde_json::to_value(content).unwrap()
    }
    match typ {
        Typ::DeploymentCert => to_value(&deployment_cert_content()),
        Typ::InstallConfig => to_value(&install_config_content()),
        Typ::Keyset => to_value(&keyset_content()),
        Typ::RecoveryKey => to_value(&recovery_key_content()),
        Typ::Enroll => to_value(&enroll_content()),
        Typ::EnrollResult => to_value(&enroll_result_content()),
        Typ::Policy => to_value(&policy_content()),
        Typ::Assign => to_value(&assign_content()),
        Typ::Addresses => to_value(&addresses_content()),
        Typ::Update => to_value(&update_content()),
        Typ::Command => to_value(&command_content()),
    }
}

// ---------------------------------------------------------------------------
// Valid documents verify
// ---------------------------------------------------------------------------

#[test]
fn typed_contents_serialize_to_the_table() {
    for typ in Typ::ALL {
        assert_eq!(typed(typ), valid(typ), "{typ}");
    }
    assert_eq!(
        serde_json::to_value(null_update_content()).unwrap(),
        valid_null_update()
    );
}

#[test]
fn every_typ_verifies_a_valid_document() {
    for typ in Typ::ALL {
        let payload = serde_json::to_vec(&valid(typ)).unwrap();
        let jws = sign(typ, &payload);
        let outcome = verify_typ(typ, &jws, &source()).unwrap_or_else(|e| panic!("{typ}: {e:?}"));
        let (_, kid) = signer(typ);
        assert_eq!(outcome.content, valid(typ), "{typ}");
        assert_eq!(outcome.kid.as_str(), kid, "{typ}");
        assert_eq!(
            outcome.payload_hash,
            <[u8; 32]>::from(sha2::Sha256::digest(&payload))
        );
        assert_eq!(outcome.header.typ(), typ.as_str());
        assert_eq!(outcome.header.kid(), kid);
    }
}

#[test]
fn verified_contents_equal_what_was_signed() {
    fn check<T: Serialize + PartialEq + std::fmt::Debug>(
        typ: Typ,
        expected: &T,
        verify: impl Fn(&str, &Source) -> Result<T, DocumentError>,
    ) {
        let jws = sign(typ, &serde_json::to_vec(expected).unwrap());
        assert_eq!(&verify(&jws, &source()).unwrap(), expected, "{typ}");
    }
    check(Typ::DeploymentCert, &deployment_cert_content(), |j, s| {
        verify_deployment_cert(j, s).map(|d| d.into_content())
    });
    check(Typ::InstallConfig, &install_config_content(), |j, s| {
        verify_install_config(j, s).map(|d| d.into_content())
    });
    check(Typ::Keyset, &keyset_content(), |j, s| {
        verify_keyset(j, s).map(|d| d.into_content())
    });
    check(Typ::RecoveryKey, &recovery_key_content(), |j, s| {
        verify_recovery_key(j, s).map(|d| d.into_content())
    });
    check(Typ::Enroll, &enroll_content(), |j, s| {
        verify_enroll(j, s).map(|d| d.into_content())
    });
    check(Typ::EnrollResult, &enroll_result_content(), |j, s| {
        verify_enroll_result(j, s).map(|d| d.into_content())
    });
    check(Typ::Policy, &policy_content(), |j, s| {
        verify_policy(j, s).map(|d| d.into_content())
    });
    check(Typ::Assign, &assign_content(), |j, s| {
        verify_assign(j, s).map(|d| d.into_content())
    });
    check(Typ::Addresses, &addresses_content(), |j, s| {
        verify_addresses(j, s).map(|d| d.into_content())
    });
    check(Typ::Update, &update_content(), |j, s| {
        verify_update(j, s).map(|d| d.into_content())
    });
    check(Typ::Update, &null_update_content(), |j, s| {
        verify_update(j, s).map(|d| d.into_content())
    });
    check(Typ::Command, &command_content(), |j, s| {
        verify_command(j, s).map(|d| d.into_content())
    });
}

#[test]
fn keyset_verifies_signed_by_a_customer_key_and_by_a_recovery_key() {
    let payload = serde_json::to_vec(&valid(Typ::Keyset)).unwrap();
    let by_customer = customer_key().sign(Typ::Keyset, &customer_kid(1), &payload);
    let by_recovery = recovery_key().sign(Typ::Keyset, RECOVERY_KID, &payload);
    for (jws, kid, kind) in [
        (by_customer, customer_kid(1), KeyKind::Customer),
        (by_recovery, RECOVERY_KID.to_owned(), KeyKind::Recovery),
    ] {
        let document = verify_keyset(&jws, &source()).unwrap();
        assert_eq!(document.kid().as_str(), kid);
        assert_eq!(document.kid().kind(), kind);
        assert_eq!(document.content(), &keyset_content());
        assert_eq!(
            document.payload_hash(),
            &<[u8; 32]>::from(sha2::Sha256::digest(&payload))
        );
        assert_eq!(document.payload(), payload.as_slice());
        assert_eq!(document.typ(), Typ::Keyset);
    }
}

#[test]
fn payload_hash_is_of_the_signed_bytes_not_a_reserialization() {
    // Whitespace and key order the serializer would not write.
    let payload = b" {\"token_id\" : \"6ba7b810-9dad-11d1-80b4-00c04fd430c8\"}\n";
    let document = verify_enroll(&sign(Typ::Enroll, payload), &source()).unwrap();
    assert_eq!(
        document.payload_hash(),
        &<[u8; 32]>::from(sha2::Sha256::digest(payload))
    );
    assert_ne!(
        serde_json::to_vec(document.content()).unwrap(),
        payload.to_vec()
    );
}

// ---------------------------------------------------------------------------
// JSON round trip
// ---------------------------------------------------------------------------

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let json = serde_json::to_vec(value).unwrap();
    let parsed: T = strict::from_slice(&json)
        .unwrap_or_else(|e| panic!("{}: {e}", String::from_utf8_lossy(&json)));
    assert_eq!(&parsed, value);
}

#[test]
fn every_content_type_round_trips_through_strict_json() {
    round_trip(&deployment_cert_content());
    round_trip(&install_config_content());
    round_trip(&keyset_content());
    round_trip(&recovery_key_content());
    round_trip(&enroll_content());
    round_trip(&EnrollContent {
        token_id: uuid(TOKEN),
        expires_at: None,
    });
    round_trip(&enroll_result_content());
    round_trip(&policy_content());
    round_trip(&PolicyContent {
        field_exclusions: BTreeMap::new(),
        event_log_channels: BTreeMap::new(),
        collection_mode: PolicyCollectionMode::Essential,
        status_ui: StatusUi::Hidden,
        ..policy_content()
    });
    round_trip(&PolicyContent {
        status_ui: StatusUi::Notify,
        ..policy_content()
    });
    round_trip(&assign_content());
    round_trip(&addresses_content());
    round_trip(&update_content());
    round_trip(&null_update_content());
    round_trip(
        &UpdateContent::new(
            Integer::MAX,
            int(0),
            UpdateTarget::Endpoint(uuid(OTHER_ENDPOINT)),
            Some(update_release()),
            true,
            time("2026-01-01T00:00:00.123456789Z"),
            time("2026-01-01T00:00:00.123456789Z"),
        )
        .unwrap(),
    );
    round_trip(&command_content());
}

#[test]
fn optional_and_null_fields_serialize_as_specified() {
    let without = serde_json::to_value(EnrollContent {
        token_id: uuid(TOKEN),
        expires_at: None,
    })
    .unwrap();
    assert_eq!(without, json!({ "token_id": TOKEN }));

    let null = serde_json::to_value(null_update_content()).unwrap();
    let object = null.as_object().unwrap();
    assert_eq!(object.get("target_version"), Some(&Value::Null));
    for absent in ["group_id", "packages"] {
        assert!(!object.contains_key(absent), "{absent}");
    }

    let without_package = serde_json::to_value(PolicyContent {
        windows_sysmon_package: None,
        ..policy_content()
    })
    .unwrap();
    assert!(
        !without_package
            .as_object()
            .unwrap()
            .contains_key("windows_sysmon_package")
    );
}

#[test]
fn update_and_command_expose_their_window() {
    let update = verify_update(&sign_value(Typ::Update, &valid(Typ::Update)), &source())
        .unwrap()
        .into_content();
    assert_eq!(update.issued_at(), time(T0).get());
    assert_eq!(update.expires_at(), time(T0_PLUS_DAY).get());
    assert_eq!(update.target(), UpdateTarget::Group(uuid(GROUP)));
    assert_eq!(update.release(), Some(&update_release()));
    assert_eq!(update.packages(), update_packages().as_slice());
    let release = update.release().unwrap();
    assert_eq!(
        release.package("linux-x86_64-deb"),
        update_packages().get(1)
    );
    assert_eq!(release.package("linux-x86_64-rpm"), None);

    let null = verify_update(&sign_value(Typ::Update, &valid_null_update()), &source())
        .unwrap()
        .into_content();
    assert_eq!(null.issued_at(), time(T0).get());
    assert_eq!(null.expires_at(), time(T0_PLUS_DAY).get());
    assert_eq!(null.target_version(), None);
    assert_eq!(null.release(), None);
    assert!(null.packages().is_empty());
    assert_eq!(null.target(), UpdateTarget::Endpoint(uuid(OTHER_ENDPOINT)));

    let command = verify_command(&sign_value(Typ::Command, &valid(Typ::Command)), &source())
        .unwrap()
        .into_content();
    assert_eq!(command.issued_at(), time(T0).get());
    assert_eq!(command.expires_at(), time(T0_PLUS_HOUR).get());
    assert_eq!(command.kind(), CommandKind::Diagnose);
}

// ---------------------------------------------------------------------------
// Schema violations
// ---------------------------------------------------------------------------

/// Asserts that verifying `payload` as `typ` is a content schema error.
#[track_caller]
fn assert_schema_error(typ: Typ, payload: &[u8], case: &str) {
    let jws = sign(typ, payload);
    let error = match verify_typ(typ, &jws, &source()) {
        Ok(_) => panic!(
            "{typ} {case}: accepted {}",
            String::from_utf8_lossy(payload)
        ),
        Err(error) => error,
    };
    assert_eq!(error.result(), DocumentResult::SchemaError, "{typ} {case}");
    assert!(
        error.schema_error().is_some(),
        "{typ} {case}: not a content error: {error:?}"
    );
    let (_, kid) = signer(typ);
    let header = error.header().expect("a content error has the header");
    assert_eq!((header.typ(), header.kid()), (typ.as_str(), kid.as_str()));
}

#[track_caller]
fn assert_value_rejected(typ: Typ, value: &Value, case: &str) {
    assert_schema_error(typ, &serde_json::to_vec(value).unwrap(), case);
}

#[track_caller]
fn assert_value_accepted(typ: Typ, value: &Value, case: &str) {
    if let Err(error) = verify_value(typ, value) {
        panic!("{typ} {case}: {error:?}");
    }
}

/// Finds the value a case edits within a document.
type Locate = fn(&mut Value) -> &mut Value;

/// An edit of a document.
type Edit = fn(&mut Value);

/// `valid(typ)` with `edit` applied.
fn edited(typ: Typ, edit: impl FnOnce(&mut Value)) -> Value {
    let mut value = valid(typ);
    edit(&mut value);
    value
}

fn object(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value.as_object_mut().unwrap()
}

/// Inserts `member` (`"key":value`) right after the first occurrence of
/// `after` in the compact JSON of `value`.
fn insert_text(value: &Value, after: &str, member: &str) -> Vec<u8> {
    let text = serde_json::to_string(value).unwrap();
    let at = text
        .find(after)
        .unwrap_or_else(|| panic!("{after} in {text}"))
        + after.len();
    format!("{}{member},{}", &text[..at], &text[at..]).into_bytes()
}

#[test]
fn unknown_fields_are_rejected_at_the_top() {
    for typ in Typ::ALL {
        let value = edited(typ, |v| {
            object(v).insert("extra".to_owned(), json!(1));
        });
        assert_value_rejected(typ, &value, "unknown top-level field");
        // Fields are matched exactly.
        let first = valid(typ)
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let value = edited(typ, |v| {
            let field = object(v).remove(&first).unwrap();
            object(v).insert(first.to_uppercase(), field);
        });
        assert_value_rejected(typ, &value, "uppercase field name");
    }
}

#[test]
fn unknown_fields_are_rejected_in_every_nested_object() {
    let cases: [(Typ, &str, Locate); 9] = [
        (Typ::Policy, "sysmon_configs element", |v| {
            &mut v["sysmon_configs"][1]
        }),
        (
            Typ::Policy,
            "windows_sysmon_package",
            |v| &mut v["windows_sysmon_package"],
        ),
        (Typ::Update, "packages element", |v| &mut v["packages"][1]),
        (Typ::Policy, "audit_settings", |v| &mut v["audit_settings"]),
        (Typ::Keyset, "keys element", |v| &mut v["keys"][1]),
        (Typ::Keyset, "JWK", |v| &mut v["keys"][0]["key"]),
        (Typ::Addresses, "control entry", |v| {
            &mut v["control_entries"][0]
        }),
        (Typ::Addresses, "telemetry entry", |v| {
            &mut v["telemetry_entries"][1]
        }),
        (Typ::Command, "args", |v| &mut v["args"]),
    ];
    for (typ, case, at) in cases {
        let value = edited(typ, |v| {
            object(at(v)).insert("extra".to_owned(), json!(true));
        });
        assert_value_rejected(typ, &value, case);
    }
}

#[test]
fn duplicate_keys_are_rejected_at_every_depth() {
    for typ in Typ::ALL {
        let value = valid(typ);
        let (first, first_value) = value.as_object().unwrap().iter().next().unwrap();
        let member = format!("{}:{}", json!(first), first_value);
        assert_schema_error(
            typ,
            &insert_text(&value, "{", &member),
            "duplicate top-level key",
        );
    }
    let nested = [
        (
            Typ::Policy,
            r#""sysmon_configs":[{"#,
            format!(r#""sha256":{}"#, b64(&[7; 32])),
        ),
        (
            Typ::Policy,
            r#""windows_sysmon_package":{"#,
            r#""size":1"#.to_owned(),
        ),
        (
            Typ::Update,
            r#""packages":[{"#,
            r#""platform":"linux-x86_64-rpm""#.to_owned(),
        ),
        (
            Typ::Policy,
            r#""audit_settings":{"#,
            r#""linux_auditd_rules":true"#.to_owned(),
        ),
        (
            Typ::Policy,
            r#""field_exclusions":{"#,
            r#""65535":[]"#.to_owned(),
        ),
        (
            Typ::Policy,
            r#""event_log_channels":{"#,
            r#""Security":[1]"#.to_owned(),
        ),
        (
            Typ::Keyset,
            r#""keys":[{"#,
            format!(r#""kid":"{}""#, customer_kid(2)),
        ),
        (
            Typ::Addresses,
            r#""control_entries":[{"#,
            r#""address":"a.example:1""#.to_owned(),
        ),
        (
            Typ::Addresses,
            r#""telemetry_entries":[{"#,
            format!(r#""entry_id":"{ENTRY_A}""#),
        ),
    ];
    for (typ, after, member) in nested {
        assert_schema_error(typ, &insert_text(&valid(typ), after, &member), after);
    }
    // Keys equal once unescaped are the same key.
    let escaped = insert_text(
        &valid(Typ::Policy),
        r#""event_log_channels":{"#,
        r#""Securit\u0079":[1]"#,
    );
    assert_schema_error(Typ::Policy, &escaped, "escaped duplicate map key");
    // A top-level field key written escaped is the same key too.
    let escaped = insert_text(&valid(Typ::Policy), "{", r#""status_\u0075i":"tray""#);
    assert_schema_error(Typ::Policy, &escaped, "escaped duplicate field key");
}

#[test]
fn every_missing_required_field_is_rejected() {
    for typ in Typ::ALL {
        for field in valid(typ).as_object().unwrap().keys() {
            // The fields that may be left out.
            if (typ == Typ::Enroll && field == "expires_at")
                || (typ == Typ::Policy && field == "windows_sysmon_package")
            {
                continue;
            }
            let value = edited(typ, |v| {
                object(v).remove(field);
            });
            assert_value_rejected(typ, &value, &format!("missing {field}"));
        }
    }
    // The null update's fields are each required too.
    for field in valid_null_update().as_object().unwrap().keys() {
        let mut value = valid_null_update();
        object(&mut value).remove(field);
        assert_value_rejected(Typ::Update, &value, &format!("missing {field}"));
    }
}

#[test]
fn recovery_epoch_is_required_or_refused_by_typ() {
    let required = [
        Typ::Keyset,
        Typ::EnrollResult,
        Typ::Policy,
        Typ::Assign,
        Typ::Addresses,
        Typ::Update,
        Typ::Command,
    ];
    for typ in required {
        assert!(valid(typ).get("recovery_epoch").is_some(), "{typ}");
        let value = edited(typ, |v| {
            object(v).remove("recovery_epoch");
        });
        assert_value_rejected(typ, &value, "missing recovery_epoch");
    }
    let refused = [
        Typ::DeploymentCert,
        Typ::InstallConfig,
        Typ::RecoveryKey,
        Typ::Enroll,
    ];
    for typ in refused {
        let value = edited(typ, |v| {
            object(v).insert("recovery_epoch".to_owned(), json!(0));
        });
        assert_value_rejected(typ, &value, "recovery_epoch present");
    }
}

#[test]
fn integers_out_of_range_are_rejected() {
    let fields: &[(Typ, &str)] = &[
        (Typ::InstallConfig, "recovery_key_version"),
        (Typ::Keyset, "recovery_epoch"),
        (Typ::Keyset, "keyset_version"),
        (Typ::RecoveryKey, "recovery_key_version"),
        (Typ::EnrollResult, "recovery_epoch"),
        (Typ::Policy, "recovery_epoch"),
        (Typ::Policy, "version"),
        (Typ::Assign, "recovery_epoch"),
        (Typ::Assign, "version"),
        (Typ::Addresses, "recovery_epoch"),
        (Typ::Addresses, "version"),
        (Typ::Update, "recovery_epoch"),
        (Typ::Update, "version"),
        (Typ::Command, "seq"),
        (Typ::Command, "recovery_epoch"),
    ];
    for &(typ, field) in fields {
        for bad in [
            "9007199254740992",
            "-1",
            "1.0",
            "1e3",
            "18446744073709551616",
            "\"1\"",
        ] {
            let mut value = valid(typ);
            object(&mut value).insert(field.to_owned(), json!("__placeholder__"));
            let text = serde_json::to_string(&value)
                .unwrap()
                .replace("\"__placeholder__\"", bad);
            assert_schema_error(typ, text.as_bytes(), &format!("{field} = {bad}"));
        }
        let max = edited(typ, |v| {
            object(v).insert(field.to_owned(), json!(9_007_199_254_740_991_u64));
        });
        assert_value_accepted(typ, &max, &format!("{field} = 2^53 - 1"));
    }
    for (typ, field) in [
        (Typ::InstallConfig, "recovery_key_version"),
        (Typ::Keyset, "keyset_version"),
        (Typ::RecoveryKey, "recovery_key_version"),
    ] {
        let zero = edited(typ, |v| {
            object(v).insert(field.to_owned(), json!(0));
        });
        assert_value_rejected(typ, &zero, &format!("{field} = 0"));
        let one = edited(typ, |v| {
            object(v).insert(field.to_owned(), json!(1));
        });
        assert_value_accepted(typ, &one, &format!("{field} = 1"));
    }
    for (typ, field) in [
        (Typ::Keyset, "recovery_epoch"),
        (Typ::Policy, "version"),
        (Typ::Command, "seq"),
    ] {
        let zero = edited(typ, |v| {
            object(v).insert(field.to_owned(), json!(0));
        });
        assert_value_accepted(typ, &zero, &format!("{field} = 0"));
    }
}

#[test]
fn signed_document_enums_take_only_their_strings() {
    let cases = [
        (Typ::Policy, "collection_mode", "full"),
        (Typ::Policy, "collection_mode", "Extended"),
        (Typ::Policy, "collection_mode", ""),
        (Typ::Policy, "status_ui", "none"),
        (Typ::Policy, "status_ui", "TRAY"),
        (Typ::Command, "kind", "reboot"),
        (Typ::Command, "kind", "Diagnose"),
    ];
    for (typ, field, bad) in cases {
        let value = edited(typ, |v| {
            object(v).insert(field.to_owned(), json!(bad));
        });
        assert_value_rejected(typ, &value, &format!("{field} = {bad}"));
    }
    for good in ["essential", "extended"] {
        let value = edited(Typ::Policy, |v| v["collection_mode"] = json!(good));
        assert_value_accepted(Typ::Policy, &value, good);
    }
    for good in ["tray", "notify", "hidden"] {
        let value = edited(Typ::Policy, |v| v["status_ui"] = json!(good));
        assert_value_accepted(Typ::Policy, &value, good);
    }
}

#[test]
fn signed_document_enums_take_no_other_representation() {
    let cases = [
        (Typ::Policy, "collection_mode", "extended"),
        (Typ::Policy, "collection_mode", "essential"),
        (Typ::Policy, "status_ui", "tray"),
        (Typ::Policy, "status_ui", "notify"),
        (Typ::Policy, "status_ui", "hidden"),
        (Typ::Command, "kind", "diagnose"),
    ];
    for (typ, field, variant) in cases {
        let forms = [
            json!({ variant: null }),
            json!({ variant: {} }),
            json!({ variant: [] }),
            json!([variant]),
        ];
        for form in forms {
            let case = format!("{field} = {form}");
            let value = edited(typ, |v| {
                object(v).insert(field.to_owned(), form);
            });
            assert_value_rejected(typ, &value, &case);
        }
    }
}

#[test]
fn hashes_and_the_hardware_salt_are_exactly_32_bytes() {
    let fields: [(Typ, Locate); 7] = [
        (Typ::InstallConfig, |v| &mut v["hw_salt"]),
        (Typ::EnrollResult, |v| &mut v["spki_sha256"]),
        (Typ::Policy, |v| &mut v["sysmon_configs"][0]["sha256"]),
        (Typ::Policy, |v| &mut v["windows_sysmon_package"]["sha256"]),
        (Typ::Assign, |v| &mut v["uninstall_token_sha256"]),
        (Typ::Update, |v| &mut v["packages"][0]["sha256"]),
        (Typ::Update, |v| &mut v["packages"][1]["sha256"]),
    ];
    let padded = format!("{}=", b64(&[1; 32]).as_str().unwrap());
    let standard = b64(&[0xfb; 32])
        .as_str()
        .unwrap()
        .replace('-', "+")
        .replace('_', "/");
    for (typ, at) in fields {
        for bad in [
            b64(&[1; 31]),
            b64(&[1; 33]),
            b64(&[]),
            json!(padded),
            json!(standard),
            json!(1),
        ] {
            let value = edited(typ, |v| *at(v) = bad.clone());
            assert_value_rejected(typ, &value, &format!("hash {bad}"));
        }
    }
}

#[test]
fn urls_must_be_absolute() {
    let fields: [(Typ, Locate); 5] = [
        (Typ::Policy, |v| &mut v["sysmon_configs"][1]["sources"][1]),
        (Typ::Policy, |v| {
            &mut v["windows_sysmon_package"]["sources"][0]
        }),
        (Typ::Addresses, |v| &mut v["distribution_points"][0]),
        (Typ::Update, |v| &mut v["packages"][0]["sources"][0]),
        (Typ::Update, |v| &mut v["packages"][1]["sources"][1]),
    ];
    for (typ, at) in fields {
        for bad in [
            "/relative/path",
            "dist.example/file",
            "",
            "http://exa mple/",
            " https://dist.example/",
            "https://dist.example/\n",
            "https://dist\t.example/",
        ] {
            let value = edited(typ, |v| *at(v) = json!(bad));
            assert_value_rejected(typ, &value, &format!("url {bad:?}"));
        }
        for good in ["file:///opt/agent.msi", "urn:example:x", "s3://bucket/key"] {
            let value = edited(typ, |v| *at(v) = json!(good));
            assert_value_accepted(typ, &value, good);
        }
    }
}

const BAD_DNS_NAMES: &[&str] = &[
    "",
    "1.2.3.4",
    "10.0.0.1",
    "::1",
    "[::1]",
    "[2001:db8::1]",
    "2001:db8::1",
    "review.example.",
    ".review.example",
    "review..example",
    "-review.example",
    "review-.example",
    "review.-example",
    "re_view.example",
    "_srv.example",
    "review.example:443",
    "re view.example",
    "réview.example",
    "review.123",
    "123",
];

fn long_label(len: usize) -> String {
    "a".repeat(len)
}

/// A name of exactly `len` characters, in labels of 63 and a last, shorter
/// one.
fn long_name(len: usize) -> String {
    let mut labels = Vec::new();
    let mut remaining = len;
    while remaining > 63 {
        labels.push(long_label(63));
        remaining -= 64;
    }
    labels.push(long_label(remaining));
    labels.join(".")
}

#[test]
fn dns_names_follow_the_grammar() {
    let label_64 = format!("{}.example", long_label(64));
    let name_254 = long_name(254);
    assert_eq!(name_254.len(), 254);
    let mut bad: Vec<&str> = BAD_DNS_NAMES.to_vec();
    bad.push(&label_64);
    bad.push(&name_254);
    for name in bad {
        assert!(DnsName::parse(name).is_none(), "{name:?} parsed");
        let value = edited(Typ::Addresses, |v| {
            v["control_entries"][0]["expected_name"] = json!(name);
        });
        assert_value_rejected(Typ::Addresses, &value, &format!("dns name {name:?}"));
    }
}

#[test]
fn accepted_dns_names_are_accepted_by_rustls() {
    let label_63 = format!("{}.example", long_label(63));
    let name_253 = long_name(253);
    assert_eq!(name_253.len(), 253);
    let good = [
        "localhost",
        "review.example",
        "1.node.example",
        "a-1.B-2.example",
        "x",
        "0x.example",
        "example.c0m",
        label_63.as_str(),
        name_253.as_str(),
    ];
    for name in good {
        assert_eq!(DnsName::parse(name).unwrap().as_str(), name);
        expected_server_name(name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let value = edited(Typ::Addresses, |v| {
            v["telemetry_entries"][0]["expected_name"] = json!(name);
        });
        assert_value_accepted(Typ::Addresses, &value, name);
    }
}

#[test]
fn addresses_follow_the_grammar() {
    let bad = [
        "review.example:0",
        "review.example:65536",
        "review.example:080",
        "review.example:",
        "review.example",
        "review.example:+1",
        "review.example: 443",
        ":443",
        "::1:443",
        "2001:db8::1:443",
        "[::1]",
        "[::1]:",
        "[::1]:0",
        "[review.example]:443",
        "[1.2.3.4]:443",
        "[::1%eth0]:443",
        "1.2.3:443",
        "256.0.0.1:443",
        "01.2.3.4:443",
        "re_view.example:443",
        "review.example.:443",
        "",
    ];
    for address in bad {
        assert!(Address::parse(address).is_none(), "{address:?} parsed");
        let value = edited(Typ::Addresses, |v| {
            v["telemetry_entries"][0]["address"] = json!(address);
        });
        assert_value_rejected(Typ::Addresses, &value, &format!("address {address:?}"));
    }
    let good = [
        ("review.example:1", "review.example:1"),
        ("review.example:65535", "review.example:65535"),
        ("10.0.0.1:443", "10.0.0.1:443"),
        ("[::1]:443", "[::1]:443"),
        ("[0:0::1]:443", "[::1]:443"),
        ("[::ffff:10.0.0.1]:443", "[::ffff:10.0.0.1]:443"),
        ("localhost:8443", "localhost:8443"),
    ];
    for (address, written) in good {
        let parsed = Address::parse(address).unwrap();
        assert_eq!(parsed.to_string(), written);
        assert_eq!(Address::parse(written), Some(parsed));
        let value = edited(Typ::Addresses, |v| {
            v["control_entries"][0]["address"] = json!(address);
        });
        assert_value_accepted(Typ::Addresses, &value, address);
    }
    let parsed = Address::parse("[2001:db8::1]:8443").unwrap();
    assert!(matches!(parsed.host(), AddressHost::Ipv6(_)));
    assert_eq!(parsed.port(), 8443);
    assert!(Address::new(AddressHost::Dns(dns("a.example")), 0).is_none());
}

/// PEM samples, each with whether it is a good trust root element.
fn pem_samples() -> Vec<(&'static str, String, bool)> {
    let (a, b) = roots();
    let body: String = a
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    vec![
        ("one block", a.clone(), true),
        ("two blocks", format!("{a}{b}"), true),
        (
            "text around blocks",
            format!("Subject: root-a\n\n{a}\nnotes between\n{b}trailing words\n"),
            true,
        ),
        ("CRLF", a.replace('\n', "\r\n"), true),
        ("CR only", a.replace('\n', "\r"), true),
        ("no block", "just some text\nand no PEM\n".to_owned(), false),
        ("empty", String::new(), false),
        (
            "other label",
            a.replace("CERTIFICATE", "PRIVATE KEY"),
            false,
        ),
        (
            "other label beside a certificate",
            format!("{a}{}", b.replace("CERTIFICATE", "FOO")),
            false,
        ),
        (
            "unclosed block",
            format!("-----BEGIN CERTIFICATE-----\n{body}\n"),
            false,
        ),
        (
            "stray END outside a block",
            format!("{a}-----END CERTIFICATE-----\n"),
            false,
        ),
        (
            "mismatched END",
            format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END FOO-----\n"),
            false,
        ),
        (
            "nested BEGIN",
            format!("-----BEGIN CERTIFICATE-----\n{a}"),
            false,
        ),
        (
            "body not base64",
            "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n".to_owned(),
            false,
        ),
    ]
}

#[test]
fn trust_roots_are_pem_certificates() {
    for (case, pem, good) in pem_samples() {
        assert_eq!(CertificatePem::parse(&pem).is_some(), good, "{case}");
        let value = edited(Typ::Addresses, |v| v["trust_roots"] = json!([pem]));
        if good {
            assert_value_accepted(Typ::Addresses, &value, case);
        } else {
            assert_value_rejected(Typ::Addresses, &value, case);
            // A bad element beside a good one fails the list.
            let value = edited(Typ::Addresses, |v| {
                v["trust_roots"] = json!([roots().0, pem]);
            });
            assert_value_rejected(Typ::Addresses, &value, case);
        }
    }
    // A certificate block whose DER is no certificate is still PEM; the TLS
    // configuration rejects it as a root, not this schema.
    let unusable = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
    assert!(CertificatePem::parse(unusable).is_some());
}

#[test]
fn trust_root_pem_agrees_with_the_tls_configuration() {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let seed = [3; 32];
    for (case, pem, _) in pem_samples() {
        let config = endpoint_client_config(
            provider.clone(),
            &[pem.as_str()],
            endpoint_certificate(&seed, at(T0)).unwrap(),
            endpoint_private_key(&seed).unwrap().into(),
            CONTROL_ALPN,
        );
        let pem_rejected = matches!(
            config,
            Err(ClientConfigError::MalformedPem { .. }
                | ClientConfigError::NoCertificate { .. }
                | ClientConfigError::NotCertificate { .. })
        );
        assert_eq!(
            CertificatePem::parse(&pem).is_none(),
            pem_rejected,
            "{case}: {config:?}"
        );
    }
}

#[test]
fn semver_versions_follow_semver_2() {
    for bad in [
        "",
        "1",
        "1.0",
        "v1.0.0",
        "01.0.0",
        "1.01.0",
        "1.0.0-",
        "1.0.0-01",
        "1.0.0-a..b",
        "1.0.0+",
        " 1.0.0",
        "1.0.0 ",
        "1.0.0.0",
        "latest",
    ] {
        assert!(SemVer::parse(bad).is_none(), "{bad:?} parsed");
        let value = edited(Typ::Update, |v| v["target_version"] = json!(bad));
        assert_value_rejected(Typ::Update, &value, &format!("semver {bad:?}"));
    }
    for good in [
        "0.0.0",
        "1.2.3",
        "1.0.0-rc.1",
        "1.0.0+001",
        "1.0.0-x-y.0a+b.c",
    ] {
        assert_eq!(SemVer::parse(good).unwrap().to_string(), good);
        let value = edited(Typ::Update, |v| v["target_version"] = json!(good));
        assert_value_accepted(Typ::Update, &value, good);
    }
    let version = SemVer::parse("1.2.3-rc.1+build.5").unwrap();
    assert_eq!(
        (version.major(), version.minor(), version.patch()),
        (1, 2, 3)
    );
    assert_eq!((version.pre(), version.build()), ("rc.1", "build.5"));
}

#[test]
fn target_versions_compare_by_semver_precedence() {
    let target = |version: &str| {
        let value = edited(Typ::Update, |v| v["target_version"] = json!(version));
        verify_update(&sign_value(Typ::Update, &value), &source())
            .unwrap()
            .into_content()
            .target_version()
            .unwrap()
            .clone()
    };
    let rc = target("1.0.0-rc.1");
    let release = target("1.0.0");
    assert_eq!(rc.cmp_precedence(&release), Ordering::Less);
    assert_eq!(release.cmp_precedence(&rc), Ordering::Greater);
    assert_eq!(
        target("1.0.0-alpha").cmp_precedence(&target("1.0.0-alpha.1")),
        Ordering::Less
    );
    assert_eq!(
        target("1.0.0-2").cmp_precedence(&target("1.0.0-10")),
        Ordering::Less
    );
    assert_eq!(
        target("1.9.0").cmp_precedence(&target("1.10.0")),
        Ordering::Less
    );

    let build_a = target("1.0.0+a");
    let build_b = target("1.0.0+b");
    assert_eq!(build_a.cmp_precedence(&build_b), Ordering::Equal);
    assert_eq!(build_a.cmp_precedence(&release), Ordering::Equal);
    assert_ne!(build_a, build_b);
}

#[test]
fn keys_and_trust_roots_may_not_be_empty_but_other_lists_may() {
    let value = edited(Typ::Keyset, |v| v["keys"] = json!([]));
    assert_value_rejected(Typ::Keyset, &value, "empty keys");
    let value = edited(Typ::Addresses, |v| v["trust_roots"] = json!([]));
    assert_value_rejected(Typ::Addresses, &value, "empty trust_roots");

    let empty_lists: [(Typ, Edit); 8] = [
        (Typ::Keyset, |v| v["revoked_kids"] = json!([])),
        (Typ::Policy, |v| v["sysmon_configs"] = json!([])),
        (Typ::Policy, |v| v["field_exclusions"]["1"] = json!([])),
        (Typ::Policy, |v| v["field_exclusions"] = json!({})),
        (Typ::Policy, |v| {
            v["event_log_channels"] = json!({"Security": []})
        }),
        (Typ::Addresses, |v| v["control_entries"] = json!([])),
        (Typ::Addresses, |v| v["telemetry_entries"] = json!([])),
        (Typ::Addresses, |v| v["distribution_points"] = json!([])),
    ];
    for (typ, edit) in empty_lists {
        assert_value_accepted(typ, &edited(typ, edit), "empty list");
    }
    let value = edited(Typ::Policy, |v| v["event_log_channels"] = json!({}));
    assert_value_accepted(Typ::Policy, &value, "no channels");
}

#[test]
fn keyset_kids_follow_their_rules() {
    let cases: [(&str, Edit); 9] = [
        ("repeated kid in keys", |v| {
            v["keys"][1]["kid"] = json!(customer_kid(2));
            v["current_kid"] = json!(customer_kid(2));
        }),
        ("current_kid not in keys", |v| {
            v["current_kid"] = json!(customer_kid(4));
        }),
        ("current_kid revoked", |v| {
            v["current_kid"] = json!(customer_kid(1));
        }),
        ("revoked kid in keys", |v| {
            v["revoked_kids"] = json!([customer_kid(1), customer_kid(2)]);
        }),
        ("keys kid of another kind", |v| {
            v["keys"][0]["kid"] = json!("recovery-acme:2");
        }),
        ("current_kid of another kind", |v| {
            v["current_kid"] = json!(RECOVERY_KID);
        }),
        ("revoked kid of another kind", |v| {
            v["revoked_kids"] = json!(["install-acme:1"]);
        }),
        ("kid out of grammar", |v| {
            v["keys"][0]["kid"] = json!(format!("endpoint-{ENDPOINT}:0"));
        }),
        ("key not a JWK", |v| {
            v["keys"][0]["key"] = json!({"kty": "OKP", "crv": "X25519", "x": "AA"});
        }),
    ];
    for (case, edit) in cases {
        assert_value_rejected(Typ::Keyset, &edited(Typ::Keyset, edit), case);
    }

    let entry = |version| KeysetEntry {
        kid: ckid(version),
        key: customer_key().jwk(),
    };
    let make = |keys: Vec<KeysetEntry>, current: CustomerKid, revoked: Vec<CustomerKid>| {
        KeysetContent::new(
            uuid(ENDPOINT),
            key_name(),
            int(0),
            positive(1),
            keys,
            current,
            revoked,
        )
    };
    assert_eq!(make(vec![], ckid(1), vec![]), Err(ContentError::EmptyKeys));
    assert_eq!(
        make(vec![entry(1), entry(1)], ckid(1), vec![]),
        Err(ContentError::DuplicateKid)
    );
    assert_eq!(
        make(vec![entry(1)], ckid(2), vec![]),
        Err(ContentError::CurrentKidNotInKeys)
    );
    assert_eq!(
        make(vec![entry(1), entry(2)], ckid(2), vec![ckid(1)]),
        Err(ContentError::RevokedKidInKeys)
    );
    assert!(CustomerKid::parse(RECOVERY_KID).is_none());
}

#[test]
fn install_signing_kid_names_the_install() {
    let cases = [
        ("recovery kid", "recovery-acme:1".to_owned()),
        ("customer kid", customer_kid(1)),
        ("vendor kid", "vendor-release-1".to_owned()),
        ("other install", "install-other:1".to_owned()),
        ("install id prefix only", "install-acm:1".to_owned()),
        ("no version", "install-acme".to_owned()),
        ("version 0", "install-acme:0".to_owned()),
    ];
    for (case, kid) in cases {
        let value = edited(Typ::DeploymentCert, |v| {
            v["install_signing_kid"] = json!(kid)
        });
        assert_value_rejected(Typ::DeploymentCert, &value, case);
    }
    let value = edited(Typ::DeploymentCert, |v| {
        v["install_id"] = json!("other");
    });
    assert_value_rejected(Typ::DeploymentCert, &value, "install_id differs");
    let value = edited(Typ::DeploymentCert, |v| {
        v["install_id"] = json!("other");
        v["install_signing_kid"] = json!("install-other:7");
    });
    assert_value_accepted(Typ::DeploymentCert, &value, "matching install id");

    let make = |kid: &str| {
        DeploymentCertContent::new(
            install_id(),
            text("Acme"),
            install_key().jwk(),
            Kid::parse(kid).unwrap(),
            time(T0),
        )
    };
    assert_eq!(
        make("recovery-acme:1"),
        Err(ContentError::InstallSigningKidKind)
    );
    assert_eq!(
        make("install-other:1"),
        Err(ContentError::InstallSigningKidInstallId)
    );
}

#[test]
fn telemetry_entry_ids_are_unique() {
    let value = edited(Typ::Addresses, |v| {
        v["telemetry_entries"][1]["entry_id"] = json!(ENTRY_A);
    });
    assert_value_rejected(Typ::Addresses, &value, "repeated entry_id");
    let entry = TelemetryEntry {
        entry_id: uuid(ENTRY_A),
        address: Address::parse("a.example:1").unwrap(),
        expected_name: dns("a.example"),
    };
    assert_eq!(
        AddressesContent::new(
            int(0),
            int(0),
            vec![],
            vec![entry.clone(), entry],
            vec![CertificatePem::parse(&roots().0).unwrap()],
            vec![],
        ),
        Err(ContentError::DuplicateEntryId)
    );
    assert_eq!(
        AddressesContent::new(int(0), int(0), vec![], vec![], vec![], vec![]),
        Err(ContentError::EmptyTrustRoots)
    );
}

#[test]
fn field_exclusions_follow_their_rules() {
    for key in [
        "0",
        "65536",
        "01",
        "+1",
        "-1",
        "1.0",
        "a",
        "",
        " 1",
        "4294967297",
    ] {
        let value = edited(Typ::Policy, |v| {
            v["field_exclusions"] = json!({ key: ["Image"] });
        });
        assert_value_rejected(Typ::Policy, &value, &format!("kind key {key:?}"));
    }
    for bad in [
        json!([""]),
        json!([1]),
        json!("Image"),
        json!({}),
        json!(["Image", ""]),
    ] {
        let value = edited(Typ::Policy, |v| v["field_exclusions"]["1"] = bad.clone());
        assert_value_rejected(Typ::Policy, &value, &format!("field names {bad}"));
    }
    // A kind the registry may not have yet is accepted.
    let value = edited(Typ::Policy, |v| {
        v["field_exclusions"] = json!({"1": ["Image"], "40000": ["x"], "9": ["CommandLine"]});
    });
    assert_value_accepted(Typ::Policy, &value, "any kind number");
}

#[test]
fn event_log_channels_follow_their_rules() {
    let value = edited(Typ::Policy, |v| v["event_log_channels"] = json!({"": [1]}));
    assert_value_rejected(Typ::Policy, &value, "empty channel name");
    for bad in [
        json!([65536]),
        json!([-1]),
        json!(["1"]),
        json!([1.5]),
        json!(1),
    ] {
        let value = edited(Typ::Policy, |v| {
            v["event_log_channels"]["Security"] = bad.clone()
        });
        assert_value_rejected(Typ::Policy, &value, &format!("event ids {bad}"));
    }
    let value = edited(Typ::Policy, |v| {
        v["event_log_channels"] = json!({
            "Microsoft-Windows-Sysmon/Operational": [1],
            "Windows PowerShell": [400],
            "Application": [0, 65535],
        });
    });
    assert_value_accepted(Typ::Policy, &value, "channel names of any form");
}

#[test]
fn command_args_are_the_empty_object() {
    for bad in [json!({"x": 1}), json!([]), json!(null), json!("")] {
        let value = edited(Typ::Command, |v| v["args"] = bad.clone());
        assert_value_rejected(Typ::Command, &value, &format!("args {bad}"));
    }
}

#[test]
fn expires_at_is_not_before_issued_at() {
    for typ in [Typ::Update, Typ::Command] {
        let value = edited(typ, |v| v["expires_at"] = json!(BEFORE_T0));
        assert_value_rejected(typ, &value, "expires_at before issued_at");
        let value = edited(typ, |v| v["expires_at"] = json!(T0));
        assert_value_accepted(typ, &value, "expires_at equal to issued_at");
    }
    let value = {
        let mut v = valid_null_update();
        v["expires_at"] = json!(BEFORE_T0);
        v
    };
    assert_value_rejected(Typ::Update, &value, "null update expiring before issue");
    assert_eq!(
        CommandContent::new(
            uuid(COMMAND),
            uuid(ENDPOINT),
            int(0),
            time(T0),
            time(BEFORE_T0),
            int(0),
            CommandAction::Diagnose(DiagnoseArgs::default()),
        ),
        Err(ContentError::ExpiresBeforeIssued)
    );
}

#[test]
fn update_targets_and_packages_follow_their_rules() {
    // A version update without `packages`.
    let value = edited(Typ::Update, |v| {
        object(v).remove("packages");
    });
    assert_value_rejected(Typ::Update, &value, "without packages");
    // A release with `packages`, even an empty one.
    let semver = valid(Typ::Update);
    for packages in [semver["packages"].clone(), json!([])] {
        let mut value = valid_null_update();
        object(&mut value).insert("packages".to_owned(), packages);
        assert_value_rejected(Typ::Update, &value, "null with packages");
    }
    // A release to a group.
    let mut value = valid_null_update();
    let endpoint = object(&mut value).remove("endpoint_id").unwrap();
    object(&mut value).insert("group_id".to_owned(), endpoint);
    assert_value_rejected(Typ::Update, &value, "null for a group");
    // `target_version` missing altogether, with or without package fields.
    let value = edited(Typ::Update, |v| {
        object(v).remove("target_version");
    });
    assert_value_rejected(Typ::Update, &value, "no target_version");
    let mut value = valid_null_update();
    object(&mut value).remove("target_version");
    assert_value_rejected(Typ::Update, &value, "no target_version, no package");
    // Both targets, and neither.
    let value = edited(Typ::Update, |v| {
        object(v).insert("endpoint_id".to_owned(), json!(OTHER_ENDPOINT));
    });
    assert_value_rejected(Typ::Update, &value, "both targets");
    let mut value = valid_null_update();
    object(&mut value).insert("group_id".to_owned(), json!(GROUP));
    assert_value_rejected(Typ::Update, &value, "both targets, null");
    let value = edited(Typ::Update, |v| {
        object(v).remove("group_id");
    });
    assert_value_rejected(Typ::Update, &value, "no target");
    // An explicit null anywhere else.
    for field in ["packages", "group_id"] {
        let value = edited(Typ::Update, |v| v[field] = Value::Null);
        assert_value_rejected(Typ::Update, &value, &format!("{field} null"));
    }

    // The accepted shapes.
    assert_value_accepted(Typ::Update, &valid_null_update(), "null for an endpoint");
    let value = edited(Typ::Update, |v| {
        let group = object(v).remove("group_id").unwrap();
        object(v).insert("endpoint_id".to_owned(), group);
    });
    assert_value_accepted(Typ::Update, &value, "version for an endpoint");

    assert_eq!(
        UpdateContent::new(
            int(0),
            int(0),
            UpdateTarget::Group(uuid(GROUP)),
            None,
            false,
            time(T0),
            time(T0),
        ),
        Err(ContentError::NullTargetVersionForGroup)
    );
}

/// Puts each of the number literals `BAD_NUMBERS` at `at` and asserts the
/// document is rejected, and the largest integer accepted.
#[track_caller]
fn assert_integer_rule_at(typ: Typ, at: Locate, case: &str) {
    for bad in BAD_NUMBERS {
        let value = edited(typ, |v| *at(v) = json!("__placeholder__"));
        let text = serde_json::to_string(&value)
            .unwrap()
            .replace("\"__placeholder__\"", bad);
        assert_schema_error(typ, text.as_bytes(), &format!("{case} = {bad}"));
    }
    let value = edited(typ, |v| *at(v) = json!(9_007_199_254_740_991_u64));
    assert_value_accepted(typ, &value, &format!("{case} = 2^53 - 1"));
    let value = edited(typ, |v| *at(v) = json!(0));
    assert_value_rejected(typ, &value, &format!("{case} = 0"));
    let value = edited(typ, |v| *at(v) = json!(1));
    assert_value_accepted(typ, &value, &format!("{case} = 1"));
}

const BAD_NUMBERS: [&str; 6] = [
    "9007199254740992",
    "-1",
    "1.0",
    "1e3",
    "18446744073709551616",
    "\"1\"",
];

#[test]
fn updates_carry_a_package_per_platform() {
    let update = verify_update(&sign_value(Typ::Update, &valid(Typ::Update)), &source())
        .unwrap()
        .into_content();
    let platforms: Vec<&str> = update
        .packages()
        .iter()
        .map(|package| package.platform().as_str())
        .collect();
    assert_eq!(platforms, ["windows-x86_64-msi", "linux-x86_64-deb"]);
    let linux = update.packages().get(1).unwrap();
    assert_eq!(linux.sha256(), &Base64UrlArray::from([19; 32]));
    assert_eq!(linux.size().get(), 2_097_152);
    assert_eq!(linux.sources().len(), 2);

    // A third platform, and one the crate does not know, are accepted.
    let value = edited(Typ::Update, |v| {
        let mut rpm = v["packages"][1].clone();
        rpm["platform"] = json!("linux-x86_64-rpm");
        let mut other = v["packages"][0].clone();
        other["platform"] = json!("macos-aarch64-pkg");
        v["packages"].as_array_mut().unwrap().extend([rpm, other]);
    });
    assert_value_accepted(Typ::Update, &value, "four platforms");
    // A single package is enough.
    let value = edited(Typ::Update, |v| {
        v["packages"].as_array_mut().unwrap().truncate(1);
    });
    assert_value_accepted(Typ::Update, &value, "one platform");
}

#[test]
fn update_packages_follow_their_rules() {
    let cases: [(&str, Edit); 12] = [
        ("empty packages", |v| v["packages"] = json!([])),
        ("repeated platform", |v| {
            v["packages"][1]["platform"] = json!("windows-x86_64-msi");
        }),
        ("empty platform", |v| {
            v["packages"][0]["platform"] = json!("")
        }),
        ("platform not a string", |v| {
            v["packages"][0]["platform"] = json!(1);
        }),
        ("empty package sources", |v| {
            v["packages"][1]["sources"] = json!([]);
        }),
        ("packages not a list", |v| {
            v["packages"] = v["packages"][0].clone();
        }),
        ("package without platform", |v| {
            object(&mut v["packages"][0]).remove("platform");
        }),
        ("package without sha256", |v| {
            object(&mut v["packages"][0]).remove("sha256");
        }),
        ("package without size", |v| {
            object(&mut v["packages"][0]).remove("size");
        }),
        ("package without sources", |v| {
            object(&mut v["packages"][0]).remove("sources");
        }),
        ("package null", |v| v["packages"][0] = Value::Null),
        ("size null", |v| v["packages"][0]["size"] = Value::Null),
    ];
    for (case, edit) in cases {
        assert_value_rejected(Typ::Update, &edited(Typ::Update, edit), case);
    }
    assert_integer_rule_at(Typ::Update, |v| &mut v["packages"][1]["size"], "size");

    // The fields `packages` replaced are unknown fields now, beside
    // `packages` or in its place.
    let old = [
        ("package_sha256", b64(&[9; 32])),
        ("package_size", json!(1_048_576)),
        ("sources", json!(["https://dist.example/agent-1.2.3.msi"])),
    ];
    for (field, old_value) in &old {
        let value = edited(Typ::Update, |v| {
            object(v).insert((*field).to_owned(), old_value.clone());
        });
        assert_value_rejected(Typ::Update, &value, &format!("with {field}"));
        let mut value = valid_null_update();
        object(&mut value).insert((*field).to_owned(), old_value.clone());
        assert_value_rejected(Typ::Update, &value, &format!("null with {field}"));
    }
    let value = edited(Typ::Update, |v| {
        object(v).remove("packages");
        for (field, old_value) in &old {
            object(v).insert((*field).to_owned(), old_value.clone());
        }
    });
    assert_value_rejected(Typ::Update, &value, "the 0.1 form");

    let package = |platform: &str, sources: Vec<AbsoluteUrl>| {
        UpdatePackage::new(
            text(platform),
            Base64UrlArray::from([1; 32]),
            positive(1),
            sources,
        )
    };
    assert_eq!(
        package("linux-x86_64-deb", vec![]),
        Err(ContentError::EmptyPackageSources)
    );
    let deb = package("linux-x86_64-deb", vec![url("https://dist.example/a.deb")]).unwrap();
    let version = SemVer::parse("1.0.0").unwrap();
    assert_eq!(
        UpdateRelease::new(version.clone(), vec![]),
        Err(ContentError::EmptyPackages)
    );
    assert_eq!(
        UpdateRelease::new(version.clone(), vec![deb.clone(), deb.clone()]),
        Err(ContentError::DuplicatePlatform)
    );
    let release = UpdateRelease::new(version.clone(), vec![deb.clone()]).unwrap();
    assert_eq!(release.target_version(), &version);
    assert_eq!(release.packages(), std::slice::from_ref(&deb));
    assert_eq!(release.package("linux-x86_64-deb"), Some(&deb));
}

#[test]
fn policies_carry_sysmon_configs_and_the_sysmon_package() {
    let policy = verify_policy(&sign_value(Typ::Policy, &valid(Typ::Policy)), &source())
        .unwrap()
        .into_content();
    assert_eq!(policy, policy_content());
    let names: Vec<&str> = policy
        .sysmon_configs
        .as_slice()
        .iter()
        .map(|config| config.os().as_str())
        .collect();
    assert_eq!(names, ["windows", "linux"]);
    let linux = policy.sysmon_configs.get("linux").unwrap();
    assert_eq!(linux.sha256(), &Base64UrlArray::from([17; 32]));
    assert_eq!(linux.sources().len(), 2);
    assert_eq!(policy.sysmon_configs.get("macos"), None);
    assert_eq!(policy.existing_sysmon, ExistingSysmon::TakeOver);
    let package = policy.windows_sysmon_package.as_ref().unwrap();
    assert_eq!(package.version().as_str(), "15.15");
    assert_eq!(package.sha256(), &Base64UrlArray::from([27; 32]));
    assert_eq!(package.size().get(), 4_194_304);
    assert_eq!(package.sources().len(), 1);

    let accepted: [(&str, Edit); 6] = [
        ("empty sysmon_configs", |v| v["sysmon_configs"] = json!([])),
        ("an unknown os", |v| {
            v["sysmon_configs"][1]["os"] = json!("macos")
        }),
        ("one sysmon config", |v| {
            v["sysmon_configs"].as_array_mut().unwrap().truncate(1);
        }),
        ("existing_sysmon keep", |v| {
            v["existing_sysmon"] = json!("keep");
        }),
        ("no windows_sysmon_package", |v| {
            object(v).remove("windows_sysmon_package");
        }),
        ("the package's version any text", |v| {
            v["windows_sysmon_package"]["version"] = json!("v15.15 (build 7)");
        }),
    ];
    for (case, edit) in accepted {
        assert_value_accepted(Typ::Policy, &edited(Typ::Policy, edit), case);
    }
    let value = edited(Typ::Policy, |v| v["existing_sysmon"] = json!("keep"));
    let policy = verify_policy(&sign_value(Typ::Policy, &value), &source())
        .unwrap()
        .into_content();
    assert_eq!(policy.existing_sysmon, ExistingSysmon::Keep);
    let value = edited(Typ::Policy, |v| {
        object(v).remove("windows_sysmon_package");
    });
    let policy = verify_policy(&sign_value(Typ::Policy, &value), &source())
        .unwrap()
        .into_content();
    assert_eq!(policy.windows_sysmon_package, None);
}

#[test]
fn policy_sysmon_fields_follow_their_rules() {
    let cases: [(&str, Edit); 26] = [
        ("repeated os", |v| {
            v["sysmon_configs"][1]["os"] = json!("windows")
        }),
        ("empty os", |v| v["sysmon_configs"][0]["os"] = json!("")),
        ("os not a string", |v| {
            v["sysmon_configs"][0]["os"] = json!(1)
        }),
        ("empty sysmon config sources", |v| {
            v["sysmon_configs"][0]["sources"] = json!([]);
        }),
        ("sysmon config without os", |v| {
            object(&mut v["sysmon_configs"][0]).remove("os");
        }),
        ("sysmon config without sha256", |v| {
            object(&mut v["sysmon_configs"][0]).remove("sha256");
        }),
        ("sysmon config without sources", |v| {
            object(&mut v["sysmon_configs"][0]).remove("sources");
        }),
        ("sysmon_configs missing", |v| {
            object(v).remove("sysmon_configs");
        }),
        ("sysmon_configs null", |v| v["sysmon_configs"] = Value::Null),
        ("sysmon_configs an object", |v| {
            v["sysmon_configs"] = v["sysmon_configs"][0].clone();
        }),
        ("existing_sysmon missing", |v| {
            object(v).remove("existing_sysmon");
        }),
        ("existing_sysmon unknown", |v| {
            v["existing_sysmon"] = json!("replace");
        }),
        ("existing_sysmon in another case", |v| {
            v["existing_sysmon"] = json!("Keep");
        }),
        ("existing_sysmon camel case", |v| {
            v["existing_sysmon"] = json!("takeOver");
        }),
        ("existing_sysmon tagged", |v| {
            v["existing_sysmon"] = json!({"keep": null});
        }),
        ("existing_sysmon null", |v| {
            v["existing_sysmon"] = Value::Null
        }),
        ("windows_sysmon_package null", |v| {
            v["windows_sysmon_package"] = Value::Null;
        }),
        ("empty package version", |v| {
            v["windows_sysmon_package"]["version"] = json!("");
        }),
        ("package version a number", |v| {
            v["windows_sysmon_package"]["version"] = json!(15);
        }),
        ("empty package sources", |v| {
            v["windows_sysmon_package"]["sources"] = json!([]);
        }),
        ("package sha256 of 31 bytes", |v| {
            v["windows_sysmon_package"]["sha256"] = b64(&[1; 31]);
        }),
        ("package sha256 of 33 bytes", |v| {
            v["windows_sysmon_package"]["sha256"] = b64(&[1; 33]);
        }),
        ("package without version", |v| {
            object(&mut v["windows_sysmon_package"]).remove("version");
        }),
        ("package without sha256", |v| {
            object(&mut v["windows_sysmon_package"]).remove("sha256");
        }),
        ("package without size", |v| {
            object(&mut v["windows_sysmon_package"]).remove("size");
        }),
        ("package without sources", |v| {
            object(&mut v["windows_sysmon_package"]).remove("sources");
        }),
    ];
    for (case, edit) in cases {
        assert_value_rejected(Typ::Policy, &edited(Typ::Policy, edit), case);
    }
    let value = edited(Typ::Policy, |v| {
        object(&mut v["windows_sysmon_package"]).insert("extra".to_owned(), json!(1));
    });
    assert_value_rejected(Typ::Policy, &value, "unknown package field");
    assert_integer_rule_at(
        Typ::Policy,
        |v| &mut v["windows_sysmon_package"]["size"],
        "windows_sysmon_package.size",
    );

    // `sysmon_config`, which `sysmon_configs` replaced, is an unknown field
    // now, beside `sysmon_configs` or in its place.
    let old = json!({
        "sha256": b64(&[7; 32]),
        "sources": ["https://dist.example/sysmon.xml"],
    });
    let value = edited(Typ::Policy, |v| {
        object(v).insert("sysmon_config".to_owned(), old.clone());
    });
    assert_value_rejected(Typ::Policy, &value, "with sysmon_config");
    let value = edited(Typ::Policy, |v| {
        object(v).remove("sysmon_configs");
        object(v).remove("existing_sysmon");
        object(v).remove("windows_sysmon_package");
        object(v).insert("sysmon_config".to_owned(), old.clone());
    });
    assert_value_rejected(Typ::Policy, &value, "the 0.1 form");

    let config = |os: &str, sources: Vec<AbsoluteUrl>| {
        SysmonConfig::new(text(os), Base64UrlArray::from([1; 32]), sources)
    };
    assert_eq!(
        config("linux", vec![]),
        Err(ContentError::EmptySysmonConfigSources)
    );
    let linux = config("linux", vec![url("https://dist.example/s.xml")]).unwrap();
    assert_eq!(
        SysmonConfigs::new(vec![linux.clone(), linux.clone()]),
        Err(ContentError::DuplicateSysmonOs)
    );
    assert_eq!(SysmonConfigs::new(vec![]), Ok(SysmonConfigs::default()));
    assert_eq!(
        WindowsSysmonPackage::new(
            text("15.15"),
            Base64UrlArray::from([1; 32]),
            positive(1),
            vec![]
        ),
        Err(ContentError::EmptyWindowsSysmonPackageSources)
    );
}

/// A JSON value whose objects keep their members in the order written.
#[derive(Debug)]
enum Ordered {
    Object(Vec<(String, Ordered)>),
    Array(Vec<Ordered>),
    Scalar,
}

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor;

        impl<'de> serde::de::Visitor<'de> for OrderedVisitor {
            type Value = Ordered;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Ordered, E> {
                Ok(Ordered::Scalar)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Ordered, E> {
                Ok(Ordered::Scalar)
            }

            fn visit_str<E>(self, _: &str) -> Result<Ordered, E> {
                Ok(Ordered::Scalar)
            }

            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Scalar)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Ordered::Array(items))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Ordered, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(Ordered::Object(members))
            }
        }

        deserializer.deserialize_any(OrderedVisitor)
    }
}

impl Ordered {
    fn keys(&self) -> Vec<&str> {
        match self {
            Self::Object(members) => members.iter().map(|(key, _)| key.as_str()).collect(),
            _ => panic!("not an object: {self:?}"),
        }
    }

    fn get(&self, key: &str) -> &Self {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .unwrap_or_else(|| panic!("no {key}")),
            _ => panic!("not an object: {self:?}"),
        }
    }

    fn items(&self) -> &[Self] {
        match self {
            Self::Array(items) => items,
            _ => panic!("not an array: {self:?}"),
        }
    }
}

fn ordered<T: Serialize>(content: &T) -> Ordered {
    serde_json::from_slice(&serde_json::to_vec(content).unwrap()).unwrap()
}

#[test]
fn policy_and_update_serialize_in_the_fixed_member_order() {
    let policy = ordered(&policy_content());
    assert_eq!(
        policy.keys(),
        [
            "recovery_epoch",
            "group_id",
            "version",
            "collection_mode",
            "sysmon_configs",
            "existing_sysmon",
            "windows_sysmon_package",
            "field_exclusions",
            "audit_settings",
            "event_log_channels",
            "status_ui",
        ]
    );
    for config in policy.get("sysmon_configs").items() {
        assert_eq!(config.keys(), ["os", "sha256", "sources"]);
    }
    assert_eq!(
        policy.get("windows_sysmon_package").keys(),
        ["version", "sha256", "size", "sources"]
    );
    let without = ordered(&PolicyContent {
        windows_sysmon_package: None,
        ..policy_content()
    });
    assert_eq!(
        without.keys(),
        [
            "recovery_epoch",
            "group_id",
            "version",
            "collection_mode",
            "sysmon_configs",
            "existing_sysmon",
            "field_exclusions",
            "audit_settings",
            "event_log_channels",
            "status_ui",
        ]
    );

    let update = ordered(&update_content());
    assert_eq!(
        update.keys(),
        [
            "recovery_epoch",
            "version",
            "group_id",
            "target_version",
            "packages",
            "rollback",
            "issued_at",
            "expires_at",
        ]
    );
    for package in update.get("packages").items() {
        assert_eq!(package.keys(), ["platform", "sha256", "size", "sources"]);
    }
    assert_eq!(
        ordered(&null_update_content()).keys(),
        [
            "recovery_epoch",
            "version",
            "endpoint_id",
            "target_version",
            "rollback",
            "issued_at",
            "expires_at",
        ]
    );
}

#[test]
fn string_fields_follow_their_forms() {
    let cases: [(Typ, &str, Value); 22] = [
        (Typ::DeploymentCert, "install_name", json!("")),
        (Typ::DeploymentCert, "install_id", json!("")),
        (
            Typ::DeploymentCert,
            "issued_at",
            json!("2026-01-01T00:00:00+00:00"),
        ),
        (
            Typ::DeploymentCert,
            "install_signing_key",
            json!("not a jwk"),
        ),
        (Typ::InstallConfig, "install_id", json!("ac:me")),
        (Typ::InstallConfig, "install_id", json!("ac me")),
        (Typ::InstallConfig, "install_id", json!("äcme")),
        (
            Typ::InstallConfig,
            "customer_endpoint_id",
            json!(ENDPOINT.to_uppercase()),
        ),
        (Typ::InstallConfig, "customer_key_name", json!(ENDPOINT)),
        (
            Typ::InstallConfig,
            "customer_key_name",
            json!(format!("endpoint-{}", ENDPOINT.to_uppercase())),
        ),
        (
            Typ::InstallConfig,
            "customer_key_name",
            json!(format!("endpoint-{ENDPOINT}:1")),
        ),
        (
            Typ::InstallConfig,
            "customer_key_name",
            json!("install-acme"),
        ),
        (Typ::InstallConfig, "keyset", json!("")),
        (Typ::InstallConfig, "addresses", json!("")),
        (Typ::InstallConfig, "enroll_token", json!("")),
        (Typ::InstallConfig, "deployment_cert", json!("")),
        (Typ::InstallConfig, "vdi_mode", json!("false")),
        (Typ::Keyset, "customer_key_name", json!("endpoint-")),
        (Typ::RecoveryKey, "install_id", json!("")),
        (Typ::Enroll, "expires_at", Value::Null),
        (Typ::Enroll, "token_id", json!(format!("{{{TOKEN}}}"))),
        (Typ::Command, "issued_at", json!("2026-01-01T00:00:60Z")),
    ];
    for (typ, field, bad) in cases {
        let value = edited(typ, |v| v[field] = bad.clone());
        assert_value_rejected(typ, &value, &format!("{field} = {bad}"));
    }
    // Install ids take any printable ASCII but `:`.
    let value = edited(Typ::RecoveryKey, |v| v["install_id"] = json!("!~x/y"));
    assert_value_accepted(Typ::RecoveryKey, &value, "printable install id");
}

#[test]
fn enroll_tokens_may_leave_out_expires_at() {
    let value = edited(Typ::Enroll, |v| {
        object(v).remove("expires_at");
    });
    let document = verify_enroll(&sign_value(Typ::Enroll, &value), &source()).unwrap();
    assert_eq!(document.content().expires_at, None);
}

#[test]
fn schema_errors_name_where_they_are() {
    let cases: [(Typ, Vec<u8>, &str); 5] = [
        (
            Typ::Policy,
            serde_json::to_vec(&edited(Typ::Policy, |v| {
                v["sysmon_configs"][1]["sources"][0] = json!("/x");
            }))
            .unwrap(),
            "$.sysmon_configs[1].sources[0]",
        ),
        (
            Typ::Policy,
            serde_json::to_vec(&edited(Typ::Policy, |v| {
                object(&mut v["audit_settings"]).insert("extra".to_owned(), json!(1));
            }))
            .unwrap(),
            "$.audit_settings.extra",
        ),
        (
            Typ::Addresses,
            serde_json::to_vec(&edited(Typ::Addresses, |v| {
                v["control_entries"][0]["expected_name"] = json!("1.2.3.4");
            }))
            .unwrap(),
            "$.control_entries[0].expected_name",
        ),
        (
            Typ::Keyset,
            serde_json::to_vec(&edited(Typ::Keyset, |v| v["keys"] = json!([]))).unwrap(),
            "$",
        ),
        (
            Typ::Assign,
            serde_json::to_vec(&edited(Typ::Assign, |v| {
                v["uninstall_token_sha256"] = b64(&[0; 31]);
            }))
            .unwrap(),
            "$.uninstall_token_sha256",
        ),
    ];
    for (typ, payload, path) in cases {
        let error = verify_bytes(typ, &payload).unwrap_err();
        assert_eq!(error.schema_error().unwrap().path(), path, "{error:?}");
    }
}

#[test]
fn content_errors_of_the_new_fields_name_them() {
    // A rule an entry or a list breaks is reported at the value holding it.
    let cases: [(Typ, Edit, &str, &str); 7] = [
        (
            Typ::Update,
            |v| v["packages"][1]["sources"] = json!([]),
            "$.packages",
            "the sources of a packages entry is empty",
        ),
        (
            Typ::Update,
            |v| v["packages"] = json!([]),
            "$",
            "packages is empty",
        ),
        (
            Typ::Update,
            |v| v["packages"][1]["platform"] = json!("windows-x86_64-msi"),
            "$",
            "packages repeats a platform",
        ),
        (
            Typ::Update,
            |v| {
                object(v).remove("packages");
            },
            "$",
            "an update with a target_version has packages",
        ),
        (
            Typ::Policy,
            |v| v["sysmon_configs"][0]["sources"] = json!([]),
            "$.sysmon_configs",
            "the sources of a sysmon_configs entry is empty",
        ),
        (
            Typ::Policy,
            |v| v["sysmon_configs"][1]["os"] = json!("windows"),
            "$",
            "sysmon_configs repeats an os",
        ),
        (
            Typ::Policy,
            |v| v["windows_sysmon_package"]["sources"] = json!([]),
            "$.windows_sysmon_package",
            "the sources of windows_sysmon_package is empty",
        ),
    ];
    for (typ, edit, path, message) in cases {
        let error = verify_value(typ, &edited(typ, edit)).unwrap_err();
        let schema = error.schema_error().unwrap();
        assert_eq!(schema.path(), path, "{error:?}");
        assert!(schema.to_string().contains(message), "{schema}");
    }
    let mut value = valid_null_update();
    object(&mut value).insert(
        "packages".to_owned(),
        valid(Typ::Update)["packages"].clone(),
    );
    let error = verify_value(Typ::Update, &value).unwrap_err();
    assert!(
        error
            .schema_error()
            .unwrap()
            .to_string()
            .contains("an update whose target_version is null has no packages"),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// Verifier failures and their results
// ---------------------------------------------------------------------------

#[test]
fn verifier_errors_map_to_document_results() {
    let payload = serde_json::to_vec(&valid(Typ::Policy)).unwrap();
    let kid = customer_kid(1);
    let customer = customer_key();
    let header = |members: &str| customer.sign_raw(members.as_bytes(), &payload);

    let known = source();
    let wrong_class = Source::default().with(&kid, &customer, KeyKind::Recovery);
    let revoked = Source::default().revoked(&kid);

    type Check = fn(&VerifyError) -> bool;
    let cases: [(&str, String, &Source, DocumentResult, Check); 10] = [
        (
            "format",
            "not.a-jws".to_owned(),
            &known,
            DocumentResult::SchemaError,
            |e| matches!(e, VerifyError::Format(_)),
        ),
        (
            "header",
            header(&format!(
                r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","crit":[]}}"#
            )),
            &known,
            DocumentResult::SchemaError,
            |e| matches!(e, VerifyError::Header(_)),
        ),
        (
            "typ mismatch",
            customer.sign(Typ::Assign, &kid, &payload),
            &known,
            DocumentResult::SchemaError,
            |e| matches!(e, VerifyError::TypMismatch { .. }),
        ),
        (
            "kid grammar",
            customer.sign(Typ::Policy, "endpoint-x:1", &payload),
            &known,
            DocumentResult::SchemaError,
            |e| matches!(e, VerifyError::Kid { .. }),
        ),
        (
            "kid kind not allowed",
            recovery_key().sign(Typ::Policy, RECOVERY_KID, &payload),
            &known,
            DocumentResult::WrongKeyClass,
            |e| {
                matches!(
                    e,
                    VerifyError::KeyKind {
                        registered_kind: None,
                        ..
                    }
                )
            },
        ),
        (
            "registered as another kind",
            customer.sign(Typ::Policy, &kid, &payload),
            &wrong_class,
            DocumentResult::WrongKeyClass,
            |e| {
                matches!(
                    e,
                    VerifyError::KeyKind {
                        registered_kind: Some(KeyKind::Recovery),
                        ..
                    }
                )
            },
        ),
        (
            "unknown kid",
            customer.sign(Typ::Policy, &customer_kid(9), &payload),
            &known,
            DocumentResult::UnknownKid,
            |e| matches!(e, VerifyError::UnknownKid { .. }),
        ),
        (
            "revoked kid",
            customer.sign(Typ::Policy, &kid, &payload),
            &revoked,
            DocumentResult::RevokedKid,
            |e| matches!(e, VerifyError::RevokedKid { .. }),
        ),
        (
            "signature by another key",
            stranger_key().sign(Typ::Policy, &kid, &payload),
            &known,
            DocumentResult::BadSignature,
            |e| matches!(e, VerifyError::Signature { .. }),
        ),
        (
            "signature bytes altered",
            break_signature(&customer.sign(Typ::Policy, &kid, &payload)),
            &known,
            DocumentResult::BadSignature,
            |e| matches!(e, VerifyError::Signature { .. }),
        ),
    ];
    for (case, jws, source, result, check) in cases {
        let error = verify_policy(&jws, source).unwrap_err();
        assert_eq!(error.result(), result, "{case}");
        let cause = error
            .verify_error()
            .unwrap_or_else(|| panic!("{case}: {error:?}"));
        assert!(check(cause), "{case}: {cause:?}");
        assert!(error.schema_error().is_none(), "{case}");
        assert_eq!(error.header(), cause.header(), "{case}");
    }
}

#[test]
fn a_bad_signature_wins_over_a_schema_violation() {
    let bad_content = edited(Typ::Policy, |v| {
        object(v).insert("extra".to_owned(), json!(1));
    });
    let jws = break_signature(&sign_value(Typ::Policy, &bad_content));
    let error = verify_policy(&jws, &source()).unwrap_err();
    assert_eq!(error.result(), DocumentResult::BadSignature);
    assert!(matches!(
        error.verify_error(),
        Some(VerifyError::Signature { .. })
    ));
    // Not even JSON.
    let jws = break_signature(&sign(Typ::Policy, b"not json"));
    assert_eq!(
        verify_policy(&jws, &source()).unwrap_err().result(),
        DocumentResult::BadSignature
    );
}

#[test]
fn diagnostics_hold_the_header_as_written() {
    let payload = serde_json::to_vec(&valid(Typ::Policy)).unwrap();
    let kid = customer_kid(1);

    // The signature fails: the header passed, so its values are reported.
    let error =
        verify_policy(&stranger_key().sign(Typ::Policy, &kid, &payload), &source()).unwrap_err();
    let header = error.header().unwrap();
    assert_eq!((header.typ(), header.kid()), ("senta-policy", kid.as_str()));

    // The content fails.
    let error = verify_policy(&sign(Typ::Policy, b"{}"), &source()).unwrap_err();
    let header = error.header().unwrap();
    assert_eq!((header.typ(), header.kid()), ("senta-policy", kid.as_str()));

    // A typ mismatch and a bad kid report what the header held.
    let error =
        verify_policy(&customer_key().sign(Typ::Assign, &kid, &payload), &source()).unwrap_err();
    assert_eq!(error.header().unwrap().typ(), "senta-assign");
    let error = verify_policy(
        &customer_key().sign(Typ::Policy, "no such kid", &payload),
        &source(),
    )
    .unwrap_err();
    assert_eq!(error.header().unwrap().kid(), "no such kid");

    // The format and the header themselves: nothing to report.
    assert_eq!(verify_policy("a.b", &source()).unwrap_err().header(), None);
    let header_error = customer_key().sign_raw(
        br#"{"alg":"none","typ":"senta-policy","kid":"x"}"#,
        &payload,
    );
    assert_eq!(
        verify_policy(&header_error, &source())
            .unwrap_err()
            .header(),
        None
    );
}

// ---------------------------------------------------------------------------
// Key sets signed by their own current_kid
// ---------------------------------------------------------------------------

#[test]
fn self_signed_key_set_verifies_under_its_own_current_kid() {
    let payload = serde_json::to_vec(&valid(Typ::Keyset)).unwrap();
    // `current_kid` is version 3, whose key in `keys` is `stranger_key`.
    let jws = stranger_key().sign(Typ::Keyset, &customer_kid(3), &payload);
    let verified = verify_self_signed_keyset(&jws).unwrap();
    assert_eq!(verified.kid().as_str(), customer_kid(3));
    assert_eq!(verified.typ(), Typ::Keyset);
    assert_eq!(verified.payload(), payload.as_slice());
    assert_eq!(verified.content(), &keyset_content());
    // The same document `verify_keyset` gives with that one key.
    let source = Source::default().with(&customer_kid(3), &stranger_key(), KeyKind::Customer);
    assert_eq!(
        outcome!(verify_self_signed_keyset(&jws)),
        verify_typ(Typ::Keyset, &jws, &source)
    );
}

#[test]
fn self_signed_key_set_rejects_every_other_signer() {
    let payload = serde_json::to_vec(&valid(Typ::Keyset)).unwrap();
    let cases = [
        // Another kid of `keys`, with its own key.
        (
            customer_key().sign(Typ::Keyset, &customer_kid(2), &payload),
            DocumentResult::UnknownKid,
        ),
        // The recovery key.
        (
            recovery_key().sign(Typ::Keyset, RECOVERY_KID, &payload),
            DocumentResult::UnknownKid,
        ),
        // `current_kid`, with another key.
        (
            customer_key().sign(Typ::Keyset, &customer_kid(3), &payload),
            DocumentResult::BadSignature,
        ),
        (
            break_signature(&stranger_key().sign(Typ::Keyset, &customer_kid(3), &payload)),
            DocumentResult::BadSignature,
        ),
        // Another `typ`.
        (
            stranger_key().sign(Typ::Policy, &customer_kid(3), &payload),
            DocumentResult::SchemaError,
        ),
        // Not a JWS.
        ("a.b".to_owned(), DocumentResult::SchemaError),
    ];
    for (jws, expected) in cases {
        let error = verify_self_signed_keyset(&jws).unwrap_err();
        assert_eq!(error.result(), expected, "{error:?}");
        assert!(matches!(error, DocumentError::Verify(_)), "{error:?}");
    }

    // `current_kid` is not in `keys`.
    let mut value = valid(Typ::Keyset);
    value["current_kid"] = json!(customer_kid(4));
    let payload = serde_json::to_vec(&value).unwrap();
    let error =
        verify_self_signed_keyset(&stranger_key().sign(Typ::Keyset, &customer_kid(4), &payload))
            .unwrap_err();
    assert_eq!(error.result(), DocumentResult::SchemaError);
    assert!(error.schema_error().is_some(), "{error:?}");
}

// ---------------------------------------------------------------------------
// Reading before the signature is verified
// ---------------------------------------------------------------------------

#[test]
fn inspection_reads_without_a_key_source_or_a_good_signature() {
    for typ in INSPECTABLE {
        let payload = serde_json::to_vec(&valid(typ)).unwrap();
        let jws = sign(typ, &payload);
        let verified = verify_typ(typ, &jws, &source()).unwrap();
        for candidate in [jws.clone(), break_signature(&jws), {
            let (_, kid) = signer(typ);
            stranger_key().sign(typ, &kid, &payload)
        }] {
            let inspected = inspect_typ(typ, &candidate).unwrap_or_else(|e| panic!("{typ}: {e:?}"));
            assert_eq!(inspected, verified, "{typ}");
        }
    }
}

#[test]
fn inspection_gives_the_kid_to_choose_the_key_by() {
    let payload = serde_json::to_vec(&valid(Typ::Keyset)).unwrap();
    let by_recovery =
        inspect_keyset(&recovery_key().sign(Typ::Keyset, RECOVERY_KID, &payload)).unwrap();
    assert_eq!(by_recovery.kid().kind(), KeyKind::Recovery);
    assert_eq!(by_recovery.kid().key_name(), "recovery-acme");
    assert_eq!(by_recovery.kid().install_id(), Some(INSTALL_ID));
    assert_eq!(by_recovery.kid().version(), Some(4));
    assert_eq!(by_recovery.kid().as_str(), RECOVERY_KID);
    assert_eq!(by_recovery.header().kid(), RECOVERY_KID);
    assert_eq!(by_recovery.header().typ(), "senta-keyset");
    assert_eq!(by_recovery.typ(), Typ::Keyset);
    assert_eq!(by_recovery.payload(), payload.as_slice());
    assert_eq!(by_recovery.content().keyset_version().get(), 3);

    let by_customer =
        inspect_keyset(&customer_key().sign(Typ::Keyset, &customer_kid(1), &payload)).unwrap();
    assert_eq!(by_customer.kid().kind(), KeyKind::Customer);
    assert_eq!(by_customer.kid().endpoint_id(), Some(uuid(ENDPOINT).get()));
    assert_eq!(by_customer.kid().version(), Some(1));

    // The same content signed by two keys is one document.
    assert_eq!(by_recovery.payload_hash(), by_customer.payload_hash());
    assert_eq!(
        by_recovery.payload_hash(),
        &<[u8; 32]>::from(sha2::Sha256::digest(&payload))
    );
    assert_eq!(by_recovery.into_content(), keyset_content());

    let recovery =
        inspect_recovery_key(&sign_value(Typ::RecoveryKey, &valid(Typ::RecoveryKey))).unwrap();
    assert_eq!(recovery.content().recovery_key_version.get(), 5);
    assert_eq!(recovery.kid().install_id(), Some(INSTALL_ID));

    let config =
        inspect_install_config(&sign_value(Typ::InstallConfig, &valid(Typ::InstallConfig)))
            .unwrap();
    assert_eq!(
        config.content().deployment_cert.as_str(),
        "deployment.jws.here"
    );
    assert_eq!(config.content().install_id.as_str(), INSTALL_ID);
    assert_eq!(config.kid().kind(), KeyKind::InstallSigning);
}

#[test]
fn inspection_fails_as_verification_does_before_the_signature() {
    for typ in INSPECTABLE {
        let (key, kid) = signer(typ);
        let payload = serde_json::to_vec(&valid(typ)).unwrap();
        let other_typ = if typ == Typ::Keyset {
            Typ::Policy
        } else {
            Typ::Keyset
        };
        let bad_content = serde_json::to_vec(&edited(typ, |v| {
            object(v).insert("extra".to_owned(), json!(1));
        }))
        .unwrap();
        let cases = [
            ("format", "a.b.c.d".to_owned()),
            (
                "header",
                key.sign_raw(
                    format!(r#"{{"alg":"EdDSA","typ":"{typ}","kid":"{kid}","x":1}}"#).as_bytes(),
                    &payload,
                ),
            ),
            ("typ mismatch", key.sign(other_typ, &kid, &payload)),
            ("kid grammar", key.sign(typ, "recovery-:1", &payload)),
            ("key kind", key.sign(typ, VENDOR_KID, &payload)),
            ("schema", key.sign(typ, &kid, &bad_content)),
            ("not JSON", key.sign(typ, &kid, b"[1, 2]")),
        ];
        for (case, jws) in cases {
            let inspected = inspect_typ(typ, &jws).unwrap_err();
            let verified = verify_typ(typ, &jws, &source()).unwrap_err();
            assert_eq!(inspected, verified, "{typ} {case}");
            assert_eq!(inspected.result(), verified.result(), "{typ} {case}");
        }
        // The diagnostics and the cause of a content error.
        let error = inspect_typ(typ, &key.sign(typ, &kid, &bad_content)).unwrap_err();
        assert_eq!(error.result(), DocumentResult::SchemaError);
        assert_eq!(error.schema_error().unwrap().path(), "$.extra");
        assert_eq!(error.header().unwrap().kid(), kid);
        // A key kind the typ does not allow.
        let error = inspect_typ(typ, &key.sign(typ, VENDOR_KID, &payload)).unwrap_err();
        assert_eq!(error.result(), DocumentResult::WrongKeyClass);
        assert!(matches!(
            error.verify_error(),
            Some(VerifyError::KeyKind { .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// The validity window
// ---------------------------------------------------------------------------

fn at(text: &str) -> Timestamp {
    text.parse().unwrap()
}

const NANO: SignedDuration = SignedDuration::from_nanos(1);
const MILLI: SignedDuration = SignedDuration::from_millis(1);

#[test]
fn window_constants_are_public_and_exact() {
    assert_eq!(CLOCK_SKEW, SignedDuration::from_hours(1));
    assert_eq!(MAX_COMMAND_LIFETIME, SignedDuration::from_hours(24));
    assert_eq!(MAX_UPDATE_LIFETIME, SignedDuration::from_hours(720));
}

#[test]
fn window_passes_on_each_bound_and_fails_just_past_it() {
    let issued = at(T0);
    let expires = issued + SignedDuration::from_hours(2);
    for lifetime in [MAX_COMMAND_LIFETIME, MAX_UPDATE_LIFETIME] {
        // `expires_at + 1h`.
        let last = expires + CLOCK_SKEW;
        assert_eq!(
            check_validity_window(last, issued, expires, lifetime),
            Ok(())
        );
        assert_eq!(
            check_validity_window(last + NANO, issued, expires, lifetime),
            Err(DocumentResult::Expired)
        );
        // `issued_at − 1h`.
        let first = issued - CLOCK_SKEW;
        assert_eq!(
            check_validity_window(first, issued, expires, lifetime),
            Ok(())
        );
        assert_eq!(
            check_validity_window(first - NANO, issued, expires, lifetime),
            Err(DocumentResult::NotYetValid)
        );
        // Inside the window.
        assert_eq!(
            check_validity_window(issued, issued, expires, lifetime),
            Ok(())
        );
    }
    // The lifetime caps, checked at a `now` no other check rejects.
    for lifetime in [MAX_COMMAND_LIFETIME, MAX_UPDATE_LIFETIME] {
        let longest = issued + lifetime;
        assert_eq!(
            check_validity_window(issued, issued, longest, lifetime),
            Ok(())
        );
        assert_eq!(
            check_validity_window(issued, issued, longest + MILLI, lifetime),
            Err(DocumentResult::Expired)
        );
        assert_eq!(
            check_validity_window(issued, issued, longest + NANO, lifetime),
            Err(DocumentResult::Expired)
        );
    }
    // A command may not live as long as an update.
    let month = issued + MAX_UPDATE_LIFETIME;
    assert_eq!(
        check_validity_window(issued, issued, month, MAX_COMMAND_LIFETIME),
        Err(DocumentResult::Expired)
    );
    assert_eq!(
        check_validity_window(issued, issued, month, MAX_UPDATE_LIFETIME),
        Ok(())
    );
}

#[test]
fn window_checks_run_in_order() {
    let issued = at(T0);
    let too_long = issued + MAX_COMMAND_LIFETIME + MILLI;
    // Too long and not yet valid: the lifetime decides.
    let early = issued - SignedDuration::from_hours(5);
    assert_eq!(
        check_validity_window(early, issued, too_long, MAX_COMMAND_LIFETIME),
        Err(DocumentResult::Expired)
    );
    // Not yet valid and, impossibly, already past `expires_at`: a window
    // that ends before it begins is not yet valid when `now` is before it.
    let backwards_expires = issued - SignedDuration::from_hours(10);
    assert_eq!(
        check_validity_window(
            issued - SignedDuration::from_hours(2),
            issued,
            backwards_expires,
            MAX_COMMAND_LIFETIME
        ),
        Err(DocumentResult::NotYetValid)
    );
}

#[test]
fn window_never_panics_at_the_ends_of_time() {
    let times = [
        Timestamp::MIN,
        Timestamp::UNIX_EPOCH,
        at(T0),
        Timestamp::MAX,
    ];
    let lifetimes = [
        MAX_COMMAND_LIFETIME,
        MAX_UPDATE_LIFETIME,
        SignedDuration::ZERO,
        SignedDuration::MAX,
        SignedDuration::MIN,
    ];
    for now in times {
        for issued in times {
            for expires in times {
                for lifetime in lifetimes {
                    let _ = check_validity_window(now, issued, expires, lifetime);
                }
            }
        }
    }
    assert_eq!(
        check_validity_window(
            Timestamp::MAX,
            Timestamp::MIN,
            Timestamp::MAX,
            MAX_UPDATE_LIFETIME
        ),
        Err(DocumentResult::Expired)
    );
    assert_eq!(
        check_validity_window(
            Timestamp::MIN,
            Timestamp::MAX,
            Timestamp::MAX,
            MAX_UPDATE_LIFETIME
        ),
        Err(DocumentResult::NotYetValid)
    );
    assert_eq!(
        check_validity_window(
            Timestamp::MAX,
            Timestamp::MIN,
            Timestamp::MIN,
            MAX_UPDATE_LIFETIME
        ),
        Err(DocumentResult::Expired)
    );
    assert_eq!(
        check_validity_window(
            Timestamp::MAX,
            Timestamp::MAX,
            Timestamp::MAX,
            MAX_UPDATE_LIFETIME
        ),
        Ok(())
    );
}
