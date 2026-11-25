//! What the generator builds documents from: fixed identifiers and times,
//! the keys, the issuing side's version rule, and the document contents.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use senta_protocol::auth::jws::Typ;
use senta_protocol::auth::jws::test_util::TestKey;
use sha2::{Digest as _, Sha256};

use crate::json::J;
use crate::model::{JwkJson, KeyEntry, KeyKindName};

// --- identifiers -------------------------------------------------------------

/// The install id of the installation every sequence case runs in.
pub const INSTALL_ID: &str = "acme";
/// Another installation, whose deployment certificate is mixed in.
pub const OTHER_INSTALL_ID: &str = "globex";
/// The customer's endpoint id, which names its customer keys.
pub const CUSTOMER: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
/// Another customer endpoint id.
pub const OTHER_CUSTOMER: &str = "1b4e28ba-2fa1-4d2e-a9c4-6f8e0f6a7c11";
/// The endpoint id the enrollment result gives the endpoint under test.
pub const ENDPOINT: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
/// Another endpoint of the same customer.
pub const OTHER_ENDPOINT: &str = "9b2f3c44-1d5e-4f60-8a71-b2c3d4e5f601";
/// The group the endpoint is assigned to.
pub const GROUP: &str = "16fd2706-8baf-433b-82eb-8c7fada847da";
/// The `token_id` of the installation's enrollment token.
pub const TOKEN: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
/// The `token_id` of another enrollment token.
pub const OTHER_TOKEN: &str = "6ba7b812-9dad-11d1-80b4-00c04fd430c8";
/// The id of the enrollment attempt.
pub const ATTEMPT: &str = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
/// The id of another enrollment attempt.
pub const OTHER_ATTEMPT: &str = "6ba7b813-9dad-11d1-80b4-00c04fd430c8";
/// The `entry_id` of the address document's telemetry entry.
pub const ENTRY: &str = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11";

/// The kid of the vendor release key.
pub const VENDOR_RELEASE: &str = "vendor-release-1";
/// The kid of a vendor test key.
pub const VENDOR_TEST: &str = "vendor-test-1";
/// A vendor kid that follows neither vendor prefix.
pub const VENDOR_OTHER: &str = "vendor-other-1";

/// The `recovery_epoch` of the installation's key set.
pub const EPOCH: u64 = 1;

/// The senta version installed, for `senta-update`.
pub const SENTA_VERSION: &str = "1.0.0";
/// The version an update installs.
pub const TARGET_VERSION: &str = "1.2.0";

/// The platforms of the packages an update carries.
pub const WINDOWS_MSI: &str = "windows-x86_64-msi";
pub const LINUX_DEB: &str = "linux-x86_64-deb";
pub const LINUX_RPM: &str = "linux-x86_64-rpm";

/// The largest integer a signed document carries, 2^53 − 1.
pub const MAX_INTEGER: u64 = (1 << 53) - 1;

/// A trust root certificate for the address documents: a self-signed
/// Ed25519 CA, fixed so that the documents carrying it never change.
const TRUST_ROOT: &str = "-----BEGIN CERTIFICATE-----
MIIBIzCB1qADAgECAhQJuTfxvJz3rnJ/r/78GYaRqnPEcTAFBgMrZXAwFzEVMBMG
A1UEAwwMcm9vdC5leGFtcGxlMCAXDTI2MTEyMzAzNTAzM1oYDzIxMjYxMDMwMDM1
MDMzWjAXMRUwEwYDVQQDDAxyb290LmV4YW1wbGUwKjAFBgMrZXADIQAJANwZQYmS
GAlwS16TwQ3++fhn4jgXt+DDNOoykNICk6MyMDAwHQYDVR0OBBYEFCIgzjawfAax
Ji6MhR/tcil8pda9MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA1V3ZEWZcnDk/
yYRO75Z9pBwXh+pD3MeiDWBTD+JAoRsZphb2l8HUO7P9vKGZO92HykhyvHj370Lf
4P36CiFfAQ==
-----END CERTIFICATE-----
";

/// Returns the customer kid of version `version`.
pub fn customer_kid(version: u64) -> String {
    format!("endpoint-{CUSTOMER}:{version}")
}

pub fn install_kid(install_id: &str) -> String {
    format!("install-{install_id}:1")
}

pub fn recovery_kid(install_id: &str, version: u64) -> String {
    format!("recovery-{install_id}:{version}")
}

/// Returns the command id numbered `n`.
pub fn command_id(n: u8) -> String {
    format!("c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a{n:02x}")
}

/// Returns 32 bytes derived from `label`, for fixed hashes and salts.
pub fn bytes32(label: &str) -> [u8; 32] {
    Sha256::digest(format!("senta-protocol test vector bytes: {label}")).into()
}

pub fn spki() -> [u8; 32] {
    bytes32("endpoint spki")
}

pub fn hw_salt() -> [u8; 32] {
    bytes32("hw_salt")
}

// --- times ----------------------------------------------------------------------

/// When the installation's documents are issued.
pub fn install_time() -> Timestamp {
    time("2026-01-01T00:00:00Z")
}

/// The endpoint's own clock in every step that takes one.
pub fn now() -> Timestamp {
    time("2026-01-02T00:00:00Z")
}

pub fn time(text: &str) -> Timestamp {
    text.parse().expect("a fixed RFC 3339 time")
}

/// Writes a time as an RFC 3339 UTC string.
pub fn rfc3339(at: Timestamp) -> String {
    at.to_string()
}

// --- bytes ---------------------------------------------------------------------------

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// --- keys -------------------------------------------------------------------------------

/// Returns the fixed seed of the key under `kid`.
pub fn seed_of(kid: &str) -> [u8; 32] {
    Sha256::digest(format!("senta-protocol test vector seed: {kid}")).into()
}

/// Returns the kind of key a kid names by its prefix; `vendor-other-1`,
/// which follows no vendor prefix, is still meant as a vendor key.
pub fn kind_of(kid: &str) -> KeyKindName {
    if kid.starts_with("endpoint-") {
        KeyKindName::Customer
    } else if kid.starts_with("install-") {
        KeyKindName::InstallSigning
    } else if kid.starts_with("recovery-") {
        KeyKindName::Recovery
    } else {
        KeyKindName::Vendor
    }
}

/// The keys one vector file uses, collected as documents are signed.
#[derive(Default)]
pub struct KeyRing {
    kids: BTreeMap<String, KeyKindName>,
}

impl KeyRing {
    /// Returns the key under `kid`, adding it to the file's key list.
    pub fn key(&mut self, kid: &str) -> TestKey {
        self.kids.insert(kid.to_owned(), kind_of(kid));
        TestKey::from_seed(&seed_of(kid))
    }

    /// Returns the public key under `kid` as a JWK.
    pub fn jwk(&mut self, kid: &str) -> J {
        let key = self.key(kid);
        J::obj([
            ("kty", J::str("OKP")),
            ("crv", J::str("Ed25519")),
            ("x", J::str(b64(&key.public_key_bytes()))),
        ])
    }

    /// Signs `payload` as a compact JWS with the header
    /// `{"alg":"EdDSA","typ":<typ>,"kid":<kid>}`.
    pub fn sign(&mut self, typ: Typ, kid: &str, payload: &J) -> String {
        self.key(kid).sign(typ, kid, payload.to_text().as_bytes())
    }

    /// Signs a compact JWS of `header` and `payload` exactly as given.
    pub fn sign_raw(&mut self, kid: &str, header: &[u8], payload: &[u8]) -> String {
        self.key(kid).sign_raw(header, payload)
    }

    /// Returns the file's key list, in kid order.
    pub fn entries(&self) -> Vec<KeyEntry> {
        self.kids
            .iter()
            .map(|(kid, &kind)| {
                let seed = seed_of(kid);
                let key = TestKey::from_seed(&seed);
                KeyEntry {
                    kid: kid.clone(),
                    kind,
                    seed: b64(&seed),
                    jwk: JwkJson {
                        kty: "OKP".to_owned(),
                        crv: "Ed25519".to_owned(),
                        x: b64(&key.public_key_bytes()),
                    },
                }
            })
            .collect()
    }
}

// --- the issuing side's versions -------------------------------------------------------

/// The issuing side's rule for versions and sequence numbers: the Unix
/// milliseconds of the issue time, or the previous value + 1 for the same
/// (`typ`, target) or the same endpoint when that is not above it.
///
/// It also hands out issue times, one minute apart, so that every document
/// issued in a case has a time of its own.
pub struct Issuer {
    last: BTreeMap<String, u64>,
    clock: Timestamp,
}

impl Issuer {
    /// Starts issuing one hour before [`now`].
    pub fn new() -> Self {
        Self {
            last: BTreeMap::new(),
            clock: now() - SignedDuration::from_hours(1),
        }
    }

    /// Returns the next issue time.
    pub fn tick(&mut self) -> Timestamp {
        self.clock += SignedDuration::from_mins(1);
        self.clock
    }

    /// Returns the version or sequence number of a document issued at `at`
    /// for `key`, and records it.
    pub fn number(&mut self, key: &str, at: Timestamp) -> u64 {
        let millis =
            u64::try_from(at.as_millisecond()).expect("every issue time is after the Unix epoch");
        let number = match self.last.get(key) {
            Some(&last) if millis <= last => last + 1,
            _ => millis,
        };
        self.last.insert(key.to_owned(), number);
        number
    }

    /// Issues at the next time for `key`, returning the time and number.
    pub fn issue(&mut self, key: &str) -> (Timestamp, u64) {
        let at = self.tick();
        (at, self.number(key, at))
    }
}

// --- contents ---------------------------------------------------------------------------

pub fn deployment_cert(ring: &mut KeyRing, install_id: &str) -> J {
    let signing_kid = install_kid(install_id);
    J::obj([
        ("install_id", J::str(install_id)),
        ("install_name", J::str(format!("{install_id} corp"))),
        ("install_signing_key", ring.jwk(&signing_kid)),
        ("install_signing_kid", J::str(signing_kid)),
        ("issued_at", J::str(rfc3339(install_time()))),
    ])
}

/// A key set of `customer` at (`epoch`, `version`) holding the customer
/// keys of versions `keys`, `current` among them, and revoking `revoked`.
pub struct KeysetSpec<'a> {
    pub customer: &'a str,
    pub epoch: u64,
    pub version: u64,
    pub keys: &'a [u64],
    pub current: u64,
    pub revoked: &'a [u64],
}

impl<'a> KeysetSpec<'a> {
    /// A key set of [`CUSTOMER`].
    pub fn of(epoch: u64, version: u64, keys: &'a [u64], current: u64, revoked: &'a [u64]) -> Self {
        KeysetSpec {
            customer: CUSTOMER,
            epoch,
            version,
            keys,
            current,
            revoked,
        }
    }
}

pub fn keyset(ring: &mut KeyRing, spec: &KeysetSpec<'_>) -> J {
    let kid = |version: u64| format!("endpoint-{}:{version}", spec.customer);
    J::obj([
        ("customer_endpoint_id", J::str(spec.customer)),
        (
            "customer_key_name",
            J::str(format!("endpoint-{}", spec.customer)),
        ),
        ("recovery_epoch", J::Int(spec.epoch)),
        ("keyset_version", J::Int(spec.version)),
        (
            "keys",
            J::arr(spec.keys.iter().map(|&version| {
                J::obj([
                    ("kid", J::str(kid(version))),
                    ("key", ring.jwk(&kid(version))),
                ])
            })),
        ),
        ("current_kid", J::str(kid(spec.current))),
        (
            "revoked_kids",
            J::arr(spec.revoked.iter().map(|&version| J::str(kid(version)))),
        ),
    ])
}

pub fn recovery_key(ring: &mut KeyRing, version: u64) -> J {
    J::obj([
        ("install_id", J::str(INSTALL_ID)),
        ("recovery_key_version", J::Int(version)),
        ("recovery_key", ring.jwk(&recovery_kid(INSTALL_ID, version))),
    ])
}

pub fn addresses(epoch: u64, version: u64) -> J {
    J::obj([
        ("recovery_epoch", J::Int(epoch)),
        ("version", J::Int(version)),
        (
            "control_entries",
            J::arr([J::obj([
                ("address", J::str("review.example:443")),
                ("expected_name", J::str("review.example")),
            ])]),
        ),
        (
            "telemetry_entries",
            J::arr([J::obj([
                ("entry_id", J::str(ENTRY)),
                ("address", J::str("store.example:8443")),
                ("expected_name", J::str("store.example")),
            ])]),
        ),
        ("trust_roots", J::arr([J::str(TRUST_ROOT)])),
        (
            "distribution_points",
            J::arr([J::str("https://dist.example/")]),
        ),
    ])
}

pub fn enroll(token_id: &str) -> J {
    J::obj([
        ("token_id", J::str(token_id)),
        (
            "expires_at",
            J::str(rfc3339(
                install_time() + SignedDuration::from_hours(30 * 24),
            )),
        ),
    ])
}

/// The enrollment result held against an attempt; each field is one the
/// attempt is compared with.
pub struct EnrollResultSpec<'a> {
    pub epoch: u64,
    pub endpoint_id: &'a str,
    pub token_id: &'a str,
    pub attempt_id: &'a str,
}

impl EnrollResultSpec<'_> {
    /// The result matching the attempt, at `epoch`.
    pub fn matching(epoch: u64) -> Self {
        EnrollResultSpec {
            epoch,
            endpoint_id: ENDPOINT,
            token_id: TOKEN,
            attempt_id: ATTEMPT,
        }
    }
}

pub fn enroll_result(spec: &EnrollResultSpec<'_>) -> J {
    J::obj([
        ("recovery_epoch", J::Int(spec.epoch)),
        ("endpoint_id", J::str(spec.endpoint_id)),
        ("spki_sha256", J::str(b64(&spki()))),
        ("token_id", J::str(spec.token_id)),
        ("attempt_id", J::str(spec.attempt_id)),
    ])
}

/// The Sysmon configuration of a policy for `os`.
pub fn sysmon_config(os: &str) -> J {
    J::obj([
        ("os", J::str(os)),
        (
            "sha256",
            J::str(b64(&bytes32(&format!("sysmon config {os}")))),
        ),
        (
            "sources",
            J::arr([J::str(format!("https://dist.example/sysmon/{os}.xml"))]),
        ),
    ])
}

/// The standalone Sysmon package a policy has Windows endpoints install.
pub fn windows_sysmon_package() -> J {
    J::obj([
        ("version", J::str("15.15")),
        ("sha256", J::str(b64(&bytes32("windows sysmon package")))),
        ("size", J::Int(4_194_304)),
        (
            "sources",
            J::arr([J::str("https://dist.example/sysmon/sysmon.zip")]),
        ),
    ])
}

/// A policy with a Sysmon configuration for Windows and one for Linux,
/// keeping a standalone Sysmon already installed, and deploying the
/// Windows Sysmon package.
pub fn policy(epoch: u64, version: u64, status_ui: &str) -> J {
    J::obj([
        ("recovery_epoch", J::Int(epoch)),
        ("group_id", J::str(GROUP)),
        ("version", J::Int(version)),
        ("collection_mode", J::str("extended")),
        (
            "sysmon_configs",
            J::arr([sysmon_config("windows"), sysmon_config("linux")]),
        ),
        ("existing_sysmon", J::str("keep")),
        ("windows_sysmon_package", windows_sysmon_package()),
        (
            "field_exclusions",
            J::obj([("1", J::arr([J::str("CommandLine")]))]),
        ),
        (
            "audit_settings",
            J::obj([
                ("windows_local_apply", J::Bool(true)),
                ("linux_auditd_rules", J::Bool(false)),
            ]),
        ),
        (
            "event_log_channels",
            J::obj([("Security", J::arr([J::Int(4624)]))]),
        ),
        ("status_ui", J::str(status_ui)),
    ])
}

pub fn assign(epoch: u64, version: u64) -> J {
    J::obj([
        ("recovery_epoch", J::Int(epoch)),
        ("endpoint_id", J::str(ENDPOINT)),
        ("version", J::Int(version)),
        ("group_id", J::str(GROUP)),
        (
            "uninstall_token_sha256",
            J::str(b64(&bytes32("uninstall token"))),
        ),
    ])
}

/// The package of [`TARGET_VERSION`] for `platform`.
pub fn update_package(platform: &str) -> J {
    let size = match platform {
        WINDOWS_MSI => 1_048_576,
        LINUX_DEB => 917_504,
        _ => 925_696,
    };
    J::obj([
        ("platform", J::str(platform)),
        (
            "sha256",
            J::str(b64(&bytes32(&format!(
                "package {TARGET_VERSION} {platform}"
            )))),
        ),
        ("size", J::Int(size)),
        (
            "sources",
            J::arr([J::str(format!(
                "https://dist.example/packages/{TARGET_VERSION}/{platform}"
            ))]),
        ),
    ])
}

/// An update of the group to [`TARGET_VERSION`], with a package for each
/// of the three platforms.
pub fn group_update(epoch: u64, version: u64, issued_at: Timestamp, expires_at: Timestamp) -> J {
    J::obj([
        ("recovery_epoch", J::Int(epoch)),
        ("version", J::Int(version)),
        ("group_id", J::str(GROUP)),
        ("target_version", J::str(TARGET_VERSION)),
        (
            "packages",
            J::arr([
                update_package(WINDOWS_MSI),
                update_package(LINUX_DEB),
                update_package(LINUX_RPM),
            ]),
        ),
        ("rollback", J::Bool(false)),
        ("issued_at", J::str(rfc3339(issued_at))),
        ("expires_at", J::str(rfc3339(expires_at))),
    ])
}

/// An update of [`ENDPOINT`] whose `target_version` is `null`, releasing
/// it from a pinned version, and so with no `packages`.
pub fn endpoint_release(
    epoch: u64,
    version: u64,
    issued_at: Timestamp,
    expires_at: Timestamp,
) -> J {
    J::obj([
        ("recovery_epoch", J::Int(epoch)),
        ("version", J::Int(version)),
        ("endpoint_id", J::str(ENDPOINT)),
        ("target_version", J::Null),
        ("rollback", J::Bool(false)),
        ("issued_at", J::str(rfc3339(issued_at))),
        ("expires_at", J::str(rfc3339(expires_at))),
    ])
}

/// A command for `endpoint_id`.
pub struct CommandSpec<'a> {
    pub command_id: &'a str,
    pub endpoint_id: &'a str,
    pub seq: u64,
    pub issued_at: Timestamp,
    pub epoch: u64,
}

pub fn command(spec: &CommandSpec<'_>) -> J {
    J::obj([
        ("command_id", J::str(spec.command_id)),
        ("endpoint_id", J::str(spec.endpoint_id)),
        ("seq", J::Int(spec.seq)),
        ("issued_at", J::str(rfc3339(spec.issued_at))),
        (
            "expires_at",
            J::str(rfc3339(spec.issued_at + SignedDuration::from_hours(1))),
        ),
        ("recovery_epoch", J::Int(spec.epoch)),
        ("kind", J::str("diagnose")),
        ("args", J::obj::<&str>([])),
    ])
}

// --- install configurations --------------------------------------------------------------

/// The parts of an install configuration.
pub struct InstallSpec {
    /// The `install_id` written in the configuration.
    pub install_id: String,
    /// The `customer_endpoint_id`.
    pub customer: String,
    pub keyset: String,
    pub recovery_key_version: u64,
    pub addresses: String,
    pub enroll_token: String,
    pub deployment_cert: String,
    /// The kid the configuration is signed under.
    pub signer: String,
}

pub fn install_config_content(ring: &mut KeyRing, spec: &InstallSpec) -> J {
    J::obj([
        ("install_id", J::str(&spec.install_id)),
        ("customer_endpoint_id", J::str(&spec.customer)),
        (
            "customer_key_name",
            J::str(format!("endpoint-{}", spec.customer)),
        ),
        ("keyset", J::str(&spec.keyset)),
        (
            "recovery_key",
            ring.jwk(&recovery_kid(INSTALL_ID, spec.recovery_key_version)),
        ),
        ("recovery_key_version", J::Int(spec.recovery_key_version)),
        ("addresses", J::str(&spec.addresses)),
        ("enroll_token", J::str(&spec.enroll_token)),
        ("hw_salt", J::str(b64(&hw_salt()))),
        ("vdi_mode", J::Bool(false)),
        ("deployment_cert", J::str(&spec.deployment_cert)),
    ])
}

pub fn sign_install_config(ring: &mut KeyRing, spec: &InstallSpec) -> String {
    let content = install_config_content(ring, spec);
    ring.sign(Typ::InstallConfig, &spec.signer, &content)
}

/// The parts of the installation every sequence case starts from, before
/// they are put together, so that a case can change one.
pub fn standard_install_spec(ring: &mut KeyRing) -> InstallSpec {
    let keyset_content = keyset(ring, &KeysetSpec::of(EPOCH, 1, &[1], 1, &[]));
    let signer = customer_kid(1);
    let keyset = ring.sign(Typ::Keyset, &signer, &keyset_content);
    let addresses_version = Issuer::new().number(Typ::Addresses.as_str(), install_time());
    let addresses = ring.sign(
        Typ::Addresses,
        &signer,
        &addresses(EPOCH, addresses_version),
    );
    let enroll_token = ring.sign(Typ::Enroll, &signer, &enroll(TOKEN));
    let certificate = deployment_cert(ring, INSTALL_ID);
    let deployment_cert = ring.sign(Typ::DeploymentCert, VENDOR_RELEASE, &certificate);
    InstallSpec {
        install_id: INSTALL_ID.to_owned(),
        customer: CUSTOMER.to_owned(),
        keyset,
        recovery_key_version: 1,
        addresses,
        enroll_token,
        deployment_cert,
        signer: install_kid(INSTALL_ID),
    }
}

/// The install configuration every sequence case starts from: the key set
/// (1, 1) of the customer key version 1, and the recovery key version 1.
pub fn standard_install(ring: &mut KeyRing) -> String {
    let spec = standard_install_spec(ring);
    sign_install_config(ring, &spec)
}
