//! The content types of the eleven signed document `typ`s.
//!
//! A content type whose fields stand alone has public fields. One with a
//! rule across fields, or a list that may not be empty, keeps them private
//! behind a constructor that checks the rule, and reads through a private
//! raw type, with `#[serde(try_from)]`, that is checked by the same rule;
//! so a value made outside the crate always serializes to JSON that parses
//! back to it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jiff::Timestamp;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::forms::{
    AbsoluteUrl, Address, CertificatePem, CustomerKeyName, CustomerKid, DnsName, InstallId,
    Integer, JwsText, KindNumber, NonEmptyString, PositiveInteger, SemVer,
};
use crate::auth::jws::strict::{Base64UrlArray, LowerUuid, Nullable, UtcTimestamp};
use crate::auth::jws::{Jwk, KeyKind, Kid};

/// Implements `as_str`, `Display`, `Serialize` and `Deserialize` for a
/// closed enum written as one of a fixed set of JSON strings.
///
/// `Deserialize` reads through `deserialize_str`, so only a JSON string of
/// the set is accepted. A derived `Deserialize` would go through
/// `deserialize_enum`, which also takes the externally tagged object form
/// (`{"extended": null}`) that a signed document must not carry.
macro_rules! string_enum {
    ($ty:ident, $expecting:literal, { $($variant:ident => $text:literal),+ $(,)? }) => {
        impl $ty {
            /// Returns the string the value is written as.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                const VARIANTS: &[&str] = &[$($text),+];

                struct StrVisitor;

                impl Visitor<'_> for StrVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: de::Error>(self, text: &str) -> Result<$ty, E> {
                        match text {
                            $($text => Ok($ty::$variant),)+
                            _ => Err(E::unknown_variant(text, VARIANTS)),
                        }
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }
    };
}

/// A SHA-256 hash, or any other 32 bytes, as unpadded base64url.
pub type Hash32 = Base64UrlArray<32>;

/// A rule across the fields of a content that a value breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContentError {
    /// `install_signing_kid` is not an install signing key's kid.
    #[error("install_signing_kid is not an install signing key kid")]
    InstallSigningKidKind,
    /// `install_signing_kid` names another install id than `install_id`.
    #[error("install_signing_kid names an install id other than install_id")]
    InstallSigningKidInstallId,
    /// `keys` is empty.
    #[error("keys is empty")]
    EmptyKeys,
    /// Two entries of `keys` have the same kid.
    #[error("keys repeats a kid")]
    DuplicateKid,
    /// `current_kid` is none of the kids in `keys`.
    #[error("current_kid is not a kid in keys")]
    CurrentKidNotInKeys,
    /// A kid in `revoked_kids` is also in `keys`.
    #[error("a kid in revoked_kids is also in keys")]
    RevokedKidInKeys,
    /// `trust_roots` is empty.
    #[error("trust_roots is empty")]
    EmptyTrustRoots,
    /// Two telemetry entries have the same `entry_id`.
    #[error("telemetry_entries repeats an entry_id")]
    DuplicateEntryId,
    /// `expires_at` is before `issued_at`.
    #[error("expires_at is before issued_at")]
    ExpiresBeforeIssued,
    /// An update names both or neither of `group_id` and `endpoint_id`.
    #[error("an update names exactly one of group_id and endpoint_id")]
    UpdateTarget,
    /// An update with a `target_version` has no `packages`.
    #[error("an update with a target_version has packages")]
    MissingPackages,
    /// An update whose `target_version` is `null` has `packages`.
    #[error("an update whose target_version is null has no packages")]
    UnexpectedPackages,
    /// An update's `packages` is empty.
    #[error("packages is empty")]
    EmptyPackages,
    /// Two entries of an update's `packages` have the same `platform`.
    #[error("packages repeats a platform")]
    DuplicatePlatform,
    /// The `sources` of an entry of an update's `packages` is empty.
    #[error("the sources of a packages entry is empty")]
    EmptyPackageSources,
    /// Two entries of a policy's `sysmon_configs` have the same `os`.
    #[error("sysmon_configs repeats an os")]
    DuplicateSysmonOs,
    /// The `sources` of an entry of a policy's `sysmon_configs` is empty.
    #[error("the sources of a sysmon_configs entry is empty")]
    EmptySysmonConfigSources,
    /// The `sources` of a policy's `windows_sysmon_package` is empty.
    #[error("the sources of windows_sysmon_package is empty")]
    EmptyWindowsSysmonPackageSources,
    /// An update to a group has a `null` `target_version`, which only an
    /// update to an endpoint may have.
    #[error("only an update to an endpoint may have a null target_version")]
    NullTargetVersionForGroup,
}

fn check_window(issued_at: UtcTimestamp, expires_at: UtcTimestamp) -> Result<(), ContentError> {
    if expires_at < issued_at {
        Err(ContentError::ExpiresBeforeIssued)
    } else {
        Ok(())
    }
}

// --- senta-deployment-cert ---------------------------------------------

/// The content of a `senta-deployment-cert` document, signed by the vendor
/// key.
///
/// `install_signing_kid` is an install signing key's kid whose install id is
/// `install_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDeploymentCert", into = "RawDeploymentCert")]
pub struct DeploymentCertContent {
    install_id: InstallId,
    install_name: NonEmptyString,
    install_signing_key: Jwk,
    install_signing_kid: Kid,
    issued_at: UtcTimestamp,
}

impl DeploymentCertContent {
    /// Creates the content.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::InstallSigningKidKind`] if
    /// `install_signing_kid` is not an install signing key's kid, and
    /// [`ContentError::InstallSigningKidInstallId`] if its install id is not
    /// `install_id`.
    pub fn new(
        install_id: InstallId,
        install_name: NonEmptyString,
        install_signing_key: Jwk,
        install_signing_kid: Kid,
        issued_at: UtcTimestamp,
    ) -> Result<Self, ContentError> {
        if install_signing_kid.kind() != KeyKind::InstallSigning {
            return Err(ContentError::InstallSigningKidKind);
        }
        if install_signing_kid.install_id() != Some(install_id.as_str()) {
            return Err(ContentError::InstallSigningKidInstallId);
        }
        Ok(Self {
            install_id,
            install_name,
            install_signing_key,
            install_signing_kid,
            issued_at,
        })
    }

    /// Returns `install_id`.
    #[must_use]
    pub fn install_id(&self) -> &InstallId {
        &self.install_id
    }

    /// Returns `install_name`.
    #[must_use]
    pub fn install_name(&self) -> &NonEmptyString {
        &self.install_name
    }

    /// Returns `install_signing_key`.
    #[must_use]
    pub fn install_signing_key(&self) -> &Jwk {
        &self.install_signing_key
    }

    /// Returns `install_signing_kid`.
    #[must_use]
    pub fn install_signing_kid(&self) -> &Kid {
        &self.install_signing_kid
    }

    /// Returns `issued_at`.
    #[must_use]
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at.get()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawDeploymentCert {
    install_id: InstallId,
    install_name: NonEmptyString,
    install_signing_key: Jwk,
    install_signing_kid: Kid,
    issued_at: UtcTimestamp,
}

impl TryFrom<RawDeploymentCert> for DeploymentCertContent {
    type Error = ContentError;

    fn try_from(raw: RawDeploymentCert) -> Result<Self, ContentError> {
        Self::new(
            raw.install_id,
            raw.install_name,
            raw.install_signing_key,
            raw.install_signing_kid,
            raw.issued_at,
        )
    }
}

impl From<DeploymentCertContent> for RawDeploymentCert {
    fn from(content: DeploymentCertContent) -> Self {
        Self {
            install_id: content.install_id,
            install_name: content.install_name,
            install_signing_key: content.install_signing_key,
            install_signing_kid: content.install_signing_kid,
            issued_at: content.issued_at,
        }
    }
}

// --- senta-install-config -----------------------------------------------

/// The content of a `senta-install-config` document, signed by an install
/// signing key.
///
/// The JWS strings it carries (`keyset`, `addresses`, `enroll_token`,
/// `deployment_cert`) are not verified here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallConfigContent {
    /// The install id.
    pub install_id: InstallId,
    /// The customer's endpoint id.
    pub customer_endpoint_id: LowerUuid,
    /// The customer key name, `endpoint-<uuid>`.
    pub customer_key_name: CustomerKeyName,
    /// The `senta-keyset` JWS.
    pub keyset: JwsText,
    /// The recovery key.
    pub recovery_key: Jwk,
    /// The recovery key version, at least 1.
    pub recovery_key_version: PositiveInteger,
    /// The `senta-addresses` JWS.
    pub addresses: JwsText,
    /// The `senta-enroll` JWS.
    pub enroll_token: JwsText,
    /// The hardware salt, exactly 32 bytes.
    pub hw_salt: Hash32,
    /// Whether the endpoint runs in VDI mode.
    pub vdi_mode: bool,
    /// The `senta-deployment-cert` JWS.
    pub deployment_cert: JwsText,
}

// --- senta-keyset --------------------------------------------------------

/// One key of a key set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetEntry {
    /// The key's kid.
    pub kid: CustomerKid,
    /// The public key.
    pub key: Jwk,
}

/// The content of a `senta-keyset` document, signed by a customer key or a
/// recovery key.
///
/// `keys` is not empty and repeats no kid, `current_kid` is one of its
/// kids, and no kid of `revoked_kids` is among them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawKeyset", into = "RawKeyset")]
pub struct KeysetContent {
    customer_endpoint_id: LowerUuid,
    customer_key_name: CustomerKeyName,
    recovery_epoch: Integer,
    keyset_version: PositiveInteger,
    keys: Vec<KeysetEntry>,
    current_kid: CustomerKid,
    revoked_kids: Vec<CustomerKid>,
}

impl KeysetContent {
    /// Creates the content.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptyKeys`] if `keys` is empty,
    /// [`ContentError::DuplicateKid`] if it repeats a kid,
    /// [`ContentError::CurrentKidNotInKeys`] if `current_kid` is not one of
    /// its kids, and [`ContentError::RevokedKidInKeys`] if a kid of
    /// `revoked_kids` is.
    pub fn new(
        customer_endpoint_id: LowerUuid,
        customer_key_name: CustomerKeyName,
        recovery_epoch: Integer,
        keyset_version: PositiveInteger,
        keys: Vec<KeysetEntry>,
        current_kid: CustomerKid,
        revoked_kids: Vec<CustomerKid>,
    ) -> Result<Self, ContentError> {
        if keys.is_empty() {
            return Err(ContentError::EmptyKeys);
        }
        let mut kids = BTreeSet::new();
        if !keys.iter().all(|entry| kids.insert(&entry.kid)) {
            return Err(ContentError::DuplicateKid);
        }
        if !kids.contains(&current_kid) {
            return Err(ContentError::CurrentKidNotInKeys);
        }
        if revoked_kids.iter().any(|kid| kids.contains(kid)) {
            return Err(ContentError::RevokedKidInKeys);
        }
        Ok(Self {
            customer_endpoint_id,
            customer_key_name,
            recovery_epoch,
            keyset_version,
            keys,
            current_kid,
            revoked_kids,
        })
    }

    /// Returns `customer_endpoint_id`.
    #[must_use]
    pub fn customer_endpoint_id(&self) -> LowerUuid {
        self.customer_endpoint_id
    }

    /// Returns `customer_key_name`.
    #[must_use]
    pub fn customer_key_name(&self) -> &CustomerKeyName {
        &self.customer_key_name
    }

    /// Returns `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> Integer {
        self.recovery_epoch
    }

    /// Returns `keyset_version`.
    #[must_use]
    pub fn keyset_version(&self) -> PositiveInteger {
        self.keyset_version
    }

    /// Returns `keys`, never empty.
    #[must_use]
    pub fn keys(&self) -> &[KeysetEntry] {
        &self.keys
    }

    /// Returns `current_kid`.
    #[must_use]
    pub fn current_kid(&self) -> &CustomerKid {
        &self.current_kid
    }

    /// Returns `revoked_kids`.
    #[must_use]
    pub fn revoked_kids(&self) -> &[CustomerKid] {
        &self.revoked_kids
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawKeyset {
    customer_endpoint_id: LowerUuid,
    customer_key_name: CustomerKeyName,
    recovery_epoch: Integer,
    keyset_version: PositiveInteger,
    keys: Vec<KeysetEntry>,
    current_kid: CustomerKid,
    revoked_kids: Vec<CustomerKid>,
}

impl TryFrom<RawKeyset> for KeysetContent {
    type Error = ContentError;

    fn try_from(raw: RawKeyset) -> Result<Self, ContentError> {
        Self::new(
            raw.customer_endpoint_id,
            raw.customer_key_name,
            raw.recovery_epoch,
            raw.keyset_version,
            raw.keys,
            raw.current_kid,
            raw.revoked_kids,
        )
    }
}

impl From<KeysetContent> for RawKeyset {
    fn from(content: KeysetContent) -> Self {
        Self {
            customer_endpoint_id: content.customer_endpoint_id,
            customer_key_name: content.customer_key_name,
            recovery_epoch: content.recovery_epoch,
            keyset_version: content.keyset_version,
            keys: content.keys,
            current_kid: content.current_kid,
            revoked_kids: content.revoked_kids,
        }
    }
}

// --- senta-recovery-key ---------------------------------------------------

/// The content of a `senta-recovery-key` document, signed by a recovery key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKeyContent {
    /// The install id.
    pub install_id: InstallId,
    /// The version of the new recovery key, at least 1.
    pub recovery_key_version: PositiveInteger,
    /// The new recovery key.
    pub recovery_key: Jwk,
}

// --- senta-enroll -----------------------------------------------------------

/// The content of a `senta-enroll` document, the enrollment token, signed by
/// a customer key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollContent {
    /// The token id.
    pub token_id: LowerUuid,
    /// When the token expires; a token without one does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
}

// --- senta-enroll-result -----------------------------------------------------

/// The content of a `senta-enroll-result` document, signed by a customer
/// key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResultContent {
    /// The recovery epoch.
    pub recovery_epoch: Integer,
    /// The endpoint id given to the enrolled endpoint.
    pub endpoint_id: LowerUuid,
    /// The SHA-256 of the endpoint's SubjectPublicKeyInfo.
    pub spki_sha256: Hash32,
    /// The id of the enrollment token used.
    pub token_id: LowerUuid,
    /// The id of the enrollment attempt.
    pub attempt_id: LowerUuid,
}

// --- senta-policy ----------------------------------------------------------

/// How much a policy collects, as a signed policy writes it.
///
/// Closed: a value other than these is a schema error, unlike a transport
/// enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyCollectionMode {
    /// `extended`.
    Extended,
    /// `essential`.
    Essential,
}

string_enum!(PolicyCollectionMode, "`extended` or `essential`", {
    Extended => "extended",
    Essential => "essential",
});

/// How the endpoint shows its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatusUi {
    /// `tray`.
    Tray,
    /// `notify`.
    Notify,
    /// `hidden`.
    Hidden,
}

string_enum!(StatusUi, "`tray`, `notify` or `hidden`", {
    Tray => "tray",
    Notify => "notify",
    Hidden => "hidden",
});

/// What the endpoint does with a standalone Sysmon already installed on
/// its host, as `existing_sysmon` writes it.
///
/// Closed: a value other than these is a schema error, unlike a transport
/// enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExistingSysmon {
    /// `keep`: the installed Sysmon is used as it is.
    Keep,
    /// `take_over`: the endpoint takes the installed Sysmon over.
    TakeOver,
}

string_enum!(ExistingSysmon, "`keep` or `take_over`", {
    Keep => "keep",
    TakeOver => "take_over",
});

/// The Sysmon configuration of a policy for one operating system, an entry
/// of `sysmon_configs`.
///
/// `os` is a lowercase operating system name, such as `windows` or
/// `linux`, of which only emptiness is checked: a name the endpoint does
/// not know is kept, and the endpoint ignores it. `sources` is not empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSysmonConfig", into = "RawSysmonConfig")]
pub struct SysmonConfig {
    os: NonEmptyString,
    sha256: Hash32,
    sources: Vec<AbsoluteUrl>,
}

impl SysmonConfig {
    /// Creates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptySysmonConfigSources`] if `sources` is
    /// empty.
    pub fn new(
        os: NonEmptyString,
        sha256: Hash32,
        sources: Vec<AbsoluteUrl>,
    ) -> Result<Self, ContentError> {
        if sources.is_empty() {
            return Err(ContentError::EmptySysmonConfigSources);
        }
        Ok(Self {
            os,
            sha256,
            sources,
        })
    }

    /// Returns `os`, the operating system the configuration is for.
    #[must_use]
    pub fn os(&self) -> &NonEmptyString {
        &self.os
    }

    /// Returns `sha256`, the SHA-256 of the configuration file.
    #[must_use]
    pub fn sha256(&self) -> &Hash32 {
        &self.sha256
    }

    /// Returns `sources`, where the configuration file is fetched from;
    /// never empty.
    #[must_use]
    pub fn sources(&self) -> &[AbsoluteUrl] {
        &self.sources
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawSysmonConfig {
    os: NonEmptyString,
    sha256: Hash32,
    sources: Vec<AbsoluteUrl>,
}

impl TryFrom<RawSysmonConfig> for SysmonConfig {
    type Error = ContentError;

    fn try_from(raw: RawSysmonConfig) -> Result<Self, ContentError> {
        Self::new(raw.os, raw.sha256, raw.sources)
    }
}

impl From<SysmonConfig> for RawSysmonConfig {
    fn from(config: SysmonConfig) -> Self {
        Self {
            os: config.os,
            sha256: config.sha256,
            sources: config.sources,
        }
    }
}

/// The Sysmon configurations of a policy, `sysmon_configs`: at most one
/// per `os`, and possibly none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<SysmonConfig>", into = "Vec<SysmonConfig>")]
pub struct SysmonConfigs(Vec<SysmonConfig>);

impl SysmonConfigs {
    /// Creates the list, in the order given.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::DuplicateSysmonOs`] if two configurations
    /// have the same `os`.
    pub fn new(configs: Vec<SysmonConfig>) -> Result<Self, ContentError> {
        let mut names = BTreeSet::new();
        if !configs.iter().all(|config| names.insert(&config.os)) {
            return Err(ContentError::DuplicateSysmonOs);
        }
        Ok(Self(configs))
    }

    /// Returns the configurations, in the order written.
    #[must_use]
    pub fn as_slice(&self) -> &[SysmonConfig] {
        &self.0
    }

    /// Returns the configuration whose `os` is exactly `os`, if any.
    #[must_use]
    pub fn get(&self, os: &str) -> Option<&SysmonConfig> {
        self.0.iter().find(|config| config.os.as_str() == os)
    }
}

impl TryFrom<Vec<SysmonConfig>> for SysmonConfigs {
    type Error = ContentError;

    fn try_from(configs: Vec<SysmonConfig>) -> Result<Self, ContentError> {
        Self::new(configs)
    }
}

impl From<SysmonConfigs> for Vec<SysmonConfig> {
    fn from(configs: SysmonConfigs) -> Self {
        configs.0
    }
}

/// The standalone Sysmon package a policy has Windows endpoints install,
/// `windows_sysmon_package`.
///
/// `version` is the Sysmon version, `size` at least 1, and `sources` not
/// empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawWindowsSysmonPackage", into = "RawWindowsSysmonPackage")]
pub struct WindowsSysmonPackage {
    version: NonEmptyString,
    sha256: Hash32,
    size: PositiveInteger,
    sources: Vec<AbsoluteUrl>,
}

impl WindowsSysmonPackage {
    /// Creates the package.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptyWindowsSysmonPackageSources`] if
    /// `sources` is empty.
    pub fn new(
        version: NonEmptyString,
        sha256: Hash32,
        size: PositiveInteger,
        sources: Vec<AbsoluteUrl>,
    ) -> Result<Self, ContentError> {
        if sources.is_empty() {
            return Err(ContentError::EmptyWindowsSysmonPackageSources);
        }
        Ok(Self {
            version,
            sha256,
            size,
            sources,
        })
    }

    /// Returns `version`, the Sysmon version of the package.
    #[must_use]
    pub fn version(&self) -> &NonEmptyString {
        &self.version
    }

    /// Returns `sha256`, the SHA-256 of the package file.
    #[must_use]
    pub fn sha256(&self) -> &Hash32 {
        &self.sha256
    }

    /// Returns `size`, the size of the package file in bytes.
    #[must_use]
    pub fn size(&self) -> PositiveInteger {
        self.size
    }

    /// Returns `sources`, where the package file is fetched from; never
    /// empty.
    #[must_use]
    pub fn sources(&self) -> &[AbsoluteUrl] {
        &self.sources
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawWindowsSysmonPackage {
    version: NonEmptyString,
    sha256: Hash32,
    size: PositiveInteger,
    sources: Vec<AbsoluteUrl>,
}

impl TryFrom<RawWindowsSysmonPackage> for WindowsSysmonPackage {
    type Error = ContentError;

    fn try_from(raw: RawWindowsSysmonPackage) -> Result<Self, ContentError> {
        Self::new(raw.version, raw.sha256, raw.size, raw.sources)
    }
}

impl From<WindowsSysmonPackage> for RawWindowsSysmonPackage {
    fn from(package: WindowsSysmonPackage) -> Self {
        Self {
            version: package.version,
            sha256: package.sha256,
            size: package.size,
            sources: package.sources,
        }
    }
}

/// The audit settings of a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Whether the Windows local audit policy is applied.
    pub windows_local_apply: bool,
    /// Whether the Linux auditd rules are applied.
    pub linux_auditd_rules: bool,
}

/// The content of a `senta-policy` document, signed by a customer key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContent {
    /// The recovery epoch.
    pub recovery_epoch: Integer,
    /// The group the policy is for.
    pub group_id: LowerUuid,
    /// The policy version.
    pub version: Integer,
    /// How much is collected.
    pub collection_mode: PolicyCollectionMode,
    /// The Sysmon configuration of each operating system, at most one per
    /// `os`.
    pub sysmon_configs: SysmonConfigs,
    /// What the endpoint does with a standalone Sysmon already installed.
    pub existing_sysmon: ExistingSysmon,
    /// The standalone Sysmon package Windows endpoints install, or `None`
    /// when the policy deploys none; written only when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_sysmon_package: Option<WindowsSysmonPackage>,
    /// The names of the fields left out of each event kind, by kind number.
    pub field_exclusions: BTreeMap<KindNumber, Vec<NonEmptyString>>,
    /// The audit settings.
    pub audit_settings: AuditSettings,
    /// The event ids collected from each event log channel, by channel name.
    pub event_log_channels: BTreeMap<NonEmptyString, Vec<u16>>,
    /// How the endpoint shows its status.
    pub status_ui: StatusUi,
}

// --- senta-assign -------------------------------------------------------------

/// The content of a `senta-assign` document, signed by a customer key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignContent {
    /// The recovery epoch.
    pub recovery_epoch: Integer,
    /// The endpoint assigned.
    pub endpoint_id: LowerUuid,
    /// The assignment version.
    pub version: Integer,
    /// The group the endpoint is assigned to.
    pub group_id: LowerUuid,
    /// The SHA-256 of the uninstall token.
    pub uninstall_token_sha256: Hash32,
}

// --- senta-addresses -----------------------------------------------------------

/// A control ingress entry of an address document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEntry {
    /// Where to connect.
    pub address: Address,
    /// The DNS name the server's certificate is verified against.
    pub expected_name: DnsName,
}

/// A telemetry ingress entry of an address document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEntry {
    /// The entry's id, which `HelloAck` names the entry by.
    pub entry_id: LowerUuid,
    /// Where to connect.
    pub address: Address,
    /// The DNS name the server's certificate is verified against.
    pub expected_name: DnsName,
}

/// The content of a `senta-addresses` document, signed by a customer key.
///
/// `trust_roots` is not empty, and no two telemetry entries have the same
/// `entry_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAddresses", into = "RawAddresses")]
pub struct AddressesContent {
    recovery_epoch: Integer,
    version: Integer,
    control_entries: Vec<ControlEntry>,
    telemetry_entries: Vec<TelemetryEntry>,
    trust_roots: Vec<CertificatePem>,
    distribution_points: Vec<AbsoluteUrl>,
}

impl AddressesContent {
    /// Creates the content.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptyTrustRoots`] if `trust_roots` is empty,
    /// and [`ContentError::DuplicateEntryId`] if two telemetry entries have
    /// the same `entry_id`.
    pub fn new(
        recovery_epoch: Integer,
        version: Integer,
        control_entries: Vec<ControlEntry>,
        telemetry_entries: Vec<TelemetryEntry>,
        trust_roots: Vec<CertificatePem>,
        distribution_points: Vec<AbsoluteUrl>,
    ) -> Result<Self, ContentError> {
        if trust_roots.is_empty() {
            return Err(ContentError::EmptyTrustRoots);
        }
        let mut entry_ids = BTreeSet::new();
        if !telemetry_entries
            .iter()
            .all(|entry| entry_ids.insert(entry.entry_id))
        {
            return Err(ContentError::DuplicateEntryId);
        }
        Ok(Self {
            recovery_epoch,
            version,
            control_entries,
            telemetry_entries,
            trust_roots,
            distribution_points,
        })
    }

    /// Returns `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> Integer {
        self.recovery_epoch
    }

    /// Returns `version`.
    #[must_use]
    pub fn version(&self) -> Integer {
        self.version
    }

    /// Returns `control_entries`.
    #[must_use]
    pub fn control_entries(&self) -> &[ControlEntry] {
        &self.control_entries
    }

    /// Returns `telemetry_entries`.
    #[must_use]
    pub fn telemetry_entries(&self) -> &[TelemetryEntry] {
        &self.telemetry_entries
    }

    /// Returns `trust_roots`, never empty.
    #[must_use]
    pub fn trust_roots(&self) -> &[CertificatePem] {
        &self.trust_roots
    }

    /// Returns `distribution_points`.
    #[must_use]
    pub fn distribution_points(&self) -> &[AbsoluteUrl] {
        &self.distribution_points
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawAddresses {
    recovery_epoch: Integer,
    version: Integer,
    control_entries: Vec<ControlEntry>,
    telemetry_entries: Vec<TelemetryEntry>,
    trust_roots: Vec<CertificatePem>,
    distribution_points: Vec<AbsoluteUrl>,
}

impl TryFrom<RawAddresses> for AddressesContent {
    type Error = ContentError;

    fn try_from(raw: RawAddresses) -> Result<Self, ContentError> {
        Self::new(
            raw.recovery_epoch,
            raw.version,
            raw.control_entries,
            raw.telemetry_entries,
            raw.trust_roots,
            raw.distribution_points,
        )
    }
}

impl From<AddressesContent> for RawAddresses {
    fn from(content: AddressesContent) -> Self {
        Self {
            recovery_epoch: content.recovery_epoch,
            version: content.version,
            control_entries: content.control_entries,
            telemetry_entries: content.telemetry_entries,
            trust_roots: content.trust_roots,
            distribution_points: content.distribution_points,
        }
    }
}

// --- senta-update ------------------------------------------------------------

/// Whom an update is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpdateTarget {
    /// Every endpoint of a group, written as `group_id`.
    Group(LowerUuid),
    /// One endpoint, written as `endpoint_id`.
    Endpoint(LowerUuid),
}

/// The package of an update for one platform, an entry of `packages`.
///
/// `platform` is a lowercase `<os>-<arch>-<format>` string, such as
/// `windows-x86_64-msi`, of which only emptiness is checked: a platform
/// the endpoint does not know is kept, and the endpoint looks only at the
/// entry of its own. `size` is at least 1, and `sources` is not empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawUpdatePackage", into = "RawUpdatePackage")]
pub struct UpdatePackage {
    platform: NonEmptyString,
    sha256: Hash32,
    size: PositiveInteger,
    sources: Vec<AbsoluteUrl>,
}

impl UpdatePackage {
    /// Creates the package.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptyPackageSources`] if `sources` is empty.
    pub fn new(
        platform: NonEmptyString,
        sha256: Hash32,
        size: PositiveInteger,
        sources: Vec<AbsoluteUrl>,
    ) -> Result<Self, ContentError> {
        if sources.is_empty() {
            return Err(ContentError::EmptyPackageSources);
        }
        Ok(Self {
            platform,
            sha256,
            size,
            sources,
        })
    }

    /// Returns `platform`, the platform the package is for.
    #[must_use]
    pub fn platform(&self) -> &NonEmptyString {
        &self.platform
    }

    /// Returns `sha256`, the SHA-256 of the package.
    #[must_use]
    pub fn sha256(&self) -> &Hash32 {
        &self.sha256
    }

    /// Returns `size`, the size of the package in bytes.
    #[must_use]
    pub fn size(&self) -> PositiveInteger {
        self.size
    }

    /// Returns `sources`, where the package is fetched from; never empty.
    #[must_use]
    pub fn sources(&self) -> &[AbsoluteUrl] {
        &self.sources
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawUpdatePackage {
    platform: NonEmptyString,
    sha256: Hash32,
    size: PositiveInteger,
    sources: Vec<AbsoluteUrl>,
}

impl TryFrom<RawUpdatePackage> for UpdatePackage {
    type Error = ContentError;

    fn try_from(raw: RawUpdatePackage) -> Result<Self, ContentError> {
        Self::new(raw.platform, raw.sha256, raw.size, raw.sources)
    }
}

impl From<UpdatePackage> for RawUpdatePackage {
    fn from(package: UpdatePackage) -> Self {
        Self {
            platform: package.platform,
            sha256: package.sha256,
            size: package.size,
            sources: package.sources,
        }
    }
}

/// What an update with a `target_version` installs: that version, and its
/// package for each platform, `packages`.
///
/// `packages` is not empty and repeats no `platform`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRelease {
    target_version: SemVer,
    packages: Vec<UpdatePackage>,
}

impl UpdateRelease {
    /// Creates the release, its packages in the order given.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::EmptyPackages`] if `packages` is empty, and
    /// [`ContentError::DuplicatePlatform`] if two packages have the same
    /// `platform`.
    pub fn new(target_version: SemVer, packages: Vec<UpdatePackage>) -> Result<Self, ContentError> {
        if packages.is_empty() {
            return Err(ContentError::EmptyPackages);
        }
        let mut platforms = BTreeSet::new();
        if !packages
            .iter()
            .all(|package| platforms.insert(&package.platform))
        {
            return Err(ContentError::DuplicatePlatform);
        }
        Ok(Self {
            target_version,
            packages,
        })
    }

    /// Returns `target_version`, the version to install.
    #[must_use]
    pub fn target_version(&self) -> &SemVer {
        &self.target_version
    }

    /// Returns `packages`, in the order written; never empty.
    #[must_use]
    pub fn packages(&self) -> &[UpdatePackage] {
        &self.packages
    }

    /// Returns the package whose `platform` is exactly `platform`, if any.
    #[must_use]
    pub fn package(&self, platform: &str) -> Option<&UpdatePackage> {
        self.packages
            .iter()
            .find(|package| package.platform.as_str() == platform)
    }
}

/// The content of a `senta-update` document, signed by a customer key.
///
/// It names exactly one of `group_id` and `endpoint_id`. Its
/// `target_version` is a SemVer version together with `packages`, or an
/// explicit `null` without `packages`, which releases the endpoint from a
/// pinned version and only an update to an endpoint may have. `expires_at`
/// is not before `issued_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawUpdate", into = "RawUpdate")]
pub struct UpdateContent {
    recovery_epoch: Integer,
    version: Integer,
    target: UpdateTarget,
    release: Option<UpdateRelease>,
    rollback: bool,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
}

impl UpdateContent {
    /// Creates the content; `release` is `None` for a `null`
    /// `target_version`.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::NullTargetVersionForGroup`] if `release` is
    /// `None` and `target` a group, and
    /// [`ContentError::ExpiresBeforeIssued`] if `expires_at` is before
    /// `issued_at`.
    pub fn new(
        recovery_epoch: Integer,
        version: Integer,
        target: UpdateTarget,
        release: Option<UpdateRelease>,
        rollback: bool,
        issued_at: UtcTimestamp,
        expires_at: UtcTimestamp,
    ) -> Result<Self, ContentError> {
        if release.is_none() && matches!(target, UpdateTarget::Group(_)) {
            return Err(ContentError::NullTargetVersionForGroup);
        }
        check_window(issued_at, expires_at)?;
        Ok(Self {
            recovery_epoch,
            version,
            target,
            release,
            rollback,
            issued_at,
            expires_at,
        })
    }

    /// Returns `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> Integer {
        self.recovery_epoch
    }

    /// Returns `version`.
    #[must_use]
    pub fn version(&self) -> Integer {
        self.version
    }

    /// Returns whom the update is for.
    #[must_use]
    pub fn target(&self) -> UpdateTarget {
        self.target
    }

    /// Returns the release, or `None` when `target_version` is `null`.
    #[must_use]
    pub fn release(&self) -> Option<&UpdateRelease> {
        self.release.as_ref()
    }

    /// Returns `target_version`, or `None` when it is `null`.
    #[must_use]
    pub fn target_version(&self) -> Option<&SemVer> {
        self.release.as_ref().map(UpdateRelease::target_version)
    }

    /// Returns `packages`, or an empty slice when `target_version` is
    /// `null` and the update has none.
    #[must_use]
    pub fn packages(&self) -> &[UpdatePackage] {
        self.release.as_ref().map_or(&[], UpdateRelease::packages)
    }

    /// Returns `rollback`.
    #[must_use]
    pub fn rollback(&self) -> bool {
        self.rollback
    }

    /// Returns `issued_at`.
    #[must_use]
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at.get()
    }

    /// Returns `expires_at`.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at.get()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawUpdate {
    recovery_epoch: Integer,
    version: Integer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<LowerUuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint_id: Option<LowerUuid>,
    // Required: without `#[serde(default)]`, a missing key is an error, and
    // `null` is the only explicit null any content accepts.
    target_version: Nullable<SemVer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packages: Option<Vec<UpdatePackage>>,
    rollback: bool,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
}

impl TryFrom<RawUpdate> for UpdateContent {
    type Error = ContentError;

    fn try_from(raw: RawUpdate) -> Result<Self, ContentError> {
        let target = match (raw.group_id, raw.endpoint_id) {
            (Some(group_id), None) => UpdateTarget::Group(group_id),
            (None, Some(endpoint_id)) => UpdateTarget::Endpoint(endpoint_id),
            _ => return Err(ContentError::UpdateTarget),
        };
        let release = match (raw.target_version, raw.packages) {
            (Nullable::Value(target_version), Some(packages)) => {
                Some(UpdateRelease::new(target_version, packages)?)
            }
            (Nullable::Value(_), None) => return Err(ContentError::MissingPackages),
            (_, None) => None,
            (_, Some(_)) => return Err(ContentError::UnexpectedPackages),
        };
        Self::new(
            raw.recovery_epoch,
            raw.version,
            target,
            release,
            raw.rollback,
            raw.issued_at,
            raw.expires_at,
        )
    }
}

impl From<UpdateContent> for RawUpdate {
    fn from(content: UpdateContent) -> Self {
        let (group_id, endpoint_id) = match content.target {
            UpdateTarget::Group(group_id) => (Some(group_id), None),
            UpdateTarget::Endpoint(endpoint_id) => (None, Some(endpoint_id)),
        };
        let (target_version, packages) = match content.release {
            Some(release) => (
                Nullable::Value(release.target_version),
                Some(release.packages),
            ),
            None => (Nullable::Null, None),
        };
        Self {
            recovery_epoch: content.recovery_epoch,
            version: content.version,
            group_id,
            endpoint_id,
            target_version,
            packages,
            rollback: content.rollback,
            issued_at: content.issued_at,
            expires_at: content.expires_at,
        }
    }
}

// --- senta-command ----------------------------------------------------------

/// The kind of a command, as written in `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandKind {
    /// `diagnose`.
    Diagnose,
}

string_enum!(CommandKind, "`diagnose`", {
    Diagnose => "diagnose",
});

/// The `args` of a `diagnose` command: the empty object `{}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiagnoseArgs {}

/// What a command does: its `kind` with the `args` of that kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandAction {
    /// `kind` `diagnose`.
    Diagnose(DiagnoseArgs),
}

impl CommandAction {
    /// Returns the kind.
    #[must_use]
    pub fn kind(self) -> CommandKind {
        match self {
            Self::Diagnose(_) => CommandKind::Diagnose,
        }
    }
}

/// The content of a `senta-command` document, signed by a customer key.
///
/// `expires_at` is not before `issued_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCommand", into = "RawCommand")]
pub struct CommandContent {
    command_id: LowerUuid,
    endpoint_id: LowerUuid,
    seq: Integer,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    recovery_epoch: Integer,
    action: CommandAction,
}

impl CommandContent {
    /// Creates the content.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::ExpiresBeforeIssued`] if `expires_at` is
    /// before `issued_at`.
    pub fn new(
        command_id: LowerUuid,
        endpoint_id: LowerUuid,
        seq: Integer,
        issued_at: UtcTimestamp,
        expires_at: UtcTimestamp,
        recovery_epoch: Integer,
        action: CommandAction,
    ) -> Result<Self, ContentError> {
        check_window(issued_at, expires_at)?;
        Ok(Self {
            command_id,
            endpoint_id,
            seq,
            issued_at,
            expires_at,
            recovery_epoch,
            action,
        })
    }

    /// Returns `command_id`.
    #[must_use]
    pub fn command_id(&self) -> LowerUuid {
        self.command_id
    }

    /// Returns `endpoint_id`.
    #[must_use]
    pub fn endpoint_id(&self) -> LowerUuid {
        self.endpoint_id
    }

    /// Returns `seq`.
    #[must_use]
    pub fn seq(&self) -> Integer {
        self.seq
    }

    /// Returns `issued_at`.
    #[must_use]
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at.get()
    }

    /// Returns `expires_at`.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at.get()
    }

    /// Returns `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> Integer {
        self.recovery_epoch
    }

    /// Returns `kind`.
    #[must_use]
    pub fn kind(&self) -> CommandKind {
        self.action.kind()
    }

    /// Returns the kind with its `args`.
    #[must_use]
    pub fn action(&self) -> CommandAction {
        self.action
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RawCommand {
    command_id: LowerUuid,
    endpoint_id: LowerUuid,
    seq: Integer,
    issued_at: UtcTimestamp,
    expires_at: UtcTimestamp,
    recovery_epoch: Integer,
    kind: CommandKind,
    args: DiagnoseArgs,
}

impl TryFrom<RawCommand> for CommandContent {
    type Error = ContentError;

    fn try_from(raw: RawCommand) -> Result<Self, ContentError> {
        let action = match raw.kind {
            CommandKind::Diagnose => CommandAction::Diagnose(raw.args),
        };
        Self::new(
            raw.command_id,
            raw.endpoint_id,
            raw.seq,
            raw.issued_at,
            raw.expires_at,
            raw.recovery_epoch,
            action,
        )
    }
}

impl From<CommandContent> for RawCommand {
    fn from(content: CommandContent) -> Self {
        let (kind, args) = match content.action {
            CommandAction::Diagnose(args) => (CommandKind::Diagnose, args),
        };
        Self {
            command_id: content.command_id,
            endpoint_id: content.endpoint_id,
            seq: content.seq,
            issued_at: content.issued_at,
            expires_at: content.expires_at,
            recovery_epoch: content.recovery_epoch,
            kind,
            args,
        }
    }
}
