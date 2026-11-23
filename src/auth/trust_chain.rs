//! The trust chain of an install configuration, from the vendor key to the
//! endpoint's first trust state.
//!
//! An install configuration (`senta-install-config`) is trusted through a
//! chain that starts at a vendor key: the vendor key signs the deployment
//! certificate (`senta-deployment-cert`), the deployment certificate's
//! install signing key signs the install configuration, and the key set
//! inside the install configuration signs the address document and the
//! enrollment token. [`verify`] checks the whole chain in five steps and
//! stops at the first failure:
//!
//! 1. The install configuration is read **without verifying its
//!    signature**, for its `deployment_cert`.
//! 2. The deployment certificate is checked against the vendor keys: its
//!    format, header, `typ`, kid grammar and key kind; then the test key
//!    policy; then the key lookup, the signature and the content.
//! 3. The install configuration is verified with the deployment
//!    certificate's install signing key, and its `install_id` compared
//!    with the deployment certificate's.
//! 4. The key set is verified with its own `current_kid`, and its
//!    customer identifiers compared with the install configuration's.
//! 5. The trust state is made from the key set and the recovery key, and
//!    the address document and the enrollment token are verified against
//!    it; the address document must be of the key set's recovery epoch.
//!
//! What step 1 reads only picks the deployment certificate to check, and
//! what step 2's checks before the signature read only reject. Every value
//! of the trust state and of the [`VerifiedInstall`] comes from a document
//! whose signature has verified.
//!
//! The crate holds no vendor key. The caller passes the vendor public keys
//! it trusts as [`VendorKeys`], and whether it trusts vendor test keys
//! (`vendor-test-<number>`) at all. Nothing here reads the time: a
//! deployment certificate does not expire, and the enrollment token's
//! `expires_at` is the server's to enforce.
//!
//! Everything here is sans-IO, except that
//! [`VerifiedInstall::create_document_versions`] writes the first document
//! version state to the caller's [`VersionStore`].

#[cfg(test)]
mod tests;

use std::fmt;

use jiff::Timestamp;

use super::documents::{
    self, AddressesContent, CustomerKeyName, DeploymentCertContent, DocumentError, EnrollContent,
    Hash32, InstallConfigContent, InstallId, JwsText, KeysetContent, NonEmptyString,
    VerifiedDocument,
};
use super::jws::strict::LowerUuid;
use super::jws::{
    self, Jwk, KeyKind, KeyLookup, KeySource, Kid, KidError, PublicKey, Typ, VendorKeyClass,
};
use super::keyset::{CurrentKidSource, TrustState};
use super::versions::{DocumentVersions, MemoryVersionStore, VersionStore, VersionsError};
use crate::results::{DocumentResult, InstallConfigFailure};

// --- vendor keys ------------------------------------------------------------

/// The vendor public keys the caller trusts, each under its kid.
///
/// Every kid is a vendor key's, `vendor-release-<number>` or
/// `vendor-test-<number>`, and no kid appears twice. Whether a test key is
/// trusted at all is decided when [`verify`] is called, not here.
///
/// As a [`KeySource`] it finds a key only under exactly the kid string it
/// was registered under, as a [`KeyKind::Vendor`] key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VendorKeys {
    keys: Vec<(Kid, PublicKey)>,
}

/// Why a list of vendor keys could not be made: the caller's configuration
/// is at fault, not an install configuration.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VendorKeysError {
    /// A kid does not follow the kid grammar.
    #[error("vendor key kid {kid:?} is not a valid kid")]
    Kid {
        /// The kid as given.
        kid: String,
        /// What is wrong with it.
        #[source]
        source: KidError,
    },
    /// A kid follows the kid grammar but is not a vendor key's.
    #[error("vendor key kid {kid:?} is a {kind} kid, not a vendor key's")]
    NotVendorKid {
        /// The kid as given.
        kid: String,
        /// The kind of key it names.
        kind: KeyKind,
    },
    /// A kid appears more than once.
    #[error("vendor key kid {kid:?} appears more than once")]
    DuplicateKid {
        /// The kid that repeats.
        kid: String,
    },
}

impl VendorKeys {
    /// Creates the list from `(kid, key)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`VendorKeysError::Kid`] if a kid does not follow the kid
    /// grammar, [`VendorKeysError::NotVendorKid`] if it is not a vendor
    /// key's, and [`VendorKeysError::DuplicateKid`] if a kid appears twice,
    /// compared as the whole kid string.
    pub fn new<I, K>(keys: I) -> Result<Self, VendorKeysError>
    where
        I: IntoIterator<Item = (K, Jwk)>,
        K: AsRef<str>,
    {
        let mut list: Vec<(Kid, PublicKey)> = Vec::new();
        for (kid, key) in keys {
            let text = kid.as_ref();
            let parsed = Kid::parse(text).map_err(|source| VendorKeysError::Kid {
                kid: text.to_owned(),
                source,
            })?;
            if parsed.kind() != KeyKind::Vendor {
                return Err(VendorKeysError::NotVendorKid {
                    kid: text.to_owned(),
                    kind: parsed.kind(),
                });
            }
            if list
                .iter()
                .any(|(have, _)| have.as_str() == parsed.as_str())
            {
                return Err(VendorKeysError::DuplicateKid {
                    kid: text.to_owned(),
                });
            }
            list.push((parsed, key.public_key()));
        }
        Ok(Self { keys: list })
    }

    /// Returns the number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether the list holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KeySource for VendorKeys {
    /// Finds the vendor key registered under exactly `kid`.
    ///
    /// A lookup that does not allow a vendor key, a kid that is not a
    /// vendor key's, and a kid not in the list are unknown.
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        if !allowed.contains(&KeyKind::Vendor) || kid.kind() != KeyKind::Vendor {
            return KeyLookup::Unknown;
        }
        self.keys
            .iter()
            .find(|(have, _)| have.as_str() == kid.as_str())
            .map_or(KeyLookup::Unknown, |&(_, key)| KeyLookup::Found {
                key,
                kind: KeyKind::Vendor,
            })
    }
}

/// The key lookup for the install configuration: only the deployment
/// certificate's install signing key, under exactly its
/// `install_signing_kid`.
struct InstallSigningSource<'a> {
    certificate: &'a DeploymentCertContent,
}

impl KeySource for InstallSigningSource<'_> {
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        if allowed.contains(&KeyKind::InstallSigning)
            && kid.kind() == KeyKind::InstallSigning
            && kid.as_str() == self.certificate.install_signing_kid().as_str()
        {
            KeyLookup::Found {
                key: self.certificate.install_signing_key().public_key(),
                kind: KeyKind::InstallSigning,
            }
        } else {
            KeyLookup::Unknown
        }
    }
}

// --- failure ------------------------------------------------------------------

/// The step of [`verify`] at which a chain failed, in the order the steps
/// run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// 1. Reading the install configuration before its signature is
    ///    verified.
    ReadInstallConfig,
    /// 2. Checking the deployment certificate against the vendor keys.
    DeploymentCert,
    /// 3. Verifying the install configuration with the install signing key
    ///    and comparing its install id.
    InstallConfig,
    /// 4. Verifying the key set with its own `current_kid` and comparing its
    ///    customer identifiers.
    Keyset,
    /// 5. Verifying the address document and the enrollment token against
    ///    the trust state.
    SignedDocuments,
}

impl Step {
    /// Returns the step's number, from 1 to 5.
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::ReadInstallConfig => 1,
            Self::DeploymentCert => 2,
            Self::InstallConfig => 3,
            Self::Keyset => 4,
            Self::SignedDocuments => 5,
        }
    }
}

/// The document of the chain a failure is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainDocument {
    /// The `senta-deployment-cert`.
    DeploymentCert,
    /// The `senta-install-config`.
    InstallConfig,
    /// The `senta-keyset` inside the install configuration.
    Keyset,
    /// The `senta-addresses` inside the install configuration.
    Addresses,
    /// The `senta-enroll` inside the install configuration.
    EnrollToken,
}

impl ChainDocument {
    /// Returns the `typ` of the document.
    #[must_use]
    pub fn typ(self) -> Typ {
        match self {
            Self::DeploymentCert => Typ::DeploymentCert,
            Self::InstallConfig => Typ::InstallConfig,
            Self::Keyset => Typ::Keyset,
            Self::Addresses => Typ::Addresses,
            Self::EnrollToken => Typ::Enroll,
        }
    }
}

/// A customer identifier of a key set, compared with the install
/// configuration's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustomerField {
    /// `customer_endpoint_id`.
    CustomerEndpointId,
    /// `customer_key_name`.
    CustomerKeyName,
}

impl CustomerField {
    /// Returns the field's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustomerEndpointId => "customer_endpoint_id",
            Self::CustomerKeyName => "customer_key_name",
        }
    }
}

/// What made a step fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureCause {
    /// A verification function, or a reading before the signature is
    /// verified, rejected the document; its error is kept as it was, with
    /// the [`DocumentResult`] it gives.
    Document(DocumentError),
    /// The deployment certificate is signed under a vendor test key's kid,
    /// and vendor test keys are not trusted. The kid is the header's, read
    /// before the signature was checked.
    UntrustedVendorKey {
        /// The kid the test key policy rejected.
        kid: Kid,
    },
    /// The verified install configuration's `install_id` is not the
    /// deployment certificate's.
    InstallIdMismatch {
        /// The deployment certificate's `install_id`.
        deployment_cert: InstallId,
        /// The install configuration's `install_id`.
        install_config: InstallId,
    },
    /// A customer identifier of the verified key set is not the install
    /// configuration's.
    CustomerMismatch {
        /// The field that differs; `customer_endpoint_id` is compared first.
        field: CustomerField,
    },
    /// The verified address document is of another recovery epoch than the
    /// key set.
    EpochMismatch {
        /// The address document's `recovery_epoch`.
        addresses: u64,
        /// The key set's `recovery_epoch`.
        keyset: u64,
    },
}

impl FailureCause {
    /// Returns the [`DocumentResult`] of a document rejected by a
    /// verification function or a reading, or `None` for any other cause.
    #[must_use]
    pub fn document_result(&self) -> Option<DocumentResult> {
        match self {
            Self::Document(error) => Some(error.result()),
            _ => None,
        }
    }
}

impl fmt::Display for FailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document(error) => fmt::Display::fmt(error, f),
            Self::UntrustedVendorKey { kid } => {
                write!(f, "vendor test key {kid} is not trusted")
            }
            Self::InstallIdMismatch {
                deployment_cert,
                install_config,
            } => write!(
                f,
                "install id {install_config} is not the deployment certificate's {deployment_cert}"
            ),
            Self::CustomerMismatch { field } => {
                write!(
                    f,
                    "the key set's {} is not the install configuration's",
                    field.as_str()
                )
            }
            Self::EpochMismatch { addresses, keyset } => write!(
                f,
                "the address document's recovery epoch {addresses} is not the key set's {keyset}"
            ),
        }
    }
}

/// Why an install configuration failed its trust chain: the step, the
/// document, the [`InstallConfigFailure`] to report, and the cause.
///
/// It holds no state: a failed chain makes none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustChainError {
    step: Step,
    document: ChainDocument,
    failure: InstallConfigFailure,
    // Boxed, so that a `Result` carrying the error stays small.
    cause: Box<FailureCause>,
}

impl TrustChainError {
    fn new(
        step: Step,
        document: ChainDocument,
        failure: InstallConfigFailure,
        cause: FailureCause,
    ) -> Self {
        Self {
            step,
            document,
            failure,
            cause: Box::new(cause),
        }
    }

    /// Returns the step that failed.
    #[must_use]
    pub fn step(&self) -> Step {
        self.step
    }

    /// Returns the document the failure is about.
    #[must_use]
    pub fn document(&self) -> ChainDocument {
        self.document
    }

    /// Returns the failure to report.
    #[must_use]
    pub fn failure(&self) -> &InstallConfigFailure {
        &self.failure
    }

    /// Returns what made the step fail.
    #[must_use]
    pub fn cause(&self) -> &FailureCause {
        &self.cause
    }
}

impl fmt::Display for TrustChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "install configuration trust chain failed at step {} on the {}: {}",
            self.step.number(),
            self.document.typ(),
            self.cause
        )
    }
}

impl std::error::Error for TrustChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &*self.cause {
            FailureCause::Document(error) => Some(error),
            _ => None,
        }
    }
}

// --- success ------------------------------------------------------------------

/// The enrollment token as the install configuration carried it.
///
/// The token is a bearer credential for enrollment, so its `Debug` prints
/// `<redacted>` and a derived `Debug` on [`VerifiedInstall`] cannot leak it.
#[derive(Clone)]
struct EnrollToken(JwsText);

impl fmt::Debug for EnrollToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollToken(<redacted>)")
    }
}

/// An install configuration whose whole trust chain verified, with what the
/// endpoint starts from.
///
/// Only [`verify`] makes one. Every value in it comes from a document whose
/// signature verified.
#[derive(Clone, Debug)]
pub struct VerifiedInstall {
    trust: TrustState,
    install_name: NonEmptyString,
    customer_endpoint_id: LowerUuid,
    customer_key_name: CustomerKeyName,
    hw_salt: Hash32,
    vdi_mode: bool,
    enroll_token: EnrollToken,
    enroll: EnrollContent,
    addresses: VerifiedDocument<AddressesContent>,
}

impl VerifiedInstall {
    /// Returns the first trust state: the install configuration's key set
    /// with its (recovery epoch, version), and its recovery key with that
    /// key's version.
    #[must_use]
    pub fn trust_state(&self) -> &TrustState {
        &self.trust
    }

    /// Returns the install id.
    #[must_use]
    pub fn install_id(&self) -> &InstallId {
        self.trust.install_id()
    }

    /// Returns the deployment certificate's `install_name`, for display.
    #[must_use]
    pub fn install_name(&self) -> &NonEmptyString {
        &self.install_name
    }

    /// Returns the install configuration's `customer_endpoint_id`.
    #[must_use]
    pub fn customer_endpoint_id(&self) -> LowerUuid {
        self.customer_endpoint_id
    }

    /// Returns the install configuration's `customer_key_name`.
    #[must_use]
    pub fn customer_key_name(&self) -> &CustomerKeyName {
        &self.customer_key_name
    }

    /// Returns the install configuration's `hw_salt`.
    #[must_use]
    pub fn hw_salt(&self) -> &Hash32 {
        &self.hw_salt
    }

    /// Returns the install configuration's `vdi_mode`.
    #[must_use]
    pub fn vdi_mode(&self) -> bool {
        self.vdi_mode
    }

    /// Returns the enrollment token, the `senta-enroll` JWS exactly as the
    /// install configuration carried it.
    ///
    /// The token is a bearer credential for enrollment: keep it out of
    /// logs. The `Debug` output of [`VerifiedInstall`] shows it only as
    /// `<redacted>`.
    #[must_use]
    pub fn enroll_token(&self) -> &str {
        self.enroll_token.0.as_str()
    }

    /// Returns the enrollment token's verified `token_id`.
    #[must_use]
    pub fn token_id(&self) -> LowerUuid {
        self.enroll.token_id
    }

    /// Returns the enrollment token's verified `expires_at`, or `None` for
    /// a token that does not expire. It is not checked here.
    #[must_use]
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.enroll.expires_at.map(Into::into)
    }

    /// Returns the verified address document.
    #[must_use]
    pub fn addresses(&self) -> &VerifiedDocument<AddressesContent> {
        &self.addresses
    }

    /// Creates the endpoint's first document version state in `store`, and
    /// returns its state machine.
    ///
    /// The state is at the key set's recovery epoch, without an endpoint
    /// id, and its address slot holds the install configuration's address
    /// document as verified and applied, as
    /// [`DocumentVersions::install_addresses`] leaves it; no
    /// [`DocumentApplier`](super::versions::DocumentApplier) is called.
    ///
    /// **Before calling this, the caller must have stored
    /// [`trust_state`](Self::trust_state) in its
    /// [`TrustStore`](super::versions::TrustStore)**, as every method of
    /// [`DocumentVersions`] taking a trust state requires. This does not
    /// touch the trust store.
    ///
    /// `store` is written at most once, with the whole first state: the
    /// state is built in memory with [`DocumentVersions::create`] and
    /// [`DocumentVersions::install_addresses`], then saved, then read back
    /// with [`DocumentVersions::restore`].
    ///
    /// # Errors
    ///
    /// - [`VersionsError::AlreadyCreated`] if `store` already holds a state,
    ///   which is left as it was; nothing is written.
    /// - [`VersionsError::Store`] if reading `store` before writing, or the
    ///   write itself, fails. Nothing was written, `self` is unchanged, and
    ///   calling this again with it creates the state.
    /// - [`VersionsError::Store`] if the write succeeded but reading the
    ///   state back fails. The state is stored then: calling this again
    ///   returns [`VersionsError::AlreadyCreated`], and the caller goes on
    ///   with [`DocumentVersions::restore`].
    pub fn create_document_versions<S: VersionStore>(
        &self,
        mut store: S,
    ) -> Result<DocumentVersions<S>, VersionsError> {
        if store.load().map_err(VersionsError::Store)?.is_some() {
            return Err(VersionsError::AlreadyCreated);
        }
        let mut first = DocumentVersions::create(MemoryVersionStore::new(), &self.trust)?;
        let result = first.install_addresses(self.addresses.clone())?;
        // `verify` checked that the address document is of the key set's
        // recovery epoch, the epoch `create` starts the state at, and the
        // address slot of a state just created holds nothing.
        debug_assert_eq!(result, DocumentResult::Applied);
        store.save(first.state()).map_err(VersionsError::Store)?;
        DocumentVersions::restore(store)
    }
}

// --- verification ---------------------------------------------------------------

/// Verifies the trust chain of the install configuration `install_config`,
/// a `senta-install-config` JWS, from the vendor keys `vendor_keys`.
///
/// A deployment certificate signed under a `vendor-test-<number>` kid is
/// rejected as [`InstallConfigFailure::UntrustedVendorKey`] unless
/// `trust_test_keys` is true, whether or not the kid is in `vendor_keys` and
/// whether or not its signature verifies.
///
/// The steps, in the order they run, and the failure each reports:
///
/// 1. The install configuration is read without verifying its signature,
///    for its `deployment_cert`: `InstallConfigInvalid`.
/// 2. The deployment certificate: its format, header, `typ`, kid grammar
///    and key kind, `DeploymentCertInvalid`; the test key policy,
///    `UntrustedVendorKey`; the key lookup in `vendor_keys`, the signature
///    and the content, `DeploymentCertInvalid`.
/// 3. The install configuration, verified with the deployment
///    certificate's install signing key under exactly its
///    `install_signing_kid`: `InstallConfigInvalid`. Its `install_id` is
///    not the deployment certificate's: `InstallIdMismatch`.
/// 4. The key set, verified with the key of its own `current_kid`, read
///    from the key set before its signature is verified: a key set signed
///    by its recovery key or by another key of its `keys` fails. Its
///    `customer_endpoint_id`, then its `customer_key_name`, is not the
///    install configuration's: `KeysetInvalid` for each.
/// 5. With the trust state made from the key set, the install id and the
///    recovery key and its version, which takes every key of `keys` not
///    revoked: the address document, `AddressesInvalid`, also when its
///    `recovery_epoch` is not the key set's; then the enrollment token,
///    `EnrollTokenInvalid`.
///
/// A key set that a recovery key signed is taken in only once the customer
/// key named by its `current_kid` has signed the same content again; there
/// is no exception for the key set of a recovery.
///
/// # Errors
///
/// Returns the [`TrustChainError`] of the first step that failed.
pub fn verify(
    install_config: &str,
    vendor_keys: &VendorKeys,
    trust_test_keys: bool,
) -> Result<VerifiedInstall, TrustChainError> {
    // 1. What is read here only picks the deployment certificate.
    let inspected = documents::inspect_install_config(install_config).map_err(|error| {
        TrustChainError::new(
            Step::ReadInstallConfig,
            ChainDocument::InstallConfig,
            InstallConfigFailure::InstallConfigInvalid,
            FailureCause::Document(error),
        )
    })?;

    // 2.
    let certificate = verify_deployment_cert(
        inspected.content().deployment_cert.as_str(),
        vendor_keys,
        trust_test_keys,
    )?
    .into_content();

    // 3. From here on only the verified install configuration is used.
    let config = documents::verify_install_config(
        install_config,
        &InstallSigningSource {
            certificate: &certificate,
        },
    )
    .map_err(|error| {
        TrustChainError::new(
            Step::InstallConfig,
            ChainDocument::InstallConfig,
            InstallConfigFailure::InstallConfigInvalid,
            FailureCause::Document(error),
        )
    })?
    .into_content();
    if config.install_id != *certificate.install_id() {
        return Err(TrustChainError::new(
            Step::InstallConfig,
            ChainDocument::InstallConfig,
            InstallConfigFailure::InstallIdMismatch,
            FailureCause::InstallIdMismatch {
                deployment_cert: certificate.install_id().clone(),
                install_config: config.install_id,
            },
        ));
    }

    // 4.
    let keyset = verify_keyset(&config)?;

    // 5.
    let trust = TrustState::new(
        keyset,
        config.install_id,
        config.recovery_key,
        config.recovery_key_version,
    );
    let addresses = documents::verify_addresses(config.addresses.as_str(), &trust)
        .map_err(|error| addresses_error(FailureCause::Document(error)))?;
    let addresses_epoch = addresses.content().recovery_epoch().get();
    if addresses_epoch != trust.recovery_epoch() {
        return Err(addresses_error(FailureCause::EpochMismatch {
            addresses: addresses_epoch,
            keyset: trust.recovery_epoch(),
        }));
    }
    let enroll = documents::verify_enroll(config.enroll_token.as_str(), &trust)
        .map_err(|error| {
            TrustChainError::new(
                Step::SignedDocuments,
                ChainDocument::EnrollToken,
                InstallConfigFailure::EnrollTokenInvalid,
                FailureCause::Document(error),
            )
        })?
        .into_content();

    Ok(VerifiedInstall {
        trust,
        install_name: certificate.install_name().clone(),
        customer_endpoint_id: config.customer_endpoint_id,
        customer_key_name: config.customer_key_name,
        hw_salt: config.hw_salt,
        vdi_mode: config.vdi_mode,
        enroll_token: EnrollToken(config.enroll_token),
        enroll,
        addresses,
    })
}

/// Step 2 of [`verify`].
fn verify_deployment_cert(
    jws: &str,
    vendor_keys: &VendorKeys,
    trust_test_keys: bool,
) -> Result<VerifiedDocument<DeploymentCertContent>, TrustChainError> {
    let invalid = |error: DocumentError| {
        TrustChainError::new(
            Step::DeploymentCert,
            ChainDocument::DeploymentCert,
            InstallConfigFailure::DeploymentCertInvalid,
            FailureCause::Document(error),
        )
    };
    // The checks before the key lookup, read only to reject.
    let unverified = jws::inspect(jws, Typ::DeploymentCert)
        .map_err(|error| invalid(DocumentError::Verify(error)))?;
    if !trust_test_keys && unverified.kid().vendor_class() == Some(VendorKeyClass::Test) {
        return Err(TrustChainError::new(
            Step::DeploymentCert,
            ChainDocument::DeploymentCert,
            InstallConfigFailure::UntrustedVendorKey,
            FailureCause::UntrustedVendorKey {
                kid: unverified.kid().clone(),
            },
        ));
    }
    documents::verify_deployment_cert(jws, vendor_keys).map_err(invalid)
}

/// Step 4 of [`verify`].
fn verify_keyset(
    config: &InstallConfigContent,
) -> Result<VerifiedDocument<KeysetContent>, TrustChainError> {
    let invalid = |cause: FailureCause| {
        TrustChainError::new(
            Step::Keyset,
            ChainDocument::Keyset,
            InstallConfigFailure::KeysetInvalid,
            cause,
        )
    };
    let jws = config.keyset.as_str();
    // Read only to pick the key: the key set's own `current_kid`.
    let inspected =
        documents::inspect_keyset(jws).map_err(|error| invalid(FailureCause::Document(error)))?;
    let keyset = documents::verify_keyset(
        jws,
        &CurrentKidSource {
            keyset: inspected.content(),
        },
    )
    .map_err(|error| invalid(FailureCause::Document(error)))?;
    let content = keyset.content();
    if content.customer_endpoint_id() != config.customer_endpoint_id {
        return Err(invalid(FailureCause::CustomerMismatch {
            field: CustomerField::CustomerEndpointId,
        }));
    }
    if *content.customer_key_name() != config.customer_key_name {
        return Err(invalid(FailureCause::CustomerMismatch {
            field: CustomerField::CustomerKeyName,
        }));
    }
    Ok(keyset)
}

fn addresses_error(cause: FailureCause) -> TrustChainError {
    TrustChainError::new(
        Step::SignedDocuments,
        ChainDocument::Addresses,
        InstallConfigFailure::AddressesInvalid,
        cause,
    )
}
