//! Signed documents: the content of each `typ`, its verification, and the
//! validity window of commands and updates.
//!
//! Each of the eleven [`Typ`]s has a content type, whose JSON schema is
//! fixed, and a verification function: `verify_<typ>` runs
//! [`jws::verify`] with that `typ` and, only once the signature has
//! verified, parses the content with [`strict::from_slice`]. Every rule of
//! the schema, the cross-field ones included, is checked inside that parse,
//! so every violation is a [`strict::SchemaError`] naming where it is.
//!
//! A failure is a [`DocumentError`], which gives the [`DocumentResult`] to
//! report, the original cause, and the header's diagnostic `typ` and `kid`:
//!
//! | Failure | [`DocumentResult`] |
//! | --- | --- |
//! | format, header, `typ` mismatch, kid grammar | `SchemaError` |
//! | key kind | `WrongKeyClass` |
//! | unknown kid | `UnknownKid` |
//! | revoked kid | `RevokedKid` |
//! | signature | `BadSignature` |
//! | content schema | `SchemaError` |
//!
//! Verification does not compare recovery epochs, versions or sequence
//! numbers, targets, or validity windows; the state machines do.
//! [`check_validity_window`] is the window check they run on commands and
//! updates.
//!
//! [`verify_self_signed_keyset`] verifies a `senta-keyset` document with no
//! key source: the key is the one its own content gives its `current_kid`.
//! That shows the document is self-signed, not that it is to be trusted.
//!
//! Three `typ`s, `senta-keyset`, `senta-recovery-key` and
//! `senta-install-config`, can also be read before their signature is
//! verified, with `inspect_<typ>`, to choose the key to verify with or to
//! skip a document already held. **That reading checks no signature**; see
//! [`InspectedDocument`] for the only uses it may be put to.

mod content;
mod forms;
#[cfg(test)]
mod tests;
mod window;

use serde::de::DeserializeOwned;

pub use self::content::{
    AddressesContent, AssignContent, AuditSettings, CommandAction, CommandContent, CommandKind,
    ContentError, ControlEntry, DeploymentCertContent, DiagnoseArgs, EnrollContent,
    EnrollResultContent, ExistingSysmon, Hash32, InstallConfigContent, KeysetContent, KeysetEntry,
    PolicyCollectionMode, PolicyContent, RecoveryKeyContent, StatusUi, SysmonConfig, SysmonConfigs,
    TelemetryEntry, UpdateContent, UpdatePackage, UpdateRelease, UpdateTarget,
    WindowsSysmonPackage,
};
pub use self::forms::{
    AbsoluteUrl, Address, AddressHost, CertificatePem, CustomerKeyName, CustomerKid, DnsName,
    InstallId, Integer, JwsText, KindNumber, NonEmptyString, PositiveInteger, SemVer,
};
pub use self::window::{
    CLOCK_SKEW, MAX_COMMAND_LIFETIME, MAX_UPDATE_LIFETIME, check_validity_window,
};
use super::jws::strict::{self, SchemaError};
use super::jws::{self, HeaderDiagnostics, KeySource, Kid, Typ, Unverified, Verified, VerifyError};
use super::keyset::CurrentKidSource;
use crate::results::DocumentResult;

/// A signed document whose signature verified, with its content parsed.
///
/// Only the `verify_<typ>` functions make one.
#[derive(Clone, Debug)]
pub struct VerifiedDocument<C> {
    content: C,
    jws: Verified,
}

impl<C> VerifiedDocument<C> {
    /// Returns the content.
    #[must_use]
    pub fn content(&self) -> &C {
        &self.content
    }

    /// Returns the content, consuming `self`.
    #[must_use]
    pub fn into_content(self) -> C {
        self.content
    }

    /// Returns the kid that signed the document.
    #[must_use]
    pub fn kid(&self) -> &Kid {
        self.jws.kid()
    }

    /// Returns the SHA-256 of the content bytes: the payload segment
    /// base64url-decoded, not the content serialized again.
    #[must_use]
    pub fn payload_hash(&self) -> &[u8; 32] {
        self.jws.payload_hash()
    }

    /// Returns the content bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.jws.payload()
    }

    /// Returns the `typ` of the document.
    #[must_use]
    pub fn typ(&self) -> Typ {
        self.jws.typ()
    }

    /// Returns the header's `typ` and `kid` as the header held them, for
    /// diagnostics.
    #[must_use]
    pub fn header(&self) -> &HeaderDiagnostics {
        self.jws.header()
    }
}

/// A signed document read **without verifying its signature**, with its
/// content parsed.
///
/// Only `inspect_keyset`, `inspect_recovery_key` and
/// `inspect_install_config` make one. Its signature may be anything, a
/// forgery included, so it is no ground for trusting the document. The
/// contract is that nothing in it creates or changes trust state: use it to
/// choose the key to verify the document with (the kid's kind, install id
/// and version; the deployment certificate inside an install configuration),
/// to reject, or to skip a document already held without changing state
/// (the version, and the payload hash, which is the same for the same
/// content however it is signed). Every value that creates or changes state
/// comes from the [`VerifiedDocument`] of the same document.
///
/// It is a different type from [`VerifiedDocument`], and does not pass
/// where one is expected:
///
/// ```compile_fail,E0308
/// use senta_protocol::auth::documents::{InspectedDocument, KeysetContent, VerifiedDocument};
///
/// fn accept(_: VerifiedDocument<KeysetContent>) {}
/// fn pass(inspected: InspectedDocument<KeysetContent>) {
///     accept(inspected);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct InspectedDocument<C> {
    content: C,
    jws: Unverified,
}

impl<C> InspectedDocument<C> {
    /// Returns the content, whose signature has not been verified.
    #[must_use]
    pub fn content(&self) -> &C {
        &self.content
    }

    /// Returns the content, whose signature has not been verified, consuming
    /// `self`.
    #[must_use]
    pub fn into_content(self) -> C {
        self.content
    }

    /// Returns the header's kid, which has not been shown to have signed
    /// the document.
    #[must_use]
    pub fn kid(&self) -> &Kid {
        self.jws.kid()
    }

    /// Returns the SHA-256 of the content bytes, as
    /// [`VerifiedDocument::payload_hash`] does for the same document.
    #[must_use]
    pub fn payload_hash(&self) -> &[u8; 32] {
        self.jws.payload_hash()
    }

    /// Returns the content bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.jws.payload()
    }

    /// Returns the `typ` of the document.
    #[must_use]
    pub fn typ(&self) -> Typ {
        self.jws.typ()
    }

    /// Returns the header's `typ` and `kid` as the header held them, for
    /// diagnostics.
    #[must_use]
    pub fn header(&self) -> &HeaderDiagnostics {
        self.jws.header()
    }
}

/// Why a signed document was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DocumentError {
    /// The JWS failed a check of [`jws::verify`] (or, for an
    /// `inspect_<typ>` function, of [`jws::inspect`]).
    #[error(transparent)]
    Verify(VerifyError),
    /// The JWS passed, but its content does not match the schema of its
    /// `typ`.
    #[error("the document content does not match its schema")]
    Schema {
        /// Where and how the content broke the schema.
        #[source]
        source: SchemaError,
        /// The header's values.
        header: HeaderDiagnostics,
    },
}

impl DocumentError {
    /// Returns the result to report for the failure.
    #[must_use]
    pub fn result(&self) -> DocumentResult {
        match self {
            Self::Verify(
                VerifyError::Format(_)
                | VerifyError::Header(_)
                | VerifyError::TypMismatch { .. }
                | VerifyError::Kid { .. },
            )
            | Self::Schema { .. } => DocumentResult::SchemaError,
            Self::Verify(VerifyError::KeyKind { .. }) => DocumentResult::WrongKeyClass,
            Self::Verify(VerifyError::UnknownKid { .. }) => DocumentResult::UnknownKid,
            Self::Verify(VerifyError::RevokedKid { .. }) => DocumentResult::RevokedKid,
            Self::Verify(VerifyError::Signature { .. }) => DocumentResult::BadSignature,
        }
    }

    /// Returns the header's `typ` and `kid` as the header held them, for
    /// diagnostics and reports only; absent when the format or the header
    /// itself was at fault.
    #[must_use]
    pub fn header(&self) -> Option<&HeaderDiagnostics> {
        match self {
            Self::Verify(error) => error.header(),
            Self::Schema { header, .. } => Some(header),
        }
    }

    /// Returns the JWS check that failed, if one did.
    #[must_use]
    pub fn verify_error(&self) -> Option<&VerifyError> {
        match self {
            Self::Verify(error) => Some(error),
            Self::Schema { .. } => None,
        }
    }

    /// Returns the schema error, if the content was at fault.
    #[must_use]
    pub fn schema_error(&self) -> Option<&SchemaError> {
        match self {
            Self::Verify(_) => None,
            Self::Schema { source, .. } => Some(source),
        }
    }
}

fn verify_as<C: DeserializeOwned, K: KeySource + ?Sized>(
    jws: &str,
    typ: Typ,
    key_source: &K,
) -> Result<VerifiedDocument<C>, DocumentError> {
    let verified = jws::verify(jws, typ, key_source).map_err(DocumentError::Verify)?;
    match strict::from_slice(verified.payload()) {
        Ok(content) => Ok(VerifiedDocument {
            content,
            jws: verified,
        }),
        Err(source) => Err(DocumentError::Schema {
            source,
            header: verified.header().clone(),
        }),
    }
}

fn inspect_as<C: DeserializeOwned>(
    jws: &str,
    typ: Typ,
) -> Result<InspectedDocument<C>, DocumentError> {
    let unverified = jws::inspect(jws, typ).map_err(DocumentError::Verify)?;
    match strict::from_slice(unverified.payload()) {
        Ok(content) => Ok(InspectedDocument {
            content,
            jws: unverified,
        }),
        Err(source) => Err(DocumentError::Schema {
            source,
            header: unverified.header().clone(),
        }),
    }
}

macro_rules! verify_fn {
    ($(#[$doc:meta])* $name:ident, $typ:expr, $content:ty) => {
        $(#[$doc])*
        ///
        /// Runs [`jws::verify`] with the key `key_source` holds under the
        /// header's kid, then parses the content strictly, only once the
        /// signature has verified. Recovery epochs, versions, targets and
        /// validity windows are not checked.
        ///
        /// # Errors
        ///
        /// Returns [`DocumentError::Verify`] if the JWS fails a check of
        /// [`jws::verify`], and [`DocumentError::Schema`] if the content does
        /// not match its schema.
        pub fn $name<K: KeySource + ?Sized>(
            jws: &str,
            key_source: &K,
        ) -> Result<VerifiedDocument<$content>, DocumentError> {
            verify_as(jws, $typ, key_source)
        }
    };
}

macro_rules! inspect_fn {
    ($(#[$doc:meta])* $name:ident, $typ:expr, $content:ty) => {
        $(#[$doc])*
        ///
        /// **The signature is not verified.** Runs the checks of
        /// [`jws::inspect`] — the format, the header, the `typ`, the kid
        /// grammar and the key kind, as [`jws::verify`] does — and parses the
        /// content strictly, with no key lookup and no signature check. See
        /// [`InspectedDocument`] for what the result may be used for.
        ///
        /// # Errors
        ///
        /// Returns [`DocumentError::Verify`] if the JWS fails a check of
        /// [`jws::inspect`], and [`DocumentError::Schema`] if the content
        /// does not match its schema.
        pub fn $name(jws: &str) -> Result<InspectedDocument<$content>, DocumentError> {
            inspect_as(jws, $typ)
        }
    };
}

verify_fn!(
    /// Verifies a `senta-deployment-cert` document, signed by the vendor key.
    verify_deployment_cert,
    Typ::DeploymentCert,
    DeploymentCertContent
);
verify_fn!(
    /// Verifies a `senta-install-config` document, signed by an install
    /// signing key.
    verify_install_config,
    Typ::InstallConfig,
    InstallConfigContent
);
verify_fn!(
    /// Verifies a `senta-keyset` document, signed by a customer key or a
    /// recovery key.
    verify_keyset,
    Typ::Keyset,
    KeysetContent
);
verify_fn!(
    /// Verifies a `senta-recovery-key` document, signed by a recovery key.
    verify_recovery_key,
    Typ::RecoveryKey,
    RecoveryKeyContent
);
verify_fn!(
    /// Verifies a `senta-enroll` document, signed by a customer key.
    verify_enroll,
    Typ::Enroll,
    EnrollContent
);
verify_fn!(
    /// Verifies a `senta-enroll-result` document, signed by a customer key.
    verify_enroll_result,
    Typ::EnrollResult,
    EnrollResultContent
);
verify_fn!(
    /// Verifies a `senta-policy` document, signed by a customer key.
    verify_policy,
    Typ::Policy,
    PolicyContent
);
verify_fn!(
    /// Verifies a `senta-assign` document, signed by a customer key.
    verify_assign,
    Typ::Assign,
    AssignContent
);
verify_fn!(
    /// Verifies a `senta-addresses` document, signed by a customer key.
    verify_addresses,
    Typ::Addresses,
    AddressesContent
);
verify_fn!(
    /// Verifies a `senta-update` document, signed by a customer key.
    verify_update,
    Typ::Update,
    UpdateContent
);
verify_fn!(
    /// Verifies a `senta-command` document, signed by a customer key.
    verify_command,
    Typ::Command,
    CommandContent
);

/// Verifies a `senta-keyset` document against its own `current_kid`.
///
/// The document passes only if it is signed by the customer kid its content
/// names as `current_kid`, under that kid's key in its own `keys`: the rule
/// the install configuration's chain applies to its key set. Any other kid —
/// another customer kid of the same key set, a recovery kid — is a kid with
/// no key. The JWS goes through the checks of [`verify_keyset`] and its
/// content through the strict parse of [`KeysetContent`], every rule of
/// that schema included.
///
/// **This shows only that the document is consistently self-signed, not
/// that it comes from anyone in particular.** Anyone holding a key can make
/// a key set naming that key as its `current_kid`, so the result is no
/// ground for trusting the document. That ground must come from how the
/// caller obtained the document. Nothing else is checked: not the recovery
/// epoch or version, not the customer endpoint identifier or key name, and
/// not the `revoked_kids` of a key set already trusted.
///
/// # Errors
///
/// Returns [`DocumentError::Verify`] if the JWS fails a check of
/// [`jws::inspect`] or [`jws::verify`]: a header kid that is a customer kid
/// other than `current_kid`, or a recovery kid, is
/// [`VerifyError::UnknownKid`], and a signature that does not verify under
/// `current_kid`'s key is [`VerifyError::Signature`]. Returns
/// [`DocumentError::Schema`] if the content does not match its schema,
/// including a `current_kid` that is not in `keys`.
pub fn verify_self_signed_keyset(
    jws: &str,
) -> Result<VerifiedDocument<KeysetContent>, DocumentError> {
    // Read only to pick the key: the key set's own `current_kid`.
    let inspected = inspect_keyset(jws)?;
    verify_keyset(
        jws,
        &CurrentKidSource {
            keyset: inspected.content(),
        },
    )
}

inspect_fn!(
    /// Reads a `senta-keyset` document without verifying its signature, for
    /// its version and keys: to skip a key set already held, and to check a
    /// key set signed by its own `current_kid`.
    inspect_keyset,
    Typ::Keyset,
    KeysetContent
);
inspect_fn!(
    /// Reads a `senta-recovery-key` document without verifying its
    /// signature, for its version: to skip a replacement already held.
    inspect_recovery_key,
    Typ::RecoveryKey,
    RecoveryKeyContent
);
inspect_fn!(
    /// Reads a `senta-install-config` document without verifying its
    /// signature, for its `deployment_cert` and `install_id`: to verify the
    /// deployment certificate first and get the install signing key from it.
    inspect_install_config,
    Typ::InstallConfig,
    InstallConfigContent
);

/// Doctests asserting that exactly three `typ`s can be read before their
/// signature is verified: every other `inspect_<typ>` must not resolve.
#[cfg(doctest)]
mod inspection_scope {
    /// ```
    /// use senta_protocol::auth::documents::{
    ///     inspect_install_config, inspect_keyset, inspect_recovery_key,
    /// };
    /// ```
    struct Inspectable;

    macro_rules! not_inspectable {
        ($($name:ident: $function:literal)*) => {$(
            #[doc = "```compile_fail,E0432"]
            #[doc = concat!("use senta_protocol::auth::documents::", $function, ";")]
            #[doc = "```"]
            struct $name;
        )*};
    }

    not_inspectable! {
        DeploymentCert: "inspect_deployment_cert"
        Enroll: "inspect_enroll"
        EnrollResult: "inspect_enroll_result"
        Policy: "inspect_policy"
        Assign: "inspect_assign"
        Addresses: "inspect_addresses"
        Update: "inspect_update"
        Command: "inspect_command"
    }
}
