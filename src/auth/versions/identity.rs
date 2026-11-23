//! What a received document is, for acknowledging it without reading it
//! again.

use super::DocumentContent;
use crate::auth::documents::{self, DocumentError, InstallId, UpdateTarget};
use crate::auth::jws::strict::LowerUuid;
use crate::auth::jws::{self, Typ};

/// Whom a document is for, by kind and value, so that two documents of the
/// same id and version with targets of different kinds are told apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DocumentTarget {
    /// A group, `group_id`: a `senta-policy` or an update to a group.
    Group(LowerUuid),
    /// An endpoint, `endpoint_id`: a `senta-assign` or an update to an
    /// endpoint.
    Endpoint(LowerUuid),
    /// A customer, `customer_endpoint_id`: a `senta-keyset`.
    Customer(LowerUuid),
    /// An install, `install_id`: a `senta-recovery-key`.
    Install(InstallId),
}

/// The `typ`, target, recovery epoch and version of a received document, as
/// far as they were read, to fill in its acknowledgement.
///
/// - The `typ` is the header's, whatever it is; absent when the header
///   could not be read.
/// - The target, recovery epoch and version come from the content, and are
///   present only when it was read: for a policy, assignment, address
///   document or update, once its signature verified; for a key set or a
///   recovery key, once it was read before its signature is verified, even
///   if the signature then fails.
/// - An address document has no target: there is one per customer.
/// - Only a key set has a recovery epoch here.
/// - The version is a key set's `keyset_version`, a recovery key's
///   `recovery_key_version`, and any other document's `version`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocumentIdentity {
    typ: Option<String>,
    target: Option<DocumentTarget>,
    recovery_epoch: Option<u64>,
    version: Option<u64>,
}

impl DocumentIdentity {
    /// Returns the header's `typ`.
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// Returns whom the document is for.
    #[must_use]
    pub fn target(&self) -> Option<&DocumentTarget> {
        self.target.as_ref()
    }

    /// Returns a key set's `recovery_epoch`.
    #[must_use]
    pub fn recovery_epoch(&self) -> Option<u64> {
        self.recovery_epoch
    }

    /// Returns the document's version.
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    pub(super) fn of_typ(typ: Option<String>) -> Self {
        Self {
            typ,
            ..Self::default()
        }
    }

    /// Fills in the target and version of a verified document.
    pub(super) fn read_content(&mut self, content: &DocumentContent) {
        self.target = match content {
            DocumentContent::Policy(content) => Some(DocumentTarget::Group(content.group_id)),
            DocumentContent::Assign(content) => Some(DocumentTarget::Endpoint(content.endpoint_id)),
            DocumentContent::Addresses(_) => None,
            DocumentContent::Update(content) => Some(match content.target() {
                UpdateTarget::Group(group_id) => DocumentTarget::Group(group_id),
                UpdateTarget::Endpoint(endpoint_id) => DocumentTarget::Endpoint(endpoint_id),
            }),
        };
        self.version = Some(content.version());
    }

    /// Reads a `senta-keyset` or `senta-recovery-key` document, whose
    /// header's `typ` is `typ`, without verifying its signature, for its
    /// identity only.
    pub(super) fn of_key_document(jws: &str, typ: Option<String>) -> Self {
        let mut identity = Self::of_typ(typ);
        match identity.typ.as_deref() {
            Some(text) if text == Typ::Keyset.as_str() => {
                if let Ok(inspected) = documents::inspect_keyset(jws) {
                    let content = inspected.content();
                    identity.target =
                        Some(DocumentTarget::Customer(content.customer_endpoint_id()));
                    identity.recovery_epoch = Some(content.recovery_epoch().get());
                    identity.version = Some(content.keyset_version().get());
                }
            }
            Some(text) if text == Typ::RecoveryKey.as_str() => {
                if let Ok(inspected) = documents::inspect_recovery_key(jws) {
                    let content = inspected.into_content();
                    identity.version = Some(content.recovery_key_version.get());
                    identity.target = Some(DocumentTarget::Install(content.install_id));
                }
            }
            _ => {}
        }
        identity
    }
}

/// Returns the `typ` a JWS header holds, whatever it is, or `None` if the
/// JWS or its header does not follow the rules far enough to read it.
pub(super) fn header_typ(jws: &str) -> Option<String> {
    // Any expected `typ` does: a header of another `typ` fails as
    // `TypMismatch`, which carries the header's own.
    match jws::inspect(jws, Typ::Policy) {
        Ok(unverified) => Some(unverified.header().typ().to_owned()),
        Err(error) => error.header().map(|header| header.typ().to_owned()),
    }
}

/// The `typ`s of the documents with versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VersionedTyp {
    Policy,
    Assign,
    Addresses,
    Update,
}

impl VersionedTyp {
    pub(super) fn from_header(typ: &str) -> Option<Self> {
        [
            (Typ::Policy, Self::Policy),
            (Typ::Assign, Self::Assign),
            (Typ::Addresses, Self::Addresses),
            (Typ::Update, Self::Update),
        ]
        .into_iter()
        .find_map(|(known, versioned)| (known.as_str() == typ).then_some(versioned))
    }

    /// Verifies `jws` as a document of this `typ` with `key_source`,
    /// returning its content and content hash.
    pub(super) fn verify<K: jws::KeySource + ?Sized>(
        self,
        jws: &str,
        key_source: &K,
    ) -> Result<(DocumentContent, [u8; 32]), DocumentError> {
        Ok(match self {
            Self::Policy => {
                let verified = documents::verify_policy(jws, key_source)?;
                let hash = *verified.payload_hash();
                (DocumentContent::Policy(verified.into_content()), hash)
            }
            Self::Assign => {
                let verified = documents::verify_assign(jws, key_source)?;
                let hash = *verified.payload_hash();
                (DocumentContent::Assign(verified.into_content()), hash)
            }
            Self::Addresses => {
                let verified = documents::verify_addresses(jws, key_source)?;
                let hash = *verified.payload_hash();
                (DocumentContent::Addresses(verified.into_content()), hash)
            }
            Self::Update => {
                let verified = documents::verify_update(jws, key_source)?;
                let hash = *verified.payload_hash();
                (DocumentContent::Update(verified.into_content()), hash)
            }
        })
    }
}
