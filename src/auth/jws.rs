//! The JWS verifier for signed documents.
//!
//! Every document that changes what an endpoint does arrives as a JWS. The
//! rules are fixed here rather than left to a general-purpose JWT crate:
//!
//! - Only the compact serialization: three non-empty segments of unpadded,
//!   canonical base64url separated by `.`, with nothing else in the input.
//!   The signature is 64 bytes.
//! - The header is a JSON object with exactly the string members `alg`,
//!   `typ` and `kid`, and `alg` is `EdDSA`. Any other member, `crit`
//!   included, is rejected, as is a repeated one.
//! - `typ` must be the [`Typ`] the caller expects, and the kid must follow
//!   the [`Kid`] grammar and name a [`KeyKind`] that `typ` allows.
//! - The signature is checked with `ed25519-dalek`'s `verify_strict`.
//!
//! [`verify`] runs all of it and [`inspect`] runs everything but the key
//! lookup and the signature. Neither parses the content; content types do,
//! through [`strict::from_slice`].

mod b64;
mod jwk;
mod kid;
pub mod strict;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
#[cfg(test)]
mod tests;
mod typ;

use std::fmt;

use ed25519_dalek::Signature;
use serde::Deserializer as _;
use serde::de::{self, MapAccess, Visitor};
use sha2::{Digest, Sha256};

pub use self::jwk::{InvalidPublicKey, Jwk, PublicKey};
pub use self::kid::{Kid, KidError, VendorKeyClass};
pub use self::typ::{KeyKind, Typ};

const SEPARATOR: char = '.';
const ALG_EDDSA: &str = "EdDSA";
const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;
const HEADER_ALG: &str = "alg";
const HEADER_TYP: &str = "typ";
const HEADER_KID: &str = "kid";
const HEADER_MEMBERS: &[&str] = &[HEADER_ALG, HEADER_TYP, HEADER_KID];

/// Where [`verify`] looks up the key a kid names.
///
/// Implemented by whoever holds the keys: the key-set state machine, the
/// trust chain and the like.
pub trait KeySource {
    /// Looks up the key registered under `kid`.
    ///
    /// `allowed` is the key kinds the expected `typ` allows; `kid` names one
    /// of them. A key counts as found only when it is registered under the
    /// whole kid string, exactly: a key under the same key name with another
    /// version is not it. The contract is to return only a key registered as
    /// one of `allowed`; [`verify`] does not rely on that, and rejects a key
    /// whose registered kind differs from the kid's or is not allowed.
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup;
}

/// What a [`KeySource`] knows about a kid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLookup {
    /// A key is registered under exactly this kid.
    Found {
        /// The public key.
        key: PublicKey,
        /// The kind the key was registered as.
        kind: KeyKind,
    },
    /// No key is registered under this kid.
    Unknown,
    /// The key registered under this kid has been revoked.
    Revoked,
}

/// The `typ` and `kid` of a JWS header, exactly as the header's JSON strings
/// held them, for diagnostics and reports only.
///
/// They are present on every outcome of a JWS whose header passed the header
/// rules, successful or not, and absent when the format or the header
/// itself was at fault. Nothing is decided on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDiagnostics {
    typ: String,
    kid: String,
}

impl HeaderDiagnostics {
    /// Returns the header's `typ`, whether or not it is a known one.
    #[must_use]
    pub fn typ(&self) -> &str {
        &self.typ
    }

    /// Returns the header's `kid`, whether or not it parses.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// A JWS that does not follow the compact serialization rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct FormatError {
    reason: &'static str,
}

/// A JWS header that does not follow the header rules.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct HeaderError {
    reason: String,
}

/// Why a JWS was rejected, by the first check that failed.
///
/// The checks run in the order of the variants. Every variant after
/// [`VerifyError::Header`] carries the header's [`HeaderDiagnostics`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The input is not a compact JWS of unpadded, canonical base64url with a
    /// 64-byte signature.
    #[error("malformed JWS: {0}")]
    Format(FormatError),
    /// The header is not a JSON object of exactly `alg`, `typ` and `kid`
    /// strings with `alg` `EdDSA`.
    #[error("invalid JWS header: {0}")]
    Header(HeaderError),
    /// The header's `typ` is not the expected one.
    #[error("JWS typ is not the expected {expected}")]
    TypMismatch {
        /// The `typ` the caller expected.
        expected: Typ,
        /// The header's values.
        header: HeaderDiagnostics,
    },
    /// The header's kid does not follow the kid grammar.
    #[error("invalid JWS kid")]
    Kid {
        /// What is wrong with the kid.
        #[source]
        source: KidError,
        /// The header's values.
        header: HeaderDiagnostics,
    },
    /// The key is of a kind the `typ` does not allow, or was registered as a
    /// kind other than the one its kid names.
    #[error("{}", key_kind_message(*.typ, *.kid_kind, *.registered_kind))]
    KeyKind {
        /// The expected `typ`.
        typ: Typ,
        /// The kind the kid names.
        kid_kind: KeyKind,
        /// The kind the key source registered the key as, when the key
        /// source was asked and its answer was the fault.
        registered_kind: Option<KeyKind>,
        /// The header's values.
        header: HeaderDiagnostics,
    },
    /// The key source knows no key under the kid.
    #[error("unknown JWS kid")]
    UnknownKid {
        /// The header's values.
        header: HeaderDiagnostics,
    },
    /// The key under the kid has been revoked.
    #[error("revoked JWS kid")]
    RevokedKid {
        /// The header's values.
        header: HeaderDiagnostics,
    },
    /// The signature does not verify under the key.
    #[error("JWS signature does not verify")]
    Signature {
        /// The header's values.
        header: HeaderDiagnostics,
    },
}

fn key_kind_message(typ: Typ, kid_kind: KeyKind, registered_kind: Option<KeyKind>) -> String {
    match registered_kind {
        Some(registered) if registered != kid_kind => {
            format!("the key under a {kid_kind} kid is registered as a {registered}")
        }
        _ => format!("a {kid_kind} may not sign {typ}"),
    }
}

impl VerifyError {
    /// Returns the header's values, present on every error after
    /// [`VerifyError::Header`].
    #[must_use]
    pub fn header(&self) -> Option<&HeaderDiagnostics> {
        match self {
            Self::Format(_) | Self::Header(_) => None,
            Self::TypMismatch { header, .. }
            | Self::Kid { header, .. }
            | Self::KeyKind { header, .. }
            | Self::UnknownKid { header }
            | Self::RevokedKid { header }
            | Self::Signature { header } => Some(header),
        }
    }
}

/// What the checks before the signature yield.
#[derive(Clone, Debug)]
struct Document {
    payload: Vec<u8>,
    payload_hash: [u8; 32],
    kid: Kid,
    typ: Typ,
    header: HeaderDiagnostics,
}

macro_rules! document_accessors {
    () => {
        /// Returns the content: the payload segment, base64url-decoded.
        #[must_use]
        pub fn payload(&self) -> &[u8] {
            &self.document.payload
        }

        /// Returns the content, consuming `self`.
        #[must_use]
        pub fn into_payload(self) -> Vec<u8> {
            self.document.payload
        }

        /// Returns the SHA-256 of the content bytes, which is the same for the
        /// same content whatever the header or the signature.
        #[must_use]
        pub fn payload_hash(&self) -> &[u8; 32] {
            &self.document.payload_hash
        }

        /// Returns the kid of the header.
        #[must_use]
        pub fn kid(&self) -> &Kid {
            &self.document.kid
        }

        /// Returns the `typ` of the header.
        #[must_use]
        pub fn typ(&self) -> Typ {
            self.document.typ
        }

        /// Returns the header's `typ` and `kid` as the header held them.
        #[must_use]
        pub fn header(&self) -> &HeaderDiagnostics {
            &self.document.header
        }
    };
}

/// A JWS whose signature verified under the key its kid names.
///
/// Only [`verify`] makes one.
#[derive(Clone, Debug)]
pub struct Verified {
    document: Document,
}

impl Verified {
    document_accessors!();
}

/// A JWS that passed every check before the key lookup, read without
/// checking its signature.
///
/// **This is no ground for trusting the document.** Its signature may be
/// anything, a forgery included. Never accept the document, nor change any
/// state, on the strength of it: use it only to reject (for instance a vendor
/// test key the trust chain does not trust), to pick the key to verify with,
/// or to skip work without changing state, such as a version already held.
/// Whatever is accepted goes through [`verify`].
///
/// It is a different type from [`Verified`], and does not pass where one is
/// expected:
///
/// ```compile_fail,E0308
/// use senta_protocol::auth::jws::{Unverified, Verified};
///
/// fn accept(_: Verified) {}
/// fn pass(unverified: Unverified) {
///     accept(unverified);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Unverified {
    document: Document,
}

impl Unverified {
    document_accessors!();
}

/// Verifies a compact JWS as a document of `expected_typ`, with the key
/// `key_source` holds under its kid.
///
/// The checks run in this order, and the first to fail decides the error:
///
/// 1. the compact format, decoding all three segments;
/// 2. the header;
/// 3. the header's `typ` against `expected_typ`;
/// 4. the kid grammar;
/// 5. the kid's key kind against those `expected_typ` allows, without asking
///    `key_source`;
/// 6. the key lookup in `key_source`, and the kind the key was registered as;
/// 7. the signature over `<header segment>.<payload segment>`, with
///    `verify_strict`.
///
/// The content is not parsed.
///
/// # Errors
///
/// Returns the [`VerifyError`] of the first check that failed.
pub fn verify<K: KeySource + ?Sized>(
    jws: &str,
    expected_typ: Typ,
    key_source: &K,
) -> Result<Verified, VerifyError> {
    let Checked {
        document,
        signing_input,
        signature,
    } = check(jws, expected_typ)?;

    let kid_kind = document.kid.kind();
    let key = match key_source.find_key(&document.kid, expected_typ.allowed_key_kinds()) {
        KeyLookup::Found { key, kind } if kind == kid_kind && expected_typ.allows(kind) => key,
        KeyLookup::Found { kind, .. } => {
            return Err(VerifyError::KeyKind {
                typ: expected_typ,
                kid_kind,
                registered_kind: Some(kind),
                header: document.header,
            });
        }
        KeyLookup::Unknown => {
            return Err(VerifyError::UnknownKid {
                header: document.header,
            });
        }
        KeyLookup::Revoked => {
            return Err(VerifyError::RevokedKid {
                header: document.header,
            });
        }
    };

    if key
        .verifying_key()
        .verify_strict(signing_input.as_bytes(), &signature)
        .is_err()
    {
        return Err(VerifyError::Signature {
            header: document.header,
        });
    }
    Ok(Verified { document })
}

/// Runs the checks of [`verify`] that come before the key lookup — the
/// format, the header, the `typ`, the kid grammar and the key kind — and
/// reads the document without checking its signature.
///
/// **Passing is no ground for trusting the document**; see [`Unverified`]
/// for the only uses it may be put to. A JWS with a wrong signature passes.
/// The errors, diagnostics included, are those [`verify`] returns for the
/// same checks.
///
/// # Errors
///
/// Returns the [`VerifyError`] of the first check that failed, always one of
/// [`VerifyError::Format`], [`VerifyError::Header`],
/// [`VerifyError::TypMismatch`], [`VerifyError::Kid`] or
/// [`VerifyError::KeyKind`].
pub fn inspect(jws: &str, expected_typ: Typ) -> Result<Unverified, VerifyError> {
    check(jws, expected_typ).map(|checked| Unverified {
        document: checked.document,
    })
}

/// What passed checks 1–5, with what the signature check needs.
struct Checked<'a> {
    document: Document,
    signing_input: &'a str,
    signature: Signature,
}

fn format_error(reason: &'static str) -> VerifyError {
    VerifyError::Format(FormatError { reason })
}

/// Runs checks 1–5 of [`verify`].
fn check(jws: &str, expected_typ: Typ) -> Result<Checked<'_>, VerifyError> {
    // 1. Format.
    if jws.starts_with('{') {
        return Err(format_error(
            "the JSON serialization is not accepted, only the compact one",
        ));
    }
    let Some((signing_input, signature_segment)) = jws.rsplit_once(SEPARATOR) else {
        return Err(format_error("not three segments separated by `.`"));
    };
    let Some((header_segment, payload_segment)) = signing_input.split_once(SEPARATOR) else {
        return Err(format_error("not three segments separated by `.`"));
    };
    if payload_segment.contains(SEPARATOR) {
        return Err(format_error("not three segments separated by `.`"));
    }
    if header_segment.is_empty() || payload_segment.is_empty() || signature_segment.is_empty() {
        return Err(format_error("a segment is empty"));
    }
    let header_bytes = b64::decode(header_segment)
        .ok_or_else(|| format_error("the header segment is not unpadded, canonical base64url"))?;
    let payload = b64::decode(payload_segment)
        .ok_or_else(|| format_error("the payload segment is not unpadded, canonical base64url"))?;
    let signature_bytes = b64::decode(signature_segment).ok_or_else(|| {
        format_error("the signature segment is not unpadded, canonical base64url")
    })?;
    let signature_bytes: [u8; SIGNATURE_LEN] = signature_bytes
        .try_into()
        .map_err(|_| format_error("the signature is not 64 bytes"))?;

    // 2. Header.
    let header = parse_header(&header_bytes).map_err(VerifyError::Header)?;
    let diagnostics = HeaderDiagnostics {
        typ: header.typ,
        kid: header.kid,
    };

    // 3. `typ`.
    if diagnostics.typ != expected_typ.as_str() {
        return Err(VerifyError::TypMismatch {
            expected: expected_typ,
            header: diagnostics,
        });
    }

    // 4. Kid grammar.
    let kid = match Kid::parse(&diagnostics.kid) {
        Ok(kid) => kid,
        Err(source) => {
            return Err(VerifyError::Kid {
                source,
                header: diagnostics,
            });
        }
    };

    // 5. Key kind.
    if !expected_typ.allows(kid.kind()) {
        return Err(VerifyError::KeyKind {
            typ: expected_typ,
            kid_kind: kid.kind(),
            registered_kind: None,
            header: diagnostics,
        });
    }

    let payload_hash = Sha256::digest(&payload).into();
    Ok(Checked {
        document: Document {
            payload,
            payload_hash,
            kid,
            typ: expected_typ,
            header: diagnostics,
        },
        signing_input,
        signature: Signature::from_bytes(&signature_bytes),
    })
}

/// The three header members, all present.
struct Header {
    typ: String,
    kid: String,
}

fn parse_header(bytes: &[u8]) -> Result<Header, HeaderError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let header = de
        .deserialize_map(HeaderVisitor)
        .and_then(|header| de.end().map(|()| header))
        .map_err(|error| HeaderError {
            reason: error.to_string(),
        })?;
    if header.alg != ALG_EDDSA {
        return Err(HeaderError {
            reason: format!("alg is not `{ALG_EDDSA}`"),
        });
    }
    Ok(Header {
        typ: header.typ,
        kid: header.kid,
    })
}

struct RawHeader {
    alg: String,
    typ: String,
    kid: String,
}

struct HeaderVisitor;

impl<'de> Visitor<'de> for HeaderVisitor {
    type Value = RawHeader;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object of `alg`, `typ` and `kid`")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawHeader, A::Error> {
        let mut alg = None;
        let mut typ = None;
        let mut kid = None;
        // Keys arrive unescaped, so `"alg"` is `alg` here.
        while let Some(key) = map.next_key::<String>()? {
            let slot = match key.as_str() {
                HEADER_ALG => &mut alg,
                HEADER_TYP => &mut typ,
                HEADER_KID => &mut kid,
                _ => return Err(de::Error::unknown_field(&key, HEADER_MEMBERS)),
            };
            if slot.is_some() {
                return Err(de::Error::custom(format_args!(
                    "duplicate header member `{key}`"
                )));
            }
            *slot = Some(map.next_value::<String>()?);
        }
        Ok(RawHeader {
            alg: alg.ok_or_else(|| de::Error::missing_field(HEADER_ALG))?,
            typ: typ.ok_or_else(|| de::Error::missing_field(HEADER_TYP))?,
            kid: kid.ok_or_else(|| de::Error::missing_field(HEADER_KID))?,
        })
    }
}
