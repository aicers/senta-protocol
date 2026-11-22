//! The kid grammar shared by JWS headers and the kids signed documents carry.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::strict::parse_lower_uuid;
use super::typ::KeyKind;

const CUSTOMER_PREFIX: &str = "endpoint-";
const INSTALL_SIGNING_PREFIX: &str = "install-";
const RECOVERY_PREFIX: &str = "recovery-";
const VENDOR_RELEASE_PREFIX: &str = "vendor-release-";
const VENDOR_TEST_PREFIX: &str = "vendor-test-";
const VERSION_SEPARATOR: char = ':';
/// The largest key version, 2^53 − 1, the largest integer every JSON
/// implementation represents exactly.
const MAX_VERSION: u64 = (1 << 53) - 1;

/// Whether a vendor key is a release key or a test key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VendorKeyClass {
    /// `vendor-release-<number>`.
    Release,
    /// `vendor-test-<number>`.
    Test,
}

/// The part of a kid that depends on its key kind.
#[derive(Clone, Copy, Debug)]
enum Detail {
    Customer {
        endpoint_id: uuid::Uuid,
        version: u64,
    },
    InstallSigning {
        version: u64,
    },
    Recovery {
        version: u64,
    },
    Vendor {
        class: VendorKeyClass,
    },
}

/// A kid that follows the kid grammar.
///
/// One of:
///
/// - `endpoint-<uuid>:<version>`, a customer key, where `<uuid>` is a
///   lowercase hyphenated UUID;
/// - `install-<install id>:<version>`, an install signing key;
/// - `recovery-<install id>:<version>`, a recovery key;
/// - `vendor-release-<number>` or `vendor-test-<number>`, a vendor key,
///   with no version.
///
/// `<version>` is a decimal integer from 1 to 2^53 − 1 without a leading
/// zero. `<install id>` is one or more printable ASCII characters
/// (0x21–0x7E) other than `:`. `<number>` is one or more ASCII digits, and
/// may start with zero.
///
/// The original string is kept byte for byte, and two kids are equal exactly
/// when their strings are: `vendor-release-001` and `vendor-release-1` are
/// different kids.
///
/// Whether a vendor test key is trusted is not decided here: a
/// `vendor-test-<number>` kid parses exactly as a `vendor-release-<number>`
/// one does, and [`Kid::vendor_class`] tells the two apart for whoever
/// decides.
#[derive(Clone, Debug)]
pub struct Kid {
    raw: String,
    /// The length of the key name: the part before `:`, or the whole kid for
    /// a vendor key.
    name_len: usize,
    /// The length of the prefix that names the key kind.
    prefix_len: usize,
    detail: Detail,
}

/// The reason a string is not a valid kid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid kid: {reason}")]
pub struct KidError {
    reason: &'static str,
}

impl KidError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Kid {
    /// Parses a kid.
    ///
    /// # Errors
    ///
    /// Returns [`KidError`] when `kid` follows none of the four forms.
    pub fn parse(kid: &str) -> Result<Self, KidError> {
        let (prefix_len, name_len, detail) = parse_parts(kid)?;
        Ok(Self {
            raw: kid.to_owned(),
            name_len,
            prefix_len,
            detail,
        })
    }

    /// Returns the kid exactly as it was parsed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the kind of key the kid names.
    #[must_use]
    pub fn kind(&self) -> KeyKind {
        match self.detail {
            Detail::Customer { .. } => KeyKind::Customer,
            Detail::InstallSigning { .. } => KeyKind::InstallSigning,
            Detail::Recovery { .. } => KeyKind::Recovery,
            Detail::Vendor { .. } => KeyKind::Vendor,
        }
    }

    /// Returns the key name: the part before `:` (`endpoint-<uuid>`,
    /// `install-<install id>`, `recovery-<install id>`), or the whole kid for
    /// a vendor key.
    #[must_use]
    pub fn key_name(&self) -> &str {
        self.slice(0, self.name_len)
    }

    /// Returns the key version, or `None` for a vendor key, which has none.
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        match self.detail {
            Detail::Customer { version, .. }
            | Detail::InstallSigning { version }
            | Detail::Recovery { version } => Some(version),
            Detail::Vendor { .. } => None,
        }
    }

    /// Returns the endpoint UUID of a customer key, or `None` for any other
    /// kind.
    #[must_use]
    pub fn endpoint_id(&self) -> Option<uuid::Uuid> {
        match self.detail {
            Detail::Customer { endpoint_id, .. } => Some(endpoint_id),
            _ => None,
        }
    }

    /// Returns the install id of an install signing key or a recovery key,
    /// or `None` for any other kind.
    #[must_use]
    pub fn install_id(&self) -> Option<&str> {
        match self.detail {
            Detail::InstallSigning { .. } | Detail::Recovery { .. } => {
                Some(self.slice(self.prefix_len, self.name_len))
            }
            _ => None,
        }
    }

    /// Returns whether a vendor key is a release or a test key, or `None` for
    /// any other kind.
    #[must_use]
    pub fn vendor_class(&self) -> Option<VendorKeyClass> {
        match self.detail {
            Detail::Vendor { class } => Some(class),
            _ => None,
        }
    }

    /// Returns the number of a vendor key as written, leading zeros
    /// included, or `None` for any other kind.
    #[must_use]
    pub fn vendor_number(&self) -> Option<&str> {
        match self.detail {
            Detail::Vendor { .. } => Some(self.slice(self.prefix_len, self.raw.len())),
            _ => None,
        }
    }

    fn slice(&self, start: usize, end: usize) -> &str {
        self.raw
            .get(start..end)
            .expect("parsing recorded ASCII-only boundaries within the kid")
    }
}

/// Splits `kid` into the prefix length, the key name length and the
/// kind-specific detail.
fn parse_parts(kid: &str) -> Result<(usize, usize, Detail), KidError> {
    for (prefix, class) in [
        (VENDOR_RELEASE_PREFIX, VendorKeyClass::Release),
        (VENDOR_TEST_PREFIX, VendorKeyClass::Test),
    ] {
        if let Some(number) = kid.strip_prefix(prefix) {
            if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
                return Err(KidError::new(
                    "a vendor kid ends in one or more ASCII digits and has no version",
                ));
            }
            return Ok((prefix.len(), kid.len(), Detail::Vendor { class }));
        }
    }

    let Some((name, version)) = kid.split_once(VERSION_SEPARATOR) else {
        return Err(KidError::new(
            "kid is neither `<key name>:<version>` nor a vendor kid",
        ));
    };
    let version = parse_version(version)?;
    if let Some(endpoint_id) = name.strip_prefix(CUSTOMER_PREFIX) {
        let endpoint_id = parse_lower_uuid(endpoint_id).ok_or(KidError::new(
            "endpoint id is not a lowercase hyphenated UUID",
        ))?;
        return Ok((
            CUSTOMER_PREFIX.len(),
            name.len(),
            Detail::Customer {
                endpoint_id,
                version,
            },
        ));
    }
    for (prefix, detail) in [
        (INSTALL_SIGNING_PREFIX, Detail::InstallSigning { version }),
        (RECOVERY_PREFIX, Detail::Recovery { version }),
    ] {
        if let Some(install_id) = name.strip_prefix(prefix) {
            // `name` holds no `:`, since it ends at the first one.
            if install_id.is_empty() || !install_id.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(KidError::new(
                    "install id is not one or more printable ASCII characters",
                ));
            }
            return Ok((prefix.len(), name.len(), detail));
        }
    }
    Err(KidError::new(
        "key name starts with none of `endpoint-`, `install-`, `recovery-`",
    ))
}

fn parse_version(version: &str) -> Result<u64, KidError> {
    const INVALID: KidError =
        KidError::new("version is not a decimal integer from 1 to 2^53 - 1 without leading zeros");
    if version.starts_with('0')
        || version.is_empty()
        || !version.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(INVALID);
    }
    match version.parse::<u64>() {
        Ok(value) if value <= MAX_VERSION => Ok(value),
        _ => Err(INVALID),
    }
}

impl FromStr for Kid {
    type Err = KidError;

    fn from_str(kid: &str) -> Result<Self, KidError> {
        Self::parse(kid)
    }
}

impl TryFrom<String> for Kid {
    type Error = KidError;

    fn try_from(kid: String) -> Result<Self, KidError> {
        let (prefix_len, name_len, detail) = parse_parts(&kid)?;
        Ok(Self {
            raw: kid,
            name_len,
            prefix_len,
            detail,
        })
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl PartialEq for Kid {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for Kid {}

impl Hash for Kid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl PartialOrd for Kid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Kid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl Serialize for Kid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Kid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KidVisitor;

        impl de::Visitor<'_> for KidVisitor {
            type Value = Kid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a kid string")
            }

            fn visit_str<E: de::Error>(self, kid: &str) -> Result<Kid, E> {
                Kid::parse(kid).map_err(E::custom)
            }

            fn visit_string<E: de::Error>(self, kid: String) -> Result<Kid, E> {
                Kid::try_from(kid).map_err(E::custom)
            }
        }

        deserializer.deserialize_string(KidVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    fn kid(text: &str) -> Kid {
        text.parse().unwrap()
    }

    #[test]
    fn parses_a_customer_kid() {
        let parsed = kid(&format!("endpoint-{UUID}:7"));
        assert_eq!(parsed.kind(), KeyKind::Customer);
        assert_eq!(parsed.key_name(), format!("endpoint-{UUID}"));
        assert_eq!(parsed.version(), Some(7));
        assert_eq!(parsed.endpoint_id(), Some(UUID.parse().unwrap()));
        assert_eq!(parsed.install_id(), None);
        assert_eq!(parsed.vendor_class(), None);
        assert_eq!(parsed.vendor_number(), None);
        assert_eq!(parsed.as_str(), format!("endpoint-{UUID}:7"));
    }

    #[test]
    fn parses_install_signing_and_recovery_kids() {
        let install = kid("install-acme-01:3");
        assert_eq!(install.kind(), KeyKind::InstallSigning);
        assert_eq!(install.key_name(), "install-acme-01");
        assert_eq!(install.install_id(), Some("acme-01"));
        assert_eq!(install.version(), Some(3));
        assert_eq!(install.endpoint_id(), None);

        let recovery = kid("recovery-!~x/y:9007199254740991");
        assert_eq!(recovery.kind(), KeyKind::Recovery);
        assert_eq!(recovery.key_name(), "recovery-!~x/y");
        assert_eq!(recovery.install_id(), Some("!~x/y"));
        assert_eq!(recovery.version(), Some(9_007_199_254_740_991));
    }

    #[test]
    fn parses_vendor_kids() {
        let release = kid("vendor-release-001");
        assert_eq!(release.kind(), KeyKind::Vendor);
        assert_eq!(release.as_str(), "vendor-release-001");
        assert_eq!(release.key_name(), "vendor-release-001");
        assert_eq!(release.vendor_class(), Some(VendorKeyClass::Release));
        assert_eq!(release.vendor_number(), Some("001"));
        assert_eq!(release.version(), None);
        assert_ne!(release, kid("vendor-release-1"));

        let test = kid("vendor-test-2");
        assert_eq!(test.kind(), KeyKind::Vendor);
        assert_eq!(test.vendor_class(), Some(VendorKeyClass::Test));
        assert_eq!(test.vendor_number(), Some("2"));
    }

    #[test]
    fn rejects_kids_outside_the_grammar() {
        let upper = UUID.to_uppercase();
        let simple = UUID.replace('-', "");
        let rejected = [
            format!("endpoint-{upper}:1"),
            format!("endpoint-{{{UUID}}}:1"),
            format!("endpoint-{simple}:1"),
            format!("endpoint-{UUID}:0"),
            format!("endpoint-{UUID}:01"),
            format!("endpoint-{UUID}:9007199254740992"),
            format!("endpoint-{UUID}:18446744073709551616"),
            format!("endpoint-{UUID}:"),
            format!("endpoint-{UUID}"),
            format!("endpoint-{UUID}:+1"),
            format!("endpoint-{UUID}:1:1"),
            format!("endpoint-{UUID}: 1"),
            "install-:1".to_owned(),
            "install-a b:1".to_owned(),
            "install-é:1".to_owned(),
            "recovery-x".to_owned(),
            "vendor-other-1".to_owned(),
            "vendor-release-1:1".to_owned(),
            "vendor-release-".to_owned(),
            "vendor-test-".to_owned(),
            "vendor-release-1a".to_owned(),
            "vendor-1".to_owned(),
            "other-x:1".to_owned(),
            "Endpoint-x:1".to_owned(),
            String::new(),
        ];
        for text in rejected {
            assert!(Kid::parse(&text).is_err(), "{text:?} parsed");
            assert!(Kid::try_from(text.clone()).is_err(), "{text:?} parsed");
        }
    }

    #[test]
    fn equality_is_on_the_whole_string() {
        assert_eq!(kid("install-a:1"), kid("install-a:1"));
        assert_ne!(kid("install-a:1"), kid("install-a:2"));
        assert_ne!(kid("install-a:1"), kid("recovery-a:1"));
    }

    #[test]
    fn round_trips_through_serde() {
        let parsed: Kid = serde_json::from_str("\"install-a:1\"").unwrap();
        assert_eq!(parsed, kid("install-a:1"));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"install-a:1\"");
        assert!(serde_json::from_str::<Kid>("\"install-a:0\"").is_err());
    }
}
