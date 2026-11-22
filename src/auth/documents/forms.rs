//! Field forms of signed document contents that the strict parser's own
//! forms do not cover.
//!
//! Every form checks its rule as it is deserialized, through
//! `deserialize_str` for a string and `deserialize_u64` for an integer, so a
//! value out of rule fails inside [`strict::from_slice`] with the path of the
//! field. Every form is also built only through a constructor that checks the
//! same rule, so a value that serializes always parses back.

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::auth::jws::strict::{self, LowerUuid};
use crate::auth::jws::{KeyKind, Kid};
use crate::auth::tls;

/// The prefix of a customer key name.
const CUSTOMER_KEY_PREFIX: &str = "endpoint-";
/// The longest DNS name, in characters.
const MAX_DNS_NAME_LEN: usize = 253;
/// The longest DNS label, in characters.
const MAX_DNS_LABEL_LEN: usize = 63;

/// Implements `Deserialize` for a type read from one JSON string by
/// `$parse`, which returns `None` for a string out of rule, and `Serialize`
/// as the string its `Display` writes.
macro_rules! string_form {
    ($ty:ty, $expecting:literal, $parse:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct StrVisitor;

                impl Visitor<'_> for StrVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: de::Error>(self, text: &str) -> Result<$ty, E> {
                        let parse: fn(&str) -> Option<$ty> = $parse;
                        parse(text)
                            .ok_or_else(|| E::invalid_value(de::Unexpected::Str(text), &$expecting))
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
    };
}

/// Implements `Display` for a type as the string its `as_str` returns.
macro_rules! display_as_str {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// Implements `Deserialize` for an integer form read by `$new`, which
/// returns `None` for a value out of rule, and `Serialize` as the number.
macro_rules! integer_form {
    ($ty:ty, $expecting:literal) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct U64Visitor;

                impl Visitor<'_> for U64Visitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_u64<E: de::Error>(self, value: u64) -> Result<$ty, E> {
                        <$ty>::new(value).ok_or_else(|| {
                            E::invalid_value(de::Unexpected::Unsigned(value), &$expecting)
                        })
                    }
                }

                deserializer.deserialize_u64(U64Visitor)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_u64(self.get())
            }
        }
    };
}

/// An integer from 0 to 2^53 − 1, the range of every integer in a signed
/// document's content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Integer(u64);

impl Integer {
    /// The largest integer, 2^53 − 1.
    pub const MAX: Self = Self(strict::MAX_INTEGER);

    /// Returns `value` as an integer, or `None` if it is above 2^53 − 1.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= strict::MAX_INTEGER {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u32> for Integer {
    fn from(value: u32) -> Self {
        Self(u64::from(value))
    }
}

impl From<Integer> for u64 {
    fn from(value: Integer) -> Self {
        value.0
    }
}

integer_form!(Integer, "an integer from 0 to 2^53 - 1");

/// An integer from 1 to 2^53 − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositiveInteger(u64);

impl PositiveInteger {
    /// Returns `value` as a positive integer, or `None` if it is 0 or above
    /// 2^53 − 1.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value >= 1 && value <= strict::MAX_INTEGER {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<PositiveInteger> for u64 {
    fn from(value: PositiveInteger) -> Self {
        value.0
    }
}

integer_form!(PositiveInteger, "an integer from 1 to 2^53 - 1");

/// A string of at least one character.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    /// Returns `text` as a non-empty string, or `None` if it is empty.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Option<Self> {
        let text = text.into();
        (!text.is_empty()).then_some(Self(text))
    }

    /// Returns the string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

display_as_str!(NonEmptyString);

string_form!(NonEmptyString, "a non-empty string", |text| {
    NonEmptyString::new(text)
});

/// A JWS carried inside a document's content, as a non-empty string.
///
/// The JWS inside is not checked here; whoever reads it verifies it as a
/// document of its own.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JwsText(String);

impl JwsText {
    /// Returns `jws` as a carried JWS, or `None` if it is empty.
    #[must_use]
    pub fn new(jws: impl Into<String>) -> Option<Self> {
        let jws = jws.into();
        (!jws.is_empty()).then_some(Self(jws))
    }

    /// Returns the JWS string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

display_as_str!(JwsText);

string_form!(JwsText, "a non-empty JWS string", |text| JwsText::new(text));

/// An install id: one or more printable ASCII characters (0x21–0x7E) other
/// than `:`, the `<install id>` of the kid grammar.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstallId(String);

impl InstallId {
    /// Parses an install id, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        is_install_id(text).then(|| Self(text.to_owned()))
    }

    /// Returns the install id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_install_id(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_graphic() && b != b':')
}

display_as_str!(InstallId);

string_form!(
    InstallId,
    "an install id of printable ASCII other than `:`",
    InstallId::parse
);

/// A customer key name, `endpoint-<uuid>` with a lowercase hyphenated UUID.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomerKeyName(LowerUuid);

impl CustomerKeyName {
    /// Parses a customer key name, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        text.strip_prefix(CUSTOMER_KEY_PREFIX)
            .and_then(LowerUuid::parse)
            .map(Self)
    }

    /// Returns the customer key name of the endpoint `endpoint_id`.
    #[must_use]
    pub fn from_endpoint_id(endpoint_id: LowerUuid) -> Self {
        Self(endpoint_id)
    }

    /// Returns the UUID of the name.
    #[must_use]
    pub fn endpoint_id(&self) -> LowerUuid {
        self.0
    }
}

impl fmt::Display for CustomerKeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{CUSTOMER_KEY_PREFIX}{}", self.0.get().hyphenated())
    }
}

string_form!(
    CustomerKeyName,
    "a customer key name `endpoint-<uuid>`",
    CustomerKeyName::parse
);

/// A customer kid, `endpoint-<uuid>:<version>`: a [`Kid`] of kind
/// [`KeyKind::Customer`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomerKid(Kid);

impl CustomerKid {
    /// Returns `kid` as a customer kid, or `None` if it names another kind of
    /// key.
    #[must_use]
    pub fn new(kid: Kid) -> Option<Self> {
        (kid.kind() == KeyKind::Customer).then_some(Self(kid))
    }

    /// Parses a customer kid, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Kid::parse(text).ok().and_then(Self::new)
    }

    /// Returns the kid.
    #[must_use]
    pub fn as_kid(&self) -> &Kid {
        &self.0
    }

    /// Returns the kid string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<CustomerKid> for Kid {
    fn from(kid: CustomerKid) -> Self {
        kid.0
    }
}

display_as_str!(CustomerKid);

string_form!(
    CustomerKid,
    "a customer kid `endpoint-<uuid>:<version>`",
    CustomerKid::parse
);

/// An absolute URL, of any scheme, as the WHATWG URL standard parses it.
///
/// The text may hold no ASCII whitespace or control character: the URL
/// parser would strip them silently, so the URL would not be the text that
/// was signed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsoluteUrl(url::Url);

impl AbsoluteUrl {
    /// Parses an absolute URL, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return None;
        }
        url::Url::parse(text).ok().map(Self)
    }

    /// Returns the URL in the parser's serialization, which may differ from
    /// the text parsed (`HTTP://Example.com` is `http://example.com/`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

display_as_str!(AbsoluteUrl);

string_form!(AbsoluteUrl, "an absolute URL", AbsoluteUrl::parse);

/// A DNS name.
///
/// One to 253 ASCII characters in labels separated by `.`; each label is 1
/// to 63 letters, digits and `-`, and neither starts nor ends with `-`. A
/// trailing `.`, an empty label, `_`, and a last label of digits only
/// (dotted IPv4 included) are rejected. Every name accepted is one rustls
/// accepts as a DNS server name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// Parses a DNS name, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        is_dns_name(text).then(|| Self(text.to_owned()))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_dns_name(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_DNS_NAME_LEN {
        return false;
    }
    let mut last_label = "";
    for label in text.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_DNS_LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !valid {
            return false;
        }
        last_label = label;
    }
    !last_label.bytes().all(|b| b.is_ascii_digit())
}

display_as_str!(DnsName);

string_form!(DnsName, "a DNS name", DnsName::parse);

/// The host of an [`Address`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressHost {
    /// A DNS name.
    Dns(DnsName),
    /// A dotted IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address, written in brackets.
    Ipv6(Ipv6Addr),
}

/// A network address, `<host>:<port>`.
///
/// The host is a [`DnsName`], a dotted IPv4 address, or an IPv6 address in
/// brackets; the port is a decimal number from 1 to 65535 without a leading
/// zero.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    host: AddressHost,
    port: u16,
}

impl Address {
    /// Returns the address of `host` and `port`, or `None` if `port` is 0.
    #[must_use]
    pub fn new(host: AddressHost, port: u16) -> Option<Self> {
        (port != 0).then_some(Self { host, port })
    }

    /// Parses `<host>:<port>`, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (ipv6, port) = rest.split_once("]:")?;
            (AddressHost::Ipv6(ipv6.parse().ok()?), port)
        } else {
            let (host, port) = text.rsplit_once(':')?;
            let host = match DnsName::parse(host) {
                Some(name) => AddressHost::Dns(name),
                None => AddressHost::Ipv4(host.parse().ok()?),
            };
            (host, port)
        };
        let port_ok =
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !port.starts_with('0');
        if !port_ok {
            return None;
        }
        Self::new(host, port.parse().ok()?)
    }

    /// Returns the host.
    #[must_use]
    pub fn host(&self) -> &AddressHost {
        &self.host
    }

    /// Returns the port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            AddressHost::Dns(name) => write!(f, "{}:{}", name.as_str(), self.port),
            AddressHost::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            AddressHost::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

string_form!(Address, "an address `<host>:<port>`", Address::parse);

/// PEM holding one or more `CERTIFICATE` blocks, as one trust root element.
///
/// The rule is the one [`tls::endpoint_client_config`] reads each trust
/// root with: well-formed PEM, at least one block, and every block a
/// `CERTIFICATE` whose body is base64. Text outside the blocks is ignored,
/// and lines may end at CRLF, CR or LF. Whether a certificate can be a trust
/// anchor is not looked at; the TLS configuration decides that.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificatePem(String);

impl CertificatePem {
    /// Checks `pem` as a trust root element, or returns `None`.
    #[must_use]
    pub fn parse(pem: &str) -> Option<Self> {
        tls::pem_certificates(pem)
            .is_ok()
            .then(|| Self(pem.to_owned()))
    }

    /// Returns the PEM text as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CertificatePem {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

display_as_str!(CertificatePem);

string_form!(
    CertificatePem,
    "PEM of one or more CERTIFICATE blocks",
    CertificatePem::parse
);

/// A SemVer 2.0.0 version.
///
/// Two versions are equal when their strings are, build metadata included.
/// [`SemVer::cmp_precedence`] orders them by SemVer precedence, in which
/// build metadata takes no part: `1.0.0-rc.1` comes before `1.0.0`, and
/// `1.0.0+a` and `1.0.0+b` have the same precedence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SemVer(semver::Version);

impl SemVer {
    /// Parses a SemVer 2.0.0 version, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        semver::Version::parse(text).ok().map(Self)
    }

    /// Compares two versions by SemVer precedence, ignoring build metadata.
    #[must_use]
    pub fn cmp_precedence(&self, other: &Self) -> Ordering {
        self.0.cmp_precedence(&other.0)
    }

    /// Returns the major version.
    #[must_use]
    pub fn major(&self) -> u64 {
        self.0.major
    }

    /// Returns the minor version.
    #[must_use]
    pub fn minor(&self) -> u64 {
        self.0.minor
    }

    /// Returns the patch version.
    #[must_use]
    pub fn patch(&self) -> u64 {
        self.0.patch
    }

    /// Returns the pre-release identifiers, empty when there are none.
    #[must_use]
    pub fn pre(&self) -> &str {
        self.0.pre.as_str()
    }

    /// Returns the build metadata, empty when there is none.
    #[must_use]
    pub fn build(&self) -> &str {
        self.0.build.as_str()
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

string_form!(SemVer, "a SemVer 2.0.0 version", SemVer::parse);

/// An event kind number from 1 to 65535, written as a map key in decimal
/// without a leading zero.
///
/// Whether the kind is in the registry is not looked at, so a kind added by
/// a later version is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KindNumber(u16);

impl KindNumber {
    /// Returns `kind` as a kind number, or `None` if it is 0.
    #[must_use]
    pub const fn new(kind: u16) -> Option<Self> {
        if kind == 0 { None } else { Some(Self(kind)) }
    }

    /// Parses a decimal kind number without a leading zero, or returns
    /// `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits_ok =
            !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && !text.starts_with('0');
        if !digits_ok {
            return None;
        }
        Self::new(text.parse().ok()?)
    }

    /// Returns the kind number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for KindNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

string_form!(
    KindNumber,
    "a kind number from 1 to 65535 in decimal",
    KindNumber::parse
);
