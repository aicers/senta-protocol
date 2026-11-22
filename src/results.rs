//! Result enums shared by the trust state machines and the control channel.
//!
//! [`DocumentResult`] is what applying a signed document comes to,
//! [`CommandResultKind`] what running a command comes to, and
//! [`InstallConfigFailure`] why verifying an install configuration failed.
//! They belong to no feature, so this module is always public.
//!
//! # CBOR shape
//!
//! Each enum is tagged by a text string, and its shape holds across
//! versions of this crate that know different sets of tags:
//!
//! - A variant without content is its tag as a text string, `"applied"`.
//! - A variant with content is a map of exactly one entry, the tag mapped
//!   to the content: `{"keyset_gap": {"have_epoch": 3, "have_version": 7}}`.
//!   A field map's keys are its field names; `u64` is an unsigned integer
//!   and `String` a text string. The order of the fields is not part of
//!   the contract, and a decoder takes them in any order.
//! - `Other(s)` is the text string `s`.
//!
//! Decoding is lenient where a newer peer may have added something and
//! strict everywhere else:
//!
//! - A tag this crate does not know becomes `Other(tag)`, whether it comes
//!   as text or as a one-entry map; a map's content is then discarded,
//!   whatever its type, a bignum of any size included. The one exception
//!   is a simple value other than `false`, `true`, `null` and `undefined`,
//!   anywhere in the content: ciborium's deserializer hands none to serde
//!   on any path, so it fails decoding, as it fails decoding ciborium's
//!   own `Value`.
//! - A field this crate does not know is ignored.
//! - A known tag without content that comes as a map decodes to its
//!   variant, discarding the content.
//! - A known tag that needs content but comes as text, a field map with a
//!   missing or mistyped field, a map with no entry or more than one, a
//!   map key that is not text where a tag or field name is expected, and
//!   any value that is neither text nor a map are errors.
//! - A map in which the same key appears twice is an error at any depth,
//!   including inside content that is discarded or ignored. Keys compare
//!   as CBOR values: an integer by its numeric value, whether it comes as
//!   a plain integer or as a bignum (tags 2 and 3) of any length and with
//!   any leading zeros, a text or byte string by its contents, a float by
//!   the bit pattern of its value whatever width it was encoded at (the
//!   width is not part of the CBOR data model, RFC 8949 section 2), so
//!   `0.0` and `-0.0` differ but a half and a double `1.5` are the same
//!   key, arrays and maps element by element in order, and
//!   any other tagged value by its tag number and then its value. An
//!   integer never equals a float, nor a text string a byte string.
//!
//! Decoding never yields `Other` for a tag the enum knows, so `Other(s)`
//! survives a round trip only when `s` is not one of the enum's tags.

use std::{borrow::Cow, collections::BTreeSet, convert::Infallible, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{
        self, DeserializeSeed, EnumAccess, IgnoredAny, MapAccess, SeqAccess, VariantAccess, Visitor,
    },
    ser::SerializeMap,
};

const APPLIED: &str = "applied";
const DUPLICATE: &str = "duplicate";
const STALE: &str = "stale";
const CONFLICT: &str = "conflict";
const EPOCH_MISMATCH: &str = "epoch_mismatch";
const WRONG_TARGET: &str = "wrong_target";
const BAD_SIGNATURE: &str = "bad_signature";
const UNKNOWN_KID: &str = "unknown_kid";
const REVOKED_KID: &str = "revoked_kid";
const WRONG_KEY_CLASS: &str = "wrong_key_class";
const SCHEMA_ERROR: &str = "schema_error";
const EXPIRED: &str = "expired";
const NOT_YET_VALID: &str = "not_yet_valid";
const KEYSET_GAP: &str = "keyset_gap";
const RECOVERY_KEY_GAP: &str = "recovery_key_gap";
const APPLY_FAILED: &str = "apply_failed";

const DONE: &str = "done";
const ALREADY_DONE: &str = "already_done";
const FAILED: &str = "failed";
const REJECTED: &str = "rejected";

const DEPLOYMENT_CERT_INVALID: &str = "deployment_cert_invalid";
const UNTRUSTED_VENDOR_KEY: &str = "untrusted_vendor_key";
const INSTALL_CONFIG_INVALID: &str = "install_config_invalid";
const INSTALL_ID_MISMATCH: &str = "install_id_mismatch";
const KEYSET_INVALID: &str = "keyset_invalid";
const ADDRESSES_INVALID: &str = "addresses_invalid";
const ENROLL_TOKEN_INVALID: &str = "enroll_token_invalid";

const HAVE_EPOCH: &str = "have_epoch";
const HAVE_VERSION: &str = "have_version";
const HAVE: &str = "have";
const REASON: &str = "reason";

/// The outcome of receiving a signed document.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentResult {
    /// The document was applied.
    Applied,
    /// The document is a retry of the version already verified, with the
    /// same content, and has been applied.
    Duplicate,
    /// The document's version is below the version already verified.
    Stale,
    /// The document has the version already verified but different content.
    Conflict,
    /// The document's recovery epoch is not the current one.
    EpochMismatch,
    /// The document is addressed to another endpoint.
    WrongTarget,
    /// The document's signature does not verify.
    BadSignature,
    /// The document was signed by a key the receiver does not know.
    UnknownKid,
    /// The document was signed by a revoked key.
    RevokedKid,
    /// The document was signed by a key of the wrong class for its type.
    WrongKeyClass,
    /// The document's content does not match its schema.
    SchemaError,
    /// The document's validity window has passed.
    Expired,
    /// The document's validity window has not begun.
    NotYetValid,
    /// The key set skips past the next version after the one the receiver
    /// has.
    KeysetGap {
        /// The recovery epoch of the key set the receiver has.
        have_epoch: u64,
        /// The version, within that epoch, of the key set the receiver has.
        have_version: u64,
    },
    /// The recovery key replacement skips past the next version after the
    /// one the receiver has.
    RecoveryKeyGap {
        /// The recovery key version the receiver has.
        have: u64,
    },
    /// The document was verified but applying it failed.
    ApplyFailed {
        /// Why applying it failed.
        reason: String,
    },
    /// A result this version of the crate does not know, by its tag.
    Other(String),
}

/// The outcome of running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandResultKind {
    /// The command ran to completion.
    Done,
    /// The command had already run, and its stored result stands.
    AlreadyDone,
    /// The command ran and failed.
    Failed {
        /// Why the command failed.
        reason: String,
    },
    /// The signed command was rejected, for the reason given.
    Rejected(DocumentResult),
    /// A result this version of the crate does not know, by its tag.
    Other(String),
}

/// The reason verifying an install configuration failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallConfigFailure {
    /// The deployment certificate is invalid.
    DeploymentCertInvalid,
    /// The vendor key is not trusted.
    UntrustedVendorKey,
    /// The install configuration is invalid.
    InstallConfigInvalid,
    /// The install identifier does not match.
    InstallIdMismatch,
    /// The key set is invalid.
    KeysetInvalid,
    /// The addresses are invalid.
    AddressesInvalid,
    /// The enrollment token is invalid.
    EnrollTokenInvalid,
    /// A failure this version of the crate does not know, by its tag.
    Other(String),
}

impl Serialize for DocumentResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Applied => APPLIED,
            Self::Duplicate => DUPLICATE,
            Self::Stale => STALE,
            Self::Conflict => CONFLICT,
            Self::EpochMismatch => EPOCH_MISMATCH,
            Self::WrongTarget => WRONG_TARGET,
            Self::BadSignature => BAD_SIGNATURE,
            Self::UnknownKid => UNKNOWN_KID,
            Self::RevokedKid => REVOKED_KID,
            Self::WrongKeyClass => WRONG_KEY_CLASS,
            Self::SchemaError => SCHEMA_ERROR,
            Self::Expired => EXPIRED,
            Self::NotYetValid => NOT_YET_VALID,
            Self::KeysetGap {
                have_epoch,
                have_version,
            } => {
                return serialize_entry(
                    serializer,
                    KEYSET_GAP,
                    &U64Fields(&[(HAVE_EPOCH, *have_epoch), (HAVE_VERSION, *have_version)]),
                );
            }
            Self::RecoveryKeyGap { have } => {
                return serialize_entry(serializer, RECOVERY_KEY_GAP, &U64Fields(&[(HAVE, *have)]));
            }
            Self::ApplyFailed { reason } => {
                return serialize_entry(serializer, APPLY_FAILED, &ReasonFields(reason));
            }
            Self::Other(tag) => tag,
        };
        serializer.serialize_str(tag)
    }
}

impl Serialize for CommandResultKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Done => serializer.serialize_str(DONE),
            Self::AlreadyDone => serializer.serialize_str(ALREADY_DONE),
            Self::Failed { reason } => serialize_entry(serializer, FAILED, &ReasonFields(reason)),
            Self::Rejected(result) => serialize_entry(serializer, REJECTED, result),
            Self::Other(tag) => serializer.serialize_str(tag),
        }
    }
}

impl Serialize for InstallConfigFailure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::DeploymentCertInvalid => DEPLOYMENT_CERT_INVALID,
            Self::UntrustedVendorKey => UNTRUSTED_VENDOR_KEY,
            Self::InstallConfigInvalid => INSTALL_CONFIG_INVALID,
            Self::InstallIdMismatch => INSTALL_ID_MISMATCH,
            Self::KeysetInvalid => KEYSET_INVALID,
            Self::AddressesInvalid => ADDRESSES_INVALID,
            Self::EnrollTokenInvalid => ENROLL_TOKEN_INVALID,
            Self::Other(tag) => tag,
        })
    }
}

/// Serializes a variant with content as the one-entry map `{tag: content}`.
fn serialize_entry<S: Serializer, V: Serialize + ?Sized>(
    serializer: S,
    tag: &str,
    content: &V,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry(tag, content)?;
    map.end()
}

/// A field map whose fields are all `u64`.
struct U64Fields<'a>(&'a [(&'static str, u64)]);

impl Serialize for U64Fields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

/// The field map `{"reason": reason}`.
struct ReasonFields<'a>(&'a str);

impl Serialize for ReasonFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(REASON, self.0)?;
        map.end()
    }
}

/// What a tag names in one of the enums.
enum Class<T: Tagged> {
    /// A variant without content.
    Unit(T),
    /// A variant whose content has to be read.
    Content(T::Content),
    /// A tag the enum does not know.
    Unknown,
}

/// The decoding side of an enum tagged by a text string.
trait Tagged: Sized {
    /// The variants with content, read by [`Tagged::read_content`].
    type Content;

    /// What the enum's decoder expects, for error messages.
    const EXPECTING: &'static str;

    /// Returns what `tag` names in this enum.
    fn classify(tag: &str) -> Class<Self>;

    /// Reads the content of a variant from the value of the map entry
    /// whose key has just been read.
    fn read_content<'de, A: MapAccess<'de>>(
        content: Self::Content,
        map: &mut A,
    ) -> Result<Self, A::Error>;

    /// Returns the `Other` variant holding `tag`.
    fn other(tag: String) -> Self;
}

/// The variants of [`DocumentResult`] with content.
enum DocumentContent {
    KeysetGap,
    RecoveryKeyGap,
    ApplyFailed,
}

impl Tagged for DocumentResult {
    type Content = DocumentContent;

    const EXPECTING: &'static str = "a document result tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            APPLIED => Self::Applied,
            DUPLICATE => Self::Duplicate,
            STALE => Self::Stale,
            CONFLICT => Self::Conflict,
            EPOCH_MISMATCH => Self::EpochMismatch,
            WRONG_TARGET => Self::WrongTarget,
            BAD_SIGNATURE => Self::BadSignature,
            UNKNOWN_KID => Self::UnknownKid,
            REVOKED_KID => Self::RevokedKid,
            WRONG_KEY_CLASS => Self::WrongKeyClass,
            SCHEMA_ERROR => Self::SchemaError,
            EXPIRED => Self::Expired,
            NOT_YET_VALID => Self::NotYetValid,
            KEYSET_GAP => return Class::Content(DocumentContent::KeysetGap),
            RECOVERY_KEY_GAP => return Class::Content(DocumentContent::RecoveryKeyGap),
            APPLY_FAILED => return Class::Content(DocumentContent::ApplyFailed),
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: DocumentContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        Ok(match content {
            DocumentContent::KeysetGap => {
                let KeysetGapFields {
                    have_epoch,
                    have_version,
                } = map.next_value()?;
                Self::KeysetGap {
                    have_epoch,
                    have_version,
                }
            }
            DocumentContent::RecoveryKeyGap => {
                let HaveFields { have } = map.next_value()?;
                Self::RecoveryKeyGap { have }
            }
            DocumentContent::ApplyFailed => {
                let ReasonFieldsOwned { reason } = map.next_value()?;
                Self::ApplyFailed { reason }
            }
        })
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

/// The variants of [`CommandResultKind`] with content.
enum CommandContent {
    Failed,
    Rejected,
}

impl Tagged for CommandResultKind {
    type Content = CommandContent;

    const EXPECTING: &'static str = "a command result tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        match tag {
            DONE => Class::Unit(Self::Done),
            ALREADY_DONE => Class::Unit(Self::AlreadyDone),
            FAILED => Class::Content(CommandContent::Failed),
            REJECTED => Class::Content(CommandContent::Rejected),
            _ => Class::Unknown,
        }
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: CommandContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        Ok(match content {
            CommandContent::Failed => {
                let ReasonFieldsOwned { reason } = map.next_value()?;
                Self::Failed { reason }
            }
            CommandContent::Rejected => Self::Rejected(map.next_value()?),
        })
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl Tagged for InstallConfigFailure {
    type Content = Infallible;

    const EXPECTING: &'static str =
        "an install configuration failure tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            DEPLOYMENT_CERT_INVALID => Self::DeploymentCertInvalid,
            UNTRUSTED_VENDOR_KEY => Self::UntrustedVendorKey,
            INSTALL_CONFIG_INVALID => Self::InstallConfigInvalid,
            INSTALL_ID_MISMATCH => Self::InstallIdMismatch,
            KEYSET_INVALID => Self::KeysetInvalid,
            ADDRESSES_INVALID => Self::AddressesInvalid,
            ENROLL_TOKEN_INVALID => Self::EnrollTokenInvalid,
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: Infallible,
        _map: &mut A,
    ) -> Result<Self, A::Error> {
        match content {}
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl<'de> Deserialize<'de> for DocumentResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

impl<'de> Deserialize<'de> for CommandResultKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

impl<'de> Deserialize<'de> for InstallConfigFailure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

/// Decodes one of the tagged enums from text or a one-entry map.
struct TaggedVisitor<T>(PhantomData<T>);

impl<T: Tagged> TaggedVisitor<T> {
    fn from_text<E: de::Error>(tag: Cow<'_, str>) -> Result<T, E> {
        match T::classify(&tag) {
            Class::Unit(value) => Ok(value),
            Class::Content(_) => Err(E::invalid_value(
                de::Unexpected::Str(&tag),
                &"a tag without content; this one needs a one-entry map",
            )),
            Class::Unknown => Ok(T::other(tag.into_owned())),
        }
    }
}

impl<'de, T: Tagged> Visitor<'de> for TaggedVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(T::EXPECTING)
    }

    fn visit_str<E: de::Error>(self, tag: &str) -> Result<T, E> {
        Self::from_text(Cow::Borrowed(tag))
    }

    fn visit_string<E: de::Error>(self, tag: String) -> Result<T, E> {
        Self::from_text(Cow::Owned(tag))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
        let Some(tag) = map.next_key_seed(TextKey)? else {
            return Err(de::Error::invalid_length(0, &self));
        };
        let value = match T::classify(&tag) {
            Class::Content(content) => T::read_content(content, &mut map)?,
            Class::Unit(value) => {
                map.next_value_seed(CheckedIgnore)?;
                value
            }
            Class::Unknown => {
                map.next_value_seed(CheckedIgnore)?;
                T::other(tag)
            }
        };
        if map.next_key::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(
                "expected a map with exactly one entry, found more",
            ));
        }
        Ok(value)
    }
}

/// The field map of [`DocumentResult::KeysetGap`].
struct KeysetGapFields {
    have_epoch: u64,
    have_version: u64,
}

impl<'de> Deserialize<'de> for KeysetGapFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = KeysetGapFields;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with the fields `have_epoch` and `have_version`")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let mut have_epoch = None;
                let mut have_version = None;
                read_fields(map, |name, map| {
                    match name {
                        HAVE_EPOCH => have_epoch = Some(map.next_value()?),
                        HAVE_VERSION => have_version = Some(map.next_value()?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                Ok(KeysetGapFields {
                    have_epoch: have_epoch.ok_or_else(|| de::Error::missing_field(HAVE_EPOCH))?,
                    have_version: have_version
                        .ok_or_else(|| de::Error::missing_field(HAVE_VERSION))?,
                })
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

/// The field map of [`DocumentResult::RecoveryKeyGap`].
struct HaveFields {
    have: u64,
}

impl<'de> Deserialize<'de> for HaveFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = HaveFields;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with the field `have`")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let mut have = None;
                read_fields(map, |name, map| {
                    if name != HAVE {
                        return Ok(false);
                    }
                    have = Some(map.next_value()?);
                    Ok(true)
                })?;
                Ok(HaveFields {
                    have: have.ok_or_else(|| de::Error::missing_field(HAVE))?,
                })
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

/// The field map `{"reason": ...}`, as decoded.
struct ReasonFieldsOwned {
    reason: String,
}

impl<'de> Deserialize<'de> for ReasonFieldsOwned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = ReasonFieldsOwned;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with the field `reason`")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let mut reason = None;
                read_fields(map, |name, map| {
                    if name != REASON {
                        return Ok(false);
                    }
                    reason = Some(map.next_value()?);
                    Ok(true)
                })?;
                Ok(ReasonFieldsOwned {
                    reason: reason.ok_or_else(|| de::Error::missing_field(REASON))?,
                })
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

/// Walks a field map whose keys must be text and must not repeat.
///
/// `known` is handed each field name; it reads the value and returns
/// `true` for a field it knows, and returns `false` without reading for
/// one it does not, whose value is then checked and discarded.
fn read_fields<'de, A, F>(mut map: A, mut known: F) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
    F: FnMut(&str, &mut A) -> Result<bool, A::Error>,
{
    let mut seen = BTreeSet::new();
    while let Some(name) = map.next_key_seed(TextKey)? {
        if seen.contains(&name) {
            return Err(de::Error::custom(format_args!("duplicate field `{name}`")));
        }
        if !known(&name, &mut map)? {
            map.next_value_seed(CheckedIgnore)?;
        }
        seen.insert(name);
    }
    Ok(())
}

/// Reads a map key that has to be a text string.
struct TextKey;

impl<'de> DeserializeSeed<'de> for TextKey {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl Visitor<'_> for TextKey {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a text map key")
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<String, E> {
        Ok(key.to_owned())
    }

    fn visit_string<E: de::Error>(self, key: String) -> Result<String, E> {
        Ok(key)
    }
}

/// A CBOR value held as a map key, to tell whether two keys are the same.
///
/// An integer is held by its numeric value however it was encoded: a
/// plain integer and a bignum (tags 2 and 3) of any length, leading zeros
/// included, that come to the same number are the same key.
///
/// The derived order is what a [`BTreeSet`] needs and means nothing else.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// An unsigned integer up to `u128::MAX`.
    Unsigned(u128),
    /// A negative integer `-1 - n` with `n` up to `u128::MAX`, held as `n`,
    /// as CBOR encodes it.
    Negative(u128),
    /// An unsigned integer past `u128::MAX`, as big-endian bytes without
    /// leading zeros.
    BigUnsigned(Vec<u8>),
    /// A negative integer `-1 - n` with `n` past `u128::MAX`, held as `n`
    /// in big-endian bytes without leading zeros.
    BigNegative(Vec<u8>),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Key>),
    Map(Vec<(Key, Key)>),
    /// A float by the bit pattern of its value as an `f64`, which every
    /// width it may be encoded at widens to exactly.
    Float(u64),
    Bool(bool),
    Null,
    /// A tagged value other than a bignum: the tag, then the value.
    Tagged(u64, Box<Key>),
}

impl Key {
    fn signed(value: i128) -> Self {
        match u128::try_from(value) {
            Ok(value) => Self::Unsigned(value),
            // `!value` is `-1 - value`, which is non-negative here.
            Err(_) => Self::Negative((!value).unsigned_abs()),
        }
    }

    /// Returns the integer a bignum's magnitude bytes encode: `n` for tag 2,
    /// `-1 - n` for tag 3.
    fn bignum(negative: bool, mut digits: Vec<u8>) -> Self {
        let leading_zeros = digits.iter().take_while(|&&b| b == 0).count();
        digits.drain(..leading_zeros);
        if digits.len() > U128_BYTES {
            return if negative {
                Self::BigNegative(digits)
            } else {
                Self::BigUnsigned(digits)
            };
        }
        let value = digits
            .iter()
            .fold(0, |value, &digit| (value << 8) | u128::from(digit));
        if negative {
            Self::Negative(value)
        } else {
            Self::Unsigned(value)
        }
    }
}

/// The number of bytes in a `u128`.
const U128_BYTES: usize = 16;

/// Inserts `key` into the keys of a map seen so far, failing if it is
/// already there.
fn insert_key<E: de::Error>(seen: &mut BTreeSet<Key>, key: Key) -> Result<(), E> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(E::custom("duplicate map key"))
    }
}

/// The enum name by which ciborium reads a CBOR tag through serde.
///
/// Asked for an enum of this name, ciborium's deserializer, and its
/// `Value`'s, yields the variant [`CIBORIUM_TAGGED`], whose two-element
/// tuple is the tag number and the tagged value, or [`CIBORIUM_UNTAGGED`],
/// whose newtype is the value itself. Only through it does a bignum reach
/// a visitor as its bytes: `deserialize_any` turns a bignum of up to 16
/// bytes into an integer first, and fails on a negative one below
/// `i128::MIN`.
const CIBORIUM_TAG: &str = "@@TAG@@";
const CIBORIUM_TAGGED: &str = "@@TAGGED@@";
const CIBORIUM_UNTAGGED: &str = "@@UNTAGGED@@";
const CIBORIUM_TAG_VARIANTS: &[&str] = &[CIBORIUM_UNTAGGED, CIBORIUM_TAGGED];

/// The CBOR tag of an unsigned bignum.
const TAG_POSITIVE_BIGNUM: u64 = 2;
/// The CBOR tag of a negative bignum.
const TAG_NEGATIVE_BIGNUM: u64 = 3;

/// A reader of any CBOR value, tags included, that rejects a map with a
/// repeated key at any depth.
trait AnyValue: Copy {
    type Value;

    /// Reads a value that is not tagged.
    fn untagged<'de, D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error>;

    /// Combines a tag number with the tagged value, read by `self`.
    fn tagged(self, tag: u64, value: Self::Value) -> Self::Value;

    /// Reads a value, tagged or not.
    fn read<'de, D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_enum(CIBORIUM_TAG, CIBORIUM_TAG_VARIANTS, TagVisitor(self))
    }
}

/// Tells a tagged value from an untagged one by ciborium's tag protocol.
struct TagVisitor<R>(R);

impl<'de, R: AnyValue> Visitor<'de> for TagVisitor<R> {
    type Value = R::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any CBOR value")
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<R::Value, A::Error> {
        let (tagged, access) = data.variant_seed(TagVariant)?;
        if tagged {
            access.tuple_variant(2, TagAndValue(self.0))
        } else {
            access.newtype_variant_seed(Untagged(self.0))
        }
    }
}

/// Reads the variant of ciborium's tag protocol, `true` for a tagged value.
struct TagVariant;

impl<'de> DeserializeSeed<'de> for TagVariant {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}

impl Visitor<'_> for TagVariant {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("ciborium's tag variant")
    }

    fn visit_str<E: de::Error>(self, variant: &str) -> Result<bool, E> {
        match variant {
            CIBORIUM_TAGGED => Ok(true),
            CIBORIUM_UNTAGGED => Ok(false),
            _ => Err(E::unknown_variant(variant, CIBORIUM_TAG_VARIANTS)),
        }
    }
}

/// Reads a tagged value as its tag number, then the value.
struct TagAndValue<R>(R);

impl<'de, R: AnyValue> Visitor<'de> for TagAndValue<R> {
    type Value = R::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a tag number and a tagged value")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<R::Value, A::Error> {
        let tag: u64 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let value = seq
            .next_element_seed(Any(self.0))?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        Ok(self.0.tagged(tag, value))
    }
}

/// Reads a value, tagged or not, with `R`.
struct Any<R>(R);

impl<'de, R: AnyValue> DeserializeSeed<'de> for Any<R> {
    type Value = R::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<R::Value, D::Error> {
        self.0.read(deserializer)
    }
}

/// Reads a value known not to be tagged with `R`.
struct Untagged<R>(R);

impl<'de, R: AnyValue> DeserializeSeed<'de> for Untagged<R> {
    type Value = R::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<R::Value, D::Error> {
        self.0.untagged(deserializer)
    }
}

/// Reads any value as a [`Key`].
#[derive(Clone, Copy)]
struct KeyReader;

impl AnyValue for KeyReader {
    type Value = Key;

    fn untagged<'de, D: Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        deserializer.deserialize_any(KeyVisitor)
    }

    fn tagged(self, tag: u64, value: Key) -> Key {
        match (tag, value) {
            (TAG_POSITIVE_BIGNUM, Key::Bytes(magnitude)) => Key::bignum(false, magnitude),
            (TAG_NEGATIVE_BIGNUM, Key::Bytes(magnitude)) => Key::bignum(true, magnitude),
            (tag, value) => Key::Tagged(tag, Box::new(value)),
        }
    }
}

/// Reads an untagged value as a [`Key`].
struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any CBOR value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Key, E> {
        Ok(Key::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Key, E> {
        Ok(Key::signed(i128::from(v)))
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Key, E> {
        Ok(Key::signed(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Key, E> {
        Ok(Key::Unsigned(u128::from(v)))
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Key, E> {
        Ok(Key::Unsigned(v))
    }

    fn visit_f32<E: de::Error>(self, v: f32) -> Result<Key, E> {
        Ok(Key::Float(f64::from(v).to_bits()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Key, E> {
        Ok(Key::Float(v.to_bits()))
    }

    fn visit_char<E: de::Error>(self, v: char) -> Result<Key, E> {
        Ok(Key::Text(v.to_string()))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Key, E> {
        Ok(Key::Text(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Key, E> {
        Ok(Key::Text(v))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Key, E> {
        Ok(Key::Bytes(v.to_owned()))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Key, E> {
        Ok(Key::Bytes(v))
    }

    fn visit_none<E: de::Error>(self) -> Result<Key, E> {
        Ok(Key::Null)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Key, E> {
        Ok(Key::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        KeyReader.read(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        KeyReader.read(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Key, A::Error> {
        let mut elements = Vec::new();
        while let Some(element) = seq.next_element_seed(Any(KeyReader))? {
            elements.push(element);
        }
        Ok(Key::Array(elements))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Key, A::Error> {
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key_seed(Any(KeyReader))? {
            insert_key(&mut seen, key.clone())?;
            let value = map.next_value_seed(Any(KeyReader))?;
            entries.push((key, value));
        }
        Ok(Key::Map(entries))
    }
}

/// Discards any value, tags and bignums of any size included, after
/// rejecting a map with a repeated key at any depth within it. Map keys
/// may be of any type.
///
/// A simple value other than `false`, `true`, `null` and `undefined`
/// still fails: ciborium's deserializer reports it as an error on every
/// path, before any visitor sees it.
#[derive(Clone, Copy)]
struct CheckedIgnore;

impl<'de> DeserializeSeed<'de> for CheckedIgnore {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.read(deserializer)
    }
}

impl AnyValue for CheckedIgnore {
    type Value = ();

    fn untagged<'de, D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(IgnoreVisitor)
    }

    fn tagged(self, _: u64, (): ()) {}
}

/// Discards an untagged value, checking the maps within it.
struct IgnoreVisitor;

impl<'de> Visitor<'de> for IgnoreVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any CBOR value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_char<E: de::Error>(self, _: char) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        CheckedIgnore.read(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        CheckedIgnore.read(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(CheckedIgnore)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key_seed(Any(KeyReader))? {
            insert_key(&mut seen, key)?;
            map.next_value_seed(CheckedIgnore)?;
        }
        Ok(())
    }
}
