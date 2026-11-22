//! Strict JSON parsing for the contents of signed documents.
//!
//! [`from_slice`] reads one UTF-8 JSON object into a content type that
//! derives [`serde::Deserialize`], and rejects, as a [`SchemaError`] naming
//! where the rule was broken:
//!
//! - a top-level value that is not an object, trailing data, and malformed
//!   UTF-8;
//! - a key the content type does not define, at any depth. Keys are matched
//!   exactly, so `groupId` and `Group_id` are unknown keys for a `group_id`
//!   field. Keys of a map-typed field are data and are not held to field
//!   naming;
//! - a missing required field;
//! - an object, a map-typed field's included, that repeats a key at any
//!   depth, keys compared after JSON unescaping;
//! - a number, at any depth, that is not an integer from 0 to 2^53 − 1
//!   written without a sign, fraction or exponent (`1.0`, `1e3` and `-1` are
//!   all rejected);
//! - an explicit `null` for an [`Option`] field, which is optional only by
//!   being left out. A field that has to tell `null` apart from a value and
//!   from absence uses [`Nullable`];
//! - a struct written as a JSON array.
//!
//! Content types write fields as their snake_case Rust names (lowercase
//! ASCII letters, digits and `_`); a field renamed to anything else fails
//! every parse. Times are [`UtcTimestamp`], UUIDs [`LowerUuid`], and bytes
//! [`Base64UrlBytes`] or, at a fixed length, [`Base64UrlArray`]. A map's
//! keys reach its key type as strings, so the key type reads from a string
//! (a `String`, a UUID, a [`super::Kid`], an enum of unit variants), not
//! from a number.
//!
//! A field's `#[serde(alias)]` names are further names it is read under,
//! held to the same snake_case rule. Content types must not use
//! `#[serde(flatten)]`, an internally tagged (`#[serde(tag = "...")]`),
//! adjacently tagged (`#[serde(tag = "...", content = "...")]`) or
//! `#[serde(untagged)]` enum, nor a field type that takes any JSON, such as
//! `serde_json::Value` or `serde::de::IgnoredAny`. Serde reads those
//! without a schema, buffering the content before handing it to the target
//! type out of reach of the field rules here, so a value it would read that
//! way is rejected as a [`SchemaError`] rather than let through unchecked:
//! a flattened field fails on any key it would receive, and the others on
//! every input. An externally tagged enum, serde's default, is held to
//! every rule.

mod de;
mod shape;

use std::fmt;
use std::marker::PhantomData;

use serde::de::{DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use self::de::{NULLABLE, Path, Recorder, Strict};
use self::shape::Node;
use super::b64;

/// The largest integer accepted, 2^53 − 1, the largest every JSON
/// implementation represents exactly.
pub(crate) const MAX_INTEGER: u64 = (1 << 53) - 1;

/// A content that breaks the strict JSON rules or its content type's schema.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message} (at {path})")]
pub struct SchemaError {
    path: String,
    message: String,
}

impl SchemaError {
    /// Returns where the error arose, as a path from the root `$`, such as
    /// `$.sources[2]` or `$.channels["a b"]`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns what was wrong, including the line and column where the JSON
    /// parser stood.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Parses a signed document's content into `T` under the strict JSON rules
/// of this module.
///
/// # Errors
///
/// Returns [`SchemaError`] when `content` is not a single UTF-8 JSON object
/// that follows the rules in the [module documentation](self), or does not
/// match `T`.
pub fn from_slice<T: DeserializeOwned>(content: &[u8]) -> Result<T, SchemaError> {
    let rec = Recorder::default();
    let fail = |error: serde_json::Error| SchemaError {
        path: rec.take().unwrap_or_else(|| Path::Root.to_string()),
        message: error.to_string(),
    };

    // The shape first, independently of `T`: one object, no repeated key and
    // no number out of rule at any depth, whatever `T` reads or skips.
    let mut shape = serde_json::Deserializer::from_slice(content);
    shape
        .deserialize_map(Node::new(&Path::Root, &rec))
        .map_err(fail)?;
    shape.end().map_err(fail)?;

    let mut typed = serde_json::Deserializer::from_slice(content);
    let value = T::deserialize(Strict::new(&mut typed, &Path::Root, &rec)).map_err(fail)?;
    typed.end().map_err(fail)?;
    Ok(value)
}

/// A field that tells an explicit `null` apart from a value and from
/// absence.
///
/// Mark the field `#[serde(default)]` to make it optional, so that a
/// missing field reads as [`Nullable::Absent`]; without it, the field is
/// required and is either `null` or a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Nullable<T> {
    /// The field was left out.
    #[default]
    Absent,
    /// The field was an explicit `null`.
    Null,
    /// The field had a value.
    Value(T),
}

impl<T> Nullable<T> {
    /// Returns whether the field was left out, for
    /// `#[serde(skip_serializing_if = "Nullable::is_absent")]`.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// Returns the value, if there was one.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Absent | Self::Null => None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NullableVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for NullableVisitor<T> {
            type Value = Nullable<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("null or a value")
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Nullable<T>, D::Error> {
                deserializer.deserialize_option(self)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Nullable<T>, E> {
                Ok(Nullable::Null)
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Nullable<T>, D::Error> {
                T::deserialize(deserializer).map(Nullable::Value)
            }
        }

        deserializer.deserialize_newtype_struct(NULLABLE, NullableVisitor(PhantomData))
    }
}

impl<T: Serialize> Serialize for Nullable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Absent | Self::Null => serializer.serialize_none(),
            Self::Value(value) => serializer.serialize_some(value),
        }
    }
}

/// Implements `Deserialize` for a type read from one JSON string by
/// `$parse`, which returns `None` for a string out of rule.
macro_rules! deserialize_from_str {
    ($ty:ty, $expecting:literal, $parse:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct StrVisitor;

                impl Visitor<'_> for StrVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<$ty, E> {
                        let parse: fn(&str) -> Option<$ty> = $parse;
                        parse(text).ok_or_else(|| {
                            E::invalid_value(serde::de::Unexpected::Str(text), &$expecting)
                        })
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }
    };
}

/// An RFC 3339 UTC time, `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
///
/// The time must end in an uppercase `Z`; `+00:00`, `-00:00`, any other
/// offset and a lowercase `t` or `z` are rejected. The fraction of a second
/// has 1 to 9 digits, or is left out together with its `.`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp(jiff::Timestamp);

impl UtcTimestamp {
    /// Parses an RFC 3339 UTC time ending in `Z`, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        parse_utc_timestamp(text).map(Self)
    }

    /// Returns the time.
    #[must_use]
    pub fn get(self) -> jiff::Timestamp {
        self.0
    }
}

impl From<jiff::Timestamp> for UtcTimestamp {
    fn from(timestamp: jiff::Timestamp) -> Self {
        Self(timestamp)
    }
}

impl From<UtcTimestamp> for jiff::Timestamp {
    fn from(timestamp: UtcTimestamp) -> Self {
        timestamp.0
    }
}

deserialize_from_str!(
    UtcTimestamp,
    "an RFC 3339 UTC time ending in `Z`",
    UtcTimestamp::parse
);

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `Timestamp`'s `Display` writes RFC 3339 in UTC with a `Z`.
        serializer.collect_str(&self.0)
    }
}

fn parse_utc_timestamp(text: &str) -> Option<jiff::Timestamp> {
    const TEMPLATE: &[u8; 19] = b"0000-00-00T00:00:00";
    const MAX_FRACTION_DIGITS: usize = 9;

    let bytes = text.as_bytes();
    let (head, rest) = bytes.split_at_checked(TEMPLATE.len())?;
    let head_ok = head.iter().zip(TEMPLATE).all(|(&b, &t)| {
        if t == b'0' {
            b.is_ascii_digit()
        } else {
            b == t
        }
    });
    let fraction = rest.strip_suffix(b"Z")?;
    let fraction_ok = match fraction.split_first() {
        None => true,
        Some((b'.', digits)) => {
            (1..=MAX_FRACTION_DIGITS).contains(&digits.len())
                && digits.iter().all(u8::is_ascii_digit)
        }
        Some(_) => false,
    };
    if !head_ok || !fraction_ok {
        return None;
    }
    // The shape is fixed above; jiff checks the ranges (month, day of month,
    // hour and so on).
    text.parse().ok()
}

/// A UUID in lowercase hyphenated form, 36 characters long.
///
/// Uppercase, braced, URN and unhyphenated forms are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowerUuid(uuid::Uuid);

impl LowerUuid {
    /// Parses a lowercase hyphenated UUID, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        parse_lower_uuid(text).map(Self)
    }

    /// Returns the UUID.
    #[must_use]
    pub fn get(self) -> uuid::Uuid {
        self.0
    }
}

impl From<uuid::Uuid> for LowerUuid {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl From<LowerUuid> for uuid::Uuid {
    fn from(uuid: LowerUuid) -> Self {
        uuid.0
    }
}

deserialize_from_str!(LowerUuid, "a lowercase hyphenated UUID", LowerUuid::parse);

impl Serialize for LowerUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0.hyphenated())
    }
}

/// Parses a UUID in lowercase hyphenated form only.
pub(crate) fn parse_lower_uuid(text: &str) -> Option<uuid::Uuid> {
    const TEMPLATE: &[u8; 36] = b"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

    let bytes = text.as_bytes();
    let shape_ok = bytes.len() == TEMPLATE.len()
        && bytes.iter().zip(TEMPLATE).all(|(&b, &t)| {
            if t == b'-' {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        });
    if !shape_ok {
        return None;
    }
    uuid::Uuid::try_parse(text).ok()
}

/// Bytes written as unpadded, canonical base64url.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Base64UrlBytes(Vec<u8>);

impl Base64UrlBytes {
    /// Decodes unpadded, canonical base64url, or returns `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        b64::decode(text).map(Self)
    }

    /// Returns the bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the bytes, consuming the value.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Base64UrlBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

deserialize_from_str!(Base64UrlBytes, "unpadded base64url", Base64UrlBytes::parse);

impl Serialize for Base64UrlBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64::encode(&self.0))
    }
}

/// Exactly `N` bytes written as unpadded, canonical base64url, such as a
/// SHA-256 hash as `Base64UrlArray<32>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Base64UrlArray<const N: usize>([u8; N]);

impl<const N: usize> Base64UrlArray<N> {
    /// Decodes unpadded, canonical base64url of exactly `N` bytes, or returns
    /// `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        b64::decode_array(text).map(Self)
    }

    /// Returns the bytes.
    #[must_use]
    pub fn get(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Base64UrlArray<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Base64UrlArray<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ArrayVisitor<const N: usize>;

        impl<const N: usize> Visitor<'_> for ArrayVisitor<N> {
            type Value = Base64UrlArray<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "unpadded base64url of exactly {N} bytes")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
                Base64UrlArray::parse(text)
                    .ok_or_else(|| E::invalid_value(serde::de::Unexpected::Str(text), &self))
            }
        }

        deserializer.deserialize_str(ArrayVisitor)
    }
}

impl<const N: usize> Serialize for Base64UrlArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64::encode(&self.0))
    }
}

#[cfg(test)]
mod tests;
