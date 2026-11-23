//! The CBOR rules every message body follows, as functions and serde
//! helpers.
//!
//! - A struct is a map with text keys, its field names in snake_case:
//!   `#[serde(rename_all = "snake_case")]` where Rust's names differ.
//! - A map holding the same key twice, at any depth, fails to decode.
//!   [`from_slice`] checks that, so every body is decoded through it.
//! - A field the receiver does not know is ignored: no
//!   `#[serde(deny_unknown_fields)]` on a transport message.
//! - An optional field with no value is not sent, and a missing key and a
//!   CBOR null both read as no value:
//!   `#[serde(default, skip_serializing_if = "Option::is_none")]`.
//! - An enum is a snake_case string tag: a variant without a value is a
//!   text string, and one with a value a map of one entry,
//!   `{tag: content}`. That is serde's default, external tagging, under
//!   `#[serde(rename_all = "snake_case")]`.
//! - A byte value is a CBOR byte string ([`bytes`]), a UUID a byte string
//!   of 16 bytes ([`uuid`]), and a point in time an integer count of
//!   nanoseconds since the Unix epoch within the range of an `i64`
//!   ([`timestamp`]).
//! - A value decodes only from the CBOR type its rule names. A byte string
//!   never stands in for an array, nor an array for a byte string or a
//!   struct, nor a byte string for text; a struct's keys and an enum's
//!   tags are text strings, at a definite length or in chunks.
//!
//! Each helper module has an `option` module beside its functions for the
//! same type wrapped in `Option`.
//!
//! ```
//! use jiff::Timestamp;
//! use senta_protocol::connection::cbor;
//! use serde::{Deserialize, Serialize};
//! use uuid::Uuid;
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct Example {
//!     #[serde(with = "cbor::uuid")]
//!     id: Uuid,
//!     #[serde(with = "cbor::timestamp")]
//!     at: Timestamp,
//!     #[serde(
//!         default,
//!         skip_serializing_if = "Option::is_none",
//!         with = "cbor::bytes::option"
//!     )]
//!     digest: Option<Vec<u8>>,
//! }
//!
//! let value = Example {
//!     id: Uuid::from_u128(7),
//!     at: Timestamp::UNIX_EPOCH,
//!     digest: None,
//! };
//! let bytes = cbor::to_vec(&value)?;
//! assert_eq!(cbor::from_slice::<Example>(&bytes)?, value);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod de;
mod scan;

use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) use self::scan::{Head, Reader, ScanError, check_well_formed, put_head};

/// The kind of failure a [`DecodeError`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The bytes are not one well-formed CBOR value: truncated, a reserved
    /// encoding, a misplaced break, or a text string that is not UTF-8.
    Malformed,
    /// A complete value is followed by more bytes.
    TrailingBytes,
    /// Arrays and maps nest deeper than the decoder follows.
    TooDeep,
    /// A map, at some depth, holds the same key twice.
    DuplicateKey,
    /// The value is well-formed CBOR but not the shape of the type it is
    /// decoded into: a required field missing, a map key of a struct that
    /// is not text, or a value of the wrong CBOR type (a byte string for
    /// an array, say) or out of range.
    Invalid,
}

/// An error decoding a CBOR body into a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    message: Option<String>,
}

impl DecodeError {
    /// Returns the kind of failure.
    #[must_use]
    pub fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    /// Returns a [`DecodeErrorKind::Invalid`] error with its message.
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: DecodeErrorKind::Invalid,
            message: Some(message.into()),
        }
    }
}

impl From<ScanError> for DecodeError {
    fn from(error: ScanError) -> Self {
        let kind = match error {
            ScanError::Malformed => DecodeErrorKind::Malformed,
            ScanError::TrailingBytes => DecodeErrorKind::TrailingBytes,
            ScanError::TooDeep => DecodeErrorKind::TooDeep,
            ScanError::DuplicateKey => DecodeErrorKind::DuplicateKey,
        };
        Self {
            kind,
            message: None,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, &self.message) {
            (DecodeErrorKind::Malformed, _) => f.write_str("malformed CBOR"),
            (DecodeErrorKind::TrailingBytes, _) => {
                f.write_str("bytes follow the end of the CBOR value")
            }
            (DecodeErrorKind::TooDeep, _) => f.write_str("CBOR value nested too deeply"),
            (DecodeErrorKind::DuplicateKey, _) => f.write_str("duplicate map key"),
            (DecodeErrorKind::Invalid, Some(message)) => {
                write!(f, "unexpected CBOR value: {message}")
            }
            (DecodeErrorKind::Invalid, None) => f.write_str("unexpected CBOR value"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// An error encoding a value as CBOR, or a frame too long for its length
/// prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    message: String,
}

impl EncodeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot encode: {}", self.message)
    }
}

impl std::error::Error for EncodeError {}

/// Decodes a CBOR body into `T`, refusing a map with a duplicate key at any
/// depth.
///
/// The bytes are scanned before anything is decoded: they must be exactly
/// one well-formed CBOR value, so no length declared in them can outgrow
/// the bytes themselves, and no map in them, at any depth, may hold the
/// same key twice. Keys compare as values, not encodings, and `null` and
/// `undefined` are the same key, as they are to [`crate::results`]. The
/// check is not quadratic in the number of keys. Then the value is
/// decoded, ignoring map keys `T` does not name.
///
/// Each value decodes only from the CBOR type its rule names, with no
/// stand-in: a sequence only from an array, never a byte string; a byte
/// value only from a byte string, never an array; a string only from a
/// text string; a struct only from a map; and a field or variant name only
/// from a text string, written at a definite length or in chunks. Tags are
/// passed over, except the bignums (tags 2 and 3), which read as the
/// integers they hold.
///
/// A type that reads CBOR tags through ciborium's tag protocol, an enum
/// named `@@TAG@@` as [`crate::results`] does, reads them here as it does
/// from ciborium, and through `deserialize_any` `undefined` reaches it as
/// none, as from ciborium. A typed read still refuses `undefined`, so it
/// never stands in for null in an optional field.
///
/// # Errors
///
/// Returns an error when the bytes are not one well-formed CBOR value, nest
/// arrays and maps deeper than 256 levels, hold a duplicate map key, or do
/// not decode into `T`, which includes a type reading more than 256 nested
/// tags through ciborium's tag protocol.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    scan::check_body(bytes)?;
    de::from_slice(bytes).map_err(|error| DecodeError::invalid(error.to_string()))
}

/// Encodes a value as CBOR.
///
/// # Errors
///
/// Returns an error when the value refuses to serialize, as a
/// [`timestamp`] outside the range of an `i64` count of nanoseconds does.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|error| EncodeError::new(error.to_string()))?;
    Ok(out)
}

/// A serde helper writing a byte value as a CBOR byte string.
///
/// It serializes anything that is `AsRef<[u8]>` and deserializes into
/// anything a `Vec<u8>` converts into, such as `Vec<u8>` or `[u8; 32]`; a
/// byte string of the wrong length for a fixed-size array fails to decode.
/// Only a byte string decodes; an array of integers does not.
pub mod bytes {
    use std::fmt;

    use serde::de::{self, Deserializer, Visitor};
    use serde::{Deserialize, Serialize, Serializer};

    /// Serializes a byte value as a CBOR byte string.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + ?Sized,
        S: Serializer,
    {
        serializer.serialize_bytes(value.as_ref())
    }

    /// Deserializes a CBOR byte string.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a byte string, or when `T`
    /// refuses its length.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: TryFrom<Vec<u8>>,
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_byte_buf(ByteVisitor)?;
        let len = bytes.len();
        T::try_from(bytes)
            .map_err(|_| de::Error::custom(format_args!("unexpected byte length {len}")))
    }

    struct ByteVisitor;

    impl Visitor<'_> for ByteVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(value)
        }
    }

    pub(super) struct Repr<T>(pub(super) T);

    impl<T: AsRef<[u8]>> Serialize for Repr<&T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serialize(self.0, serializer)
        }
    }

    impl<'de, T: TryFrom<Vec<u8>>> Deserialize<'de> for Repr<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize(deserializer).map(Repr)
        }
    }

    /// The same, for an optional byte value.
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};

        use super::Repr;

        /// Serializes an optional byte value: a byte string, or null.
        ///
        /// # Errors
        ///
        /// Returns the serializer's error.
        pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: AsRef<[u8]>,
            S: Serializer,
        {
            match value {
                Some(value) => serializer.serialize_some(&Repr(value)),
                None => serializer.serialize_none(),
            }
        }

        /// Deserializes an optional byte value; null reads as `None`.
        ///
        /// # Errors
        ///
        /// Returns an error when the value is neither a byte string nor
        /// null, or when `T` refuses its length.
        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            T: TryFrom<Vec<u8>>,
            D: Deserializer<'de>,
        {
            Ok(Option::<Repr<T>>::deserialize(deserializer)?.map(|repr| repr.0))
        }
    }
}

/// A serde helper writing a UUID as a CBOR byte string of its 16 bytes.
pub mod uuid {
    use serde::de::{self, Deserializer};
    use serde::{Deserialize, Serialize, Serializer};
    use uuid::Uuid;

    /// Serializes a UUID as a byte string of 16 bytes.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value.as_bytes())
    }

    /// Deserializes a UUID from a byte string of 16 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a byte string of exactly 16
    /// bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        let bytes: [u8; 16] = super::bytes::deserialize(deserializer)
            .map_err(|error: D::Error| de::Error::custom(format_args!("UUID: {error}")))?;
        Ok(Uuid::from_bytes(bytes))
    }

    struct Repr(Uuid);

    impl Serialize for Repr {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serialize(&self.0, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Repr {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize(deserializer).map(Repr)
        }
    }

    /// The same, for an optional UUID.
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};
        use uuid::Uuid;

        use super::Repr;

        /// Serializes an optional UUID: a byte string, or null.
        ///
        /// # Errors
        ///
        /// Returns the serializer's error.
        pub fn serialize<S: Serializer>(
            value: &Option<Uuid>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_some(&Repr(*value)),
                None => serializer.serialize_none(),
            }
        }

        /// Deserializes an optional UUID; null reads as `None`.
        ///
        /// # Errors
        ///
        /// Returns an error when the value is neither a byte string of 16
        /// bytes nor null.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Uuid>, D::Error> {
            Ok(Option::<Repr>::deserialize(deserializer)?.map(|repr| repr.0))
        }
    }
}

/// A serde helper writing a point in time as an integer count of
/// nanoseconds since the Unix epoch.
///
/// The count is an `i64`, which spans the years 1677 to 2262; a point in
/// time outside that range fails to encode.
pub mod timestamp {
    use jiff::Timestamp;
    use serde::de::{self, Deserializer};
    use serde::ser::{self, Serializer};
    use serde::{Deserialize, Serialize};

    /// Serializes a point in time as integer nanoseconds since the Unix
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the count of nanoseconds does not fit an
    /// `i64`, or the serializer's error.
    pub fn serialize<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        let nanos = i64::try_from(value.as_nanosecond()).map_err(|_| {
            ser::Error::custom(format_args!(
                "timestamp {value} is outside the range of i64 nanoseconds"
            ))
        })?;
        serializer.serialize_i64(nanos)
    }

    /// Deserializes a point in time from integer nanoseconds since the Unix
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an integer within the range
    /// of an `i64`.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        let nanos = i64::deserialize(deserializer)?;
        Timestamp::from_nanosecond(i128::from(nanos)).map_err(de::Error::custom)
    }

    struct Repr(Timestamp);

    impl Serialize for Repr {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serialize(&self.0, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Repr {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserialize(deserializer).map(Repr)
        }
    }

    /// The same, for an optional point in time.
    pub mod option {
        use jiff::Timestamp;
        use serde::{Deserialize, Deserializer, Serializer};

        use super::Repr;

        /// Serializes an optional point in time: integer nanoseconds, or
        /// null.
        ///
        /// # Errors
        ///
        /// Returns an error when the count of nanoseconds does not fit an
        /// `i64`, or the serializer's error.
        pub fn serialize<S: Serializer>(
            value: &Option<Timestamp>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_some(&Repr(*value)),
                None => serializer.serialize_none(),
            }
        }

        /// Deserializes an optional point in time; null reads as `None`.
        ///
        /// # Errors
        ///
        /// Returns an error when the value is neither an integer within the
        /// range of an `i64` nor null.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Timestamp>, D::Error> {
            Ok(Option::<Repr>::deserialize(deserializer)?.map(|repr| repr.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use ::uuid::Uuid;
    use jiff::Timestamp;
    use serde::{Deserialize, Serialize};

    use super::{DecodeErrorKind, from_slice, to_vec};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Shapes {
        #[serde(with = "super::bytes")]
        raw: Vec<u8>,
        #[serde(with = "super::bytes")]
        digest: [u8; 4],
        #[serde(with = "super::uuid")]
        id: Uuid,
        #[serde(with = "super::timestamp")]
        at: Timestamp,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::uuid::option"
        )]
        maybe_id: Option<Uuid>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::timestamp::option"
        )]
        maybe_at: Option<Timestamp>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::bytes::option"
        )]
        maybe_raw: Option<Vec<u8>>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Choice {
        Plain,
        WithValue(u8),
    }

    fn shapes() -> Shapes {
        Shapes {
            raw: vec![1, 2],
            digest: [9, 8, 7, 6],
            id: Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
            at: Timestamp::from_nanosecond(1_500_000_000_123_456_789).unwrap(),
            maybe_id: None,
            maybe_at: None,
            maybe_raw: None,
        }
    }

    /// Encodes a text string.
    fn text(out: &mut Vec<u8>, value: &str) {
        let len = u8::try_from(value.len()).unwrap();
        assert!(len < 24);
        out.push(0x60 | len);
        out.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn helpers_write_the_wire_shapes() {
        let bytes = to_vec(&shapes()).unwrap();
        let mut expected = vec![0xa4];
        text(&mut expected, "raw");
        expected.extend_from_slice(&[0x42, 1, 2]);
        text(&mut expected, "digest");
        expected.extend_from_slice(&[0x44, 9, 8, 7, 6]);
        text(&mut expected, "id");
        expected.push(0x50);
        expected.extend_from_slice(&0x0011_2233_4455_6677_8899_aabb_ccdd_eeff_u128.to_be_bytes());
        text(&mut expected, "at");
        expected.push(0x1b);
        expected.extend_from_slice(&1_500_000_000_123_456_789_u64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(from_slice::<Shapes>(&bytes).unwrap(), shapes());
    }

    #[test]
    fn long_and_chunked_byte_values_decode() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Blob(#[serde(with = "super::bytes")] Vec<u8>);
        let long = Blob(vec![7; 100_000]);
        let bytes = to_vec(&long).unwrap();
        assert_eq!(bytes.get(..5).unwrap(), [0x5a, 0x00, 0x01, 0x86, 0xa0]);
        assert_eq!(from_slice::<Blob>(&bytes).unwrap(), long);
        let chunked = [0x5f, 0x41, 1, 0x42, 2, 3, 0xff];
        assert_eq!(from_slice::<Blob>(&chunked).unwrap(), Blob(vec![1, 2, 3]));
    }

    #[test]
    fn negative_timestamps_are_negative_integers() {
        #[derive(Serialize)]
        struct At(#[serde(with = "super::timestamp")] Timestamp);
        let bytes = to_vec(&At(Timestamp::from_nanosecond(-1).unwrap())).unwrap();
        assert_eq!(bytes, [0x20]);
    }

    #[test]
    fn timestamps_outside_i64_fail_to_encode() {
        #[derive(Serialize)]
        struct At(#[serde(with = "super::timestamp")] Timestamp);
        assert!(to_vec(&At(Timestamp::MAX)).is_err());
        assert!(to_vec(&At(Timestamp::MIN)).is_err());
        let edge = Timestamp::from_nanosecond(i128::from(i64::MAX)).unwrap();
        assert!(to_vec(&At(edge)).is_ok());
    }

    #[test]
    fn optional_fields_present_round_trip() {
        let mut value = shapes();
        value.maybe_id = Some(Uuid::from_u128(5));
        value.maybe_at = Some(Timestamp::UNIX_EPOCH);
        value.maybe_raw = Some(vec![3]);
        let bytes = to_vec(&value).unwrap();
        assert_eq!(from_slice::<Shapes>(&bytes).unwrap(), value);
    }

    #[test]
    fn optional_fields_read_null_as_none() {
        let mut bytes = to_vec(&shapes()).unwrap();
        // Rewrite the map head to seven entries and add three nulls.
        if let Some(head) = bytes.first_mut() {
            *head = 0xa7;
        }
        for key in ["maybe_id", "maybe_at", "maybe_raw"] {
            text(&mut bytes, key);
            bytes.push(0xf6);
        }
        assert_eq!(from_slice::<Shapes>(&bytes).unwrap(), shapes());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let mut bytes = to_vec(&shapes()).unwrap();
        if let Some(head) = bytes.first_mut() {
            *head = 0xa5;
        }
        text(&mut bytes, "later");
        bytes.extend_from_slice(&[0xa1, 0x01, 0x02]);
        assert_eq!(from_slice::<Shapes>(&bytes).unwrap(), shapes());
    }

    #[test]
    fn wrong_shapes_fail() {
        // A UUID of 15 bytes, a byte value as an array, a timestamp as text.
        #[derive(Debug, Deserialize)]
        struct Id {
            #[serde(with = "super::uuid")]
            #[expect(dead_code, reason = "decoded only to see it fail")]
            id: Uuid,
        }
        #[derive(Debug, Deserialize)]
        struct Raw {
            #[serde(with = "super::bytes")]
            #[expect(dead_code, reason = "decoded only to see it fail")]
            raw: Vec<u8>,
        }
        #[derive(Debug, Deserialize)]
        struct At {
            #[serde(with = "super::timestamp")]
            #[expect(dead_code, reason = "decoded only to see it fail")]
            at: Timestamp,
        }
        let mut id = vec![0xa1];
        text(&mut id, "id");
        id.push(0x4f);
        id.extend_from_slice(&[0; 15]);
        assert_eq!(
            from_slice::<Id>(&id).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );

        let mut raw = vec![0xa1];
        text(&mut raw, "raw");
        raw.extend_from_slice(&[0x81, 0x01]);
        assert_eq!(
            from_slice::<Raw>(&raw).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );

        let mut at = vec![0xa1];
        text(&mut at, "at");
        text(&mut at, "now");
        assert_eq!(
            from_slice::<At>(&at).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );

        // A fixed-size byte value of the wrong length.
        let mut bytes = to_vec(&shapes()).unwrap();
        let at = bytes
            .windows(5)
            .position(|w| w == [0x44, 9, 8, 7, 6])
            .unwrap();
        bytes.splice(at..at + 5, [0x43, 9, 8, 7]);
        assert_eq!(
            from_slice::<Shapes>(&bytes).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );
    }

    #[test]
    fn enums_are_snake_case_tags() {
        assert_eq!(to_vec(&Choice::Plain).unwrap(), b"\x65plain");
        let mut with_value = vec![0xa1];
        text(&mut with_value, "with_value");
        with_value.push(0x07);
        assert_eq!(to_vec(&Choice::WithValue(7)).unwrap(), with_value);
        assert_eq!(
            from_slice::<Choice>(&with_value).unwrap(),
            Choice::WithValue(7)
        );
        assert_eq!(from_slice::<Choice>(b"\x65plain").unwrap(), Choice::Plain);
    }

    #[test]
    fn duplicate_keys_fail_even_where_serde_would_not_look() {
        #[derive(Debug, Deserialize)]
        struct Outer {
            #[expect(dead_code, reason = "decoded only to see it fail")]
            inner: Inner,
        }
        #[derive(Debug, Deserialize)]
        struct Inner {}

        // {"inner": {"x": 1, "x": 2}}: both keys unknown to `Inner`.
        let mut bytes = vec![0xa1];
        text(&mut bytes, "inner");
        bytes.push(0xa2);
        text(&mut bytes, "x");
        bytes.push(0x01);
        text(&mut bytes, "x");
        bytes.push(0x02);
        assert_eq!(
            from_slice::<Outer>(&bytes).unwrap_err().kind(),
            DecodeErrorKind::DuplicateKey
        );

        // A known key twice at the top.
        let mut bytes = to_vec(&shapes()).unwrap();
        if let Some(head) = bytes.first_mut() {
            *head = 0xa5;
        }
        text(&mut bytes, "raw");
        bytes.extend_from_slice(&[0x42, 1, 2]);
        assert_eq!(
            from_slice::<Shapes>(&bytes).unwrap_err().kind(),
            DecodeErrorKind::DuplicateKey
        );
    }

    #[test]
    fn null_and_undefined_keys_are_duplicates_in_bodies_and_results() {
        use crate::results::DocumentResult;

        #[derive(Debug, Deserialize)]
        struct Body {}

        // {null: 0, undefined: 1} in both orders, and each key alone.
        let mixed: [&[u8]; 2] = [
            &[0xa2, 0xf6, 0x00, 0xf7, 0x01],
            &[0xa2, 0xf7, 0x00, 0xf6, 0x01],
        ];
        let alone: [&[u8]; 2] = [
            &[0xa2, 0xf6, 0x00, 0x01, 0x01],
            &[0xa2, 0xf7, 0x00, 0x01, 0x01],
        ];

        // {key: content}
        let under = |key: &str, content: &[u8]| {
            let mut bytes = vec![0xa1];
            text(&mut bytes, key);
            bytes.extend_from_slice(content);
            bytes
        };
        // In a field the common body does not know, and so ignores.
        let in_body = |content: &[u8]| under("added_later", content);
        // In the ignored content of a result variant this crate does not
        // know.
        let in_result = |content: &[u8]| under("future", content);

        for content in mixed {
            assert_eq!(
                from_slice::<Body>(&in_body(content)).unwrap_err().kind(),
                DecodeErrorKind::DuplicateKey,
                "{content:02x?}"
            );
            let bytes = in_result(content);
            assert_eq!(
                from_slice::<DocumentResult>(&bytes).unwrap_err().kind(),
                DecodeErrorKind::DuplicateKey,
                "{content:02x?}"
            );
            // Decoded straight from CBOR, the result enum's own check
            // agrees.
            let error =
                ciborium::de::from_reader::<DocumentResult, _>(bytes.as_slice()).unwrap_err();
            assert!(
                error.to_string().contains("duplicate map key"),
                "{content:02x?}: {error}"
            );
        }
        for content in alone {
            assert!(
                from_slice::<Body>(&in_body(content)).is_ok(),
                "{content:02x?}"
            );
            let bytes = in_result(content);
            let future = DocumentResult::Other("future".to_owned());
            assert_eq!(
                from_slice::<DocumentResult>(&bytes).unwrap(),
                future,
                "{content:02x?}"
            );
            assert_eq!(
                ciborium::de::from_reader::<DocumentResult, _>(bytes.as_slice()).unwrap(),
                future,
                "{content:02x?}"
            );
        }
    }

    fn invalid<T: serde::de::DeserializeOwned + std::fmt::Debug>(bytes: &[u8]) {
        assert_eq!(
            from_slice::<T>(bytes).unwrap_err().kind(),
            DecodeErrorKind::Invalid,
            "{bytes:02x?}"
        );
    }

    #[test]
    fn a_byte_string_is_not_a_sequence() {
        #[derive(Debug, Deserialize)]
        struct List {
            #[expect(dead_code, reason = "decoded only to see it fail")]
            items: Vec<u16>,
        }
        let mut bytes = vec![0xa1];
        text(&mut bytes, "items");
        // h'', h'0102', and h'01' in chunks, where an array belongs.
        for value in [&[0x40][..], &[0x42, 1, 2], &[0x5f, 0x41, 1, 0xff]] {
            let mut body = bytes.clone();
            body.extend_from_slice(value);
            invalid::<List>(&body);
            invalid::<Vec<u8>>(value);
        }
        assert_eq!(from_slice::<Vec<u8>>(&[0x80]).unwrap(), Vec::<u8>::new());
        assert_eq!(from_slice::<Vec<u8>>(&[0x82, 1, 2]).unwrap(), [1, 2]);
        assert_eq!(from_slice::<Vec<u8>>(&[0x9f, 1, 2, 0xff]).unwrap(), [1, 2]);
    }

    #[test]
    fn wrong_cbor_types_do_not_stand_in() {
        #[derive(Debug, Deserialize)]
        struct Named {
            #[expect(dead_code, reason = "decoded only to see it fail")]
            name: String,
        }
        // A struct written as an array of its fields.
        invalid::<Named>(&[0x81, 0x61, b'a']);
        // A string written as a byte string.
        let mut bytes = vec![0xa1];
        text(&mut bytes, "name");
        bytes.extend_from_slice(&[0x41, b'a']);
        invalid::<Named>(&bytes);
        // A field name written as a byte string, or as the field's index.
        let mut bytes = vec![0xa1, 0x44];
        bytes.extend_from_slice(b"name");
        text(&mut bytes, "a");
        invalid::<Named>(&bytes);
        let mut bytes = vec![0xa1, 0x00];
        text(&mut bytes, "a");
        invalid::<Named>(&bytes);
        // A fixed-size array with an item too many, and an integer as a
        // float or a float as an integer.
        invalid::<[u8; 2]>(&[0x83, 1, 2, 3]);
        invalid::<f64>(&[0x01]);
        invalid::<u8>(&[0xf9, 0x3c, 0x00]);
        // undefined is not null.
        invalid::<Option<u8>>(&[0xf7]);
        // A variant without a value written as a map, and one with a value
        // written as its tag alone.
        let mut bytes = vec![0xa1];
        text(&mut bytes, "plain");
        bytes.push(0xf6);
        invalid::<Choice>(&bytes);
        let mut bytes = Vec::new();
        text(&mut bytes, "with_value");
        invalid::<Choice>(&bytes);
    }

    #[test]
    fn text_keys_decode_in_any_valid_form() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Named {
            name: String,
        }
        // {"na" "me": "a" "b", "x": 1, <a 5,000-byte key>: 2}: a known key and
        // its value in chunks, then unknown keys in chunks and past any
        // scratch buffer.
        let mut bytes = vec![0xa3, 0x7f];
        text(&mut bytes, "na");
        text(&mut bytes, "me");
        bytes.extend_from_slice(&[0xff, 0x7f]);
        text(&mut bytes, "a");
        text(&mut bytes, "b");
        bytes.extend_from_slice(&[0xff, 0x7f, 0x61, b'x', 0xff, 0x01, 0x79, 0x13, 0x88]);
        bytes.extend_from_slice(&[b'k'; 5000]);
        bytes.push(0x02);
        assert_eq!(
            from_slice::<Named>(&bytes).unwrap(),
            Named {
                name: "ab".to_owned()
            }
        );
        // An enum tag in chunks.
        let mut bytes = vec![0x7f];
        text(&mut bytes, "pla");
        text(&mut bytes, "in");
        bytes.push(0xff);
        assert_eq!(from_slice::<Choice>(&bytes).unwrap(), Choice::Plain);
        let mut bytes = vec![0xbf];
        text(&mut bytes, "with_value");
        bytes.extend_from_slice(&[0x07, 0xff]);
        assert_eq!(from_slice::<Choice>(&bytes).unwrap(), Choice::WithValue(7));
    }

    #[test]
    fn integers_decode_from_any_width_and_bignums() {
        assert_eq!(from_slice::<u16>(&[0x19, 0x01, 0x00]).unwrap(), 256);
        assert_eq!(
            from_slice::<u16>(&[0x1b, 0, 0, 0, 0, 0, 0, 1, 0]).unwrap(),
            256
        );
        assert_eq!(from_slice::<i64>(&[0x20]).unwrap(), -1);
        assert_eq!(from_slice::<u64>(&[0xc2, 0x43, 0, 1, 0]).unwrap(), 256);
        assert_eq!(from_slice::<i64>(&[0xc3, 0x41, 0x01]).unwrap(), -2);
        // A tag other than a bignum is passed over.
        assert_eq!(from_slice::<u8>(&[0xc1, 0x05]).unwrap(), 5);
        invalid::<u16>(&[0x1a, 0x00, 0x01, 0x00, 0x00]);
        invalid::<u64>(&[0x20]);
        let mut big = vec![0xc2, 0x51];
        big.extend_from_slice(&[1; 17]);
        invalid::<u128>(&big);
    }

    #[test]
    fn trailing_and_malformed_bodies_fail() {
        let mut bytes = to_vec(&shapes()).unwrap();
        bytes.push(0x00);
        assert_eq!(
            from_slice::<Shapes>(&bytes).unwrap_err().kind(),
            DecodeErrorKind::TrailingBytes
        );
        assert_eq!(
            from_slice::<Shapes>(&[0xa1]).unwrap_err().kind(),
            DecodeErrorKind::Malformed
        );
        assert_eq!(
            from_slice::<Shapes>(&[]).unwrap_err().kind(),
            DecodeErrorKind::Malformed
        );
    }

    /// Decodes `bytes` as `T` both here and with ciborium, which the result
    /// enums were written against, and asserts the two agree.
    fn same_as_ciborium<T>(bytes: &[u8]) -> Option<T>
    where
        T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let ours = from_slice::<T>(bytes).ok();
        let theirs = ciborium::de::from_reader::<T, _>(bytes).ok();
        assert_eq!(ours, theirs, "bytes {bytes:02x?}");
        ours
    }

    #[test]
    fn result_enums_decode_as_they_do_from_ciborium() {
        use crate::results::{CommandResultKind, DocumentResult};

        // A known tag without content, sent as a map: its content is
        // discarded.
        let mut bytes = vec![0xa1];
        text(&mut bytes, "applied");
        bytes.push(0xf6);
        assert_eq!(
            same_as_ciborium::<DocumentResult>(&bytes),
            Some(DocumentResult::Applied)
        );

        // A tag this crate does not know, with content of several shapes.
        let contents: [&[u8]; 6] = [
            &[0xf6],
            &[0xf7],
            &[0xc6, 0x01],
            &[0xc1, 0xc6, 0x82, 0x01, 0xf7],
            &[
                0xc2, 0x51, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            ],
            &[0xa2, 0xc6, 0x01, 0x00, 0x01, 0x00],
        ];
        for content in contents {
            let mut bytes = vec![0xa1];
            text(&mut bytes, "future");
            bytes.extend_from_slice(content);
            assert_eq!(
                same_as_ciborium::<DocumentResult>(&bytes),
                Some(DocumentResult::Other("future".to_owned()))
            );
        }

        // A field this crate does not know, nested inside a result.
        let mut fields = vec![0xa3];
        text(&mut fields, "have_epoch");
        fields.push(0x03);
        text(&mut fields, "have_version");
        fields.push(0x07);
        text(&mut fields, "x");
        fields.push(0x00);
        let gap = DocumentResult::KeysetGap {
            have_epoch: 3,
            have_version: 7,
        };
        let mut bytes = vec![0xa1];
        text(&mut bytes, "keyset_gap");
        bytes.extend_from_slice(&fields);
        assert_eq!(
            same_as_ciborium::<DocumentResult>(&bytes),
            Some(gap.clone())
        );
        let mut bytes = vec![0xa1];
        text(&mut bytes, "rejected");
        bytes.push(0xa1);
        text(&mut bytes, "keyset_gap");
        bytes.extend_from_slice(&fields);
        assert_eq!(
            same_as_ciborium::<CommandResultKind>(&bytes),
            Some(CommandResultKind::Rejected(gap))
        );

        // Keys that are the same integer, once as a bignum, inside discarded
        // content.
        let mut bytes = vec![0xa1];
        text(&mut bytes, "future");
        bytes.extend_from_slice(&[0xa2, 0xc2, 0x42, 0x00, 0x01, 0x00, 0x01, 0x00]);
        assert!(same_as_ciborium::<DocumentResult>(&bytes).is_none());
    }

    #[test]
    fn tags_read_by_ciborium_protocol_nest_boundedly() {
        use crate::results::DocumentResult;

        let nested = |tags: usize| {
            let mut bytes = vec![0xa1];
            text(&mut bytes, "future");
            bytes.extend(std::iter::repeat_n(0xc6, tags));
            bytes.push(0x00);
            bytes
        };
        assert_eq!(
            from_slice::<DocumentResult>(&nested(super::scan::MAX_DEPTH)).unwrap(),
            DocumentResult::Other("future".to_owned())
        );
        // Far more tags than the decoder follows fail without exhausting
        // the stack.
        assert_eq!(
            from_slice::<DocumentResult>(&nested(1 << 20))
                .unwrap_err()
                .kind(),
            DecodeErrorKind::Invalid
        );
    }
}
