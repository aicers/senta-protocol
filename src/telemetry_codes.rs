//! The codes a telemetry connection carries: why a telemetry entry refused
//! what it received ([`TelemetryError`]), and why an endpoint dropped a
//! range of records before sending them ([`DropReason`]).
//!
//! The messages that carry them are under the `telemetry` feature, but the
//! active list answers an endpoint that may not send with a
//! [`TelemetryError`] too, so these enums belong to no feature and this
//! module is always public.
//!
//! # CBOR shape
//!
//! Both enums are text tags and decode by the rules of [`crate::results`]:
//! a variant without content is its tag as text, and [`TelemetryError::Gap`]
//! is the one-entry map `{"gap": {"expected": n}}`, where `n` is an
//! unsigned integer. A tag this crate does not know becomes `Other(tag)`,
//! whether it comes as text or as a one-entry map whose content is
//! discarded; a known tag without content that comes as a one-entry map is
//! its variant; a field of `gap` this crate does not know is ignored. `gap`
//! as text, a field map without `expected`, a map with no entry or more
//! than one, a map key that is not text, and any value that is neither text
//! nor a map are errors. `Other(s)` encodes as the text `s`, so it survives
//! a round trip only when `s` is not one of the enum's tags.

use std::{convert::Infallible, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::MapAccess, ser::SerializeMap};

use crate::results::{Class, Tagged, TaggedVisitor};

const GAP: &str = "gap";
const BAD_RANGE: &str = "bad_range";
const CLOSED: &str = "closed";
const TOO_LARGE: &str = "too_large";
const UNKNOWN_STREAM: &str = "unknown_stream";
const UNSUPPORTED_KIND: &str = "unsupported_kind";
const NOT_LISTED: &str = "not_listed";
const SUSPENDED: &str = "suspended";
const LEASE_EXPIRED: &str = "lease_expired";

const BUFFER_OVERFLOW: &str = "buffer_overflow";
const RETENTION_EXPIRED: &str = "retention_expired";
const UNSUPPORTED: &str = "unsupported";

/// Why a telemetry entry refused what an endpoint sent it.
///
/// The first six answer a message of a stream; the last three answer the
/// endpoint itself, which the entry does not take telemetry from, and are
/// sent just before the entry closes the connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TelemetryError {
    /// A record arrived with a sequence number past the next one the entry
    /// expects, `A + 1` where `A` is the last it acknowledged, and the
    /// batch was refused. Tagged `gap`.
    Gap {
        /// The sequence number the entry expects next, `A + 1`.
        expected: u64,
    },
    /// A range of sequence numbers whose `from` is greater than its `to`.
    /// Tagged `bad_range`.
    BadRange,
    /// Data arrived for a stream that has been closed, or an `open_stream`
    /// named the id of a closed stream. Tagged `closed`.
    Closed,
    /// A record or a batch exceeds its size limit. Tagged `too_large`.
    TooLarge,
    /// Data arrived for a stream not opened on this connection. Tagged
    /// `unknown_stream`.
    UnknownStream,
    /// A record is of a kind the entry does not accept. Tagged
    /// `unsupported_kind`.
    UnsupportedKind,
    /// The endpoint is not on the active list, or its license is pending.
    /// Tagged `not_listed`.
    NotListed,
    /// The endpoint is suspended. Tagged `suspended`.
    Suspended,
    /// The endpoint's lease has expired. Tagged `lease_expired`.
    LeaseExpired,
    /// An error this version of the crate does not know, by its tag.
    Other(String),
}

/// Why an endpoint dropped a range of records instead of sending them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// The endpoint's send queue overflowed. Tagged `buffer_overflow`.
    BufferOverflow,
    /// The records outlived the endpoint's retention period before they
    /// were acknowledged. Tagged `retention_expired`.
    RetentionExpired,
    /// The record is longer than the 256 KiB a record may be. Tagged
    /// `too_large`.
    TooLarge,
    /// The record is of a kind the entry does not accept. Used only in the
    /// dropped counts of a status report, never for a dropped range.
    /// Tagged `unsupported`.
    Unsupported,
    /// A reason this version of the crate does not know, by its tag.
    Other(String),
}

/// The field map of [`TelemetryError::Gap`].
#[derive(Serialize, Deserialize)]
struct GapFields {
    expected: u64,
}

/// The variants of [`TelemetryError`] with content.
pub(crate) enum TelemetryContent {
    Gap,
}

impl Serialize for TelemetryError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let tag = match self {
            Self::Gap { expected } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(
                    GAP,
                    &GapFields {
                        expected: *expected,
                    },
                )?;
                return map.end();
            }
            Self::BadRange => BAD_RANGE,
            Self::Closed => CLOSED,
            Self::TooLarge => TOO_LARGE,
            Self::UnknownStream => UNKNOWN_STREAM,
            Self::UnsupportedKind => UNSUPPORTED_KIND,
            Self::NotListed => NOT_LISTED,
            Self::Suspended => SUSPENDED,
            Self::LeaseExpired => LEASE_EXPIRED,
            Self::Other(tag) => tag,
        };
        serializer.serialize_str(tag)
    }
}

impl Serialize for DropReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::BufferOverflow => BUFFER_OVERFLOW,
            Self::RetentionExpired => RETENTION_EXPIRED,
            Self::TooLarge => TOO_LARGE,
            Self::Unsupported => UNSUPPORTED,
            Self::Other(tag) => tag,
        })
    }
}

impl Tagged for TelemetryError {
    type Content = TelemetryContent;

    const EXPECTING: &'static str = "a telemetry error tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            GAP => return Class::Content(TelemetryContent::Gap),
            BAD_RANGE => Self::BadRange,
            CLOSED => Self::Closed,
            TOO_LARGE => Self::TooLarge,
            UNKNOWN_STREAM => Self::UnknownStream,
            UNSUPPORTED_KIND => Self::UnsupportedKind,
            NOT_LISTED => Self::NotListed,
            SUSPENDED => Self::Suspended,
            LEASE_EXPIRED => Self::LeaseExpired,
            _ => return Class::Unknown,
        })
    }

    fn read_content<'de, A: MapAccess<'de>>(
        content: TelemetryContent,
        map: &mut A,
    ) -> Result<Self, A::Error> {
        match content {
            TelemetryContent::Gap => {
                let GapFields { expected } = map.next_value()?;
                Ok(Self::Gap { expected })
            }
        }
    }

    fn other(tag: String) -> Self {
        Self::Other(tag)
    }
}

impl Tagged for DropReason {
    type Content = Infallible;

    const EXPECTING: &'static str = "a drop reason tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            BUFFER_OVERFLOW => Self::BufferOverflow,
            RETENTION_EXPIRED => Self::RetentionExpired,
            TOO_LARGE => Self::TooLarge,
            UNSUPPORTED => Self::Unsupported,
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

impl<'de> Deserialize<'de> for TelemetryError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

impl<'de> Deserialize<'de> for DropReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use ciborium::Value;
    use serde::de::DeserializeOwned;

    use super::{DropReason, TelemetryError};
    use crate::connection::{DecodeErrorKind, cbor};

    fn encode(value: &Value) -> Vec<u8> {
        cbor::to_vec(value).unwrap()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, DecodeErrorKind> {
        cbor::from_slice(&encode(value)).map_err(|error| error.kind())
    }

    fn unit_errors() -> [(TelemetryError, &'static str); 8] {
        [
            (TelemetryError::BadRange, "bad_range"),
            (TelemetryError::Closed, "closed"),
            (TelemetryError::TooLarge, "too_large"),
            (TelemetryError::UnknownStream, "unknown_stream"),
            (TelemetryError::UnsupportedKind, "unsupported_kind"),
            (TelemetryError::NotListed, "not_listed"),
            (TelemetryError::Suspended, "suspended"),
            (TelemetryError::LeaseExpired, "lease_expired"),
        ]
    }

    fn drop_reasons() -> [(DropReason, &'static str); 4] {
        [
            (DropReason::BufferOverflow, "buffer_overflow"),
            (DropReason::RetentionExpired, "retention_expired"),
            (DropReason::TooLarge, "too_large"),
            (DropReason::Unsupported, "unsupported"),
        ]
    }

    fn assert_round_trip<T>(value: &T, shape: &Value)
    where
        T: serde::Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let bytes = cbor::to_vec(value).unwrap();
        assert_eq!(bytes, encode(shape), "{value:?}");
        assert_eq!(&cbor::from_slice::<T>(&bytes).unwrap(), value);
    }

    #[test]
    fn known_variants_round_trip_in_their_shapes() {
        for (error, tag) in unit_errors() {
            assert_round_trip(&error, &text(tag));
        }
        for expected in [0, 7, u64::MAX] {
            assert_round_trip(
                &TelemetryError::Gap { expected },
                &map(vec![(
                    text("gap"),
                    map(vec![(text("expected"), Value::from(expected))]),
                )]),
            );
        }
        for (reason, tag) in drop_reasons() {
            assert_round_trip(&reason, &text(tag));
        }
    }

    #[test]
    fn unknown_tags_become_other() {
        assert_eq!(
            decode::<TelemetryError>(&text("rate_limited")),
            Ok(TelemetryError::Other("rate_limited".to_owned()))
        );
        assert_eq!(
            decode::<DropReason>(&text("disk_full")),
            Ok(DropReason::Other("disk_full".to_owned()))
        );
        for content in [
            Value::Null,
            Value::from(-3),
            text("x"),
            Value::Array(vec![Value::from(1)]),
            map(vec![(Value::from(1), Value::Bool(true))]),
        ] {
            assert_eq!(
                decode::<TelemetryError>(&map(vec![(text("rate_limited"), content.clone())])),
                Ok(TelemetryError::Other("rate_limited".to_owned()))
            );
            assert_eq!(
                decode::<DropReason>(&map(vec![(text("disk_full"), content)])),
                Ok(DropReason::Other("disk_full".to_owned()))
            );
        }
        assert_round_trip(
            &TelemetryError::Other("rate_limited".to_owned()),
            &text("rate_limited"),
        );
        assert_round_trip(
            &DropReason::Other("disk_full".to_owned()),
            &text("disk_full"),
        );
    }

    #[test]
    fn known_unit_tags_as_maps_are_their_variants() {
        for (error, tag) in unit_errors() {
            assert_eq!(
                decode::<TelemetryError>(&map(vec![(text(tag), Value::from(1))])),
                Ok(error)
            );
        }
        for (reason, tag) in drop_reasons() {
            assert_eq!(
                decode::<DropReason>(&map(vec![(text(tag), Value::Null)])),
                Ok(reason)
            );
        }
    }

    #[test]
    fn gap_needs_its_field_map() {
        assert_eq!(
            decode::<TelemetryError>(&text("gap")),
            Err(DecodeErrorKind::Invalid)
        );
        assert_eq!(
            decode::<TelemetryError>(&map(vec![(text("gap"), map(vec![]))])),
            Err(DecodeErrorKind::Invalid)
        );
        assert_eq!(
            decode::<TelemetryError>(&map(vec![(
                text("gap"),
                map(vec![(text("expected"), Value::from(-1))])
            )])),
            Err(DecodeErrorKind::Invalid)
        );
        assert_eq!(
            decode::<TelemetryError>(&map(vec![(
                text("gap"),
                map(vec![(text("expected"), text("5"))])
            )])),
            Err(DecodeErrorKind::Invalid)
        );
        assert_eq!(
            decode::<TelemetryError>(&map(vec![(
                text("gap"),
                map(vec![
                    (text("expected"), Value::from(1)),
                    (text("expected"), Value::from(2)),
                ])
            )])),
            Err(DecodeErrorKind::DuplicateKey)
        );
        assert_eq!(
            decode::<TelemetryError>(&map(vec![(
                text("gap"),
                map(vec![
                    (text("since"), Value::from(1)),
                    (text("expected"), Value::from(9)),
                ])
            )])),
            Ok(TelemetryError::Gap { expected: 9 })
        );
    }

    #[test]
    fn rejects_other_shapes() {
        let cases = [
            map(vec![]),
            map(vec![
                (text("closed"), Value::Null),
                (text("too_large"), Value::Null),
            ]),
            map(vec![(Value::from(1), Value::Null)]),
            Value::from(1),
        ];
        for case in &cases {
            assert_eq!(
                decode::<TelemetryError>(case),
                Err(DecodeErrorKind::Invalid),
                "{case:?}"
            );
            assert_eq!(
                decode::<DropReason>(case),
                Err(DecodeErrorKind::Invalid),
                "{case:?}"
            );
        }
    }
}
