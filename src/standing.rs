//! An endpoint's standing with REview: why it was suspended.
//!
//! The control channel's suspension notice carries [`SuspendReason`], and
//! the active list records it for a suspended endpoint, so the type belongs
//! to no feature and this module is always public.
//!
//! # CBOR shape
//!
//! [`SuspendReason`] is a text tag and decodes by the rules of
//! [`crate::results`]: a tag this crate does not know becomes
//! `Other(tag)`, whether it comes as text or as a one-entry map whose
//! content is discarded; a known tag that comes as a one-entry map is its
//! variant; a map with no entry or more than one, a map key that is not
//! text, and any value that is neither text nor a map are errors.
//! `Other(s)` encodes as the text `s`, so it survives a round trip only
//! when `s` is not one of the enum's tags.

use std::{convert::Infallible, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::MapAccess};

use crate::results::{Class, Tagged, TaggedVisitor};

const REVOKED: &str = "revoked";
const OPERATOR: &str = "operator";
const LICENSE: &str = "license";

/// Why an endpoint was suspended.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SuspendReason {
    /// The endpoint's registration was revoked, tagged `revoked`.
    Revoked,
    /// An operator suspended the endpoint, tagged `operator`.
    Operator,
    /// The license does not cover the endpoint, tagged `license`.
    License,
    /// A reason this version of the crate does not know, by its tag.
    Other(String),
}

impl SuspendReason {
    fn tag(&self) -> &str {
        match self {
            Self::Revoked => REVOKED,
            Self::Operator => OPERATOR,
            Self::License => LICENSE,
            Self::Other(tag) => tag,
        }
    }
}

impl Serialize for SuspendReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.tag())
    }
}

impl Tagged for SuspendReason {
    type Content = Infallible;

    const EXPECTING: &'static str = "a suspension reason tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            REVOKED => Self::Revoked,
            OPERATOR => Self::Operator,
            LICENSE => Self::License,
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

impl<'de> Deserialize<'de> for SuspendReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::SuspendReason;
    use crate::connection::{DecodeErrorKind, cbor};

    fn encode(value: &Value) -> Vec<u8> {
        cbor::to_vec(value).unwrap()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    #[test]
    fn known_tags_round_trip_as_text() {
        for (reason, tag) in [
            (SuspendReason::Revoked, "revoked"),
            (SuspendReason::Operator, "operator"),
            (SuspendReason::License, "license"),
        ] {
            let bytes = cbor::to_vec(&reason).unwrap();
            assert_eq!(bytes, encode(&text(tag)));
            assert_eq!(cbor::from_slice::<SuspendReason>(&bytes).unwrap(), reason);
        }
    }

    #[test]
    fn known_tag_as_a_map_is_its_variant() {
        let bytes = encode(&Value::Map(vec![(text("operator"), Value::from(7))]));
        assert_eq!(
            cbor::from_slice::<SuspendReason>(&bytes).unwrap(),
            SuspendReason::Operator
        );
    }

    #[test]
    fn unknown_tags_become_other_and_round_trip() {
        let other = SuspendReason::Other("quarantine".to_owned());
        assert_eq!(
            cbor::from_slice::<SuspendReason>(&encode(&text("quarantine"))).unwrap(),
            other
        );
        let mapped = encode(&Value::Map(vec![(
            text("quarantine"),
            Value::Map(vec![(text("until"), Value::from(3))]),
        )]));
        assert_eq!(cbor::from_slice::<SuspendReason>(&mapped).unwrap(), other);
        let bytes = cbor::to_vec(&other).unwrap();
        assert_eq!(bytes, encode(&text("quarantine")));
        assert_eq!(cbor::from_slice::<SuspendReason>(&bytes).unwrap(), other);
    }

    #[test]
    fn rejects_other_shapes() {
        for value in [
            Value::Map(vec![]),
            Value::Map(vec![
                (text("revoked"), Value::Null),
                (text("license"), Value::Null),
            ]),
            Value::Map(vec![(Value::from(1), Value::Null)]),
            Value::from(1),
            Value::Bytes(b"revoked".to_vec()),
            Value::Array(vec![text("revoked")]),
        ] {
            assert_eq!(
                cbor::from_slice::<SuspendReason>(&encode(&value))
                    .unwrap_err()
                    .kind(),
                DecodeErrorKind::Invalid,
                "{value:?}"
            );
        }
    }
}
