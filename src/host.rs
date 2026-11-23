//! What an endpoint reports about its host: the operating system and the
//! collection mode.
//!
//! A telemetry record's header and the control channel's registration
//! request and status report carry the same values, so they share these
//! types. They belong to no feature, so this module is always public.
//!
//! # CBOR shape
//!
//! [`OsInfo`] is a map with the field names as text keys; a field the
//! receiver does not know is ignored. [`OsFamily`] and [`CollectionMode`]
//! are text tags and decode by the rules of [`crate::results`]: a tag this
//! crate does not know becomes `Other(tag)`, whether it comes as text or
//! as a one-entry map whose content is discarded; a known tag that comes
//! as a one-entry map is its variant; a map with no entry or more than
//! one, a map key that is not text, and any value that is neither text nor
//! a map are errors. `Other(s)` encodes as the text `s`, so it survives a
//! round trip only when `s` is not one of the enum's tags.

use std::{convert::Infallible, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::MapAccess};

use crate::results::{Class, Tagged, TaggedVisitor};

const WINDOWS: &str = "windows";
const LINUX: &str = "linux";
const MACOS: &str = "macos";

const EXTENDED: &str = "extended";
const ESSENTIAL: &str = "essential";

/// An operating system family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OsFamily {
    /// Windows, tagged `windows`.
    Windows,
    /// Linux, tagged `linux`.
    Linux,
    /// macOS, tagged `macos`.
    Macos,
    /// A family this version of the crate does not know, by its tag.
    Other(String),
}

/// The operating system of a host: its family and version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OsInfo {
    /// The operating system family.
    pub family: OsFamily,
    /// The operating system version, as the host reports it.
    pub version: String,
}

/// How much an endpoint collects.
///
/// This is the value carried on the wire, in record headers and on the
/// control channel. The signed `senta-policy` document's `collection_mode`
/// is a different, closed type,
/// `senta_protocol::auth::documents::PolicyCollectionMode`, under the
/// `auth` feature; the crate converts neither into the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CollectionMode {
    /// Extended collection, tagged `extended`.
    Extended,
    /// Essential collection, tagged `essential`.
    Essential,
    /// A mode this version of the crate does not know, by its tag.
    Other(String),
}

impl OsFamily {
    fn tag(&self) -> &str {
        match self {
            Self::Windows => WINDOWS,
            Self::Linux => LINUX,
            Self::Macos => MACOS,
            Self::Other(tag) => tag,
        }
    }
}

impl CollectionMode {
    fn tag(&self) -> &str {
        match self {
            Self::Extended => EXTENDED,
            Self::Essential => ESSENTIAL,
            Self::Other(tag) => tag,
        }
    }
}

impl Serialize for OsFamily {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.tag())
    }
}

impl Serialize for CollectionMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.tag())
    }
}

impl Tagged for OsFamily {
    type Content = Infallible;

    const EXPECTING: &'static str = "an OS family tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            WINDOWS => Self::Windows,
            LINUX => Self::Linux,
            MACOS => Self::Macos,
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

impl Tagged for CollectionMode {
    type Content = Infallible;

    const EXPECTING: &'static str = "a collection mode tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            EXTENDED => Self::Extended,
            ESSENTIAL => Self::Essential,
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

impl<'de> Deserialize<'de> for OsFamily {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

impl<'de> Deserialize<'de> for CollectionMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::{CollectionMode, OsFamily, OsInfo};
    use crate::connection::{DecodeErrorKind, cbor};

    fn encode(value: &Value) -> Vec<u8> {
        cbor::to_vec(value).unwrap()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    #[test]
    fn known_tags_round_trip_as_text() {
        for (family, tag) in [
            (OsFamily::Windows, "windows"),
            (OsFamily::Linux, "linux"),
            (OsFamily::Macos, "macos"),
        ] {
            let bytes = cbor::to_vec(&family).unwrap();
            assert_eq!(bytes, encode(&text(tag)));
            assert_eq!(cbor::from_slice::<OsFamily>(&bytes).unwrap(), family);
        }
        for (mode, tag) in [
            (CollectionMode::Extended, "extended"),
            (CollectionMode::Essential, "essential"),
        ] {
            let bytes = cbor::to_vec(&mode).unwrap();
            assert_eq!(bytes, encode(&text(tag)));
            assert_eq!(cbor::from_slice::<CollectionMode>(&bytes).unwrap(), mode);
        }
    }

    #[test]
    fn unknown_and_mapped_tags() {
        let unknown = encode(&text("solaris"));
        assert_eq!(
            cbor::from_slice::<OsFamily>(&unknown).unwrap(),
            OsFamily::Other("solaris".to_owned())
        );
        let mapped_unknown = encode(&Value::Map(vec![(text("minimal"), Value::from(1))]));
        assert_eq!(
            cbor::from_slice::<CollectionMode>(&mapped_unknown).unwrap(),
            CollectionMode::Other("minimal".to_owned())
        );
        let mapped_known = encode(&Value::Map(vec![(text("linux"), Value::Null)]));
        assert_eq!(
            cbor::from_slice::<OsFamily>(&mapped_known).unwrap(),
            OsFamily::Linux
        );
        let other = CollectionMode::Other("minimal".to_owned());
        let bytes = cbor::to_vec(&other).unwrap();
        assert_eq!(cbor::from_slice::<CollectionMode>(&bytes).unwrap(), other);
    }

    #[test]
    fn rejects_two_entry_maps_and_integers() {
        let two = encode(&Value::Map(vec![
            (text("linux"), Value::Null),
            (text("macos"), Value::Null),
        ]));
        assert_eq!(
            cbor::from_slice::<OsFamily>(&two).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );
        let int = encode(&Value::from(1));
        assert_eq!(
            cbor::from_slice::<CollectionMode>(&int).unwrap_err().kind(),
            DecodeErrorKind::Invalid
        );
    }

    #[test]
    fn os_info_is_a_field_map() {
        let info = OsInfo {
            family: OsFamily::Windows,
            version: "10.0.22631".to_owned(),
        };
        let bytes = cbor::to_vec(&info).unwrap();
        assert_eq!(
            bytes,
            encode(&Value::Map(vec![
                (text("family"), text("windows")),
                (text("version"), text("10.0.22631")),
            ]))
        );
        assert_eq!(cbor::from_slice::<OsInfo>(&bytes).unwrap(), info);
    }
}
