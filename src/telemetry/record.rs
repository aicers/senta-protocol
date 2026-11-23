//! The telemetry record, its host header, its open body, and the bytes and
//! hash a record is fixed to.

use std::{convert::Infallible, fmt, marker::PhantomData, net::IpAddr};

use ciborium::Value;
use jiff::Timestamp;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned, MapAccess},
    ser::SerializeMap,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ip;
use crate::connection::{ClockOffset, DecodeError, EncodeError, cbor};
use crate::host::{CollectionMode, OsFamily, OsInfo};
use crate::results::{Class, Tagged, TaggedVisitor};

const OBSERVED: &str = "observed";
const INFERRED: &str = "inferred";
const UNKNOWN: &str = "unknown";

/// The number of leading bytes of a record's SHA-256 that make its hash.
const RECORD_HASH_LEN: usize = 16;

/// One telemetry record: the host header, the record kind and its schema
/// version, and the kind's body.
///
/// A record is a CBOR map with the keys `header`, `kind`, `schema` and
/// `body`, all required; a key the receiver does not know is ignored.
///
/// The sender fixes a record's bytes once with [`Record::to_bytes`],
/// stores them, resends exactly those bytes, and hashes them with
/// [`record_hash`]. A receiver hashes the bytes it received, never a
/// re-encoding of what it decoded, so a receiver of another version, one
/// that ignores fields it does not know, still computes the sender's hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// The host header.
    pub header: RecordHeader,
    /// The record kind's number (see [`super::kind`]).
    pub kind: u16,
    /// The schema version of the kind's body.
    pub schema: u16,
    /// The body, whose shape the kind and its schema version decide.
    pub body: RecordBody,
}

/// The host header every record carries.
///
/// A CBOR map with the field names as text keys. `clock_offset`,
/// `default_route_ip` and `process_key` are optional: with no value the key
/// is not sent, and a missing key and a null both read as no value. Every
/// other field is required, `ips` included, which is sent as an empty
/// array when there are no addresses. A key the receiver does not know is
/// ignored.
///
/// The fields of the header are not subject to field exclusion (the
/// `field_exclusions` of the `senta-policy` document): that policy applies
/// to the body only, and the sender applies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordHeader {
    /// The endpoint's id. A receiver only checks it against the id of the
    /// connection, and never takes it as the source's identity.
    #[serde(with = "cbor::uuid")]
    pub endpoint_id: Uuid,
    /// The id of the stream the record belongs to.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
    /// The record's sequence number within its stream.
    pub seq: u64,
    /// When the event happened. It stays as it is even when the time of the
    /// storage key is moved to resolve a collision.
    #[serde(with = "cbor::timestamp")]
    pub event_time: Timestamp,
    /// When the sender read the event, by its own clock.
    #[serde(with = "cbor::timestamp")]
    pub collected_at: Timestamp,
    /// The measured clock offset (server minus endpoint), its uncertainty
    /// and when it was measured. The other times are not corrected by it;
    /// it is kept beside them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_offset: Option<ClockOffset>,
    /// The host name when the event happened.
    pub hostname: String,
    /// The host's IP addresses when the event happened.
    #[serde(with = "ip::list")]
    pub ips: Vec<IpAddr>,
    /// The IP address of the default route when the event happened.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "ip::option")]
    pub default_route_ip: Option<IpAddr>,
    /// Where `ips` and `default_route_ip` come from.
    pub net_state_source: NetStateSource,
    /// The operating system.
    pub os: OsInfo,
    /// The collection mode.
    pub collection_mode: CollectionMode,
    /// The key of the record's principal process, where the kind has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_key: Option<ProcessKey>,
}

/// Where a record header's network state comes from.
///
/// A text tag, decoded by the rules of [`crate::results`]: a tag this
/// crate does not know becomes `Other(tag)`, whether it comes as text or as
/// a one-entry map whose content is discarded, and a known tag that comes
/// as a one-entry map is its variant. `Other(s)` encodes as the text `s`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetStateSource {
    /// Recorded while the sender was running, tagged `observed`.
    Observed,
    /// Carried over a short gap in the record across which the state did
    /// not change, tagged `inferred`.
    Inferred,
    /// Not known, tagged `unknown`. The header then has no addresses.
    Unknown,
    /// A source this version of the crate does not know, by its tag.
    Other(String),
}

/// The key of a process on its host: the OS family it belongs to and an
/// opaque value whose meaning that family decides.
///
/// A CBOR map `{os, value}`, with `value` a byte string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    /// The OS family whose rules made the key.
    pub os: OsFamily,
    /// The key's bytes.
    #[serde(with = "cbor::bytes")]
    pub value: Vec<u8>,
}

/// A record's body: an open CBOR map, kept entry by entry.
///
/// Decoding a record keeps every entry of its body, keys and values,
/// nested values included, without looking at what they mean, so a kind's
/// own type can read them with [`RecordBody::decode`]; encoding writes the
/// same entries back. A body that is not a map fails to decode, as does
/// one holding the same key twice at any depth. CBOR tags other than the
/// bignums, indefinite lengths and the width a float was encoded at are not
/// kept: the record's hash is taken over the bytes received, so it does not
/// depend on them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecordBody {
    entries: Vec<(Value, Value)>,
}

impl RecordBody {
    /// Encodes a kind's body type as an open map.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` refuses to serialize, or does not
    /// serialize as a CBOR map, or serializes as one that holds the same
    /// key twice at some depth.
    pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Self, EncodeError> {
        let bytes = cbor::to_vec(value)?;
        match cbor::from_slice::<Value>(&bytes) {
            Ok(Value::Map(entries)) => Ok(Self { entries }),
            Ok(_) => Err(EncodeError::new("a record body must serialize as a map")),
            Err(error) => Err(EncodeError::new(format!("record body: {error}"))),
        }
    }

    /// Decodes the body's entries into a kind's body type.
    ///
    /// The entries are read by the rules of [`cbor::from_slice`]: each
    /// value only from the CBOR type its rule names, and a field `T` does
    /// not name ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the entries do not decode into `T`, or, which
    /// entries this body was made with never cause, do not encode again.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, DecodeError> {
        let bytes = cbor::to_vec(&EntriesRef(&self.entries))
            .map_err(|error| DecodeError::invalid(format!("record body: {error}")))?;
        cbor::from_slice(&bytes)
    }
}

/// The body's entries, serialized as a map.
struct EntriesRef<'a>(&'a [(Value, Value)]);

impl Serialize for EntriesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Serialize for RecordBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EntriesRef(&self.entries).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecordBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Map(entries) => Ok(Self { entries }),
            _ => Err(de::Error::custom("a record body must be a map")),
        }
    }
}

/// An error fixing a record's bytes: the record breaks a rule a sender
/// must keep, or does not encode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordEncodeError {
    /// `net_state_source` is [`NetStateSource::Unknown`], but the header
    /// has `ips` or a `default_route_ip`.
    UnknownNetStateWithAddresses,
    /// The record does not encode as CBOR.
    Encode(EncodeError),
}

impl fmt::Display for RecordEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNetStateWithAddresses => f.write_str(
                "the network state source is unknown, but the header carries IP addresses",
            ),
            Self::Encode(error) => write!(f, "record: {error}"),
        }
    }
}

impl std::error::Error for RecordEncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnknownNetStateWithAddresses => None,
            Self::Encode(error) => Some(error),
        }
    }
}

impl From<EncodeError> for RecordEncodeError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl Record {
    /// Checks the rules a sender must keep when it makes a record.
    ///
    /// When `net_state_source` is [`NetStateSource::Unknown`], `ips` must be
    /// empty and `default_route_ip` absent. Decoding does not check this:
    /// a receiver does not refuse a record for its sender's mistake.
    ///
    /// # Errors
    ///
    /// Returns [`RecordEncodeError::UnknownNetStateWithAddresses`] when the
    /// rule above is broken.
    pub fn validate(&self) -> Result<(), RecordEncodeError> {
        let header = &self.header;
        if header.net_state_source == NetStateSource::Unknown
            && (!header.ips.is_empty() || header.default_route_ip.is_some())
        {
            return Err(RecordEncodeError::UnknownNetStateWithAddresses);
        }
        Ok(())
    }

    /// Fixes the record's bytes: checks it with [`Record::validate`], then
    /// encodes it as CBOR.
    ///
    /// The sender keeps these bytes, resends them unchanged, and hashes
    /// them with [`record_hash`].
    ///
    /// # Errors
    ///
    /// Returns the error of [`Record::validate`], or
    /// [`RecordEncodeError::Encode`] when the record does not encode, which
    /// a time outside the range of an `i64` count of nanoseconds causes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecordEncodeError> {
        self.validate()?;
        Ok(cbor::to_vec(self)?)
    }

    /// Decodes a record from its bytes, by the rules of
    /// [`cbor::from_slice`].
    ///
    /// A field the decoder does not know, at the top level, in the header
    /// or in a struct nested in it, is ignored. The body is kept entry by
    /// entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not one well-formed CBOR value,
    /// hold a duplicate map key at any depth (the body included), lack a
    /// required field, hold a `kind` or `schema` outside the range of a
    /// `u16`, or hold a body that is not a map.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        cbor::from_slice(bytes)
    }
}

/// Returns a record's hash: the first 16 bytes of the SHA-256 of its bytes.
///
/// `bytes` are the record's own CBOR value, as [`Record::to_bytes`] made
/// them or as they were received, without the head of the byte string a
/// batch wraps them in. They are not decoded, so any bytes hash, and the
/// hash is that of the bytes as they are, whatever a decoder would make of
/// them.
#[must_use]
pub fn record_hash(bytes: &[u8]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut hash = [0; RECORD_HASH_LEN];
    hash.copy_from_slice(&digest[..RECORD_HASH_LEN]);
    hash
}

impl NetStateSource {
    fn tag(&self) -> &str {
        match self {
            Self::Observed => OBSERVED,
            Self::Inferred => INFERRED,
            Self::Unknown => UNKNOWN,
            Self::Other(tag) => tag,
        }
    }
}

impl Serialize for NetStateSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.tag())
    }
}

impl Tagged for NetStateSource {
    type Content = Infallible;

    const EXPECTING: &'static str = "a network state source tag, or a one-entry map from a tag";

    fn classify(tag: &str) -> Class<Self> {
        Class::Unit(match tag {
            OBSERVED => Self::Observed,
            INFERRED => Self::Inferred,
            UNKNOWN => Self::Unknown,
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

impl<'de> Deserialize<'de> for NetStateSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TaggedVisitor(PhantomData))
    }
}
