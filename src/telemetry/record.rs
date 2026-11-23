//! The telemetry record, its host header, its open body, and the bytes and
//! hash a record is fixed to.

use std::{convert::Infallible, fmt, marker::PhantomData, net::IpAddr};

use jiff::Timestamp;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    ser::{self, SerializeMap, SerializeSeq},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ip;
use crate::connection::cbor::put_head;
use crate::connection::{ClockOffset, DecodeError, EncodeError, cbor};
use crate::host::{CollectionMode, OsFamily, OsInfo};
use crate::results::{Class, Tagged, TaggedVisitor};

const OBSERVED: &str = "observed";
const INFERRED: &str = "inferred";
const UNKNOWN: &str = "unknown";

const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;
const SIMPLE_UNDEFINED: u8 = 23;

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
///
/// `undefined` is kept apart from `null`, so [`RecordBody::decode`] refuses
/// it wherever [`cbor::from_slice`] would, an optional field included. It
/// cannot be encoded again, though: a body holding `undefined`, which only
/// a received record can, fails to encode.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecordBody {
    entries: Vec<(BodyValue, BodyValue)>,
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
        match cbor::from_slice::<BodyValue>(&bytes) {
            Ok(BodyValue::Map(entries)) => Ok(Self { entries }),
            Ok(_) => Err(EncodeError::new("a record body must serialize as a map")),
            Err(error) => Err(EncodeError::new(format!("record body: {error}"))),
        }
    }

    /// Decodes the body's entries into a kind's body type.
    ///
    /// The entries are read by the rules of [`cbor::from_slice`]: each
    /// value only from the CBOR type its rule names, `undefined` never
    /// standing in for `null`, and a field `T` does not name ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the entries do not decode into `T`, or, which
    /// entries this body was made with never cause, do not encode again.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, DecodeError> {
        let mut bytes = Vec::new();
        write_map(&mut bytes, &self.entries)
            .map_err(|error| DecodeError::invalid(format!("record body: {error}")))?;
        cbor::from_slice(&bytes)
    }
}

/// One value in a record's body: CBOR's data model less tags, with
/// `undefined` kept apart from `null`.
///
/// The crate's decoder hands `null` to a visitor as a unit and `undefined`
/// as none, which is how the two are told apart here.
#[derive(Debug, Clone, PartialEq)]
enum BodyValue {
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<BodyValue>),
    Map(Vec<(BodyValue, BodyValue)>),
    Float(f64),
    Bool(bool),
    Null,
    Undefined,
}

/// Appends the CBOR of a map of body entries.
///
/// The containers and `undefined` are written here; every other value is
/// written by [`cbor::to_vec`].
fn write_map(out: &mut Vec<u8>, entries: &[(BodyValue, BodyValue)]) -> Result<(), EncodeError> {
    put_head(out, MAJOR_MAP, len_u64(entries.len()));
    for (key, value) in entries {
        write_value(out, key)?;
        write_value(out, value)?;
    }
    Ok(())
}

/// Appends the CBOR of one body value; see [`write_map`].
fn write_value(out: &mut Vec<u8>, value: &BodyValue) -> Result<(), EncodeError> {
    match value {
        BodyValue::Array(items) => {
            put_head(out, MAJOR_ARRAY, len_u64(items.len()));
            for item in items {
                write_value(out, item)?;
            }
        }
        BodyValue::Map(entries) => write_map(out, entries)?,
        BodyValue::Undefined => put_head(out, MAJOR_SIMPLE, u64::from(SIMPLE_UNDEFINED)),
        BodyValue::Integer(_)
        | BodyValue::Bytes(_)
        | BodyValue::Text(_)
        | BodyValue::Float(_)
        | BodyValue::Bool(_)
        | BodyValue::Null => out.extend_from_slice(&cbor::to_vec(value)?),
    }
    Ok(())
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).expect("a length in memory fits in a u64 on every supported target")
}

impl Serialize for BodyValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Integer(value) => {
                if let Ok(value) = u64::try_from(*value) {
                    serializer.serialize_u64(value)
                } else if let Ok(value) = i64::try_from(*value) {
                    serializer.serialize_i64(value)
                } else {
                    serializer.serialize_i128(*value)
                }
            }
            Self::Bytes(bytes) => serializer.serialize_bytes(bytes),
            Self::Text(text) => serializer.serialize_str(text),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Map(entries) => EntriesRef(entries).serialize(serializer),
            Self::Float(value) => serializer.serialize_f64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Null => serializer.serialize_unit(),
            Self::Undefined => Err(ser::Error::custom(
                "a record body holding undefined cannot be encoded",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for BodyValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BodyValueVisitor)
    }
}

struct BodyValueVisitor;

impl<'de> Visitor<'de> for BodyValueVisitor {
    type Value = BodyValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CBOR value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<BodyValue, E> {
        Ok(BodyValue::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<BodyValue, E> {
        Ok(BodyValue::Integer(i128::from(value)))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<BodyValue, E> {
        Ok(BodyValue::Integer(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<BodyValue, E> {
        Ok(BodyValue::Integer(i128::from(value)))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<BodyValue, E> {
        i128::try_from(value)
            .map(BodyValue::Integer)
            .map_err(|_| E::custom("integer outside the range of i128"))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<BodyValue, E> {
        Ok(BodyValue::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<BodyValue, E> {
        Ok(BodyValue::Text(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<BodyValue, E> {
        Ok(BodyValue::Text(value))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<BodyValue, E> {
        Ok(BodyValue::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<BodyValue, E> {
        Ok(BodyValue::Bytes(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<BodyValue, E> {
        Ok(BodyValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<BodyValue, E> {
        Ok(BodyValue::Undefined)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<BodyValue, D::Error> {
        BodyValue::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<BodyValue, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(BodyValue::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<BodyValue, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry()? {
            entries.push(entry);
        }
        Ok(BodyValue::Map(entries))
    }
}

/// The body's entries, serialized as a map.
struct EntriesRef<'a>(&'a [(BodyValue, BodyValue)]);

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
        match BodyValue::deserialize(deserializer)? {
            BodyValue::Map(entries) => Ok(Self { entries }),
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
    /// a time outside the range of an `i64` count of nanoseconds causes, as
    /// does a received body holding `undefined` (see [`RecordBody`]).
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
