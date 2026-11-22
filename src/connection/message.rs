//! The five messages every connection shares: version negotiation and
//! liveness.

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The protocol version this crate speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// A message that travels in an envelope under a fixed `t`.
pub trait Message: Serialize + DeserializeOwned {
    /// The message's name on the wire: the `t` of its envelope.
    const T: &'static str;
}

/// An inclusive range of protocol versions.
///
/// A range whose `min` is greater than its `max` holds no version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    /// The lowest version in the range.
    pub min: u16,
    /// The highest version in the range.
    pub max: u16,
}

impl VersionRange {
    /// Creates the range from `min` to `max`, both included.
    #[must_use]
    pub const fn new(min: u16, max: u16) -> Self {
        Self { min, max }
    }

    /// Reports whether `version` lies in the range.
    #[must_use]
    pub fn contains(&self, version: u16) -> bool {
        self.min <= version && version <= self.max
    }

    /// Returns the highest version both ranges hold, or `None` when they
    /// share none.
    #[must_use]
    pub fn highest_common(&self, other: &Self) -> Option<u16> {
        let low = self.min.max(other.min);
        let high = self.max.min(other.max);
        (self.min <= self.max && other.min <= other.max && low <= high).then_some(high)
    }
}

impl Default for VersionRange {
    /// Returns `1..=1`: [`PROTOCOL_VERSION`] alone.
    fn default() -> Self {
        Self::new(PROTOCOL_VERSION, PROTOCOL_VERSION)
    }
}

/// The endpoint's first message: who it is and what it speaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The version of the sender's crate.
    pub crate_version: String,
    /// The protocol versions the sender speaks.
    pub versions: VersionRange,
    /// The sender's wall clock as it sent the message.
    #[serde(with = "super::cbor::timestamp")]
    pub sent_at: Timestamp,
}

impl Message for Hello {
    const T: &'static str = "hello";
}

/// One record kind a telemetry entry accepts, with the schema versions of
/// it that it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedKind {
    /// The record kind's number.
    pub kind: u16,
    /// The lowest schema version accepted.
    pub schema_min: u16,
    /// The highest schema version accepted.
    pub schema_max: u16,
}

/// The server's answer to a [`Hello`] that it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// The protocol version chosen.
    pub version: u16,
    /// The server's wall clock as it handled the `hello`.
    #[serde(with = "super::cbor::timestamp")]
    pub server_time: Timestamp,
    /// The telemetry entry's identity; sent on telemetry connections only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::cbor::uuid::option"
    )]
    pub entry_id: Option<Uuid>,
    /// The record kinds the telemetry entry accepts; sent on telemetry
    /// connections only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_kinds: Option<Vec<AcceptedKind>>,
}

impl Message for HelloAck {
    const T: &'static str = "hello_ack";
}

/// A liveness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// The sender's wall clock as it sent the message.
    #[serde(with = "super::cbor::timestamp")]
    pub sent_at: Timestamp,
}

impl Message for Ping {
    const T: &'static str = "ping";
}

/// The answer to a [`Ping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    /// The `sent_at` of the `ping` answered.
    #[serde(with = "super::cbor::timestamp")]
    pub ping_sent_at: Timestamp,
    /// The sender's wall clock as it sent the message.
    #[serde(with = "super::cbor::timestamp")]
    pub sent_at: Timestamp,
}

impl Message for Pong {
    const T: &'static str = "pong";
}

/// A refusal of a message the receiver does not handle, or of the
/// `hello` when no protocol version is shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unsupported {
    /// The `t` refused, or [`Unsupported::VERSION`] when version
    /// negotiation failed.
    pub kind: String,
}

impl Unsupported {
    /// The `kind` that reports a failed version negotiation.
    pub const VERSION: &'static str = "version";

    /// Creates the refusal of a failed version negotiation.
    #[must_use]
    pub fn version() -> Self {
        Self {
            kind: Self::VERSION.to_owned(),
        }
    }

    /// Reports whether this is the refusal of a failed version
    /// negotiation.
    #[must_use]
    pub fn is_version(&self) -> bool {
        self.kind == Self::VERSION
    }
}

impl Message for Unsupported {
    const T: &'static str = "unsupported";
}

/// The messages the connection helpers handle themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BuiltIn {
    Hello,
    HelloAck,
    Ping,
    Pong,
    Unsupported,
}

impl BuiltIn {
    pub(super) fn from_t(t: &str) -> Option<Self> {
        match t {
            Hello::T => Some(Self::Hello),
            HelloAck::T => Some(Self::HelloAck),
            Ping::T => Some(Self::Ping),
            Pong::T => Some(Self::Pong),
            Unsupported::T => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cbor;
    use super::super::envelope::Envelope;
    use super::super::frame::Frame;
    use super::*;

    fn at(nanos: i64) -> Timestamp {
        Timestamp::from_nanosecond(i128::from(nanos)).unwrap()
    }

    /// The text keys of a CBOR map, sorted.
    fn keys(bytes: &[u8]) -> Vec<String> {
        cbor::from_slice::<std::collections::BTreeMap<String, serde::de::IgnoredAny>>(bytes)
            .unwrap()
            .into_keys()
            .collect()
    }

    fn round_trip<M: Message + PartialEq + std::fmt::Debug>(message: &M, expected_keys: &[&str]) {
        let frame = Frame::from_message(message).unwrap();
        let envelope = Envelope::parse(frame.payload()).unwrap();
        assert_eq!(envelope.t(), M::T);
        assert_eq!(&envelope.body().decode::<M>().unwrap(), message);
        let mut expected: Vec<String> = expected_keys.iter().map(|&key| key.to_owned()).collect();
        expected.sort_unstable();
        assert_eq!(keys(envelope.body().as_bytes()), expected);
    }

    #[test]
    fn the_five_round_trip_under_their_names() {
        round_trip(
            &Hello {
                crate_version: "0.1.0".to_owned(),
                versions: VersionRange::new(1, 3),
                sent_at: at(1_700_000_000_000_000_001),
            },
            &["crate_version", "versions", "sent_at"],
        );
        round_trip(
            &HelloAck {
                version: 1,
                server_time: at(5),
                entry_id: Some(Uuid::from_u128(9)),
                accepted_kinds: Some(vec![AcceptedKind {
                    kind: 1,
                    schema_min: 1,
                    schema_max: 2,
                }]),
            },
            &["version", "server_time", "entry_id", "accepted_kinds"],
        );
        round_trip(
            &HelloAck {
                version: 1,
                server_time: at(5),
                entry_id: None,
                accepted_kinds: None,
            },
            &["version", "server_time"],
        );
        round_trip(&Ping { sent_at: at(-3) }, &["sent_at"]);
        round_trip(
            &Pong {
                ping_sent_at: at(1),
                sent_at: at(2),
            },
            &["ping_sent_at", "sent_at"],
        );
        round_trip(&Unsupported::version(), &["kind"]);

        assert_eq!(
            [Hello::T, HelloAck::T, Ping::T, Pong::T, Unsupported::T],
            ["hello", "hello_ack", "ping", "pong", "unsupported"]
        );
    }

    #[test]
    fn nested_field_names() {
        let versions = cbor::to_vec(&VersionRange::new(1, 2)).unwrap();
        assert_eq!(keys(&versions), ["max", "min"]);
        let kind = cbor::to_vec(&AcceptedKind {
            kind: 1,
            schema_min: 1,
            schema_max: 1,
        })
        .unwrap();
        assert_eq!(keys(&kind), ["kind", "schema_max", "schema_min"]);
    }

    #[test]
    fn hello_ack_reads_null_as_absent() {
        // {"version": 1, "server_time": 0, "entry_id": null, "accepted_kinds": null}
        let mut bytes = vec![0xa4, 0x67];
        bytes.extend_from_slice(b"version");
        bytes.push(0x01);
        bytes.push(0x6b);
        bytes.extend_from_slice(b"server_time");
        bytes.push(0x00);
        bytes.push(0x68);
        bytes.extend_from_slice(b"entry_id");
        bytes.push(0xf6);
        bytes.push(0x6e);
        bytes.extend_from_slice(b"accepted_kinds");
        bytes.push(0xf6);
        let ack: HelloAck = cbor::from_slice(&bytes).unwrap();
        assert_eq!(ack.entry_id, None);
        assert_eq!(ack.accepted_kinds, None);
    }

    #[test]
    fn version_ranges_negotiate_the_highest_common_version() {
        let ours = VersionRange::new(1, 3);
        assert_eq!(ours.highest_common(&VersionRange::new(2, 5)), Some(3));
        assert_eq!(ours.highest_common(&VersionRange::new(0, 1)), Some(1));
        assert_eq!(ours.highest_common(&VersionRange::new(4, 5)), None);
        assert_eq!(ours.highest_common(&VersionRange::new(3, 2)), None);
        assert_eq!(VersionRange::new(3, 2).highest_common(&ours), None);
        assert_eq!(VersionRange::default(), VersionRange::new(1, 1));
        assert!(ours.contains(2));
        assert!(!ours.contains(4));
    }
}
