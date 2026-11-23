//! A serde helper writing an IP address as a CBOR byte string of its
//! octets.
//!
//! An IPv4 address is a byte string of 4 bytes and an IPv6 address one of
//! 16 bytes; a byte string of any other length fails to decode, and so
//! does any value that is not a byte string. An IPv4-mapped IPv6 address
//! (`::ffff:a.b.c.d`) stays an IPv6 address of 16 bytes both ways: it is
//! never turned into IPv4.
//!
//! Like the helpers of [`crate::connection::cbor`], it is used with
//! `#[serde(with = "...")]`: this module for an [`IpAddr`], [`option`] for
//! an `Option<IpAddr>` and [`list`] for a `Vec<IpAddr>`.
//!
//! ```
//! use std::net::IpAddr;
//!
//! use senta_protocol::connection::cbor;
//! use senta_protocol::telemetry::ip;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct Example {
//!     #[serde(with = "ip")]
//!     peer: IpAddr,
//!     #[serde(default, skip_serializing_if = "Option::is_none", with = "ip::option")]
//!     gateway: Option<IpAddr>,
//!     #[serde(with = "ip::list")]
//!     local: Vec<IpAddr>,
//! }
//!
//! let value = Example {
//!     peer: "192.0.2.1".parse()?,
//!     gateway: None,
//!     local: vec!["2001:db8::1".parse()?],
//! };
//! let bytes = cbor::to_vec(&value)?;
//! assert_eq!(cbor::from_slice::<Example>(&bytes)?, value);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use crate::connection::cbor;

/// Serializes an IP address as a byte string of 4 or 16 bytes.
///
/// # Errors
///
/// Returns the serializer's error.
pub fn serialize<S: Serializer>(value: &IpAddr, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        IpAddr::V4(addr) => serializer.serialize_bytes(&addr.octets()),
        IpAddr::V6(addr) => serializer.serialize_bytes(&addr.octets()),
    }
}

/// Deserializes an IP address from a byte string of 4 or 16 bytes.
///
/// # Errors
///
/// Returns an error when the value is not a byte string, or is one whose
/// length is neither 4 nor 16.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<IpAddr, D::Error> {
    let bytes: Vec<u8> = cbor::bytes::deserialize(deserializer)?;
    if let Ok(octets) = <[u8; 4]>::try_from(bytes.as_slice()) {
        return Ok(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if let Ok(octets) = <[u8; 16]>::try_from(bytes.as_slice()) {
        return Ok(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    Err(de::Error::custom(format_args!(
        "IP address: unexpected byte length {}, expected 4 or 16",
        bytes.len()
    )))
}

struct Repr(IpAddr);

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

/// The same, for an optional IP address.
pub mod option {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::Repr;

    /// Serializes an optional IP address: a byte string, or null.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<S: Serializer>(
        value: &Option<IpAddr>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&Repr(*value)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional IP address; null reads as `None`.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is neither null nor a byte string of
    /// 4 or 16 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<IpAddr>, D::Error> {
        Ok(Option::<Repr>::deserialize(deserializer)?.map(|repr| repr.0))
    }
}

/// The same, for a list of IP addresses: an array of byte strings.
pub mod list {
    use std::net::IpAddr;

    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::Repr;

    /// Serializes a list of IP addresses as an array of byte strings.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<S: Serializer>(value: &[IpAddr], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for addr in value {
            seq.serialize_element(&Repr(*addr))?;
        }
        seq.end()
    }

    /// Deserializes a list of IP addresses from an array of byte strings.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an array, or when one of its
    /// elements is not a byte string of 4 or 16 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<IpAddr>, D::Error> {
        Ok(Vec::<Repr>::deserialize(deserializer)?
            .into_iter()
            .map(|repr| repr.0)
            .collect())
    }
}
