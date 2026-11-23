//! The bodies of the Sysmon record kinds, the conversion of a Sysmon
//! event's Windows notation into them, and the process key each kind's
//! record carries.
//!
//! Nineteen Sysmon events have a record kind, numbered by their event ID
//! (see [`super::kind`]): 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
//! 17, 22, 23, 25 and 26. Each has a body type here, and [`Body`] holds
//! any one of them. The other events of the Sysmon schema, 4, 16, 18 to
//! 21, 24, 100 and 255, have none.
//!
//! # Body fields
//!
//! A body holds the fields of its event in the Sysmon schema of version
//! [`BASE_SCHEMA_VERSION`], in their order there, less `UtcTime`, which
//! becomes the record header's `event_time`. A field's key is its schema
//! name in snake_case, a run of capitals making one word:
//! `ParentProcessGuid` is `parent_process_guid`, `SourceProcessGUID` is
//! `source_process_guid` and `SourceIsIpv6` is `source_is_ipv6`.
//!
//! Every field is optional: a field with no value is not sent, and a
//! missing key and a null both read as no value, so a body from an older
//! schema that lacks a field still reads. A key the receiver does not know,
//! a field of a newer schema, is ignored; a key held twice fails to decode,
//! by the rules of [`crate::connection::cbor`].
//!
//! A field's body type follows from the schema, by the first rule that
//! fits:
//!
//! | Schema field | Body type | CBOR |
//! | --- | --- | --- |
//! | named `Hashes` | a list of [`HashEntry`] | an array of `{algo, value}` maps, `value` a byte string |
//! | named `SourceIp` or `DestinationIp` | [`std::net::IpAddr`] | a byte string of 4 or 16 bytes ([`super::ip`]) |
//! | named with the suffix `UtcTime` | [`jiff::Timestamp`] | integer nanoseconds since the Unix epoch |
//! | `win:GUID` | [`uuid::Uuid`], in RFC 4122 byte order | a byte string of 16 bytes |
//! | `win:Boolean` | `bool` | a boolean |
//! | `win:UInt16` | `u16` | an integer |
//! | `win:UInt32` | `u32` | an integer |
//! | `win:UInt64`, `win:HexInt64`, `win:HexInt32` | `u64` | an integer |
//! | `win:UnicodeString`, `win:AnsiString` | `String`, as written | a text string |
//!
//! [`Body::from_record_body`] reads a body from a record's open
//! [`RecordBody`] by the record's kind number, and
//! [`Body::to_record_body`] makes one. Neither looks at the record's
//! `schema`.
//!
//! ```
//! use senta_protocol::host::OsFamily;
//! use senta_protocol::telemetry::kind;
//! use senta_protocol::telemetry::sysmon::{self, Body};
//!
//! let converted = sysmon::convert(
//!     kind::SYSMON_PROCESS_TERMINATE,
//!     &[
//!         ("RuleName", "-"),
//!         ("UtcTime", "2024-03-05 12:34:56.789"),
//!         ("ProcessGuid", "{01020304-0506-0708-090A-0B0C0D0E0F10}"),
//!         ("ProcessId", "4242"),
//!         ("Image", r"C:\Windows\System32\cmd.exe"),
//!     ],
//! )?;
//! let event_time = converted.event_time.expect("the event has a UtcTime");
//! assert_eq!(event_time.as_millisecond(), 1_709_642_096_789);
//!
//! let key = converted.body.process_key(&OsFamily::Windows);
//! let body = converted.body.to_record_body()?;
//! let received = Body::from_record_body(kind::SYSMON_PROCESS_TERMINATE, &body)?;
//! assert_eq!(received, converted.body);
//! assert_eq!(key.map(|key| key.value.len()), Some(16));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod kinds;
#[cfg(test)]
mod manifest;
mod value;

use std::collections::HashSet;
use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub use self::kinds::{
    Body, CreateRemoteThread, DnsQuery, DriverLoad, FileCreate, FileCreateStreamHash,
    FileCreateTime, FileDelete, FileDeleteDetected, ImageLoad, NetworkConnect, PipeCreated,
    ProcessAccess, ProcessCreate, ProcessTampering, ProcessTerminate, RawAccessRead,
    RegistryAddDelete, RegistryRename, RegistryValueSet,
};
use self::value::FieldValue;
use super::{ProcessKey, RecordBody};
use crate::connection::{DecodeError, EncodeError, cbor};
use crate::host::OsFamily;

/// The schema field holding the time of the event.
const UTC_TIME: &str = "UtcTime";

/// The version of the Sysmon schema the bodies follow: the
/// `<manifest schemaversion="4.90">` entry of the Sysmon manifest.
///
/// Raising the base version raises, in the kind registry
/// ([`super::kind`]), the schema version of every Sysmon kind whose body
/// shape the new base version changes. Under 4.90 every Sysmon kind is at
/// schema version 1.
///
/// The body types of 4.90 are those in the [module](self) table. A newer
/// base version that brings a type 4.90 does not use maps it by these
/// rules: `win:SYSTEMTIME` to a point in time (integer nanoseconds since
/// the Unix epoch), a signed integer type the table does not name
/// (`win:Int32` and the like) to `i64`, an unsigned integer type the table
/// does not name, hexadecimal ones included, to `u64`, and any other type
/// to text.
pub const BASE_SCHEMA_VERSION: &str = "4.90";

/// One hash of a Sysmon `Hashes` field: the algorithm as Sysmon names it
/// and the hash's bytes.
///
/// A CBOR map `{algo, value}`, `algo` a text string and `value` a byte
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashEntry {
    /// The algorithm, as written before `=`: `SHA1`, `MD5`, `SHA256`,
    /// `IMPHASH` and the like.
    pub algo: String,
    /// The hash's bytes.
    #[serde(with = "cbor::bytes")]
    pub value: Vec<u8>,
}

/// The outcome of [`convert`]: a body, and the time of the event if it
/// had one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The body.
    pub body: Body,
    /// The event's `UtcTime`, which belongs in the record header's
    /// `event_time`; `None` when the event had none.
    pub event_time: Option<Timestamp>,
}

/// An error converting a Sysmon event's Windows notation into a body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvertError {
    /// The event ID is not one of the nineteen Sysmon kinds.
    UnsupportedKind(u16),
    /// The event names this field more than once.
    DuplicateField(String),
    /// This field's value is not in the notation its body type reads.
    InvalidValue {
        /// The field's schema name.
        field: &'static str,
        /// What the notation must look like.
        expected: &'static str,
    },
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKind(kind) => write!(f, "Sysmon event {kind} has no record kind"),
            Self::DuplicateField(field) => write!(f, "Sysmon field {field} appears twice"),
            Self::InvalidValue { field, expected } => {
                write!(f, "Sysmon field {field}: expected {expected}")
            }
        }
    }
}

impl std::error::Error for ConvertError {}

/// An error reading a Sysmon body from a record's body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BodyError {
    /// The record kind is not one of the nineteen Sysmon kinds.
    UnsupportedKind(u16),
    /// The record's body does not decode into the kind's body type.
    Decode(DecodeError),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKind(kind) => write!(f, "record kind {kind} is not a Sysmon kind"),
            Self::Decode(error) => write!(f, "Sysmon body: {error}"),
        }
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedKind(_) => None,
            Self::Decode(error) => Some(error),
        }
    }
}

/// Converts a Sysmon event, as Windows writes the fields of its
/// `EventData`, into its body and the time of the event.
///
/// This is the reference conversion from the Windows notation. `kind` is
/// the event ID, which is the record kind's number, and `fields` are the
/// event's `(schema field name, value)` pairs. A notation another platform
/// writes differently, Sysmon for Linux's included, is brought to this
/// one before the call.
///
/// `UtcTime` does not go into the body: it is returned as
/// [`Converted::event_time`], for the record header's `event_time`. A field
/// missing from `fields` or with an empty value is left out of the body,
/// and a name the base schema does not give the event is passed over. The
/// values read as follows:
///
/// - An unsigned integer is hexadecimal after `0x` or `0X` and decimal
///   otherwise, and must fit its type: `0x3e7` is 999.
/// - A GUID is written `8-4-4-4-12` in hexadecimal digits of either case,
///   with or without braces around it. Its bytes are taken in the order
///   they are written, not in the memory layout of a Windows `GUID`:
///   `{01020304-0506-0708-090A-0B0C0D0E0F10}` is the bytes 01 to 10.
/// - A time, a field whose name ends in `UtcTime`, is
///   `YYYY-MM-DD HH:MM:SS` in UTC, optionally followed by `.` and 1 to 9
///   digits of a second. The date must exist, and the time must lie within
///   the range of an `i64` count of nanoseconds, the years 1677 to 2262.
/// - A boolean is `true` or `false`, in any case.
/// - An IP address is an IPv4 address in dotted notation or an IPv6
///   address.
/// - `Hashes` is `algorithm=hexadecimal` pairs separated by `,`, each
///   becoming a [`HashEntry`] in turn, `algo` as written and `value` the
///   bytes the hexadecimal digits spell. Every other field, a hash-like
///   one such as `Hash` of event 15 included, is text.
/// - Text is kept as written.
///
/// # Making a record
///
/// A conversion that succeeds does not by itself make a valid record. An
/// event without `UtcTime` converts, with [`Converted::event_time`] `None`,
/// but the record header's `event_time`, the time the event happened, is
/// required: a sender that cannot learn the event's original time
/// elsewhere cannot make a valid record of it. It never fills the field in
/// with the time it read the event, `collected_at`.
///
/// # Errors
///
/// Returns [`ConvertError::UnsupportedKind`] when `kind` is not one of the
/// nineteen Sysmon kinds, [`ConvertError::DuplicateField`] when `fields`
/// names a field twice, whatever the field, and
/// [`ConvertError::InvalidValue`] naming the field when a nonempty value,
/// `UtcTime`'s included, does not read as its type. On an error there is
/// no body.
pub fn convert(kind: u16, fields: &[(&str, &str)]) -> Result<Converted, ConvertError> {
    if !Body::has_kind(kind) {
        return Err(ConvertError::UnsupportedKind(kind));
    }
    let mut seen = HashSet::with_capacity(fields.len());
    for &(name, _) in fields {
        if !seen.insert(name) {
            return Err(ConvertError::DuplicateField(name.to_owned()));
        }
    }
    let body = Body::from_fields(kind, fields).ok_or(ConvertError::UnsupportedKind(kind))??;
    let event_time = match fields.iter().find(|&&(name, _)| name == UTC_TIME) {
        Some(&(_, raw)) if !raw.is_empty() => Some(<Timestamp as FieldValue>::parse(raw).ok_or(
            ConvertError::InvalidValue {
                field: UTC_TIME,
                expected: <Timestamp as FieldValue>::TYPE.expected(),
            },
        )?),
        _ => None,
    };
    Ok(Converted { body, event_time })
}

impl Body {
    /// Reads a Sysmon body from a record's body, by the record's kind.
    ///
    /// The record's `schema` is not consulted: a field the body type does
    /// not know is ignored and a missing one reads as no value, whichever
    /// schema version the sender wrote.
    ///
    /// # Errors
    ///
    /// Returns [`BodyError::UnsupportedKind`] when `kind` is not one of the
    /// nineteen Sysmon kinds, and [`BodyError::Decode`] when the body does
    /// not decode into the kind's body type: a field of the wrong CBOR
    /// type, say. A body holding a key twice already fails to decode as a
    /// record.
    pub fn from_record_body(kind: u16, body: &RecordBody) -> Result<Self, BodyError> {
        Self::decode(kind, body)
    }

    /// Makes a record's body from the Sysmon body, for a record of the kind
    /// [`Body::kind`] returns.
    ///
    /// # Errors
    ///
    /// Returns an error when a time in the body lies outside the range of
    /// an `i64` count of nanoseconds.
    pub fn to_record_body(&self) -> Result<RecordBody, EncodeError> {
        self.encode()
    }

    /// Returns the process key of the body's record, for a host of the OS
    /// family `os`, or `None` when the record has none.
    ///
    /// The key is the 16 bytes of the GUID of the record's principal
    /// process: `source_process_guid` for CreateRemoteThread (8) and
    /// ProcessAccess (10), whose target process stays in the body's
    /// `target_process_guid`, and `process_guid` for every other kind that
    /// has one. A kind with no process GUID, DriverLoad (6), and a body
    /// whose GUID field has no value have no key. The key's `os` is `os`.
    ///
    /// # Field exclusion
    ///
    /// The sender calls this on the body as converted, before the field
    /// exclusions of the policy (`field_exclusions` in the `senta-policy`
    /// document) are applied to it. The header is not subject to field
    /// exclusion, so the header's `process_key` stays even when the policy
    /// takes the GUID field out of the body.
    #[must_use]
    pub fn process_key(&self, os: &OsFamily) -> Option<ProcessKey> {
        self.process_guid().map(|guid| ProcessKey {
            os: os.clone(),
            value: guid.as_bytes().to_vec(),
        })
    }
}
