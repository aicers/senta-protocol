//! The bodies of the log record kinds: the Windows event log
//! ([`kind::WINDOWS_EVENT_LOG`], 1000), journald ([`kind::JOURNALD`], 1100)
//! and auditd ([`kind::AUDITD`], 1101), each at schema version 1.
//!
//! Each kind has its own body type, [`WindowsEventLogBody`],
//! [`JournaldBody`] and [`AuditdBody`], and [`LogBody`] holds any one of
//! them, told apart by the record's kind number: [`LogBody::decode`] reads
//! one from a record's kind and [`RecordBody`], and [`LogBody::to_body`]
//! makes the [`RecordBody`] back. The record's `schema` is not looked at.
//!
//! The bodies follow the CBOR rules of [`crate::connection::cbor`]: a
//! struct is a map with snake_case text keys, a map holding the same key
//! twice at any depth fails to decode, a field the receiver does not know
//! is ignored (it belongs to a later schema version), and an optional field
//! with no value is not sent, a missing key and a null both reading as no
//! value. Every top-level field of the three bodies is optional; in a list
//! no value (no key) and an empty list (an empty array) are different
//! values. Lists keep their order, and keep every element even when two
//! share a name.
//!
//! Reading the original log (an event's XML, a journal entry, an audit
//! line) and applying field exclusion (the `field_exclusions` of the
//! `senta-policy` document) are the sender's work; these types only hold
//! the result. A record of these kinds carries no `process_key` in its
//! header, which [`super::Record::validate`] checks.
//!
//! ```
//! use senta_protocol::telemetry::kind;
//! use senta_protocol::telemetry::logs::{JournaldBody, LogBody, LogField, LogValue};
//!
//! let body = LogBody::Journald(JournaldBody {
//!     fields: Some(vec![
//!         LogField {
//!             name: "MESSAGE".to_owned(),
//!             value: LogValue::Text("Started session 3.".to_owned()),
//!         },
//!         LogField {
//!             name: "_BOOT_ID".to_owned(),
//!             value: LogValue::Bytes(vec![0xff, 0xfe, 0x00]),
//!         },
//!     ]),
//! });
//! let record_body = body.to_body()?;
//!
//! let received = LogBody::decode(kind::JOURNALD, &record_body)?;
//! assert_eq!(received, body);
//! assert_eq!(received.kind(), kind::JOURNALD);
//! assert!(LogBody::decode(kind::SYSMON_PROCESS_CREATE, &record_body).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
    ser,
};

use super::{RecordBody, kind};
use crate::connection::{DecodeError, EncodeError};

/// The kind numbers that have a log body type here, in the order of
/// [`LogBody`]'s variants.
pub const KINDS: [u16; 3] = [kind::WINDOWS_EVENT_LOG, kind::JOURNALD, kind::AUDITD];

/// The name of the journal field holding an entry's cursor, which the
/// sender keeps for itself and never sends.
const JOURNALD_CURSOR: &str = "__CURSOR";

/// A value of a journald or auditd field: text, or bytes.
///
/// `Text` is a CBOR text string and `Bytes` a CBOR byte string. The sender
/// decides from the original log which shape a value takes: a journal
/// field holding binary data, and an audit value it decoded from
/// hexadecimal, are `Bytes`. The two are never converted into one another:
/// bytes that happen to be valid UTF-8, or hold a NUL, stay a byte string
/// when sent as `Bytes`. An empty value is kept as it is. Any CBOR value
/// other than a text or byte string fails to decode, `null` and
/// `undefined` included.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogValue {
    /// A text value, a CBOR text string.
    Text(String),
    /// A binary value, a CBOR byte string.
    Bytes(Vec<u8>),
}

impl Serialize for LogValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(text) => serializer.serialize_str(text),
            Self::Bytes(bytes) => serializer.serialize_bytes(bytes),
        }
    }
}

impl<'de> Deserialize<'de> for LogValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LogValueVisitor)
    }
}

struct LogValueVisitor;

impl Visitor<'_> for LogValueVisitor {
    type Value = LogValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a text string or a byte string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<LogValue, E> {
        Ok(LogValue::Text(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<LogValue, E> {
        Ok(LogValue::Text(value))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<LogValue, E> {
        Ok(LogValue::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<LogValue, E> {
        Ok(LogValue::Bytes(value))
    }
}

/// One named field of a journal entry or of an audit line.
///
/// A CBOR map `{name, value}`, both required. A key the receiver does not
/// know is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogField {
    /// The field's name, as the original log spells it.
    pub name: String,
    /// The field's value.
    pub value: LogValue,
}

/// The body of a Windows event log record, kind 1000
/// ([`kind::WINDOWS_EVENT_LOG`]).
///
/// A CBOR map with the field names below as text keys. Every field is
/// optional. A field is absent both when the event does not carry it (the
/// Windows event schema lets an event leave out `Channel`, `Version`,
/// `Keywords` and others) and when the sender's field exclusion policy
/// left it out; a receiver reads both as no value and cannot tell them
/// apart. A key the receiver does not know is ignored.
///
/// The body holds no time: when the event happened is the header's
/// `event_time` ([`super::RecordHeader::event_time`]).
///
/// Each field's documentation names where the sender takes it from in the
/// event's XML; the paths are under the `Event` element.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WindowsEventLogBody {
    /// The channel, from `System/Channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The provider, from `System/Provider/@Name`, or, for a legacy
    /// provider that has no `Name`, from `System/Provider/@EventSourceName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The event ID, from `System/EventID`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u16>,
    /// The event's version, from `System/Version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    /// The level, from `System/Level`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    /// The task, from `System/Task`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<u16>,
    /// The opcode, from `System/Opcode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opcode: Option<u8>,
    /// The keywords mask, from `System/Keywords`, whose hexadecimal
    /// notation the sender reads into the integer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<u64>,
    /// The event record ID, from `System/EventRecordID`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<u64>,
    /// The computer's name, from `System/Computer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer: Option<String>,
    /// The user's SID, from `System/Security/@UserID`, as the SID string.
    /// Its form is not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// The `Data` elements of `EventData`, in their order. An event with no
    /// `EventData` has no value here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_data: Option<Vec<EventData>>,
    /// The XML of `UserData`, as a string, where the event has one. It is
    /// neither parsed nor checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_xml: Option<String>,
}

/// One `Data` element of a Windows event's `EventData`.
///
/// A CBOR map `{name, value}`. `name` is optional and `value` required. A
/// key the receiver does not know is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventData {
    /// The element's `Name` attribute; a `Data` element with none sends no
    /// `name` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The element's text, as it is; an empty string is kept.
    pub value: String,
}

/// The body of a journald record, kind 1100 ([`kind::JOURNALD`]).
///
/// A CBOR map with the field names below as text keys. Every field is
/// optional. A field is absent both when the entry does not carry it and
/// when the sender's field exclusion policy left it out; a receiver reads
/// both as no value and cannot tell them apart. A key the receiver does
/// not know is ignored.
///
/// The body holds no time: when the event happened is the header's
/// `event_time` ([`super::RecordHeader::event_time`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JournaldBody {
    /// The entry's fields, in their order. A journal entry may hold the
    /// same field more than once, and every occurrence is kept.
    ///
    /// The entry's cursor (`__CURSOR`) is the sender's own bookmark and is
    /// never sent: serializing a body with a field named exactly
    /// `__CURSOR` fails, whether through [`LogBody::to_body`] or
    /// [`RecordBody::encode`]. Decoding does not check it, so a receiver
    /// does not refuse a record for its sender's mistake.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_journald_fields"
    )]
    pub fields: Option<Vec<LogField>>,
}

/// Serializes a journal entry's fields, refusing its cursor.
fn serialize_journald_fields<S: Serializer>(
    fields: &Option<Vec<LogField>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let Some(fields) = fields else {
        return serializer.serialize_none();
    };
    if fields.iter().any(|field| field.name == JOURNALD_CURSOR) {
        return Err(ser::Error::custom(format_args!(
            "a journald body must not carry the {JOURNALD_CURSOR} field"
        )));
    }
    serializer.serialize_some(fields)
}

/// The body of an auditd record, kind 1101 ([`kind::AUDITD`]): one audit
/// event, which may span several lines.
///
/// A CBOR map with the field names below as text keys. Every field is
/// optional. A field is absent both when the event does not carry it and
/// when the sender's field exclusion policy left it out; a receiver reads
/// both as no value and cannot tell them apart. A key the receiver does
/// not know is ignored.
///
/// The body holds no time: when the event happened is the header's
/// `event_time` ([`super::RecordHeader::event_time`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditdBody {
    /// The event's serial number, the `<serial>` of
    /// `audit(<time>:<serial>)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    /// The event's lines, in their order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<AuditRecord>>,
}

/// One line of an audit event.
///
/// A CBOR map `{type, fields}`, both required. A key the receiver does not
/// know is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The line's type name as it is, such as `SYSCALL`, `EXECVE` or
    /// `PROCTITLE`; the CBOR key is `type`.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The line's fields, in their order. A value the sender decoded from
    /// hexadecimal, such as `proctitle`, is [`LogValue::Bytes`]; which
    /// values to decode is the sender's choice, and nothing here decodes
    /// hexadecimal.
    pub fields: Vec<LogField>,
}

/// The body of a log record, of any one of the kinds in [`KINDS`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogBody {
    /// A Windows event log body, kind 1000.
    WindowsEventLog(WindowsEventLogBody),
    /// A journald body, kind 1100.
    Journald(JournaldBody),
    /// An auditd body, kind 1101.
    Auditd(AuditdBody),
}

impl LogBody {
    /// Decodes the body of a record of kind `kind`.
    ///
    /// The kind number picks the body type; the record's schema version is
    /// not looked at. The body is read by [`RecordBody::decode`].
    ///
    /// # Errors
    ///
    /// Returns a [`crate::connection::DecodeErrorKind::Invalid`] error when
    /// `kind` is not one of [`KINDS`], and the error of
    /// [`RecordBody::decode`] when the body does not decode into the kind's
    /// body type.
    pub fn decode(kind: u16, body: &RecordBody) -> Result<Self, DecodeError> {
        match kind {
            kind::WINDOWS_EVENT_LOG => body.decode().map(Self::WindowsEventLog),
            kind::JOURNALD => body.decode().map(Self::Journald),
            kind::AUDITD => body.decode().map(Self::Auditd),
            _ => Err(DecodeError::invalid(format!(
                "record kind {kind} has no log body"
            ))),
        }
    }

    /// Returns the kind number of the body.
    #[must_use]
    pub fn kind(&self) -> u16 {
        match self {
            Self::WindowsEventLog(_) => kind::WINDOWS_EVENT_LOG,
            Self::Journald(_) => kind::JOURNALD,
            Self::Auditd(_) => kind::AUDITD,
        }
    }

    /// Encodes the body as a record's [`RecordBody`].
    ///
    /// # Errors
    ///
    /// Returns an error when a journald body carries a field named
    /// `__CURSOR` (see [`JournaldBody::fields`]).
    pub fn to_body(&self) -> Result<RecordBody, EncodeError> {
        match self {
            Self::WindowsEventLog(body) => RecordBody::encode(body),
            Self::Journald(body) => RecordBody::encode(body),
            Self::Auditd(body) => RecordBody::encode(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::cbor;

    #[test]
    fn kinds_follow_the_variants_and_have_log_families() {
        let bodies = [
            LogBody::WindowsEventLog(WindowsEventLogBody::default()),
            LogBody::Journald(JournaldBody::default()),
            LogBody::Auditd(AuditdBody::default()),
        ];
        let kinds: Vec<u16> = bodies.iter().map(LogBody::kind).collect();
        assert_eq!(kinds, KINDS);
        for body in &bodies {
            let decoded = LogBody::decode(body.kind(), &body.to_body().unwrap()).unwrap();
            assert_eq!(&decoded, body);
        }
        assert_eq!(
            kind::family(kind::WINDOWS_EVENT_LOG),
            Some(kind::KindFamily::WindowsEventLog)
        );
        for linux in [kind::JOURNALD, kind::AUDITD] {
            assert_eq!(kind::family(linux), Some(kind::KindFamily::LinuxLog));
        }
    }

    #[test]
    fn log_value_keeps_its_cbor_type() {
        // A text string of "a", and a byte string of "a".
        let text = cbor::to_vec(&LogValue::Text("a".to_owned())).unwrap();
        assert_eq!(text, [0x61, b'a']);
        let bytes = cbor::to_vec(&LogValue::Bytes(b"a".to_vec())).unwrap();
        assert_eq!(bytes, [0x41, b'a']);
        assert_eq!(
            cbor::from_slice::<LogValue>(&text).unwrap(),
            LogValue::Text("a".to_owned())
        );
        assert_eq!(
            cbor::from_slice::<LogValue>(&bytes).unwrap(),
            LogValue::Bytes(b"a".to_vec())
        );
        // Chunked strings read as the strings they make up.
        let chunked_text = [0x7f, 0x61, b'a', 0x61, b'b', 0xff];
        assert_eq!(
            cbor::from_slice::<LogValue>(&chunked_text).unwrap(),
            LogValue::Text("ab".to_owned())
        );
        let chunked_bytes = [0x5f, 0x41, 0x00, 0x41, 0xff, 0xff];
        assert_eq!(
            cbor::from_slice::<LogValue>(&chunked_bytes).unwrap(),
            LogValue::Bytes(vec![0x00, 0xff])
        );
        // An integer, an array, a map, a bool, null, undefined and a float.
        for other in [
            &[0x01][..],
            &[0x80],
            &[0xa0],
            &[0xf5],
            &[0xf6],
            &[0xf7],
            &[0xf9, 0x3c, 0x00],
        ] {
            assert!(cbor::from_slice::<LogValue>(other).is_err(), "{other:02x?}");
        }
    }

    #[test]
    fn journald_cursor_is_refused_only_by_its_exact_name() {
        let body = |name: &str| JournaldBody {
            fields: Some(vec![LogField {
                name: name.to_owned(),
                value: LogValue::Text("s=1".to_owned()),
            }]),
        };
        assert!(RecordBody::encode(&body(JOURNALD_CURSOR)).is_err());
        assert!(LogBody::Journald(body(JOURNALD_CURSOR)).to_body().is_err());
        for name in ["__cursor", "_CURSOR", "__CURSOR_", "CURSOR"] {
            assert!(RecordBody::encode(&body(name)).is_ok(), "{name}");
        }
    }

    #[test]
    fn other_kinds_fail_as_invalid() {
        let body = RecordBody::encode(&WindowsEventLogBody::default()).unwrap();
        for other in [0, 1, 255, 999, 1001, 1099, 1102, 1199, 1200, u16::MAX] {
            let error = LogBody::decode(other, &body).unwrap_err();
            assert_eq!(
                error.kind(),
                crate::connection::DecodeErrorKind::Invalid,
                "{other}"
            );
        }
    }
}
