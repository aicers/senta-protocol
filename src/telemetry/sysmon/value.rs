//! The body types a Sysmon field can have: how each reads from the
//! Windows notation of an event's `EventData`, and how each is written in
//! a body's CBOR.

use std::net::IpAddr;

use jiff::Timestamp;
use jiff::civil::{Date, DateTime, Time};
use jiff::tz::Offset;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::HashEntry;
use crate::connection::cbor;
use crate::telemetry::ip;

const HEX_PREFIXES: [&str; 2] = ["0x", "0X"];
/// The length of a GUID in its hyphenated form, `8-4-4-4-12`.
const GUID_LEN: usize = 36;
/// Where the hyphens of a hyphenated GUID stand.
const GUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];
/// The most digits a fraction of a second may have.
const MAX_FRACTION_DIGITS: usize = 9;

/// The body type of a Sysmon field, as the descriptor table records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FieldType {
    /// Text, kept as written.
    Str,
    /// A `u16`.
    U16,
    /// A `u32`.
    U32,
    /// A `u64`.
    U64,
    /// A `bool`.
    Bool,
    /// A GUID: 16 bytes in RFC 4122 order.
    Guid,
    /// An IP address.
    Ip,
    /// A point in time.
    Time,
    /// A list of `{algo, value}` hashes.
    Hashes,
}

impl FieldType {
    /// Returns what the Windows notation of a value of this type must look
    /// like, for an error message.
    pub(crate) const fn expected(self) -> &'static str {
        match self {
            Self::Str => "text",
            Self::U16 => "an unsigned 16-bit integer, in decimal or in hexadecimal after `0x`",
            Self::U32 => "an unsigned 32-bit integer, in decimal or in hexadecimal after `0x`",
            Self::U64 => "an unsigned 64-bit integer, in decimal or in hexadecimal after `0x`",
            Self::Bool => "`true` or `false`, in any case",
            Self::Guid => "a GUID `8-4-4-4-12` in hexadecimal, with or without braces",
            Self::Ip => "an IPv4 address in dotted notation or an IPv6 address",
            Self::Time => {
                "a UTC time `YYYY-MM-DD HH:MM:SS`, optionally followed by `.` and 1 to 9 digits \
                 of a second, between the years 1677 and 2262"
            }
            Self::Hashes => {
                "`algorithm=hexadecimal` pairs separated by `,`, each value of an even, nonzero \
                 number of hexadecimal digits"
            }
        }
    }
}

/// A Rust type a Sysmon body field holds: its table entry, how it reads
/// from the Windows notation, and its CBOR.
pub(crate) trait FieldValue: Sized {
    /// The type the descriptor table records for the field.
    const TYPE: FieldType;

    /// Reads a value from its Windows notation, or `None` when the text is
    /// not one.
    fn parse(raw: &str) -> Option<Self>;

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>;
}

impl FieldValue for String {
    const TYPE: FieldType = FieldType::Str;

    fn parse(raw: &str) -> Option<Self> {
        Some(raw.to_owned())
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)
    }
}

/// Implements [`FieldValue`] for an unsigned integer type.
macro_rules! unsigned_field_value {
    ($ty:ty, $field_type:ident) => {
        impl FieldValue for $ty {
            const TYPE: FieldType = FieldType::$field_type;

            fn parse(raw: &str) -> Option<Self> {
                parse_unsigned(raw).and_then(|value| <$ty>::try_from(value).ok())
            }

            fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.serialize(serializer)
            }

            fn deserialize_value<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                <$ty>::deserialize(deserializer)
            }
        }
    };
}

unsigned_field_value!(u16, U16);
unsigned_field_value!(u32, U32);
unsigned_field_value!(u64, U64);

impl FieldValue for bool {
    const TYPE: FieldType = FieldType::Bool;

    fn parse(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("true") {
            Some(true)
        } else if raw.eq_ignore_ascii_case("false") {
            Some(false)
        } else {
            None
        }
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(*self)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bool::deserialize(deserializer)
    }
}

impl FieldValue for Uuid {
    const TYPE: FieldType = FieldType::Guid;

    fn parse(raw: &str) -> Option<Self> {
        let hyphenated = match raw.strip_prefix('{') {
            Some(rest) => rest.strip_suffix('}')?,
            None => raw,
        };
        let bytes = hyphenated.as_bytes();
        if bytes.len() != GUID_LEN
            || GUID_HYPHENS
                .iter()
                .any(|&at| bytes.get(at).copied() != Some(b'-'))
        {
            return None;
        }
        // The hyphenated form reads its bytes in the order they are
        // written, which is RFC 4122 order.
        Uuid::try_parse(hyphenated).ok()
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        cbor::uuid::serialize(self, serializer)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        cbor::uuid::deserialize(deserializer)
    }
}

impl FieldValue for IpAddr {
    const TYPE: FieldType = FieldType::Ip;

    fn parse(raw: &str) -> Option<Self> {
        raw.parse().ok()
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ip::serialize(self, serializer)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ip::deserialize(deserializer)
    }
}

impl FieldValue for Timestamp {
    const TYPE: FieldType = FieldType::Time;

    fn parse(raw: &str) -> Option<Self> {
        parse_time(raw)
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        cbor::timestamp::serialize(self, serializer)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        cbor::timestamp::deserialize(deserializer)
    }
}

impl FieldValue for Vec<HashEntry> {
    const TYPE: FieldType = FieldType::Hashes;

    fn parse(raw: &str) -> Option<Self> {
        raw.split(',')
            .map(|pair| {
                let (algo, hex) = pair.split_once('=')?;
                Some(HashEntry {
                    algo: algo.to_owned(),
                    value: decode_hex(hex)?,
                })
            })
            .collect()
    }

    fn serialize_value<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize(serializer)
    }

    fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::deserialize(deserializer)
    }
}

/// Reads an unsigned integer: hexadecimal after `0x` or `0X`, decimal
/// otherwise, digits only.
fn parse_unsigned(raw: &str) -> Option<u64> {
    let (digits, radix) = match HEX_PREFIXES
        .iter()
        .find_map(|prefix| raw.strip_prefix(prefix))
    {
        Some(digits) => (digits, 16),
        None => (raw, 10),
    };
    // `from_str_radix` takes a leading `+`, which is not a digit.
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Decodes a nonempty string of hexadecimal digit pairs.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    if pairs.is_empty() || !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| {
            let high = char::from(high).to_digit(16)?;
            let low = char::from(low).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Reads Sysmon's UTC time, `YYYY-MM-DD HH:MM:SS` with an optional
/// fraction of 1 to 9 digits, within the range of an `i64` count of
/// nanoseconds since the Unix epoch.
fn parse_time(raw: &str) -> Option<Timestamp> {
    let (date, rest) = raw.split_once(' ')?;
    let (time, fraction) = match rest.split_once('.') {
        Some((time, fraction)) => (time, Some(fraction)),
        None => (rest, None),
    };
    let mut date_parts = date.split('-');
    let year = fixed_digits(date_parts.next()?, 4)?;
    let month = fixed_digits(date_parts.next()?, 2)?;
    let day = fixed_digits(date_parts.next()?, 2)?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour = fixed_digits(time_parts.next()?, 2)?;
    let minute = fixed_digits(time_parts.next()?, 2)?;
    let second = fixed_digits(time_parts.next()?, 2)?;
    if time_parts.next().is_some() {
        return None;
    }
    let nanos = match fraction {
        None => 0,
        Some(fraction) => {
            let len = fraction.len();
            if !(1..=MAX_FRACTION_DIGITS).contains(&len) {
                return None;
            }
            let value = fixed_digits(fraction, len)?;
            let scale = 10_u32.pow(u32::try_from(MAX_FRACTION_DIGITS - len).ok()?);
            value.checked_mul(scale)?
        }
    };
    let date = Date::new(
        i16::try_from(year).ok()?,
        i8::try_from(month).ok()?,
        i8::try_from(day).ok()?,
    )
    .ok()?;
    let time = Time::new(
        i8::try_from(hour).ok()?,
        i8::try_from(minute).ok()?,
        i8::try_from(second).ok()?,
        i32::try_from(nanos).ok()?,
    )
    .ok()?;
    let timestamp = Offset::UTC
        .to_timestamp(DateTime::from_parts(date, time))
        .ok()?;
    i64::try_from(timestamp.as_nanosecond()).ok()?;
    Some(timestamp)
}

/// Reads exactly `len` decimal digits.
fn fixed_digits(text: &str, len: usize) -> Option<u32> {
    if text.len() != len || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The serde helper every Sysmon body field is written with: an optional
/// value in the CBOR of its [`FieldValue`] type, null or absent for none.
pub(super) mod wire {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::FieldValue;

    struct Ref<'a, T>(&'a T);

    impl<T: FieldValue> Serialize for Ref<'_, T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize_value(serializer)
        }
    }

    struct Owned<T>(T);

    impl<'de, T: FieldValue> Deserialize<'de> for Owned<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            T::deserialize_value(deserializer).map(Owned)
        }
    }

    pub(in super::super) fn serialize<T: FieldValue, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&Ref(value)),
            None => serializer.serialize_none(),
        }
    }

    pub(in super::super) fn deserialize<'de, T: FieldValue, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error> {
        Ok(Option::<Owned<T>>::deserialize(deserializer)?.map(|owned| owned.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_notations() {
        assert_eq!(u64::parse("0x3e7"), Some(999));
        assert_eq!(u64::parse("0X3E7"), Some(999));
        assert_eq!(u64::parse("999"), Some(999));
        assert_eq!(u64::parse("0xffffffffffffffff"), Some(u64::MAX));
        assert_eq!(u64::parse("0x10000000000000000"), None);
        assert_eq!(u16::parse("65535"), Some(u16::MAX));
        assert_eq!(u16::parse("65536"), None);
        assert_eq!(u32::parse("4294967296"), None);
        for bad in [
            "", "0x", "+5", "-1", " 5", "5 ", "0x+5", "12a", "0xg", "1_000",
        ] {
            assert_eq!(u64::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn guid_notations() {
        let expected: Vec<u8> = (1..=16).collect();
        for raw in [
            "{01020304-0506-0708-090A-0B0C0D0E0F10}",
            "01020304-0506-0708-090A-0B0C0D0E0F10",
            "{01020304-0506-0708-090a-0b0c0d0e0f10}",
        ] {
            assert_eq!(
                <Uuid as FieldValue>::parse(raw)
                    .unwrap()
                    .as_bytes()
                    .as_slice(),
                expected
            );
        }
        for bad in [
            "0102030405060708090A0B0C0D0E0F10",
            "urn:uuid:01020304-0506-0708-090A-0B0C0D0E0F10",
            "{01020304-0506-0708-090A-0B0C0D0E0F10",
            "01020304-0506-0708-090A-0B0C0D0E0F10}",
            "{{01020304-0506-0708-090A-0B0C0D0E0F10}}",
            "01020304-0506-0708-090A-0B0C0D0E0F1G",
            "0102030-40506-0708-090A-0B0C0D0E0F10",
            "",
        ] {
            assert_eq!(<Uuid as FieldValue>::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn time_notations() {
        let parse = |raw| <Timestamp as FieldValue>::parse(raw).map(|t| t.as_nanosecond());
        assert_eq!(parse("1970-01-01 00:00:00"), Some(0));
        assert_eq!(parse("1970-01-01 00:00:00.5"), Some(500_000_000));
        assert_eq!(parse("1970-01-01 00:00:00.000000001"), Some(1));
        assert!(parse("2024-02-29 00:00:00").is_some());
        // The range of an `i64` count of nanoseconds runs from
        // 1677-09-21 00:12:43.145224192 to 2262-04-11 23:47:16.854775807.
        assert_eq!(
            parse("1677-09-21 00:12:43.145224192"),
            Some(i128::from(i64::MIN))
        );
        assert_eq!(parse("1677-09-21 00:12:43.145224191"), None);
        assert_eq!(parse("1677-09-21 00:12:43"), None);
        assert_eq!(
            parse("2262-04-11 23:47:16.854775807"),
            Some(i128::from(i64::MAX))
        );
        assert_eq!(parse("2262-04-11 23:47:16.854775808"), None);
        assert_eq!(parse("2262-04-11 23:47:17"), None);
        assert_eq!(parse("9999-12-31 23:59:59"), None);
        assert_eq!(parse("0000-01-01 00:00:00"), None);
        for bad in [
            "2024-02-30 00:00:00",
            "2023-02-29 00:00:00",
            "2024-03-05T12:34:56Z",
            "2024-03-05 12:34:56Z",
            "2024-03-05 12:34:56.",
            "2024-03-05 12:34:56.1234567890",
            "2024-03-05 12:34:60",
            "2024-03-05 24:00:00",
            "2024-3-05 12:34:56",
            "2024-03-05  12:34:56",
            "2024-03-05 12:34",
            "2024-03-05 12:34:56:00",
            "2024-03-05-01 12:34:56",
            "+024-03-05 12:34:56",
            "2024-03-05 12:34:56.+5",
            "",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn hash_notations() {
        let hashes = Vec::<HashEntry>::parse("SHA1=00ff,IMPHASH=AbCd").unwrap();
        assert_eq!(
            hashes,
            [
                HashEntry {
                    algo: "SHA1".to_owned(),
                    value: vec![0x00, 0xff],
                },
                HashEntry {
                    algo: "IMPHASH".to_owned(),
                    value: vec![0xab, 0xcd],
                },
            ]
        );
        for bad in [
            "SHA1",
            "SHA1=",
            "SHA1=abc",
            "SHA1=zz",
            "SHA1=00,",
            ",SHA1=00",
            "SHA1=00,,MD5=00",
            "SHA1=+0",
            "",
        ] {
            assert_eq!(Vec::<HashEntry>::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ip_and_bool_notations() {
        assert_eq!(
            IpAddr::parse("192.0.2.1"),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(IpAddr::parse("fe80::1"), Some("fe80::1".parse().unwrap()));
        assert_eq!(IpAddr::parse("example.com"), None);
        assert_eq!(bool::parse("TRUE"), Some(true));
        assert_eq!(bool::parse("False"), Some(false));
        assert_eq!(bool::parse("1"), None);
        assert_eq!(bool::parse("yes"), None);
    }
}
