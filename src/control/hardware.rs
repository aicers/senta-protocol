//! The hardware identity an endpoint reports, and the hash of its machine
//! identifier.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::connection::cbor;

/// What the hardware identifier hash is computed over, ahead of `hw_salt`.
const HASH_CONTEXT: &[u8] = b"clumit-endpoint";

/// The number of hexadecimal digits in a Linux machine-id.
const MACHINE_ID_DIGITS: usize = 32;

/// The lengths of the hyphen-separated groups of a Windows MachineGuid.
const GUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

/// The number of bytes a machine identifier stands for.
const MACHINE_ID_BYTES: usize = 16;

/// The hardware identity of an endpoint.
///
/// A CBOR map with the field names as text keys. `machine_id_hash` is a
/// byte string of exactly 32 bytes; any other length fails to decode.
/// `smbios_uuid` and `smbios_serial` are optional, for hosts that cannot
/// read them: with no value the key is not sent, and a missing key and a
/// null both read as no value.
///
/// The receiver does not check the format of the SMBIOS strings; the
/// sender, senta, keeps to it: `smbios_uuid` is the SMBIOS system UUID as
/// a lowercase hyphenated UUID string,
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, and `smbios_serial` the SMBIOS
/// system serial number exactly as read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hardware {
    /// The hash of the machine identifier, from [`machine_id_hash`].
    #[serde(with = "cbor::bytes")]
    pub machine_id_hash: [u8; 32],
    /// The SMBIOS system UUID, which the sender writes as a lowercase
    /// hyphenated UUID string, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Not
    /// checked on receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smbios_uuid: Option<String>,
    /// The SMBIOS system serial number, which the sender writes exactly as
    /// read. Not checked on receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smbios_serial: Option<String>,
}

/// A machine identifier, by the kind the caller read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MachineId<'a> {
    /// A Linux machine-id: exactly 32 hexadecimal digits, of either case,
    /// with nothing around them. The caller strips the newline that ends
    /// `/etc/machine-id` before passing it.
    Linux(&'a str),
    /// A Windows MachineGuid: hexadecimal digits of either case in groups
    /// of 8, 4, 4, 4 and 12 joined by hyphens, optionally enclosed in a
    /// pair of braces (both or neither). Its bytes are the digits in the
    /// order written, as RFC 4122 lays out a UUID, not the little-endian
    /// field order of the Windows `GUID` structure.
    Windows(&'a str),
}

/// A machine identifier that does not follow the format of its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidMachineId {
    /// The Linux machine-id is not exactly 32 hexadecimal digits.
    Linux,
    /// The Windows MachineGuid is not in the `8-4-4-4-12` form, optionally
    /// enclosed in braces.
    Windows,
}

impl fmt::Display for InvalidMachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linux => "the Linux machine-id is not exactly 32 hexadecimal digits",
            Self::Windows => {
                "the Windows MachineGuid is not in the 8-4-4-4-12 form, optionally in braces"
            }
        })
    }
}

impl std::error::Error for InvalidMachineId {}

/// Computes the `machine_id_hash` of [`Hardware`] from a machine identifier
/// and the install's `hw_salt`.
///
/// The machine identifier is read as its 16 bytes, by the rules of its
/// kind (see [`MachineId`]), so the same bytes hash the same whatever the
/// case of the digits or the braces around a MachineGuid. The hash is
/// HMAC-SHA256 keyed with those 16 bytes, over the ASCII
/// `clumit-endpoint` followed by the 32 bytes of `hw_salt`.
///
/// ```
/// use senta_protocol::control::{MachineId, machine_id_hash};
///
/// let salt = [7; 32];
/// let linux = machine_id_hash(MachineId::Linux("0102030405060708090a0b0c0d0e0f10"), &salt)?;
/// let windows = machine_id_hash(
///     MachineId::Windows("{01020304-0506-0708-090A-0B0C0D0E0F10}"),
///     &salt,
/// )?;
/// assert_eq!(linux, windows);
/// # Ok::<(), senta_protocol::control::InvalidMachineId>(())
/// ```
///
/// # Errors
///
/// Returns an error, and no hash, when the identifier does not follow the
/// format of its kind.
pub fn machine_id_hash(
    machine_id: MachineId<'_>,
    hw_salt: &[u8; 32],
) -> Result<[u8; 32], InvalidMachineId> {
    let key = match machine_id {
        MachineId::Linux(text) => parse_linux(text).ok_or(InvalidMachineId::Linux)?,
        MachineId::Windows(text) => parse_windows(text).ok_or(InvalidMachineId::Windows)?,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts a key of any length");
    mac.update(HASH_CONTEXT);
    mac.update(hw_salt);
    Ok(mac.finalize().into_bytes().into())
}

/// Reads a Linux machine-id as its 16 bytes.
fn parse_linux(text: &str) -> Option<[u8; MACHINE_ID_BYTES]> {
    if text.len() != MACHINE_ID_DIGITS {
        return None;
    }
    let mut out = [0; MACHINE_ID_BYTES];
    decode_hex(text.as_bytes(), &mut out)?;
    Some(out)
}

/// Reads a Windows MachineGuid as its 16 bytes, in the order written.
fn parse_windows(text: &str) -> Option<[u8; MACHINE_ID_BYTES]> {
    let inner = match (text.strip_prefix('{'), text.strip_suffix('}')) {
        (Some(rest), Some(_)) => rest.strip_suffix('}')?,
        (None, None) => text,
        _ => return None,
    };
    let mut out = [0; MACHINE_ID_BYTES];
    let mut groups = inner.split('-');
    let mut written = 0;
    for len in GUID_GROUPS {
        let group = groups.next()?;
        if group.len() != len {
            return None;
        }
        let end = written + len / 2;
        decode_hex(group.as_bytes(), out.get_mut(written..end)?)?;
        written = end;
    }
    if groups.next().is_some() {
        return None;
    }
    Some(out)
}

/// Decodes pairs of hexadecimal digits into `out`, which must be half as
/// long as `digits`.
fn decode_hex(digits: &[u8], out: &mut [u8]) -> Option<()> {
    let (pairs, []) = digits.as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != out.len() {
        return None;
    }
    for ([high, low], byte) in pairs.iter().zip(out.iter_mut()) {
        *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
    }
    Some(())
}

/// Returns the value of one hexadecimal digit, of either case.
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
