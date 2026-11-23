//! The record kind registry: which numbers belong to which family of
//! kinds, the kinds defined so far, and whether a receiver accepts a kind.
//!
//! A record's `kind` is a `u16`, split into ranges by family:
//!
//! | Range | Family |
//! | --- | --- |
//! | 1–255 | Sysmon, numbered by event ID; Windows and Linux share a number, and the header's `os` tells them apart |
//! | 1000–1099 | Windows event logs |
//! | 1100–1199 | Linux logs |
//! | 1200–1299 | macOS |
//! | 1300–1399 | Host state |
//!
//! Every other number, 0, 256–999 and 1400 and above, belongs to no
//! family.

use crate::connection::AcceptedKind;
use crate::host::OsFamily;

/// Sysmon ProcessCreate.
pub const SYSMON_PROCESS_CREATE: u16 = 1;
/// Sysmon FileCreateTime.
pub const SYSMON_FILE_CREATE_TIME: u16 = 2;
/// Sysmon NetworkConnect.
pub const SYSMON_NETWORK_CONNECT: u16 = 3;
/// Sysmon ProcessTerminate.
pub const SYSMON_PROCESS_TERMINATE: u16 = 5;
/// Sysmon DriverLoad.
pub const SYSMON_DRIVER_LOAD: u16 = 6;
/// Sysmon ImageLoad.
pub const SYSMON_IMAGE_LOAD: u16 = 7;
/// Sysmon CreateRemoteThread.
pub const SYSMON_CREATE_REMOTE_THREAD: u16 = 8;
/// Sysmon RawAccessRead.
pub const SYSMON_RAW_ACCESS_READ: u16 = 9;
/// Sysmon ProcessAccess.
pub const SYSMON_PROCESS_ACCESS: u16 = 10;
/// Sysmon FileCreate.
pub const SYSMON_FILE_CREATE: u16 = 11;
/// Sysmon RegistryEvent (Object create and delete).
pub const SYSMON_REGISTRY_ADD_DELETE: u16 = 12;
/// Sysmon RegistryEvent (Value Set).
pub const SYSMON_REGISTRY_VALUE_SET: u16 = 13;
/// Sysmon RegistryEvent (Key and Value Rename).
pub const SYSMON_REGISTRY_RENAME: u16 = 14;
/// Sysmon FileCreateStreamHash.
pub const SYSMON_FILE_CREATE_STREAM_HASH: u16 = 15;
/// Sysmon PipeEvent (Pipe Created).
pub const SYSMON_PIPE_CREATED: u16 = 17;
/// Sysmon DnsQuery.
pub const SYSMON_DNS_QUERY: u16 = 22;
/// Sysmon FileDelete.
pub const SYSMON_FILE_DELETE: u16 = 23;
/// Sysmon ProcessTampering.
pub const SYSMON_PROCESS_TAMPERING: u16 = 25;
/// Sysmon FileDeleteDetected.
pub const SYSMON_FILE_DELETE_DETECTED: u16 = 26;
/// The Windows event log.
pub const WINDOWS_EVENT_LOG: u16 = 1000;
/// journald.
pub const JOURNALD: u16 = 1100;
/// auditd.
pub const AUDITD: u16 = 1101;

const WINDOWS: &[OsFamily] = &[OsFamily::Windows];
const LINUX: &[OsFamily] = &[OsFamily::Linux];
const WINDOWS_LINUX: &[OsFamily] = &[OsFamily::Windows, OsFamily::Linux];

/// The current schema version of every kind defined so far.
const SCHEMA_1: u16 = 1;

/// The family a record kind's number belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KindFamily {
    /// Sysmon events, 1–255.
    Sysmon,
    /// Windows event logs, 1000–1099.
    WindowsEventLog,
    /// Linux logs, 1100–1199.
    LinuxLog,
    /// macOS, 1200–1299.
    Macos,
    /// Host state, 1300–1399.
    HostState,
}

/// Returns the family a record kind's number belongs to, or `None` when it
/// belongs to none.
#[must_use]
pub fn family(kind: u16) -> Option<KindFamily> {
    match kind {
        1..=255 => Some(KindFamily::Sysmon),
        1000..=1099 => Some(KindFamily::WindowsEventLog),
        1100..=1199 => Some(KindFamily::LinuxLog),
        1200..=1299 => Some(KindFamily::Macos),
        1300..=1399 => Some(KindFamily::HostState),
        _ => None,
    }
}

/// What the registry says about a defined record kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindInfo {
    os: &'static [OsFamily],
    schema: u16,
}

impl KindInfo {
    /// Returns the OS families whose endpoints send the kind.
    #[must_use]
    pub fn os(&self) -> &'static [OsFamily] {
        self.os
    }

    /// Returns the kind's current schema version.
    #[must_use]
    pub fn schema(&self) -> u16 {
        self.schema
    }
}

/// Returns the OS families that send a record kind and its current schema
/// version, or `None` for a number that names no defined kind.
///
/// Adding a field to a kind's body raises that kind's schema version. A
/// receiver announces the kinds it accepts, each with a range of schema
/// versions, in the accepted kinds of its `HelloAck`
/// ([`crate::connection::HelloAck::accepted_kinds`]); see [`accepts`].
#[must_use]
pub fn info(kind: u16) -> Option<KindInfo> {
    let os = match kind {
        SYSMON_PROCESS_CREATE
        | SYSMON_NETWORK_CONNECT
        | SYSMON_PROCESS_TERMINATE
        | SYSMON_PROCESS_ACCESS
        | SYSMON_FILE_CREATE
        | SYSMON_FILE_DELETE => WINDOWS_LINUX,
        SYSMON_FILE_CREATE_TIME
        | SYSMON_DRIVER_LOAD
        | SYSMON_IMAGE_LOAD
        | SYSMON_CREATE_REMOTE_THREAD
        | SYSMON_REGISTRY_ADD_DELETE
        | SYSMON_REGISTRY_VALUE_SET
        | SYSMON_REGISTRY_RENAME
        | SYSMON_FILE_CREATE_STREAM_HASH
        | SYSMON_PIPE_CREATED
        | SYSMON_DNS_QUERY
        | SYSMON_PROCESS_TAMPERING
        | SYSMON_FILE_DELETE_DETECTED
        | WINDOWS_EVENT_LOG => WINDOWS,
        SYSMON_RAW_ACCESS_READ | JOURNALD | AUDITD => LINUX,
        _ => return None,
    };
    Some(KindInfo {
        os,
        schema: SCHEMA_1,
    })
}

/// Returns whether a receiver that accepts `accepted` takes a record of
/// `kind` at schema version `schema`.
///
/// It does when some element names `kind` and has
/// `schema_min ≤ schema ≤ schema_max`. An empty list accepts nothing, and
/// an element whose `schema_min` exceeds its `schema_max` accepts nothing.
#[must_use]
pub fn accepts(accepted: &[AcceptedKind], kind: u16, schema: u16) -> bool {
    accepted
        .iter()
        .any(|entry| entry.kind == kind && entry.schema_min <= schema && schema <= entry.schema_max)
}
