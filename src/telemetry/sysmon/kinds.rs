//! The nineteen Sysmon kind bodies, each declared once as its list of
//! fields, from which its struct, its serde attributes, its conversion
//! from the Windows notation and its row of the field descriptor table
//! are made.

use std::net::IpAddr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
use super::value::FieldType;
use super::value::{FieldValue, wire};
use super::{BodyError, ConvertError, HashEntry};
use crate::connection::EncodeError;
use crate::telemetry::RecordBody;
use crate::telemetry::kind::{
    SYSMON_CREATE_REMOTE_THREAD, SYSMON_DNS_QUERY, SYSMON_DRIVER_LOAD, SYSMON_FILE_CREATE,
    SYSMON_FILE_CREATE_STREAM_HASH, SYSMON_FILE_CREATE_TIME, SYSMON_FILE_DELETE,
    SYSMON_FILE_DELETE_DETECTED, SYSMON_IMAGE_LOAD, SYSMON_NETWORK_CONNECT, SYSMON_PIPE_CREATED,
    SYSMON_PROCESS_ACCESS, SYSMON_PROCESS_CREATE, SYSMON_PROCESS_TAMPERING,
    SYSMON_PROCESS_TERMINATE, SYSMON_RAW_ACCESS_READ, SYSMON_REGISTRY_ADD_DELETE,
    SYSMON_REGISTRY_RENAME, SYSMON_REGISTRY_VALUE_SET,
};

#[cfg(test)]
/// One field of a Sysmon kind's body: its name in the Sysmon schema, its
/// key in the body's CBOR, and its body type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldDesc {
    pub(crate) schema: &'static str,
    pub(crate) key: &'static str,
    pub(crate) ty: FieldType,
}

#[cfg(test)]
/// One Sysmon kind: its number, its fields in order, and the key of the
/// field its process key is taken from, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KindDesc {
    pub(crate) kind: u16,
    pub(crate) fields: &'static [FieldDesc],
    pub(crate) process_key: Option<&'static str>,
}

/// Reads one field's value from its Windows notation.
fn parse_field<T: FieldValue>(field: &'static str, raw: &str) -> Result<T, ConvertError> {
    T::parse(raw).ok_or(ConvertError::InvalidValue {
        field,
        expected: T::TYPE.expected(),
    })
}

#[cfg(test)]
/// A field's key in the body's CBOR: its renamed key, or its name.
macro_rules! field_key {
    ($field:ident) => {
        stringify!($field)
    };
    ($field:ident, $key:literal) => {
        $key
    };
}

#[cfg(test)]
/// The key of the field a process key is taken from, if any.
macro_rules! process_key_name {
    () => {
        None
    };
    ($key:ident) => {
        Some(stringify!($key))
    };
}

/// The GUID a process key is taken from, if the kind has one.
macro_rules! process_key_guid {
    ($body:ident) => {
        None
    };
    ($body:ident, $key:ident) => {
        $body.$key
    };
}

/// Declares the Sysmon kinds.
///
/// Each kind is written as
/// `Name = KIND_CONSTANT, key = field { "SchemaName" => field: Type, ... }`,
/// with `key = field` naming the GUID field its process key is taken from,
/// or left out where it has none, and a field written
/// `field as "key"` where its key cannot be its Rust name.
macro_rules! sysmon_kinds {
    ($(
        $(#[$meta:meta])*
        $name:ident = $kind:ident $(, key = $key:ident)? {
            $( $schema:literal => $field:ident $(as $rename:literal)? : $ty:ty, )*
        }
    )*) => {
        $(
            $(#[$meta])*
            ///
            /// Every field is optional: one with no value is not sent, and
            /// a missing key and a null both read as no value. A key the
            /// receiver does not know is ignored.
            #[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
            pub struct $name {
                $(
                    #[doc = concat!("The `", $schema, "` field.")]
                    #[serde(default, skip_serializing_if = "Option::is_none", with = "wire")]
                    $(#[serde(rename = $rename)])?
                    pub $field: Option<$ty>,
                )*
            }

            impl $name {
                /// The record kind's number of this body.
                pub const KIND: u16 = $kind;

                #[cfg(test)]
                const FIELDS: &'static [FieldDesc] = &[
                    $(
                        FieldDesc {
                            schema: $schema,
                            key: field_key!($field $(, $rename)?),
                            ty: <$ty as FieldValue>::TYPE,
                        },
                    )*
                ];

                /// Reads the body from the fields of an event, which hold no
                /// name twice. An empty value and a name the body does not
                /// have are passed over.
                fn from_fields(fields: &[(&str, &str)]) -> Result<Self, ConvertError> {
                    let mut body = Self::default();
                    for &(name, raw) in fields {
                        if raw.is_empty() {
                            continue;
                        }
                        match name {
                            $( $schema => body.$field = Some(parse_field($schema, raw)?), )*
                            _ => {}
                        }
                    }
                    Ok(body)
                }

                fn process_guid(&self) -> Option<Uuid> {
                    process_key_guid!(self $(, $key)?)
                }
            }

            impl From<$name> for Body {
                fn from(body: $name) -> Self {
                    Self::$name(body)
                }
            }
        )*

        /// The body of one of the nineteen Sysmon kinds, told apart by the
        /// record kind's number.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Body {
            $(
                #[doc = concat!("A [`", stringify!($name), "`] body.")]
                $name($name),
            )*
        }

        impl Body {
            /// Returns the record kind's number of the body.
            #[must_use]
            pub fn kind(&self) -> u16 {
                match self {
                    $( Self::$name(_) => $kind, )*
                }
            }

            pub(super) fn decode(kind: u16, body: &RecordBody) -> Result<Self, BodyError> {
                match kind {
                    $( $kind => body.decode().map(Self::$name).map_err(BodyError::Decode), )*
                    _ => Err(BodyError::UnsupportedKind(kind)),
                }
            }

            pub(super) fn encode(&self) -> Result<RecordBody, EncodeError> {
                match self {
                    $( Self::$name(body) => RecordBody::encode(body), )*
                }
            }

            pub(super) fn has_kind(kind: u16) -> bool {
                matches!(kind, $( $kind )|*)
            }

            pub(super) fn from_fields(
                kind: u16,
                fields: &[(&str, &str)],
            ) -> Option<Result<Self, ConvertError>> {
                match kind {
                    $( $kind => Some($name::from_fields(fields).map(Self::$name)), )*
                    _ => None,
                }
            }

            pub(super) fn process_guid(&self) -> Option<Uuid> {
                match self {
                    $( Self::$name(body) => body.process_guid(), )*
                }
            }
        }

        /// Every Sysmon kind with a body, with its fields in order.
        #[cfg(test)]
        pub(crate) const KINDS: &[KindDesc] = &[
            $(
                KindDesc {
                    kind: $kind,
                    fields: $name::FIELDS,
                    process_key: process_key_name!($($key)?),
                },
            )*
        ];
    };
}

sysmon_kinds! {
    /// The body of Sysmon ProcessCreate, event 1.
    ProcessCreate = SYSMON_PROCESS_CREATE, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "FileVersion" => file_version: String,
        "Description" => description: String,
        "Product" => product: String,
        "Company" => company: String,
        "OriginalFileName" => original_file_name: String,
        "CommandLine" => command_line: String,
        "CurrentDirectory" => current_directory: String,
        "User" => user: String,
        "LogonGuid" => logon_guid: Uuid,
        "LogonId" => logon_id: u64,
        "TerminalSessionId" => terminal_session_id: u32,
        "IntegrityLevel" => integrity_level: String,
        "Hashes" => hashes: Vec<HashEntry>,
        "ParentProcessGuid" => parent_process_guid: Uuid,
        "ParentProcessId" => parent_process_id: u32,
        "ParentImage" => parent_image: String,
        "ParentCommandLine" => parent_command_line: String,
        "ParentUser" => parent_user: String,
    }

    /// The body of Sysmon FileCreateTime, event 2.
    FileCreateTime = SYSMON_FILE_CREATE_TIME, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetFilename" => target_filename: String,
        "CreationUtcTime" => creation_utc_time: Timestamp,
        "PreviousCreationUtcTime" => previous_creation_utc_time: Timestamp,
        "User" => user: String,
    }

    /// The body of Sysmon NetworkConnect, event 3.
    NetworkConnect = SYSMON_NETWORK_CONNECT, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "User" => user: String,
        "Protocol" => protocol: String,
        "Initiated" => initiated: bool,
        "SourceIsIpv6" => source_is_ipv6: bool,
        "SourceIp" => source_ip: IpAddr,
        "SourceHostname" => source_hostname: String,
        "SourcePort" => source_port: u16,
        "SourcePortName" => source_port_name: String,
        "DestinationIsIpv6" => destination_is_ipv6: bool,
        "DestinationIp" => destination_ip: IpAddr,
        "DestinationHostname" => destination_hostname: String,
        "DestinationPort" => destination_port: u16,
        "DestinationPortName" => destination_port_name: String,
    }

    /// The body of Sysmon ProcessTerminate, event 5.
    ProcessTerminate = SYSMON_PROCESS_TERMINATE, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "User" => user: String,
    }

    /// The body of Sysmon DriverLoad, event 6. It has no process.
    DriverLoad = SYSMON_DRIVER_LOAD {
        "RuleName" => rule_name: String,
        "ImageLoaded" => image_loaded: String,
        "Hashes" => hashes: Vec<HashEntry>,
        "Signed" => signed: String,
        "Signature" => signature: String,
        "SignatureStatus" => signature_status: String,
    }

    /// The body of Sysmon ImageLoad, event 7.
    ImageLoad = SYSMON_IMAGE_LOAD, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "ImageLoaded" => image_loaded: String,
        "FileVersion" => file_version: String,
        "Description" => description: String,
        "Product" => product: String,
        "Company" => company: String,
        "OriginalFileName" => original_file_name: String,
        "Hashes" => hashes: Vec<HashEntry>,
        "Signed" => signed: String,
        "Signature" => signature: String,
        "SignatureStatus" => signature_status: String,
        "User" => user: String,
    }

    /// The body of Sysmon CreateRemoteThread, event 8. Its process key is
    /// the source process; the target stays in `target_process_guid`.
    CreateRemoteThread = SYSMON_CREATE_REMOTE_THREAD, key = source_process_guid {
        "RuleName" => rule_name: String,
        "SourceProcessGuid" => source_process_guid: Uuid,
        "SourceProcessId" => source_process_id: u32,
        "SourceImage" => source_image: String,
        "TargetProcessGuid" => target_process_guid: Uuid,
        "TargetProcessId" => target_process_id: u32,
        "TargetImage" => target_image: String,
        "NewThreadId" => new_thread_id: u32,
        "StartAddress" => start_address: String,
        "StartModule" => start_module: String,
        "StartFunction" => start_function: String,
        "SourceUser" => source_user: String,
        "TargetUser" => target_user: String,
    }

    /// The body of Sysmon RawAccessRead, event 9.
    RawAccessRead = SYSMON_RAW_ACCESS_READ, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "Device" => device: String,
        "User" => user: String,
    }

    /// The body of Sysmon ProcessAccess, event 10. Its process key is the
    /// source process; the target stays in `target_process_guid`.
    ProcessAccess = SYSMON_PROCESS_ACCESS, key = source_process_guid {
        "RuleName" => rule_name: String,
        "SourceProcessGUID" => source_process_guid: Uuid,
        "SourceProcessId" => source_process_id: u32,
        "SourceThreadId" => source_thread_id: u32,
        "SourceImage" => source_image: String,
        "TargetProcessGUID" => target_process_guid: Uuid,
        "TargetProcessId" => target_process_id: u32,
        "TargetImage" => target_image: String,
        "GrantedAccess" => granted_access: u64,
        "CallTrace" => call_trace: String,
        "SourceUser" => source_user: String,
        "TargetUser" => target_user: String,
    }

    /// The body of Sysmon FileCreate, event 11.
    FileCreate = SYSMON_FILE_CREATE, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetFilename" => target_filename: String,
        "CreationUtcTime" => creation_utc_time: Timestamp,
        "User" => user: String,
    }

    /// The body of Sysmon RegistryEvent (Object create and delete),
    /// event 12.
    RegistryAddDelete = SYSMON_REGISTRY_ADD_DELETE, key = process_guid {
        "RuleName" => rule_name: String,
        "EventType" => event_type: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetObject" => target_object: String,
        "User" => user: String,
    }

    /// The body of Sysmon RegistryEvent (Value Set), event 13.
    RegistryValueSet = SYSMON_REGISTRY_VALUE_SET, key = process_guid {
        "RuleName" => rule_name: String,
        "EventType" => event_type: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetObject" => target_object: String,
        "Details" => details: String,
        "User" => user: String,
    }

    /// The body of Sysmon RegistryEvent (Key and Value Rename), event 14.
    RegistryRename = SYSMON_REGISTRY_RENAME, key = process_guid {
        "RuleName" => rule_name: String,
        "EventType" => event_type: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetObject" => target_object: String,
        "NewName" => new_name: String,
        "User" => user: String,
    }

    /// The body of Sysmon FileCreateStreamHash, event 15. Its `hash` is
    /// text as Sysmon writes it, not a list of hashes.
    FileCreateStreamHash = SYSMON_FILE_CREATE_STREAM_HASH, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "TargetFilename" => target_filename: String,
        "CreationUtcTime" => creation_utc_time: Timestamp,
        "Hash" => hash: String,
        "Contents" => contents: String,
        "User" => user: String,
    }

    /// The body of Sysmon PipeEvent (Pipe Created), event 17.
    PipeCreated = SYSMON_PIPE_CREATED, key = process_guid {
        "RuleName" => rule_name: String,
        "EventType" => event_type: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "PipeName" => pipe_name: String,
        "Image" => image: String,
        "User" => user: String,
    }

    /// The body of Sysmon DnsQuery, event 22. Its `query_results` is text
    /// as Sysmon writes it.
    DnsQuery = SYSMON_DNS_QUERY, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "QueryName" => query_name: String,
        "QueryStatus" => query_status: String,
        "QueryResults" => query_results: String,
        "Image" => image: String,
        "User" => user: String,
    }

    /// The body of Sysmon FileDelete, event 23.
    FileDelete = SYSMON_FILE_DELETE, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "User" => user: String,
        "Image" => image: String,
        "TargetFilename" => target_filename: String,
        "Hashes" => hashes: Vec<HashEntry>,
        "IsExecutable" => is_executable: bool,
        "Archived" => archived: String,
    }

    /// The body of Sysmon ProcessTampering, event 25.
    ProcessTampering = SYSMON_PROCESS_TAMPERING, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "Image" => image: String,
        "Type" => r#type as "type": String,
        "User" => user: String,
    }

    /// The body of Sysmon FileDeleteDetected, event 26.
    FileDeleteDetected = SYSMON_FILE_DELETE_DETECTED, key = process_guid {
        "RuleName" => rule_name: String,
        "ProcessGuid" => process_guid: Uuid,
        "ProcessId" => process_id: u32,
        "User" => user: String,
        "Image" => image: String,
        "TargetFilename" => target_filename: String,
        "Hashes" => hashes: Vec<HashEntry>,
        "IsExecutable" => is_executable: bool,
    }
}
