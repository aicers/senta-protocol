//! The `control_cbor` and `active_list` vector files: control message
//! bodies and active list updates, each as its CBOR bytes and the JSON
//! view of those bytes.
//!
//! The JSON view follows the CBOR data model, with the fields a [`Schema`]
//! names written as UUID strings, RFC 3339 times or standard base64; the
//! README lays it out. [`view`] writes it from the bytes, and [`rebuild`]
//! turns it back into the CBOR data model to encode.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ciborium::Value;
use jiff::{SignedDuration, Timestamp};
use senta_protocol::auth::active_list::{EntryState, ListEntry, ListUpdate};
use senta_protocol::connection::{ClockOffset, cbor};
use senta_protocol::control::{
    AuditPolicyState, ClockStatus, CollectionStatus, DocumentSlot, DocumentSlotState,
    DocumentTarget, EndpointStatus, EnrollRequest, EnrollToken, EntryStatus, Hardware,
    InUseDocument, KeyStorage, KeysetPosition, MachineId, Problem, StatusReport, SysmonState,
    SysmonStatus, TransportStatus, machine_id_hash,
};
use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
use senta_protocol::results::DocumentResult;
use senta_protocol::standing::SuspendReason;
use serde::Serialize;
use uuid::Uuid;

use crate::fixtures::{
    ATTEMPT, CUSTOMER, ENDPOINT, ENTRY, GROUP, INSTALL_ID, OTHER_CUSTOMER, OTHER_ENDPOINT,
    SENTA_VERSION, bytes32, customer_kid, hw_salt, now,
};
use crate::json::J;
use crate::model::{
    ActiveListCase, Category, ControlCborCase, ControlMessageType, FORMAT_VERSION, VectorFile,
};

/// The enrollment token the enrollment requests carry: a fixed test value
/// in the form of a compact JWS, which nothing here verifies. Its segments
/// decode to `{"test":true}`, `{"token_id":"test"}` and `test-signature`.
pub const TEST_ENROLL_TOKEN: &str =
    "eyJ0ZXN0Ijp0cnVlfQ.eyJ0b2tlbl9pZCI6InRlc3QifQ.dGVzdC1zaWduYXR1cmU";

/// The Windows MachineGuid the hardware identities hash.
const MACHINE_GUID: &str = "{6F9619FF-8B86-D011-B42D-00C04FC964FF}";
/// The Linux machine-id the hardware identities hash.
const MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";

// --- the JSON view ------------------------------------------------------------------

/// Where a JSON view differs from the plain CBOR data model: the fields
/// that are UUIDs, points in time, and other byte strings, each a path of
/// member names, `[]` standing for every element of an array.
pub struct Schema {
    pub uuids: &'static [&'static [&'static str]],
    pub times: &'static [&'static [&'static str]],
    pub bytes: &'static [&'static [&'static str]],
}

pub const ENROLL_REQUEST: Schema = Schema {
    uuids: &[&["attempt_id"]],
    times: &[],
    bytes: &[&["hardware", "machine_id_hash"]],
};

pub const STATUS_REPORT: Schema = Schema {
    uuids: &[
        &["documents", "[]", "target", "group"],
        &["documents", "[]", "target", "endpoint"],
        &["documents", "[]", "target", "customer"],
        &["transport", "entries", "[]", "entry_id"],
    ],
    times: &[
        &["transport", "entries", "[]", "last_success_at"],
        &["clock", "offset", "measured_at"],
    ],
    bytes: &[&["hardware", "machine_id_hash"]],
};

pub const LIST_UPDATE: Schema = Schema {
    uuids: &[
        &["full", "entries", "[]", "endpoint_id"],
        &["full", "entries", "[]", "customer_endpoint_id"],
        &["diff", "upserts", "[]", "endpoint_id"],
        &["diff", "upserts", "[]", "customer_endpoint_id"],
        &["diff", "removals", "[]"],
    ],
    times: &[],
    bytes: &[
        &["full", "entries", "[]", "spki_sha256"],
        &["diff", "upserts", "[]", "spki_sha256"],
    ],
};

pub fn schema_of(message_type: ControlMessageType) -> &'static Schema {
    match message_type {
        ControlMessageType::EnrollRequest => &ENROLL_REQUEST,
        ControlMessageType::StatusReport => &STATUS_REPORT,
    }
}

/// One step into a value: a map's member, or an array's element.
#[derive(Clone)]
enum Step {
    Key(String),
    Index,
}

/// What the field at a path is, by the schema.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Uuid,
    Time,
    Bytes,
    Plain,
}

impl Schema {
    fn kind_at(&self, path: &[Step]) -> Kind {
        let matches = |pattern: &[&str]| {
            pattern.len() == path.len()
                && pattern.iter().zip(path).all(|(want, step)| match step {
                    Step::Key(key) => key == want,
                    Step::Index => *want == "[]",
                })
        };
        if self.uuids.iter().any(|pattern| matches(pattern)) {
            Kind::Uuid
        } else if self.times.iter().any(|pattern| matches(pattern)) {
            Kind::Time
        } else if self.bytes.iter().any(|pattern| matches(pattern)) {
            Kind::Bytes
        } else {
            Kind::Plain
        }
    }
}

fn at(path: &[Step]) -> String {
    let mut text = String::from("$");
    for step in path {
        match step {
            Step::Key(key) => {
                text.push('.');
                text.push_str(key);
            }
            Step::Index => text.push_str("[]"),
        }
    }
    text
}

/// Writes the JSON view of CBOR bytes, by `schema`.
pub fn view(bytes: &[u8], schema: &Schema) -> Result<J, String> {
    let value: Value = ciborium::from_reader(bytes).map_err(|error| format!("CBOR: {error}"))?;
    let mut path = Vec::new();
    view_value(&value, schema, &mut path)
}

fn view_value(value: &Value, schema: &Schema, path: &mut Vec<Step>) -> Result<J, String> {
    let kind = schema.kind_at(path);
    match (value, kind) {
        (Value::Bytes(bytes), Kind::Uuid) => {
            let bytes: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("{}: a UUID of {} bytes", at(path), bytes.len()))?;
            Ok(J::str(Uuid::from_bytes(bytes).hyphenated().to_string()))
        }
        (Value::Bytes(bytes), Kind::Bytes) => Ok(J::str(STANDARD.encode(bytes))),
        (Value::Integer(nanos), Kind::Time) => {
            let at_time = Timestamp::from_nanosecond(i128::from(*nanos))
                .map_err(|error| format!("{}: {error}", at(path)))?;
            Ok(J::str(at_time.to_string()))
        }
        (_, Kind::Uuid | Kind::Time | Kind::Bytes) => {
            Err(format!("{}: {value:?} is not of its kind", at(path)))
        }
        (Value::Bytes(_), Kind::Plain) => Err(format!(
            "{}: a byte string the schema does not name",
            at(path)
        )),
        (Value::Integer(integer), Kind::Plain) => {
            let integer = i128::from(*integer);
            match (u64::try_from(integer), i64::try_from(integer)) {
                (Ok(value), _) => Ok(J::Int(value)),
                (Err(_), Ok(value)) => Ok(J::Neg(value)),
                _ => Err(format!("{}: {integer} is out of range", at(path))),
            }
        }
        (Value::Text(text), Kind::Plain) => Ok(J::str(text)),
        (Value::Bool(value), Kind::Plain) => Ok(J::Bool(*value)),
        (Value::Null, Kind::Plain) => Ok(J::Null),
        (Value::Array(items), Kind::Plain) => {
            let mut out = Vec::new();
            for item in items {
                path.push(Step::Index);
                out.push(view_value(item, schema, path)?);
                path.pop();
            }
            Ok(J::Arr(out))
        }
        (Value::Map(members), Kind::Plain) => {
            let mut out = Vec::new();
            for (key, member) in members {
                let Value::Text(key) = key else {
                    return Err(format!("{}: a map key that is not text", at(path)));
                };
                path.push(Step::Key(key.clone()));
                out.push((key.clone(), view_value(member, schema, path)?));
                path.pop();
            }
            Ok(J::Obj(out))
        }
        (other, Kind::Plain) => Err(format!("{}: {other:?} has no JSON view", at(path))),
    }
}

/// Turns a JSON view back into the CBOR data model, by `schema`.
pub fn rebuild(view: &J, schema: &Schema) -> Result<Value, String> {
    let mut path = Vec::new();
    rebuild_value(view, schema, &mut path)
}

fn rebuild_value(view: &J, schema: &Schema, path: &mut Vec<Step>) -> Result<Value, String> {
    let kind = schema.kind_at(path);
    match (view, kind) {
        (J::Str(text), Kind::Uuid) => {
            let id = Uuid::try_parse(text).map_err(|error| format!("{}: {error}", at(path)))?;
            if id.hyphenated().to_string() != *text {
                return Err(format!("{}: {text} is not a lowercase UUID", at(path)));
            }
            Ok(Value::Bytes(id.as_bytes().to_vec()))
        }
        (J::Str(text), Kind::Bytes) => STANDARD
            .decode(text)
            .map(Value::Bytes)
            .map_err(|error| format!("{}: {error}", at(path))),
        (J::Str(text), Kind::Time) => {
            let time: Timestamp = text
                .parse()
                .map_err(|error| format!("{}: {error}", at(path)))?;
            let nanos = i64::try_from(time.as_nanosecond())
                .map_err(|_| format!("{}: {text} is out of range", at(path)))?;
            Ok(Value::Integer(nanos.into()))
        }
        (_, Kind::Uuid | Kind::Time | Kind::Bytes) => {
            Err(format!("{}: {view} is not a string", at(path)))
        }
        (J::Null, Kind::Plain) => Ok(Value::Null),
        (J::Bool(value), Kind::Plain) => Ok(Value::Bool(*value)),
        (J::Int(value), Kind::Plain) => Ok(Value::Integer((*value).into())),
        (J::Neg(value), Kind::Plain) => Ok(Value::Integer((*value).into())),
        (J::Str(text), Kind::Plain) => Ok(Value::Text(text.clone())),
        (J::Arr(items), Kind::Plain) => {
            let mut out = Vec::new();
            for item in items {
                path.push(Step::Index);
                out.push(rebuild_value(item, schema, path)?);
                path.pop();
            }
            Ok(Value::Array(out))
        }
        (J::Obj(members), Kind::Plain) => {
            let mut out = Vec::new();
            for (key, member) in members {
                path.push(Step::Key(key.clone()));
                out.push((
                    Value::Text(key.clone()),
                    rebuild_value(member, schema, path)?,
                ));
                path.pop();
            }
            Ok(Value::Map(out))
        }
        (J::Raw(_), Kind::Plain) => Err(format!("{}: raw JSON text", at(path))),
    }
}

pub fn b64_standard(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_standard_decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    cbor::to_vec(value).expect("every case value encodes")
}

// --- the values -----------------------------------------------------------------------

fn uuid(text: &str) -> Uuid {
    Uuid::try_parse(text).expect("a fixed UUID")
}

/// The id of the active list entry numbered `n`.
fn list_endpoint(n: u8) -> Uuid {
    uuid(&format!("e0eebc99-9c0b-4ef8-bb6d-6bb9bd380a{n:02x}"))
}

/// A point in time with a fraction, to show nanoseconds in the view.
fn fractional_time() -> Timestamp {
    now() - SignedDuration::new(90, 123_456_789)
}

fn windows_hardware() -> Hardware {
    Hardware {
        machine_id_hash: machine_id_hash(MachineId::Windows(MACHINE_GUID), &hw_salt())
            .expect("a fixed MachineGuid"),
        smbios_uuid: Some("4c4c4544-0042-3510-8051-b4c04f4a4d32".to_owned()),
        smbios_serial: Some("5XQ8VD2".to_owned()),
    }
}

fn linux_hardware() -> Hardware {
    Hardware {
        machine_id_hash: machine_id_hash(MachineId::Linux(MACHINE_ID), &hw_salt())
            .expect("a fixed machine-id"),
        smbios_uuid: None,
        smbios_serial: None,
    }
}

fn windows_os() -> OsInfo {
    OsInfo {
        family: OsFamily::Windows,
        version: "10.0.22631".to_owned(),
    }
}

fn linux_os() -> OsInfo {
    OsInfo {
        family: OsFamily::Linux,
        version: "6.8.0-45-generic".to_owned(),
    }
}

/// An enrollment request case: its name, description and value.
pub struct EnrollRequestCase {
    pub variant: &'static str,
    pub description: &'static str,
    pub value: EnrollRequest,
}

pub fn enroll_requests() -> Vec<EnrollRequestCase> {
    vec![
        EnrollRequestCase {
            variant: "with_smbios",
            description: "A Windows endpoint's request whose hardware carries both SMBIOS fields.",
            value: EnrollRequest {
                attempt_id: uuid(ATTEMPT),
                trusted_keyset: KeysetPosition {
                    recovery_epoch: 1,
                    keyset_version: 1,
                },
                trusted_recovery_key_version: 1,
                enroll_token: EnrollToken::new(TEST_ENROLL_TOKEN.to_owned()),
                hardware: windows_hardware(),
                hostname: "ws-0042.acme.example".to_owned(),
                os: windows_os(),
                senta_version: SENTA_VERSION.to_owned(),
                key_storage: KeyStorage::Tpm,
                vdi_mode: false,
            },
        },
        EnrollRequestCase {
            variant: "without_smbios",
            description: "A Linux endpoint's request in VDI mode whose hardware carries neither SMBIOS field.",
            value: EnrollRequest {
                attempt_id: uuid(ATTEMPT),
                trusted_keyset: KeysetPosition {
                    recovery_epoch: 2,
                    keyset_version: 7,
                },
                trusted_recovery_key_version: 3,
                enroll_token: EnrollToken::new(TEST_ENROLL_TOKEN.to_owned()),
                hardware: linux_hardware(),
                hostname: "vdi-pool-17".to_owned(),
                os: linux_os(),
                senta_version: "1.2.0-rc.1".to_owned(),
                key_storage: KeyStorage::File,
                vdi_mode: true,
            },
        },
    ]
}

fn endpoint_status(os: OsInfo, key_storage: KeyStorage) -> EndpointStatus {
    EndpointStatus {
        senta_version: SENTA_VERSION.to_owned(),
        os,
        key_storage,
        keyset: KeysetPosition {
            recovery_epoch: 1,
            keyset_version: 2,
        },
        recovery_key_version: 1,
    }
}

/// A slot of `typ` with every optional field left out.
fn bare_slot(typ: &str, state: DocumentSlotState) -> DocumentSlot {
    DocumentSlot {
        typ: typ.to_owned(),
        target: None,
        verified_version: None,
        applied_version: None,
        state,
        in_use: None,
        untrusted: false,
    }
}

fn quiet_transport(entries: Vec<EntryStatus>) -> TransportStatus {
    TransportStatus {
        entries,
        buffered_records: 0,
        buffered_bytes: 0,
        dropped_ranges: 0,
        unsupported_dropped: 0,
    }
}

fn no_clock() -> ClockStatus {
    ClockStatus {
        offset: None,
        exceeds_tolerance: false,
    }
}

/// Every value of `Problem`, in the order the crate declares them, with
/// `signature_rejected` both with and without its optional fields.
fn every_problem() -> Vec<Problem> {
    vec![
        Problem::SignatureRejected {
            typ: Some("senta-policy".to_owned()),
            kid: Some(customer_kid(2)),
            result: DocumentResult::BadSignature,
        },
        Problem::SignatureRejected {
            typ: None,
            kid: None,
            result: DocumentResult::KeysetGap {
                have_epoch: 1,
                have_version: 2,
            },
        },
        Problem::UnknownKid {
            kid: customer_kid(9),
        },
        Problem::KeysetGap,
        Problem::UpdateFailed,
        Problem::UpdateRolledBack,
        Problem::SourceUnreachable,
        Problem::PriorEpochState,
        Problem::SysmonMissing,
        Problem::ClockSkew,
        Problem::InstallConfigInvalid,
        Problem::SysmonStopped,
        Problem::SysmonConfigChanged,
        Problem::UnexpectedRestart,
        Problem::Other("disk_full".to_owned()),
    ]
}

/// A status report case: its name, description and value.
pub struct StatusReportCase {
    pub variant: &'static str,
    pub description: &'static str,
    pub value: StatusReport,
}

#[allow(clippy::too_many_lines)] // Each case written out in full, field by field.
pub fn status_reports() -> Vec<StatusReportCase> {
    vec![
        StatusReportCase {
            variant: "optional_fields_absent",
            description: "Every optional field left out: a slot with no target, versions or in_use, a Sysmon with no version, an entry with no last_success_at, no clock offset, no SMBIOS fields, and no problem.",
            value: StatusReport {
                endpoint: endpoint_status(linux_os(), KeyStorage::File),
                documents: vec![bare_slot("senta-addresses", DocumentSlotState::Current)],
                collection: CollectionStatus {
                    collection_mode: CollectionMode::Essential,
                    sysmon: SysmonStatus {
                        state: SysmonState::Absent,
                        version: None,
                    },
                    audit_policy: AuditPolicyState::Off,
                },
                transport: quiet_transport(vec![EntryStatus {
                    entry_id: uuid(ENTRY),
                    last_success_at: None,
                }]),
                clock: no_clock(),
                hardware: linux_hardware(),
                problems: Vec::new(),
            },
        },
        StatusReportCase {
            variant: "empty_lists",
            description: "No document slot, no telemetry entry and no problem.",
            value: StatusReport {
                endpoint: endpoint_status(linux_os(), KeyStorage::File),
                documents: Vec::new(),
                collection: CollectionStatus {
                    collection_mode: CollectionMode::Essential,
                    sysmon: SysmonStatus {
                        state: SysmonState::Builtin,
                        version: None,
                    },
                    audit_policy: AuditPolicyState::Applied,
                },
                transport: quiet_transport(Vec::new()),
                clock: no_clock(),
                hardware: linux_hardware(),
                problems: Vec::new(),
            },
        },
        StatusReportCase {
            variant: "optional_fields_present",
            description: "Every optional field present: slots with each target and slot state, versions and a document in use from a prior epoch, a Sysmon version, a last success with nanoseconds, a negative clock offset and both SMBIOS fields.",
            value: StatusReport {
                endpoint: endpoint_status(windows_os(), KeyStorage::Dpapi),
                documents: vec![
                    DocumentSlot {
                        typ: "senta-policy".to_owned(),
                        target: Some(DocumentTarget::Group(uuid(GROUP))),
                        verified_version: Some(1_767_225_600_000),
                        applied_version: Some(1_767_225_600_000),
                        state: DocumentSlotState::Current,
                        in_use: None,
                        untrusted: false,
                    },
                    DocumentSlot {
                        typ: "senta-assign".to_owned(),
                        target: Some(DocumentTarget::Endpoint(uuid(ENDPOINT))),
                        verified_version: Some(1_767_225_660_000),
                        applied_version: None,
                        state: DocumentSlotState::Halted {
                            reason: "group not found".to_owned(),
                        },
                        in_use: Some(InUseDocument {
                            recovery_epoch: 1,
                            version: 1_767_139_200_000,
                        }),
                        untrusted: true,
                    },
                    DocumentSlot {
                        typ: "senta-update".to_owned(),
                        target: Some(DocumentTarget::Group(uuid(GROUP))),
                        verified_version: Some(1_767_225_720_000),
                        applied_version: Some(1_767_225_600_000),
                        state: DocumentSlotState::Pending,
                        in_use: None,
                        untrusted: false,
                    },
                    DocumentSlot {
                        typ: "senta-update".to_owned(),
                        target: Some(DocumentTarget::Endpoint(uuid(ENDPOINT))),
                        verified_version: Some(1_767_225_780_000),
                        applied_version: None,
                        state: DocumentSlotState::PendingOffTarget,
                        in_use: None,
                        untrusted: false,
                    },
                    DocumentSlot {
                        typ: "senta-keyset".to_owned(),
                        target: Some(DocumentTarget::Customer(uuid(CUSTOMER))),
                        verified_version: Some(2),
                        applied_version: Some(2),
                        state: DocumentSlotState::Current,
                        in_use: None,
                        untrusted: false,
                    },
                    DocumentSlot {
                        typ: "senta-install-config".to_owned(),
                        target: Some(DocumentTarget::Install(INSTALL_ID.to_owned())),
                        verified_version: None,
                        applied_version: None,
                        state: DocumentSlotState::Current,
                        in_use: None,
                        untrusted: false,
                    },
                ],
                collection: CollectionStatus {
                    collection_mode: CollectionMode::Extended,
                    sysmon: SysmonStatus {
                        state: SysmonState::Standalone,
                        version: Some("15.15".to_owned()),
                    },
                    audit_policy: AuditPolicyState::GpoManaged,
                },
                transport: TransportStatus {
                    entries: vec![EntryStatus {
                        entry_id: uuid(ENTRY),
                        last_success_at: Some(fractional_time()),
                    }],
                    buffered_records: 1_024,
                    buffered_bytes: 1_048_576,
                    dropped_ranges: 2,
                    unsupported_dropped: 7,
                },
                clock: ClockStatus {
                    offset: Some(ClockOffset {
                        offset_ms: -1_500,
                        uncertainty_ms: 20,
                        measured_at: now(),
                    }),
                    exceeds_tolerance: false,
                },
                hardware: windows_hardware(),
                problems: vec![Problem::SourceUnreachable],
            },
        },
        StatusReportCase {
            variant: "every_problem",
            description: "Every Problem value, the three tampering signs and an unknown tag among them, with a clock offset beyond one hour.",
            value: StatusReport {
                endpoint: endpoint_status(windows_os(), KeyStorage::Tpm),
                documents: vec![bare_slot("senta-addresses", DocumentSlotState::Current)],
                collection: CollectionStatus {
                    collection_mode: CollectionMode::Extended,
                    sysmon: SysmonStatus {
                        state: SysmonState::Standalone,
                        version: Some("15.15".to_owned()),
                    },
                    audit_policy: AuditPolicyState::Applied,
                },
                transport: quiet_transport(vec![EntryStatus {
                    entry_id: uuid(ENTRY),
                    last_success_at: Some(now()),
                }]),
                clock: ClockStatus {
                    offset: Some(ClockOffset {
                        offset_ms: 3_600_001,
                        uncertainty_ms: 5,
                        measured_at: now(),
                    }),
                    exceeds_tolerance: true,
                },
                hardware: windows_hardware(),
                problems: every_problem(),
            },
        },
        StatusReportCase {
            variant: "unknown_tags",
            description: "A tag this crate does not know in each field that takes one, read as Other.",
            value: StatusReport {
                endpoint: endpoint_status(
                    OsInfo {
                        family: OsFamily::Other("freebsd".to_owned()),
                        version: "14.1".to_owned(),
                    },
                    KeyStorage::Other("hsm".to_owned()),
                ),
                documents: vec![DocumentSlot {
                    typ: "senta-future".to_owned(),
                    target: Some(DocumentTarget::Other("fleet".to_owned())),
                    verified_version: None,
                    applied_version: None,
                    state: DocumentSlotState::Other("frozen".to_owned()),
                    in_use: None,
                    untrusted: false,
                }],
                collection: CollectionStatus {
                    collection_mode: CollectionMode::Other("forensic".to_owned()),
                    sysmon: SysmonStatus {
                        state: SysmonState::Other("embedded".to_owned()),
                        version: None,
                    },
                    audit_policy: AuditPolicyState::Other("partial".to_owned()),
                },
                transport: quiet_transport(Vec::new()),
                clock: no_clock(),
                hardware: linux_hardware(),
                problems: vec![Problem::Other("disk_full".to_owned())],
            },
        },
    ]
}

/// An active list update case: its name, description and value.
pub struct ListUpdateCase {
    pub variant: &'static str,
    pub description: &'static str,
    pub value: ListUpdate,
}

/// One entry in each of the five forms of state.
fn every_state_entries() -> Vec<ListEntry> {
    let states = [
        EntryState::Active,
        EntryState::LicensePending,
        EntryState::Suspended {
            reason: SuspendReason::Revoked,
        },
        EntryState::Suspended {
            reason: SuspendReason::Operator,
        },
        EntryState::Suspended {
            reason: SuspendReason::License,
        },
    ];
    states
        .into_iter()
        .zip(1_u8..)
        .map(|(state, n)| ListEntry {
            endpoint_id: list_endpoint(n),
            spki_sha256: bytes32(&format!("active list spki {n}")),
            customer_endpoint_id: uuid(if n % 2 == 1 { CUSTOMER } else { OTHER_CUSTOMER }),
            state,
        })
        .collect()
}

pub fn list_updates() -> Vec<ListUpdateCase> {
    vec![
        ListUpdateCase {
            variant: "full_every_state",
            description: "A whole list of five entries, one in each form of state.",
            value: ListUpdate::Full {
                version: 1_767_225_600_000,
                entries: every_state_entries(),
            },
        },
        ListUpdateCase {
            variant: "full_empty",
            description: "A whole list with no entry.",
            value: ListUpdate::Full {
                version: 1,
                entries: Vec::new(),
            },
        },
        ListUpdateCase {
            variant: "diff_every_state",
            description: "A change upserting five entries, one in each form of state, and removing two endpoints.",
            value: ListUpdate::Diff {
                base_version: 1_767_225_600_000,
                version: 1_767_225_600_001,
                upserts: every_state_entries(),
                removals: vec![uuid(ENDPOINT), uuid(OTHER_ENDPOINT)],
            },
        },
        ListUpdateCase {
            variant: "diff_removals_only",
            description: "A change that only removes one endpoint.",
            value: ListUpdate::Diff {
                base_version: 7,
                version: 8,
                upserts: Vec::new(),
                removals: vec![list_endpoint(3)],
            },
        },
    ]
}

// --- the files ------------------------------------------------------------------------

fn control_case<T: Serialize>(
    message_type: ControlMessageType,
    variant: &str,
    description: &str,
    value: &T,
) -> ControlCborCase {
    let bytes = encode(value);
    let prefix = match message_type {
        ControlMessageType::EnrollRequest => "enroll_request",
        ControlMessageType::StatusReport => "status_report",
    };
    ControlCborCase {
        name: format!("{prefix}:{variant}"),
        description: description.to_owned(),
        message_type,
        value: view(&bytes, schema_of(message_type)).expect("every case has a view"),
        cbor: b64_standard(&bytes),
    }
}

pub fn control_file() -> VectorFile<ControlCborCase> {
    let mut cases = Vec::new();
    for case in enroll_requests() {
        cases.push(control_case(
            ControlMessageType::EnrollRequest,
            case.variant,
            case.description,
            &case.value,
        ));
    }
    for case in status_reports() {
        cases.push(control_case(
            ControlMessageType::StatusReport,
            case.variant,
            case.description,
            &case.value,
        ));
    }
    VectorFile {
        format_version: FORMAT_VERSION,
        category: Category::ControlCbor,
        keys: Vec::new(),
        cases,
    }
}

pub fn active_list_file() -> VectorFile<ActiveListCase> {
    let cases = list_updates()
        .into_iter()
        .map(|case| {
            let bytes = case.value.encode().expect("every case value encodes");
            ActiveListCase {
                name: format!("list_update:{}", case.variant),
                description: case.description.to_owned(),
                value: view(&bytes, &LIST_UPDATE).expect("every case has a view"),
                cbor: b64_standard(&bytes),
            }
        })
        .collect();
    VectorFile {
        format_version: FORMAT_VERSION,
        category: Category::ActiveList,
        keys: Vec::new(),
        cases,
    }
}
