//! The structure of the vector files, as `tests/vectors/README.md` lays it
//! out. Every type serializes its fields in the order declared here.

use serde::{Deserialize, Deserializer, Serialize};

use crate::json::J;

/// The format version of the vector files.
pub const FORMAT_VERSION: u32 = 1;

/// One vector file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorFile<C> {
    pub format_version: u32,
    pub category: Category,
    pub keys: Vec<KeyEntry>,
    pub cases: Vec<C>,
}

/// A vector file read only as far as its category, to pick its case type,
/// and its case names.
#[derive(Deserialize)]
pub struct FileHeader {
    pub format_version: u32,
    pub category: Category,
    pub cases: Vec<CaseName>,
}

/// A case read only as far as its name.
#[derive(Deserialize)]
pub struct CaseName {
    pub name: String,
}

/// The category of a vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Jws,
    TrustChain,
    Keyset,
    Leak,
    DocumentVersions,
    EnrollResult,
    Commands,
    HardwareHash,
}

impl Category {
    pub const ALL: [Self; 8] = [
        Self::Jws,
        Self::TrustChain,
        Self::Keyset,
        Self::Leak,
        Self::DocumentVersions,
        Self::EnrollResult,
        Self::Commands,
        Self::HardwareHash,
    ];

    /// Returns the category's name, which is also its file's name without
    /// `.json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jws => "jws",
            Self::TrustChain => "trust_chain",
            Self::Keyset => "keyset",
            Self::Leak => "leak",
            Self::DocumentVersions => "document_versions",
            Self::EnrollResult => "enroll_result",
            Self::Commands => "commands",
            Self::HardwareHash => "hardware_hash",
        }
    }

    pub fn file_name(self) -> String {
        format!("{}.json", self.as_str())
    }
}

/// The kind of a key, as its kid names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKindName {
    Vendor,
    InstallSigning,
    Customer,
    Recovery,
}

/// One entry of a file's key list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    pub kid: String,
    pub kind: KeyKindName,
    /// The 32-byte Ed25519 seed, unpadded base64url. Test only, not secret.
    pub seed: String,
    pub jwk: JwkJson,
}

/// A public key as a JWK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwkJson {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

// --- single-verdict cases ----------------------------------------------------

/// A case of the `jws` file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwsCase {
    pub name: String,
    pub description: String,
    /// The kid whose seed signed the signing input, when the signature is
    /// the genuine one; absent when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    pub input: JwsInput,
    pub expected: J,
}

/// The input of a `jws` case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwsInput {
    /// The text handed to the verifier as it is.
    pub jws: String,
    /// The decoded header, when it is UTF-8; for reading only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_json: Option<String>,
    /// The decoded payload, when it is UTF-8; for reading only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_json: Option<String>,
    pub expected_typ: String,
    pub trusted_keys: Vec<TrustedKey>,
    pub revoked_kids: Vec<String>,
}

/// A key the verifier's key source holds, registered under `kid` as `kind`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedKey {
    pub kid: String,
    pub kind: KeyKindName,
}

/// A case of the `trust_chain` file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainCase {
    pub name: String,
    pub description: String,
    pub input: ChainInput,
    pub expected: J,
}

/// What the trust chain verification takes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainInput {
    pub install_config: String,
    /// The kids, in the file's key list, of the vendor public keys.
    pub vendor_keys: Vec<String>,
    pub trust_test_keys: bool,
}

/// A case of the `hardware_hash` file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareCase {
    pub name: String,
    pub description: String,
    pub input: HardwareInput,
    pub expected: HardwareExpected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareInput {
    pub machine_id_kind: MachineIdKind,
    pub machine_id: String,
    pub hw_salt: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineIdKind {
    Linux,
    Windows,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareExpected {
    pub machine_id_hash: String,
}

// --- sequence cases -------------------------------------------------------------

/// A case of the `keyset`, `leak`, `document_versions`, `enroll_result` and
/// `commands` files: a starting state and steps taken in order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceCase {
    pub name: String,
    pub description: String,
    pub initial: ChainInput,
    pub steps: Vec<Step>,
}

/// One step of a sequence case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub action: Action,
    pub input: StepInput,
    pub env: StepEnv,
    pub expected: J,
    /// The state expected after the step, as far as the case looks at it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateSummary>,
}

/// What a step does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    ReceiveKeyset,
    ReceiveChain,
    ReceiveEnrollResult,
    ReceiveEnrollResultMessage,
    ReceiveDocument,
    ReceiveDocumentsMessage,
    ReceiveCommand,
    FinishCommand,
}

/// The input of a step; which fields an action takes is in the README.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StepInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<J>,
}

/// The environment of a step; which fields an action takes is in the
/// README.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StepEnv {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub senta_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<Attempt>,
}

/// The enrollment attempt an enrollment result is held against.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub spki_sha256: String,
    pub attempt_id: String,
    pub token_id: String,
}

/// The state expected after a step. An absent field is not looked at.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset: Option<KeysetPosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<SlotSummary>,
    /// `null` when no command has been accepted in the epoch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub last_seq: Option<Option<u64>>,
    /// `null` before the endpoint has enrolled.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub endpoint_id: Option<Option<String>>,
}

/// A key set's (recovery epoch, version).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetPosition {
    pub recovery_epoch: u64,
    pub keyset_version: u64,
}

/// The versions of one document version slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSummary {
    pub slot: J,
    pub verified_version: Option<u64>,
    pub applied_version: Option<u64>,
}

/// Reads a field that is present, `null` included, as `Some`.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Writes a vector file as the generator does: two-space indented JSON in
/// field order, ending in one newline.
pub fn to_file_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("a vector file serializes to JSON");
    bytes.push(b'\n');
    bytes
}
