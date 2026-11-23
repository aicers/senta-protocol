//! Runs the vector files through the crate's public API and compares what
//! it gives with each case's expected result and expected state.

use std::collections::BTreeMap;

use jiff::Timestamp;
use senta_protocol::auth::commands::{CommandStateMachine, CommandVerdict, MemoryCommandStore};
use senta_protocol::auth::documents::{
    DocumentError, SemVer, VerifiedDocument, verify_addresses, verify_assign, verify_command,
    verify_deployment_cert, verify_enroll, verify_enroll_result, verify_install_config,
    verify_keyset, verify_policy, verify_recovery_key, verify_update,
};
use senta_protocol::auth::jws::strict::LowerUuid;
use senta_protocol::auth::jws::test_util::TestKey;
use senta_protocol::auth::jws::{Jwk, KeyKind, KeyLookup, KeySource, Kid, PublicKey, Typ};
use senta_protocol::auth::keyset::{
    ChainOutcome, EnrollAttempt, EnrollFailure, EpochChange, TrustState, receive_enroll_result,
};
use senta_protocol::auth::trust_chain::{self, VendorKeys};
use senta_protocol::auth::versions::{
    DocumentContent, DocumentVersions, EntryOutcome, MemoryTrustStore, MemoryVersionStore, Slot,
    TrustStore as _, receive_documents,
};
use senta_protocol::connection::Envelope;
use senta_protocol::control::{ControlMessage, MachineId, machine_id_hash};
use senta_protocol::results::CommandResultKind;
use serde::de::DeserializeOwned;

use crate::fixtures::{b64, b64_decode, sha256};
use crate::json::J;
use crate::model::{
    Action, Category, ChainCase, ChainInput, FORMAT_VERSION, FileHeader, HardwareCase, JwsCase,
    KeyEntry, KeyKindName, MachineIdKind, SequenceCase, SlotSummary, StateSummary, Step,
    VectorFile,
};
use crate::notation::{chain_verified, enrolled, execute, jws_verified, not_processed, ok};

/// Runs every JSON vector file of `files` and returns one line per
/// disagreement; an empty list means every case reproduced.
pub fn reproduce(files: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (name, bytes) in files {
        if !crate::generate::is_vector_file(name) {
            continue;
        }
        let mut report = Report {
            prefix: name.clone(),
            lines: &mut mismatches,
        };
        reproduce_file(name, bytes, &mut report);
    }
    mismatches
}

struct Report<'a> {
    prefix: String,
    lines: &'a mut Vec<String>,
}

impl Report<'_> {
    fn fail(&mut self, at: &str, message: impl std::fmt::Display) {
        self.lines.push(format!("{}: {at}: {message}", self.prefix));
    }

    fn check_result(&mut self, at: &str, expected: &J, actual: &J) {
        if !expected.same(actual) {
            self.fail(at, format!("expected {expected}, got {actual}"));
        }
    }
}

fn parse<T: DeserializeOwned>(bytes: &[u8], report: &mut Report<'_>) -> Option<T> {
    match serde_json::from_slice(bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            report.fail("file", format!("does not parse: {error}"));
            None
        }
    }
}

fn reproduce_file(name: &str, bytes: &[u8], report: &mut Report<'_>) {
    let Some(header) = parse::<FileHeader>(bytes, report) else {
        return;
    };
    if header.format_version != FORMAT_VERSION {
        report.fail("format_version", format!("is {}", header.format_version));
    }
    if name != header.category.file_name() {
        report.fail(
            "category",
            format!("{} is not this file's", header.category.as_str()),
        );
    }
    match header.category {
        Category::Jws => {
            if let Some(file) = parse::<VectorFile<JwsCase>>(bytes, report) {
                let keys = read_keys(&file.keys, report);
                for case in &file.cases {
                    run_jws(case, &keys, report);
                }
            }
        }
        Category::TrustChain => {
            if let Some(file) = parse::<VectorFile<ChainCase>>(bytes, report) {
                let keys = read_keys(&file.keys, report);
                for case in &file.cases {
                    let actual = run_chain(&case.input, &keys)
                        .map_or_else(|failure| failure, |install| verified_chain(&install));
                    report.check_result(&case.name, &case.expected, &actual);
                }
            }
        }
        Category::HardwareHash => {
            if let Some(file) = parse::<VectorFile<HardwareCase>>(bytes, report) {
                if !file.keys.is_empty() {
                    report.fail("keys", "the hardware hash file uses no key");
                }
                for case in &file.cases {
                    run_hardware(case, report);
                }
            }
        }
        _ => {
            if let Some(file) = parse::<VectorFile<SequenceCase>>(bytes, report) {
                let keys = read_keys(&file.keys, report);
                for case in &file.cases {
                    run_sequence(case, &keys, report);
                }
            }
        }
    }
}

// --- keys ----------------------------------------------------------------------------------

/// A key of the key list: its seed and its public key, which the list's
/// JWK gives.
struct Key {
    seed: [u8; 32],
    public: PublicKey,
}

fn read_keys(entries: &[KeyEntry], report: &mut Report<'_>) -> BTreeMap<String, Key> {
    let mut keys = BTreeMap::new();
    for entry in entries {
        let at = format!("key {}", entry.kid);
        let seed: Option<[u8; 32]> = b64_decode(&entry.seed).and_then(|seed| seed.try_into().ok());
        let x: Option<[u8; 32]> = b64_decode(&entry.jwk.x).and_then(|x| x.try_into().ok());
        let (Some(seed), Some(x)) = (seed, x) else {
            report.fail(&at, "seed or x is not 32 bytes of base64url");
            continue;
        };
        if entry.jwk.kty != "OKP" || entry.jwk.crv != "Ed25519" {
            report.fail(&at, "the JWK is not an Ed25519 OKP key");
        }
        if TestKey::from_seed(&seed).public_key_bytes() != x {
            report.fail(&at, "the JWK is not the public key of the seed");
        }
        let Ok(public) = PublicKey::from_bytes(&x) else {
            report.fail(&at, "x is not a curve point");
            continue;
        };
        if keys
            .insert(entry.kid.clone(), Key { seed, public })
            .is_some()
        {
            report.fail(&at, "the kid appears twice");
        }
    }
    keys
}

fn key_kind(kind: KeyKindName) -> KeyKind {
    match kind {
        KeyKindName::Vendor => KeyKind::Vendor,
        KeyKindName::InstallSigning => KeyKind::InstallSigning,
        KeyKindName::Customer => KeyKind::Customer,
        KeyKindName::Recovery => KeyKind::Recovery,
    }
}

/// The key source of a `jws` case: the trusted keys and the revoked kids.
struct CaseKeys(BTreeMap<String, KeyLookup>);

impl KeySource for CaseKeys {
    fn find_key(&self, kid: &Kid, _allowed: &[KeyKind]) -> KeyLookup {
        self.0
            .get(kid.as_str())
            .copied()
            .unwrap_or(KeyLookup::Unknown)
    }
}

// --- jws --------------------------------------------------------------------------------------

fn hash_of<C>(
    result: Result<VerifiedDocument<C>, DocumentError>,
) -> Result<[u8; 32], DocumentError> {
    result.map(|document| *document.payload_hash())
}

fn verify_typ<K: KeySource>(typ: Typ, jws: &str, keys: &K) -> Result<[u8; 32], DocumentError> {
    match typ {
        Typ::DeploymentCert => hash_of(verify_deployment_cert(jws, keys)),
        Typ::InstallConfig => hash_of(verify_install_config(jws, keys)),
        Typ::Keyset => hash_of(verify_keyset(jws, keys)),
        Typ::RecoveryKey => hash_of(verify_recovery_key(jws, keys)),
        Typ::Enroll => hash_of(verify_enroll(jws, keys)),
        Typ::EnrollResult => hash_of(verify_enroll_result(jws, keys)),
        Typ::Policy => hash_of(verify_policy(jws, keys)),
        Typ::Assign => hash_of(verify_assign(jws, keys)),
        Typ::Addresses => hash_of(verify_addresses(jws, keys)),
        Typ::Update => hash_of(verify_update(jws, keys)),
        Typ::Command => hash_of(verify_command(jws, keys)),
    }
}

/// Decodes the header and payload of a JWS, compact or in the JSON
/// serialization.
fn jws_parts(jws: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    if jws.starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(jws).ok()?;
        let header = b64_decode(value.get("protected")?.as_str()?)?;
        let payload = b64_decode(value.get("payload")?.as_str()?)?;
        return Some((header, payload));
    }
    let mut parts = jws.split('.');
    let header = b64_decode(parts.next()?)?;
    let payload = b64_decode(parts.next()?)?;
    Some((header, payload))
}

fn run_jws(case: &JwsCase, keys: &BTreeMap<String, Key>, report: &mut Report<'_>) {
    let at = case.name.as_str();
    let input = &case.input;
    let Some(typ) = Typ::ALL
        .into_iter()
        .find(|typ| typ.as_str() == input.expected_typ)
    else {
        report.fail(at, format!("unknown expected_typ {}", input.expected_typ));
        return;
    };

    let mut lookups = BTreeMap::new();
    for trusted in &input.trusted_keys {
        let Some(key) = keys.get(&trusted.kid) else {
            report.fail(
                at,
                format!("trusted key {} is not in the key list", trusted.kid),
            );
            return;
        };
        lookups.insert(
            trusted.kid.clone(),
            KeyLookup::Found {
                key: key.public,
                kind: key_kind(trusted.kind),
            },
        );
    }
    for kid in &input.revoked_kids {
        lookups.insert(kid.clone(), KeyLookup::Revoked);
    }

    let actual = match verify_typ(typ, &input.jws, &CaseKeys(lookups)) {
        Ok(hash) => jws_verified(&b64(&hash)),
        Err(error) => J::of(&error.result()),
    };
    report.check_result(at, &case.expected, &actual);

    let Some((header, payload)) = jws_parts(&input.jws) else {
        report.fail(at, "the header and payload do not decode");
        return;
    };
    let readable = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).ok();
    if input.header_json != readable(&header) || input.payload_json != readable(&payload) {
        report.fail(at, "header_json or payload_json is not the decoded segment");
    }
    if let Some(expected_hash) = case
        .expected
        .get("verified")
        .and_then(|verified| verified.get("payload_sha256"))
        && *expected_hash != J::str(b64(&sha256(&payload)))
    {
        report.fail(
            at,
            "payload_sha256 is not the SHA-256 of the decoded payload",
        );
    }
    if let Some(kid) = &case.signed_by {
        let Some(key) = keys.get(kid) else {
            report.fail(at, format!("signed_by {kid} is not in the key list"));
            return;
        };
        if TestKey::from_seed(&key.seed).sign_raw(&header, &payload) != input.jws {
            report.fail(
                at,
                format!("the signature is not {kid}'s seed signing the signing input"),
            );
        }
    }
}

// --- trust chain ----------------------------------------------------------------------------

fn run_chain(
    input: &ChainInput,
    keys: &BTreeMap<String, Key>,
) -> Result<trust_chain::VerifiedInstall, J> {
    let mut vendor = Vec::new();
    for kid in &input.vendor_keys {
        let key = keys
            .get(kid)
            .ok_or_else(|| J::str(format!("vendor key {kid} is not in the key list")))?;
        vendor.push((kid.as_str(), Jwk::from(key.public)));
    }
    let vendor_keys =
        VendorKeys::new(vendor).map_err(|error| J::str(format!("vendor keys: {error}")))?;
    trust_chain::verify(&input.install_config, &vendor_keys, input.trust_test_keys).map_err(
        |error| {
            J::tagged(
                "install_failed",
                J::obj([
                    ("failure", J::of(error.failure())),
                    ("step", J::Int(u64::from(error.step().number()))),
                    ("document", J::str(error.document().typ().as_str())),
                ]),
            )
        },
    )
}

fn verified_chain(install: &trust_chain::VerifiedInstall) -> J {
    let trust = install.trust_state();
    chain_verified(
        trust.recovery_epoch(),
        trust.keyset_version(),
        trust.recovery_key_version(),
    )
}

// --- hardware hash ------------------------------------------------------------------------------

fn run_hardware(case: &HardwareCase, report: &mut Report<'_>) {
    let at = case.name.as_str();
    let Some(salt) =
        b64_decode(&case.input.hw_salt).and_then(|salt| <[u8; 32]>::try_from(salt).ok())
    else {
        report.fail(at, "hw_salt is not 32 bytes of base64url");
        return;
    };
    let machine_id = match case.input.machine_id_kind {
        MachineIdKind::Linux => MachineId::Linux(&case.input.machine_id),
        MachineIdKind::Windows => MachineId::Windows(&case.input.machine_id),
    };
    match machine_id_hash(machine_id, &salt) {
        Ok(hash) if b64(&hash) == case.expected.machine_id_hash => {}
        Ok(hash) => report.fail(
            at,
            format!(
                "expected {}, got {}",
                case.expected.machine_id_hash,
                b64(&hash)
            ),
        ),
        Err(error) => report.fail(at, format!("the crate rejected the machine id: {error}")),
    }
}

// --- sequences ------------------------------------------------------------------------------------

/// The endpoint's state through a sequence case, every store in memory.
struct Endpoint {
    trust_store: MemoryTrustStore,
    versions: DocumentVersions<MemoryVersionStore>,
    commands: Option<CommandStateMachine<MemoryCommandStore>>,
}

/// What made a step impossible to run, as opposed to a result that differs.
type StepError = String;

fn applier(_: &DocumentContent) -> Result<(), String> {
    Ok(())
}

impl Endpoint {
    fn start(initial: &ChainInput, keys: &BTreeMap<String, Key>) -> Result<Self, StepError> {
        let install = run_chain(initial, keys)
            .map_err(|failure| format!("the initial install configuration failed: {failure}"))?;
        let trust_store = MemoryTrustStore::with_state(install.trust_state().clone());
        let versions = install
            .create_document_versions(MemoryVersionStore::new())
            .map_err(|error| format!("creating the document versions: {error}"))?;
        Ok(Self {
            trust_store,
            versions,
            commands: None,
        })
    }

    fn trust(&self) -> TrustState {
        self.trust_store
            .state()
            .cloned()
            .expect("the trust store holds the installation's state from the start")
    }

    /// Stores a trust state a step changed, then hands its epoch changes on.
    fn store_trust(
        &mut self,
        trust: &TrustState,
        changes: &[EpochChange],
    ) -> Result<(), StepError> {
        self.trust_store
            .save(trust)
            .map_err(|error| format!("storing the trust state: {error}"))?;
        for &change in changes {
            self.versions
                .epoch_changed(change)
                .map_err(|error| format!("epoch change: {error}"))?;
            self.apply_epoch_change(change)?;
        }
        Ok(())
    }

    fn apply_epoch_change(&mut self, change: EpochChange) -> Result<(), StepError> {
        if let Some(commands) = &mut self.commands {
            commands
                .apply_epoch_change(change)
                .map_err(|error| format!("command epoch change: {error:?}"))?;
        }
        Ok(())
    }

    fn commands(&mut self) -> Result<&mut CommandStateMachine<MemoryCommandStore>, StepError> {
        self.commands
            .as_mut()
            .ok_or_else(|| "no command state machine before enrolling".to_owned())
    }

    fn run(&mut self, step: &Step) -> Result<J, StepError> {
        let input = &step.input;
        match step.action {
            Action::ReceiveKeyset => {
                let mut trust = self.trust();
                let receipt = trust.receive_keyset(required(input.jws.as_deref(), "jws")?);
                let changes: Vec<EpochChange> = receipt.epoch_change().into_iter().collect();
                self.store_trust(&trust, &changes)?;
                Ok(J::of(receipt.result()))
            }
            Action::ReceiveChain => {
                let documents = required(input.documents.as_deref(), "documents")?;
                let mut trust = self.trust();
                let outcome = trust.receive_chain(documents);
                self.store_trust(&trust, outcome.epoch_changes())?;
                Ok(J::Arr(chain_results(&outcome, documents.len())))
            }
            Action::ReceiveEnrollResult => {
                let chain = required(input.chain.as_deref(), "chain")?;
                let result = required(input.enroll_result.as_deref(), "enroll_result")?;
                self.enroll(step, chain, result)
            }
            Action::ReceiveEnrollResultMessage => {
                let message = decode_message(required(input.message.as_deref(), "message")?)?;
                let ControlMessage::EnrollResult(enroll_result) = message else {
                    return Err(format!(
                        "the message is a {}, not an enroll_result",
                        message.t()
                    ));
                };
                let (result, chain) = enroll_result
                    .approved()
                    .ok_or("the enroll_result is not an approval")?;
                self.enroll(step, chain, result)
            }
            Action::ReceiveDocument => {
                let jws = required(input.jws.as_deref(), "jws")?;
                let (now, senta_version) = document_env(step)?;
                let trust = self.trust();
                let receipt = self
                    .versions
                    .receive(jws, &trust, now, &senta_version, &mut applier)
                    .map_err(|error| format!("receive: {error}"))?;
                Ok(J::of(receipt.result()))
            }
            Action::ReceiveDocumentsMessage => {
                let message = decode_message(required(input.message.as_deref(), "message")?)?;
                let ControlMessage::Documents(documents) = message else {
                    return Err(format!("the message is a {}, not a documents", message.t()));
                };
                self.documents(step, &documents.documents)
            }
            Action::ReceiveCommand => {
                let jws = required(input.jws.as_deref(), "jws")?;
                let now = time(required(step.env.now.as_deref(), "now")?)?;
                let trust = self.trust();
                let verdict = self
                    .commands()?
                    .receive(jws, &trust, now)
                    .map_err(|error| format!("receive: {error:?}"))?;
                Ok(match verdict {
                    CommandVerdict::Execute(_) => execute(),
                    other => other
                        .result()
                        .map_or_else(|| J::str("no result"), |result| J::of(&result)),
                })
            }
            Action::FinishCommand => {
                let id = uuid(required(input.command_id.as_deref(), "command_id")?)?;
                let result: CommandResultKind =
                    serde_json::from_value(required(input.result.as_ref(), "result")?.to_value())
                        .map_err(|error| format!("result: {error}"))?;
                Ok(match self.commands()?.finish(id, result) {
                    Ok(()) => ok(),
                    Err(error) => J::str(format!("finish failed: {error:?}")),
                })
            }
        }
    }

    fn enroll<S: AsRef<str>>(
        &mut self,
        step: &Step,
        chain: &[S],
        enroll_result: &str,
    ) -> Result<J, StepError> {
        let attempt = required(step.env.attempt.as_ref(), "attempt")?;
        let attempt = EnrollAttempt {
            spki_sha256: b64_decode(&attempt.spki_sha256)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or("spki_sha256 is not 32 bytes of base64url")?,
            attempt_id: uuid(&attempt.attempt_id)?.get(),
            token_id: uuid(&attempt.token_id)?.get(),
        };
        let outcome = receive_enroll_result(self.trust(), chain, enroll_result, &attempt);
        self.store_trust(outcome.state(), outcome.epoch_changes())?;
        let result = match outcome.result() {
            Ok(endpoint_id) => {
                let endpoint_id = uuid(&endpoint_id.to_string())?;
                self.versions
                    .set_endpoint_id(endpoint_id)
                    .map_err(|error| format!("set_endpoint_id: {error}"))?;
                if self.commands.is_none() {
                    let commands = CommandStateMachine::create(
                        MemoryCommandStore::new(),
                        endpoint_id,
                        &self.trust(),
                    )
                    .map_err(|error| format!("creating the command state machine: {error:?}"))?;
                    self.commands = Some(commands);
                }
                enrolled(&endpoint_id.get().to_string())
            }
            Err(failure) => J::tagged("enroll_failed", failure_notation(failure)),
        };
        Ok(J::obj([
            ("chain", J::Arr(chain_results(outcome.chain(), chain.len()))),
            ("result", result),
        ]))
    }

    fn documents(&mut self, step: &Step, documents: &[String]) -> Result<J, StepError> {
        let (now, senta_version) = document_env(step)?;
        let mut trust = self.trust();
        let outcome = receive_documents(
            documents,
            &mut trust,
            &mut self.trust_store,
            &mut self.versions,
            now,
            &senta_version,
            &mut applier,
        )
        .map_err(|error| format!("receive_documents: {error}"))?;
        // `receive_documents` stored the trust state and passed the epoch
        // changes to the document versions itself.
        for &change in outcome.epoch_changes() {
            self.apply_epoch_change(change)?;
        }
        Ok(J::Arr(
            outcome
                .entries()
                .iter()
                .map(|entry| match entry.outcome() {
                    EntryOutcome::Processed(result) => J::of(result),
                    EntryOutcome::NotProcessed => not_processed(),
                })
                .collect(),
        ))
    }

    fn state(&self, expected: &StateSummary) -> Result<StateSummary, StepError> {
        let trust = self.trust();
        let mut actual = StateSummary::default();
        if expected.keyset.is_some() {
            actual.keyset = Some(crate::model::KeysetPosition {
                recovery_epoch: trust.recovery_epoch(),
                keyset_version: trust.keyset_version(),
            });
        }
        if expected.recovery_key_version.is_some() {
            actual.recovery_key_version = Some(trust.recovery_key_version());
        }
        if let Some(slot) = &expected.slot {
            let parsed: Slot = serde_json::from_value(slot.slot.to_value())
                .map_err(|error| format!("slot {}: {error}", slot.slot))?;
            let report = self.versions.report(parsed);
            actual.slot = Some(SlotSummary {
                slot: slot.slot.clone(),
                verified_version: report.verified_version,
                applied_version: report.applied_version,
            });
        }
        if expected.last_seq.is_some() {
            let commands = self
                .commands
                .as_ref()
                .ok_or("no command state machine before enrolling")?;
            actual.last_seq = Some(commands.last_seq());
        }
        if expected.endpoint_id.is_some() {
            actual.endpoint_id = Some(
                self.versions
                    .endpoint_id()
                    .map(|endpoint_id| endpoint_id.get().to_string()),
            );
        }
        Ok(actual)
    }
}

fn run_sequence(case: &SequenceCase, keys: &BTreeMap<String, Key>, report: &mut Report<'_>) {
    let mut endpoint = match Endpoint::start(&case.initial, keys) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            report.fail(&case.name, error);
            return;
        }
    };
    for (index, step) in case.steps.iter().enumerate() {
        let at = format!("{} step {index}", case.name);
        match endpoint.run(step) {
            Ok(actual) => report.check_result(&at, &step.expected, &actual),
            Err(error) => {
                report.fail(&at, error);
                return;
            }
        }
        if let Some(expected) = &step.state {
            match endpoint.state(expected) {
                Ok(actual) if actual == *expected => {}
                Ok(actual) => {
                    report.fail(&at, format!("expected state {expected:?}, got {actual:?}"))
                }
                Err(error) => {
                    report.fail(&at, error);
                    return;
                }
            }
        }
    }
}

fn chain_results(outcome: &ChainOutcome, count: usize) -> Vec<J> {
    (0..count)
        .map(|index| {
            outcome
                .results()
                .get(index)
                .map_or_else(not_processed, J::of)
        })
        .collect()
}

fn failure_notation(failure: &EnrollFailure) -> J {
    match failure {
        EnrollFailure::Chain { index, result } => J::tagged(
            "chain",
            J::obj([
                (
                    "index",
                    J::Int(u64::try_from(*index).expect("a chain index fits in u64")),
                ),
                ("result", J::of(result)),
            ]),
        ),
        EnrollFailure::Rejected(result) => J::tagged("rejected", J::of(result)),
        EnrollFailure::SpkiMismatch => J::str("spki_mismatch"),
        EnrollFailure::AttemptIdMismatch => J::str("attempt_id_mismatch"),
        EnrollFailure::TokenIdMismatch => J::str("token_id_mismatch"),
        EnrollFailure::EpochMismatch { .. } => J::str("recovery_epoch_mismatch"),
        other => J::str(format!("unknown failure {other:?}")),
    }
}

fn required<'a, T: ?Sized>(value: Option<&'a T>, field: &str) -> Result<&'a T, StepError> {
    value.ok_or_else(|| format!("the step has no {field}"))
}

fn time(text: &str) -> Result<Timestamp, StepError> {
    text.parse()
        .map_err(|error| format!("time {text:?}: {error}"))
}

fn uuid(text: &str) -> Result<LowerUuid, StepError> {
    LowerUuid::parse(text).ok_or_else(|| format!("{text:?} is not a lowercase UUID"))
}

fn document_env(step: &Step) -> Result<(Timestamp, SemVer), StepError> {
    let now = time(required(step.env.now.as_deref(), "now")?)?;
    let version = required(step.env.senta_version.as_deref(), "senta_version")?;
    let version = SemVer::parse(version).ok_or_else(|| format!("{version:?} is not SemVer"))?;
    Ok((now, version))
}

fn decode_message(message: &str) -> Result<ControlMessage, StepError> {
    let bytes = b64_decode(message).ok_or("the message is not base64url")?;
    let envelope = Envelope::parse(&bytes).map_err(|error| format!("envelope: {error}"))?;
    ControlMessage::decode(envelope.t(), envelope.body())
        .map_err(|error| format!("control message: {error}"))
}
