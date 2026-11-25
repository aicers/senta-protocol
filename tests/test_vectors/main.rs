//! The language-neutral test vectors under `tests/vectors/`: their
//! generator, the check that the committed files are its output, and the
//! check that the crate gives every expected result.
//!
//! `tests/vectors/README.md` describes the files. To write them again:
//!
//! ```sh
//! cargo test --no-default-features --features auth,control,test-util \
//!   --test test_vectors -- --ignored regenerate_vectors
//! ```
#![cfg(all(feature = "auth", feature = "control", feature = "test-util"))]

mod cbor_cases;
mod chain_cases;
mod fixtures;
mod generate;
mod hardware_cases;
mod json;
mod jws_cases;
mod model;
mod notation;
mod reproduce;
mod sequence_cases;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use senta_protocol::auth::active_list::{EntryState, ListUpdate};
use senta_protocol::connection::cbor;
use senta_protocol::control::{EnrollRequest, Problem, StatusReport};
use senta_protocol::standing::SuspendReason;

use crate::generate::{compare, generate, is_vector_file};
use crate::json::J;
use crate::model::{
    ActiveListCase, ControlCborCase, ControlMessageType, JwsCase, SequenceCase, VectorFile,
    to_file_bytes,
};
use crate::reproduce::reproduce;

/// The command that writes the vector files again.
const REGENERATE: &str = "cargo test --no-default-features --features auth,control,test-util \
     --test test_vectors -- --ignored regenerate_vectors";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Reads every file of `tests/vectors/`, by file name.
fn read_committed() -> BTreeMap<String, Vec<u8>> {
    let dir = vectors_dir();
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|error| panic!("reading {dir:?}: {error}")) {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let name = entry.file_name().into_string().unwrap();
            files.insert(name, fs::read(entry.path()).unwrap());
        }
    }
    files
}

/// Writes the generator's output to `tests/vectors/`, and removes any JSON
/// vector file it no longer produces.
#[test]
#[ignore = "writes tests/vectors/; run it to regenerate the vectors"]
fn regenerate_vectors() {
    let dir = vectors_dir();
    let generated = generate();
    for name in read_committed().keys() {
        if is_vector_file(name) && !generated.contains_key(name) {
            fs::remove_file(dir.join(name)).unwrap();
        }
    }
    for (name, bytes) in &generated {
        fs::write(dir.join(name), bytes).unwrap();
    }
}

#[test]
fn generator_is_deterministic() {
    assert_eq!(generate(), generate());
}

#[test]
fn committed_vectors_match_the_generator() {
    let mismatches = compare(&generate(), &read_committed());
    assert!(
        mismatches.is_empty(),
        "the committed vectors are not the generator's output:\n  {}\nregenerate them with:\n  {REGENERATE}",
        mismatches.join("\n  ")
    );
}

#[test]
fn every_category_has_a_file() {
    let generated = generate();
    for category in model::Category::ALL {
        assert!(generated.contains_key(&category.file_name()));
    }
}

#[test]
fn comparison_catches_a_changed_byte() {
    let generated = generate();
    let mut committed = generated.clone();
    let bytes = committed.get_mut("keyset.json").unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    let mismatches = compare(&generated, &committed);
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(mismatches[0].starts_with("keyset.json:"), "{mismatches:?}");
}

#[test]
fn comparison_catches_a_missing_file() {
    let generated = generate();
    let mut committed = generated.clone();
    committed.remove("leak.json");
    let mismatches = compare(&generated, &committed);
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(mismatches[0].starts_with("leak.json:"), "{mismatches:?}");
}

#[test]
fn comparison_catches_a_file_the_generator_does_not_produce() {
    let generated = generate();
    let mut committed = generated.clone();
    committed.insert("stale.json".to_owned(), b"{}\n".to_vec());
    let mismatches = compare(&generated, &committed);
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(mismatches[0].starts_with("stale.json:"), "{mismatches:?}");
}

#[test]
fn comparison_ignores_the_readme() {
    let generated = generate();
    let mut committed = generated.clone();
    committed.insert("README.md".to_owned(), b"# Test vectors\n".to_vec());
    assert_eq!(compare(&generated, &committed), Vec::<String>::new());
    assert!(read_committed().contains_key("README.md"));
}

#[test]
fn committed_vectors_reproduce() {
    let mismatches = reproduce(&read_committed());
    assert!(
        mismatches.is_empty(),
        "the crate disagrees with the vectors:\n  {}",
        mismatches.join("\n  ")
    );
}

#[test]
fn generated_vectors_reproduce() {
    let mismatches = reproduce(&generate());
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Changes one generated file through `change` and returns what the
/// reproduction reports for it.
fn reproduce_changed<C>(file_name: &str, change: impl FnOnce(&mut VectorFile<C>)) -> Vec<String>
where
    C: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut files = generate();
    let bytes = files.get_mut(file_name).unwrap();
    let mut file: VectorFile<C> = serde_json::from_slice(bytes).unwrap();
    change(&mut file);
    *bytes = to_file_bytes(&file);
    reproduce(&files)
}

#[test]
fn reproduction_catches_a_wrong_jws_result() {
    let mismatches = reproduce_changed::<JwsCase>("jws.json", |file| {
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name.ends_with(":signature_bit_flipped"))
            .unwrap();
        case.expected = J::str("unknown_kid");
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(
        mismatches[0].contains(":signature_bit_flipped"),
        "{mismatches:?}"
    );
}

#[test]
fn reproduction_catches_a_wrong_signer() {
    let mismatches = reproduce_changed::<JwsCase>("jws.json", |file| {
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name == "senta-command:json_serialization")
            .unwrap();
        case.signed_by = Some(fixtures::install_kid(fixtures::INSTALL_ID));
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(
        mismatches[0].contains("senta-command:json_serialization"),
        "{mismatches:?}"
    );
}

#[test]
fn reproduction_catches_a_valid_case_without_signer() {
    let mismatches = reproduce_changed::<JwsCase>("jws.json", |file| {
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name == "senta-policy:valid")
            .unwrap();
        case.signed_by = None;
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(
        mismatches[0].contains("senta-policy:valid"),
        "{mismatches:?}"
    );
}

#[test]
fn reproduction_catches_a_repeated_case_name() {
    let mismatches = reproduce_changed::<model::HardwareCase>("hardware_hash.json", |file| {
        let first = file.cases.first().unwrap().name.clone();
        file.cases.last_mut().unwrap().name = first;
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(mismatches[0].contains("appears twice"), "{mismatches:?}");
}

#[test]
fn reproduction_catches_a_wrong_step_result() {
    let mismatches = reproduce_changed::<SequenceCase>("leak.json", |file| {
        let step = file
            .cases
            .iter_mut()
            .find(|case| case.name == "seq_floor_raised_then_recovery")
            .unwrap()
            .steps
            .iter_mut()
            .find(|step| step.expected == J::tagged("rejected", J::str("stale")))
            .unwrap();
        step.expected = notation::execute();
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
}

#[test]
fn reproduction_catches_a_wrong_state() {
    let mismatches = reproduce_changed::<SequenceCase>("keyset.json", |file| {
        let case = file.cases.first_mut().unwrap();
        let state = case.steps.first_mut().unwrap().state.as_mut().unwrap();
        state.keyset.as_mut().unwrap().keyset_version += 1;
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
}

#[test]
fn reproduction_catches_a_wrong_hardware_hash() {
    let mut files = generate();
    let bytes = files.get("hardware_hash.json").unwrap();
    let mut file: VectorFile<model::HardwareCase> = serde_json::from_slice(bytes).unwrap();
    file.cases.first_mut().unwrap().expected.machine_id_hash = fixtures::b64(&[0; 32]);
    files.insert("hardware_hash.json".to_owned(), to_file_bytes(&file));
    let mismatches = reproduce(&files);
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
}

/// Reads the committed vector file `name` as cases of type `C`.
fn committed_file<C: serde::de::DeserializeOwned>(name: &str) -> VectorFile<C> {
    let committed = read_committed();
    let bytes = committed
        .get(name)
        .unwrap_or_else(|| panic!("{name} is committed"));
    serde_json::from_slice(bytes).unwrap()
}

/// Decodes the CBOR bytes of a case, which are standard base64.
fn case_bytes(cbor: &str) -> Vec<u8> {
    cbor_cases::b64_standard_decode(cbor).unwrap()
}

/// Asserts that two enrollment requests are equal field by field:
/// `EnrollRequest` has no equality, since `EnrollToken` has none.
#[track_caller]
fn assert_same_enroll_request(actual: &EnrollRequest, expected: &EnrollRequest, at: &str) {
    assert_eq!(actual.attempt_id, expected.attempt_id, "{at}");
    assert_eq!(actual.trusted_keyset, expected.trusted_keyset, "{at}");
    assert_eq!(
        actual.trusted_recovery_key_version, expected.trusted_recovery_key_version,
        "{at}"
    );
    assert_eq!(
        actual.enroll_token.expose(),
        expected.enroll_token.expose(),
        "{at}"
    );
    assert_eq!(actual.hardware, expected.hardware, "{at}");
    assert_eq!(actual.hostname, expected.hostname, "{at}");
    assert_eq!(actual.os, expected.os, "{at}");
    assert_eq!(actual.senta_version, expected.senta_version, "{at}");
    assert_eq!(actual.key_storage, expected.key_storage, "{at}");
    assert_eq!(actual.vdi_mode, expected.vdi_mode, "{at}");
}

#[test]
fn control_cbor_cases_decode_to_the_values_they_stand_for() {
    let file: VectorFile<ControlCborCase> = committed_file("control_cbor.json");
    let find = |name: &str| {
        file.cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is a case of control_cbor.json"))
    };
    let requests = cbor_cases::enroll_requests();
    let reports = cbor_cases::status_reports();
    assert_eq!(file.cases.len(), requests.len() + reports.len());
    for case in &requests {
        let name = format!("enroll_request:{}", case.variant);
        let vector = find(&name);
        assert_eq!(vector.message_type, ControlMessageType::EnrollRequest);
        let decoded: EnrollRequest = cbor::from_slice(&case_bytes(&vector.cbor)).unwrap();
        assert_same_enroll_request(&decoded, &case.value, &name);
        assert_eq!(decoded.enroll_token.expose(), cbor_cases::TEST_ENROLL_TOKEN);
    }
    for case in &reports {
        let name = format!("status_report:{}", case.variant);
        let vector = find(&name);
        assert_eq!(vector.message_type, ControlMessageType::StatusReport);
        let decoded: StatusReport = cbor::from_slice(&case_bytes(&vector.cbor)).unwrap();
        assert_eq!(decoded, case.value, "{name}");
    }
}

#[test]
fn active_list_cases_decode_to_the_values_they_stand_for() {
    let file: VectorFile<ActiveListCase> = committed_file("active_list.json");
    let updates = cbor_cases::list_updates();
    assert_eq!(file.cases.len(), updates.len());
    for case in &updates {
        let name = format!("list_update:{}", case.variant);
        let vector = file
            .cases
            .iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("{name} is a case of active_list.json"));
        let bytes = case_bytes(&vector.cbor);
        assert_eq!(ListUpdate::decode(&bytes).unwrap(), case.value, "{name}");
        assert_eq!(case.value.encode().unwrap(), bytes, "{name}");
    }
}

/// Names a `Problem` value by its variant; a variant this test does not
/// know fails it, so that a new one is added to the vectors.
fn problem_variant(problem: &Problem) -> &'static str {
    match problem {
        Problem::SignatureRejected { .. } => "signature_rejected",
        Problem::UnknownKid { .. } => "unknown_kid",
        Problem::KeysetGap => "keyset_gap",
        Problem::UpdateFailed => "update_failed",
        Problem::UpdateRolledBack => "update_rolled_back",
        Problem::SourceUnreachable => "source_unreachable",
        Problem::PriorEpochState => "prior_epoch_state",
        Problem::SysmonMissing => "sysmon_missing",
        Problem::ClockSkew => "clock_skew",
        Problem::InstallConfigInvalid => "install_config_invalid",
        Problem::SysmonStopped => "sysmon_stopped",
        Problem::SysmonConfigChanged => "sysmon_config_changed",
        Problem::UnexpectedRestart => "unexpected_restart",
        Problem::Other(_) => "other",
        other => panic!("a Problem value the vectors do not cover: {other:?}"),
    }
}

#[test]
fn cbor_cases_cover_every_problem_and_every_entry_state() {
    let problems: BTreeSet<&str> = cbor_cases::status_reports()
        .iter()
        .flat_map(|case| case.value.problems.iter().map(problem_variant))
        .collect();
    assert_eq!(
        problems,
        BTreeSet::from([
            "signature_rejected",
            "unknown_kid",
            "keyset_gap",
            "update_failed",
            "update_rolled_back",
            "source_unreachable",
            "prior_epoch_state",
            "sysmon_missing",
            "clock_skew",
            "install_config_invalid",
            "sysmon_stopped",
            "sysmon_config_changed",
            "unexpected_restart",
            "other",
        ])
    );

    let state_name = |state: &EntryState| match state {
        EntryState::Active => "active",
        EntryState::LicensePending => "license_pending",
        EntryState::Suspended {
            reason: SuspendReason::Revoked,
        } => "revoked",
        EntryState::Suspended {
            reason: SuspendReason::Operator,
        } => "operator",
        EntryState::Suspended {
            reason: SuspendReason::License,
        } => "license",
        EntryState::Suspended { reason } => panic!("an unexpected reason {reason:?}"),
    };
    let every_state = BTreeSet::from([
        "active",
        "license_pending",
        "revoked",
        "operator",
        "license",
    ]);
    let (mut full, mut diff) = (BTreeSet::new(), BTreeSet::new());
    for case in cbor_cases::list_updates() {
        match &case.value {
            ListUpdate::Full { entries, .. } => {
                full.extend(entries.iter().map(|entry| state_name(&entry.state)));
            }
            ListUpdate::Diff { upserts, .. } => {
                diff.extend(upserts.iter().map(|entry| state_name(&entry.state)));
            }
        }
    }
    assert_eq!(full, every_state, "Full");
    assert_eq!(diff, every_state, "Diff");
}

#[test]
fn reproduction_catches_a_wrong_cbor_view() {
    let mismatches = reproduce_changed::<ControlCborCase>("control_cbor.json", |file| {
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name == "status_report:every_problem")
            .unwrap();
        case.value = case.value.with("problems", J::arr([]));
    });
    assert_eq!(mismatches.len(), 2, "{mismatches:?}");
    assert!(
        mismatches
            .iter()
            .all(|line| line.contains("status_report:every_problem")),
        "{mismatches:?}"
    );
}

#[test]
fn reproduction_catches_wrong_cbor_bytes() {
    let mismatches = reproduce_changed::<ActiveListCase>("active_list.json", |file| {
        let other = file
            .cases
            .iter()
            .find(|case| case.name == "list_update:diff_removals_only")
            .unwrap()
            .cbor
            .clone();
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name == "list_update:full_empty")
            .unwrap();
        // Bytes the crate decodes, of another update than the value.
        case.cbor = other;
    });
    assert_eq!(mismatches.len(), 2, "{mismatches:?}");
    assert!(
        mismatches
            .iter()
            .all(|line| line.contains("list_update:full_empty")),
        "{mismatches:?}"
    );
}

#[test]
fn reproduction_catches_a_payload_out_of_member_order() {
    let mismatches = reproduce_changed::<JwsCase>("jws.json", |file| {
        let case = file
            .cases
            .iter_mut()
            .find(|case| case.name == "senta-update:valid")
            .unwrap();
        let kid = case.signed_by.clone().unwrap();
        let header = case.input.header_json.clone().unwrap();
        // `serde_json`'s map writes the members in name order.
        let value: serde_json::Value =
            serde_json::from_str(case.input.payload_json.as_deref().unwrap()).unwrap();
        let payload = serde_json::to_string(&value).unwrap();
        let key =
            senta_protocol::auth::jws::test_util::TestKey::from_seed(&fixtures::seed_of(&kid));
        case.input.jws = key.sign_raw(header.as_bytes(), payload.as_bytes());
        case.expected =
            notation::jws_verified(&fixtures::b64(&fixtures::sha256(payload.as_bytes())));
        case.input.payload_json = Some(payload);
    });
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert!(
        mismatches[0].contains("senta-update:valid")
            && mismatches[0].contains("order the crate serializes"),
        "{mismatches:?}"
    );
}
