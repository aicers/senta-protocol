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

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::generate::{compare, generate, is_vector_file};
use crate::json::J;
use crate::model::{JwsCase, SequenceCase, VectorFile, to_file_bytes};
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
