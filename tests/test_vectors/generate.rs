//! The generator's output as a whole, and its comparison with the files
//! committed under `tests/vectors/`.

use std::collections::BTreeMap;

use crate::model::{Category, to_file_bytes};
use crate::{chain_cases, hardware_cases, jws_cases, sequence_cases};

/// The extension of the files compared; anything else under
/// `tests/vectors/`, the README included, is not a vector file.
const VECTOR_EXTENSION: &str = ".json";

/// Generates every vector file, by file name.
pub fn generate() -> BTreeMap<String, Vec<u8>> {
    Category::ALL
        .into_iter()
        .map(|category| {
            let bytes = match category {
                Category::Jws => to_file_bytes(&jws_cases::file()),
                Category::TrustChain => to_file_bytes(&chain_cases::file()),
                Category::HardwareHash => to_file_bytes(&hardware_cases::file()),
                sequence => to_file_bytes(&sequence_cases::file(sequence)),
            };
            (category.file_name(), bytes)
        })
        .collect()
}

/// Returns whether a file name is that of a JSON vector file.
pub fn is_vector_file(name: &str) -> bool {
    name.ends_with(VECTOR_EXTENSION)
}

/// Compares the generator's output with the committed files, and returns
/// one line per difference: a file whose bytes differ, a generated file
/// missing, and a JSON vector file the generator does not produce. Files
/// that are not JSON vector files are not looked at.
pub fn compare(
    generated: &BTreeMap<String, Vec<u8>>,
    committed: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (name, bytes) in generated {
        match committed.get(name) {
            None => mismatches.push(format!("{name}: generated but not committed")),
            Some(have) if have != bytes => {
                let at = have
                    .iter()
                    .zip(bytes)
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| have.len().min(bytes.len()));
                mismatches.push(format!(
                    "{name}: committed bytes differ from the generator's, first at byte {at}"
                ));
            }
            Some(_) => {}
        }
    }
    for name in committed.keys() {
        if is_vector_file(name) && !generated.contains_key(name) {
            mismatches.push(format!(
                "{name}: committed but not produced by the generator"
            ));
        }
    }
    mismatches
}
