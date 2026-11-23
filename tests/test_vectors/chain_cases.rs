//! The `trust_chain` vector file: install configurations verified from the
//! vendor keys.

use senta_protocol::auth::jws::Typ;

use crate::fixtures::{
    self, EPOCH, INSTALL_ID, InstallSpec, Issuer, KeyRing, KeysetSpec, OTHER_INSTALL_ID, TOKEN,
    VENDOR_OTHER, VENDOR_RELEASE, VENDOR_TEST, b64, customer_kid, install_kid, install_time,
    recovery_kid,
};
use crate::model::{Category, ChainCase, ChainInput, FORMAT_VERSION, VectorFile};
use crate::notation::{chain_failed, chain_verified};

fn input(install_config: String, vendor_keys: &[&str], trust_test_keys: bool) -> ChainInput {
    ChainInput {
        install_config,
        vendor_keys: vendor_keys.iter().map(|&kid| kid.to_owned()).collect(),
        trust_test_keys,
    }
}

fn case(name: &str, description: &str, input: ChainInput, expected: crate::json::J) -> ChainCase {
    ChainCase {
        name: name.to_owned(),
        description: description.to_owned(),
        input,
        expected,
    }
}

/// A deployment certificate of `install_id` signed under `vendor_kid`.
fn deployment_cert(ring: &mut KeyRing, install_id: &str, vendor_kid: &str) -> String {
    let content = fixtures::deployment_cert(ring, install_id);
    ring.sign(Typ::DeploymentCert, vendor_kid, &content)
}

/// The standard installation with its key set replaced by `keyset`, and
/// its address document and enrollment token signed under `signer` at the
/// key set's epoch.
fn with_keyset(ring: &mut KeyRing, keyset: String, epoch: u64, signer: &str) -> InstallSpec {
    let mut spec = fixtures::standard_install_spec(ring);
    let version = Issuer::new().number(Typ::Addresses.as_str(), install_time());
    spec.keyset = keyset;
    spec.addresses = ring.sign(Typ::Addresses, signer, &fixtures::addresses(epoch, version));
    spec.enroll_token = ring.sign(Typ::Enroll, signer, &fixtures::enroll(TOKEN));
    spec
}

pub fn file() -> VectorFile<ChainCase> {
    let mut ring = KeyRing::default();
    let ring = &mut ring;
    let release = &[VENDOR_RELEASE][..];
    let with_test = &[VENDOR_RELEASE, VENDOR_TEST][..];
    let mut cases = Vec::new();

    cases.push(case(
        "valid",
        "The installation's install configuration: key set (1, 1) and recovery key version 1.",
        input(fixtures::standard_install(ring), release, false),
        chain_verified(EPOCH, 1, 1),
    ));

    // One document inside changed, the old signature kept.
    let spec = fixtures::standard_install_spec(ring);
    let signed = fixtures::sign_install_config(ring, &spec);
    let mut changed = spec;
    let version = Issuer::new().number(Typ::Addresses.as_str(), install_time()) + 1;
    changed.addresses = ring.sign(
        Typ::Addresses,
        &customer_kid(1),
        &fixtures::addresses(EPOCH, version),
    );
    let content = fixtures::install_config_content(ring, &changed);
    let mut parts = signed.split('.');
    let header = parts.next().expect("a compact JWS has a header");
    let signature = parts.nth(1).expect("a compact JWS has a signature");
    let tampered = format!("{header}.{}.{signature}", b64(content.to_text().as_bytes()));
    cases.push(case(
        "inner_document_replaced_without_resigning",
        "The address document inside is replaced by another validly signed one, and the install configuration keeps its old signature.",
        input(tampered, release, false),
        chain_failed("install_config_invalid", 3, Typ::InstallConfig.as_str()),
    ));

    let foreign_cert = deployment_cert(ring, OTHER_INSTALL_ID, VENDOR_RELEASE);
    let mut spec = fixtures::standard_install_spec(ring);
    spec.deployment_cert.clone_from(&foreign_cert);
    cases.push(case(
        "foreign_deployment_cert_own_install_key",
        "The valid deployment certificate of another installation, globex, with the configuration signed by acme's own install signing key.",
        input(fixtures::sign_install_config(ring, &spec), release, false),
        chain_failed("install_config_invalid", 3, Typ::InstallConfig.as_str()),
    ));

    let mut spec = fixtures::standard_install_spec(ring);
    spec.deployment_cert = foreign_cert;
    spec.signer = install_kid(OTHER_INSTALL_ID);
    cases.push(case(
        "foreign_deployment_cert_foreign_install_key",
        "The deployment certificate of globex, the configuration signed again by globex's install signing key, and its install_id still acme.",
        input(fixtures::sign_install_config(ring, &spec), release, false),
        chain_failed("install_id_mismatch", 3, Typ::InstallConfig.as_str()),
    ));

    let mut spec = fixtures::standard_install_spec(ring);
    spec.deployment_cert = deployment_cert(ring, INSTALL_ID, VENDOR_TEST);
    let test_signed = fixtures::sign_install_config(ring, &spec);
    cases.push(case(
        "vendor_test_key_not_trusted",
        "The deployment certificate is signed under vendor-test-1, which is in the vendor key list, and vendor test keys are not trusted.",
        input(test_signed.clone(), with_test, false),
        chain_failed("untrusted_vendor_key", 2, Typ::DeploymentCert.as_str()),
    ));
    cases.push(case(
        "vendor_test_key_trusted",
        "The same install configuration, with vendor test keys trusted.",
        input(test_signed, with_test, true),
        chain_verified(EPOCH, 1, 1),
    ));

    let mut spec = fixtures::standard_install_spec(ring);
    spec.deployment_cert = deployment_cert(ring, INSTALL_ID, VENDOR_OTHER);
    let other_signed = fixtures::sign_install_config(ring, &spec);
    for (name, trust) in [
        ("vendor_kid_out_of_grammar_test_keys_not_trusted", false),
        ("vendor_kid_out_of_grammar_test_keys_trusted", true),
    ] {
        cases.push(case(
            name,
            &format!(
                "The deployment certificate is signed under {VENDOR_OTHER}, which follows neither vendor kid prefix and so is in no vendor key list; vendor test keys {}trusted.",
                if trust { "" } else { "not " }
            ),
            input(other_signed.clone(), with_test, trust),
            chain_failed("deployment_cert_invalid", 2, Typ::DeploymentCert.as_str()),
        ));
    }

    // Key set (1, 3) after two rotations, signed by its own current_kid.
    let rotated = fixtures::keyset(ring, &KeysetSpec::of(EPOCH, 3, &[2, 3], 3, &[1]));
    let rotated = ring.sign(Typ::Keyset, &customer_kid(3), &rotated);
    let spec = with_keyset(ring, rotated, EPOCH, &customer_kid(3));
    cases.push(case(
        "rotated_keyset_v3",
        "The key set is version 3 of epoch 1, after two rotations, signed by its own current_kid.",
        input(fixtures::sign_install_config(ring, &spec), release, false),
        chain_verified(EPOCH, 3, 1),
    ));

    // Key set (2, 1) right after a recovery.
    let recovered = fixtures::keyset(ring, &KeysetSpec::of(EPOCH + 1, 1, &[4], 4, &[1]));
    let resigned = ring.sign(Typ::Keyset, &customer_kid(4), &recovered);
    let spec = with_keyset(ring, resigned, EPOCH + 1, &customer_kid(4));
    cases.push(case(
        "recovered_keyset_resigned_by_current_kid",
        "The key set (2, 1) of a recovery, the copy signed again by its own current_kid.",
        input(fixtures::sign_install_config(ring, &spec), release, false),
        chain_verified(EPOCH + 1, 1, 1),
    ));
    let recovery_signed = ring.sign(Typ::Keyset, &recovery_kid(INSTALL_ID, 1), &recovered);
    let spec = with_keyset(ring, recovery_signed, EPOCH + 1, &customer_kid(4));
    cases.push(case(
        "recovered_keyset_recovery_signed",
        "The key set (2, 1) of a recovery, the copy the recovery key signed.",
        input(fixtures::sign_install_config(ring, &spec), release, false),
        chain_failed("keyset_invalid", 4, Typ::Keyset.as_str()),
    ));

    for kid in with_test {
        ring.key(kid);
    }
    VectorFile {
        format_version: FORMAT_VERSION,
        category: Category::TrustChain,
        keys: ring.entries(),
        cases,
    }
}
