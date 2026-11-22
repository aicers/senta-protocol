//! Tests for the verifier and the pre-signature check.

use std::cell::Cell;
use std::collections::BTreeMap;

use serde::Deserialize;

use super::strict::{self, Base64UrlArray, SchemaError};
use super::test_util::TestKey;
use super::*;

const UUID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const PAYLOAD: &[u8] = br#"{"version":1}"#;

/// The order of the Ed25519 group, little-endian.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn customer_kid() -> String {
    format!("endpoint-{UUID}:1")
}

/// A kid of each kind.
fn kid_of(kind: KeyKind) -> String {
    match kind {
        KeyKind::Customer => customer_kid(),
        KeyKind::InstallSigning => "install-acme:1".to_owned(),
        KeyKind::Recovery => "recovery-acme:1".to_owned(),
        KeyKind::Vendor => "vendor-release-1".to_owned(),
    }
}

fn key(seed: u8) -> TestKey {
    TestKey::from_seed(&[seed; 32])
}

#[derive(Clone, Copy)]
enum Entry {
    Key(PublicKey, KeyKind),
    Revoked,
}

/// A key source over a fixed table, counting the lookups.
#[derive(Default)]
struct Source {
    entries: BTreeMap<String, Entry>,
    calls: Cell<usize>,
}

impl Source {
    fn with(mut self, kid: &str, key: &TestKey, kind: KeyKind) -> Self {
        self.entries
            .insert(kid.to_owned(), Entry::Key(key.public_key(), kind));
        self
    }

    fn revoked(mut self, kid: &str) -> Self {
        self.entries.insert(kid.to_owned(), Entry::Revoked);
        self
    }
}

impl KeySource for Source {
    fn find_key(&self, kid: &Kid, allowed: &[KeyKind]) -> KeyLookup {
        self.calls.set(self.calls.get() + 1);
        assert!(allowed.contains(&kid.kind()));
        match self.entries.get(kid.as_str()) {
            Some(Entry::Key(key, kind)) => KeyLookup::Found {
                key: *key,
                kind: *kind,
            },
            Some(Entry::Revoked) => KeyLookup::Revoked,
            None => KeyLookup::Unknown,
        }
    }
}

/// A JWS of `typ` signed by key 1 under `kid`, with a source that registers
/// that kid as `kind`.
fn signed(typ: Typ, kid: &str, kind: KeyKind) -> (String, Source) {
    let signer = key(1);
    let jws = signer.sign(typ, kid, PAYLOAD);
    (jws, Source::default().with(kid, &signer, kind))
}

fn policy() -> (String, Source) {
    signed(Typ::Policy, &customer_kid(), KeyKind::Customer)
}

fn segments(jws: &str) -> Vec<&str> {
    jws.split('.').collect()
}

fn join(header: &str, payload: &str, signature: &str) -> String {
    format!("{header}.{payload}.{signature}")
}

/// Flips one bit of a decoded segment and re-encodes it canonically.
fn flip_bit(segment: &str, byte: usize) -> String {
    let mut bytes = b64::decode(segment).unwrap();
    bytes[byte] ^= 1;
    b64::encode(&bytes)
}

fn diagnostics(typ: &str, kid: &str) -> HeaderDiagnostics {
    HeaderDiagnostics {
        typ: typ.to_owned(),
        kid: kid.to_owned(),
    }
}

#[test]
fn every_typ_and_key_kind_follows_the_table() {
    for typ in Typ::ALL {
        for kind in KeyKind::ALL {
            let kid = kid_of(kind);
            let (jws, source) = signed(typ, &kid, kind);
            let verified = verify(&jws, typ, &source);
            let inspected = inspect(&jws, typ);
            if typ.allows(kind) {
                let verified = verified.unwrap_or_else(|e| panic!("{typ} by {kind}: {e}"));
                assert_eq!(verified.payload(), PAYLOAD);
                assert_eq!(verified.kid().as_str(), kid);
                assert_eq!(verified.typ(), typ);
                assert_eq!(source.calls.get(), 1);
                let inspected = inspected.unwrap();
                assert_eq!(inspected.payload(), PAYLOAD);
                assert_eq!(inspected.kid(), verified.kid());
                assert_eq!(inspected.typ(), typ);
            } else {
                let expected = VerifyError::KeyKind {
                    typ,
                    kid_kind: kind,
                    registered_kind: None,
                    header: diagnostics(typ.as_str(), &kid),
                };
                assert_eq!(verified.unwrap_err(), expected, "{typ} by {kind}");
                assert_eq!(source.calls.get(), 0, "{typ} by {kind} asked the source");
                assert_eq!(inspected.unwrap_err(), expected, "{typ} by {kind}");
            }
        }
    }
}

#[test]
fn keyset_takes_customer_and_recovery_keys() {
    for kind in [KeyKind::Customer, KeyKind::Recovery] {
        let (jws, source) = signed(Typ::Keyset, &kid_of(kind), kind);
        assert!(verify(&jws, Typ::Keyset, &source).is_ok(), "{kind}");
    }
}

#[test]
fn a_header_with_another_alg_is_a_header_error() {
    let signer = key(1);
    let kid = customer_kid();
    let source = Source::default().with(&kid, &signer, KeyKind::Customer);
    for alg in [
        "none", "HS256", "ES256", "RS256", "eddsa", "EDDSA", "Ed25519", "EdDSA ", "",
    ] {
        let header = format!(r#"{{"alg":"{alg}","typ":"senta-policy","kid":"{kid}"}}"#);
        let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
        let error = verify(&jws, Typ::Policy, &source).unwrap_err();
        assert!(matches!(error, VerifyError::Header(_)), "{alg}: {error}");
        assert_eq!(error.header(), None);
        assert_eq!(inspect(&jws, Typ::Policy).unwrap_err(), error);
    }
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn header_rules_are_header_errors() {
    let signer = key(1);
    let kid = customer_kid();
    let source = Source::default().with(&kid, &signer, KeyKind::Customer);
    let headers = [
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","crit":["exp"]}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","crit":[]}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","cty":"json"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","Alg":"EdDSA"}}"#),
        format!(r#"{{"typ":"senta-policy","kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#),
        r#"{"alg":"EdDSA","typ":"senta-policy"}"#.to_owned(),
        format!(r#"{{"alg":"EdDSA","alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","kid":"{kid}"}}"#),
        // A key written with an escape is the same key.
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","alg":"EdDSA"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":1,"kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":null,"kid":"{kid}"}}"#),
        format!(r#"{{"alg":["EdDSA"],"typ":"senta-policy","kid":"{kid}"}}"#),
        r#"{"alg":"EdDSA","typ":"senta-policy","kid":{}}"#.to_owned(),
        format!(r#"[{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}}]"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}} {{}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}}x"#),
        "\"EdDSA\"".to_owned(),
        "{}".to_owned(),
        "null".to_owned(),
    ];
    for header in &headers {
        let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
        let error = verify(&jws, Typ::Policy, &source).unwrap_err();
        assert!(matches!(error, VerifyError::Header(_)), "{header}: {error}");
        assert_eq!(error.header(), None, "{header}");
        assert_eq!(inspect(&jws, Typ::Policy).unwrap_err(), error);
    }
    // An escaped key is read unescaped: a duplicate, not an unknown member.
    for header in [
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","al\u0067":"EdDSA"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","\u006bid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","\u006bid":"{kid}","kid":"{kid}"}}"#),
    ] {
        let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
        let error = verify(&jws, Typ::Policy, &source).unwrap_err();
        assert!(
            error.to_string().contains("duplicate header member"),
            "{header}: {error}"
        );
    }
    // A header that is not UTF-8.
    let jws = signer.sign_raw(b"{\"alg\":\"EdDSA\xff\"}", PAYLOAD);
    assert!(matches!(
        verify(&jws, Typ::Policy, &source),
        Err(VerifyError::Header(_))
    ));
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn escaped_header_members_and_values_are_read_unescaped() {
    let signer = key(1);
    let kid = "install-a/b:1";
    let header = r#"{"alg":"EdDSA","typ":"senta-install-config","kid":"install-a\/b:1"}"#;
    let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
    let source = Source::default().with(kid, &signer, KeyKind::InstallSigning);
    let verified = verify(&jws, Typ::InstallConfig, &source).unwrap();
    assert_eq!(verified.kid().as_str(), kid);
    assert_eq!(verified.header(), &diagnostics("senta-install-config", kid));
}

#[test]
fn the_test_signer_raw_headers_verify_or_fail_as_written() {
    let signer = key(1);
    let kid = customer_kid();
    let source = Source::default().with(&kid, &signer, KeyKind::Customer);
    let valid = format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}"}}"#);
    let jws = signer.sign_raw(valid.as_bytes(), PAYLOAD);
    assert_eq!(jws, signer.sign(Typ::Policy, &kid, PAYLOAD));
    assert!(verify(&jws, Typ::Policy, &source).is_ok());
    for header in [
        format!(r#"{{"alg":"HS256","typ":"senta-policy","kid":"{kid}"}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","crit":["b64"]}}"#),
        format!(r#"{{"alg":"EdDSA","typ":"senta-policy","kid":"{kid}","x5u":"https://a"}}"#),
    ] {
        let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
        assert!(
            matches!(
                verify(&jws, Typ::Policy, &source),
                Err(VerifyError::Header(_))
            ),
            "{header}"
        );
    }
}

#[test]
fn a_typ_other_than_the_expected_one_is_a_mismatch() {
    let (jws, source) = policy();
    let error = verify(&jws, Typ::Command, &source).unwrap_err();
    assert_eq!(
        error,
        VerifyError::TypMismatch {
            expected: Typ::Command,
            header: diagnostics("senta-policy", &customer_kid()),
        }
    );
    assert_eq!(error.header().unwrap().typ(), "senta-policy");
    assert_eq!(error.header().unwrap().kid(), customer_kid());
    assert_eq!(inspect(&jws, Typ::Command).unwrap_err(), error);

    // A typ that is none of the eleven.
    let signer = key(1);
    for typ in ["senta-other", "SENTA-POLICY", "JWT", ""] {
        let header = format!(
            r#"{{"alg":"EdDSA","typ":"{typ}","kid":"{}"}}"#,
            customer_kid()
        );
        let jws = signer.sign_raw(header.as_bytes(), PAYLOAD);
        let error = verify(&jws, Typ::Policy, &source).unwrap_err();
        assert_eq!(
            error,
            VerifyError::TypMismatch {
                expected: Typ::Policy,
                header: diagnostics(typ, &customer_kid()),
            }
        );
    }
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn a_flipped_signature_or_payload_bit_is_a_signature_error() {
    let (jws, source) = policy();
    let parts = segments(&jws);
    let header = diagnostics("senta-policy", &customer_kid());
    for byte in [0, 31, 32, 63] {
        let tampered = join(parts[0], parts[1], &flip_bit(parts[2], byte));
        assert_eq!(
            verify(&tampered, Typ::Policy, &source).unwrap_err(),
            VerifyError::Signature {
                header: header.clone()
            },
            "signature byte {byte}"
        );
    }
    for byte in 0..PAYLOAD.len() {
        let tampered = join(parts[0], &flip_bit(parts[1], byte), parts[2]);
        assert_eq!(
            verify(&tampered, Typ::Policy, &source).unwrap_err(),
            VerifyError::Signature {
                header: header.clone()
            },
            "payload byte {byte}"
        );
    }
}

#[test]
fn a_signature_by_another_key_is_a_signature_error() {
    let kid = customer_kid();
    let jws = key(2).sign(Typ::Policy, &kid, PAYLOAD);
    let source = Source::default().with(&kid, &key(1), KeyKind::Customer);
    assert!(matches!(
        verify(&jws, Typ::Policy, &source),
        Err(VerifyError::Signature { .. })
    ));
}

#[test]
fn a_non_canonical_signature_is_a_signature_error() {
    let (jws, source) = policy();
    let parts = segments(&jws);
    let mut signature = b64::decode(parts[2]).unwrap();
    // S + L encodes the same scalar as S, non-canonically; it still fits in
    // 32 bytes since S < L < 2^253.
    let mut carry = 0_u16;
    for (byte, order) in signature[32..].iter_mut().zip(GROUP_ORDER) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let tampered = join(parts[0], parts[1], &b64::encode(&signature));
    assert!(matches!(
        verify(&tampered, Typ::Policy, &source),
        Err(VerifyError::Signature { .. })
    ));
    // It is a well-formed JWS otherwise.
    assert!(inspect(&tampered, Typ::Policy).is_ok());
}

#[test]
fn format_rules_are_format_errors() {
    let (jws, source) = policy();
    let parts = segments(&jws);
    let (header, payload, signature) = (parts[0], parts[1], parts[2]);
    let signature_bytes = b64::decode(signature).unwrap();
    let short = b64::encode(&signature_bytes[..63]);
    let long = b64::encode(&[&signature_bytes[..], &[0]].concat());
    let general = format!(
        r#"{{"payload":"{payload}","signatures":[{{"protected":"{header}","signature":"{signature}"}}]}}"#
    );
    let flattened =
        format!(r#"{{"payload":"{payload}","protected":"{header}","signature":"{signature}"}}"#);
    // Padding where unpadded base64url leaves a partial quantum.
    let pad = |segment: &str| {
        assert!(!segment.len().is_multiple_of(4), "{segment}");
        format!("{segment}{}", "=".repeat(4 - segment.len() % 4))
    };
    let cases = [
        general,
        flattened,
        format!("{header}.{payload}"),
        format!("{header}.{payload}.{signature}.{signature}"),
        format!("{header}.{payload}.{signature}."),
        format!(".{header}.{payload}.{signature}"),
        format!("{header}..{signature}"),
        format!(".{payload}.{signature}"),
        format!("{header}.{payload}."),
        "..".to_owned(),
        String::new(),
        join(header, &pad(payload), signature),
        join(&pad(header), payload, signature),
        join(header, payload, &pad(signature)),
        format!("{header}.{payload}.{signature}="),
        // `+` and `/`, the standard alphabet's 62 and 63, in place of `-`
        // and `_`.
        join(header, &format!("+{}", &payload[1..]), signature),
        join(header, payload, &format!("/{}", &signature[1..])),
        join(&format!("+{}", &header[1..]), payload, signature),
        join(header, payload, &short),
        join(header, payload, &long),
        format!(" {jws}"),
        format!("{jws}\n"),
        format!("{header}. {payload}.{signature}"),
        format!("{header}.{payload}\n.{signature}"),
    ];
    for case in &cases {
        let error = verify(case, Typ::Policy, &source).unwrap_err();
        assert!(matches!(error, VerifyError::Format(_)), "{case:?}: {error}");
        assert_eq!(error.header(), None);
        assert_eq!(inspect(case, Typ::Policy).unwrap_err(), error);
    }
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn non_canonical_base64url_is_a_format_error() {
    let (jws, source) = policy();
    let parts = segments(&jws);
    // Every segment's length leaves unused trailing bits only when it is not
    // a multiple of 4; set the lowest of them.
    for index in 0..3 {
        let segment = parts[index];
        if segment.len().is_multiple_of(4) {
            continue;
        }
        let last = segment.chars().last().unwrap();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let position = alphabet
            .iter()
            .position(|&c| char::from(c) == last)
            .unwrap();
        let bumped = char::from(alphabet[position + 1]);
        let mut altered: Vec<String> = parts.iter().map(|s| (*s).to_owned()).collect();
        altered[index].pop();
        altered[index].push(bumped);
        let case = altered.join(".");
        assert!(b64::decode(&altered[index]).is_none());
        assert!(
            matches!(
                verify(&case, Typ::Policy, &source),
                Err(VerifyError::Format(_))
            ),
            "segment {index}"
        );
    }
    // The signature segment is 86 characters, which always has unused bits.
    assert_eq!(parts[2].len() % 4, 2);
}

#[test]
fn an_altered_header_segment_is_a_format_or_header_error() {
    let (jws, source) = policy();
    let parts = segments(&jws);
    // Not canonical base64url: a format error.
    let broken = join(&format!("{}*", parts[0]), parts[1], parts[2]);
    assert!(matches!(
        verify(&broken, Typ::Policy, &source),
        Err(VerifyError::Format(_))
    ));
    // Canonical base64url of a header out of rule: a header error.
    let other = b64::encode(br#"{"alg":"none","typ":"senta-policy","kid":"x"}"#);
    let broken = join(&other, parts[1], parts[2]);
    assert!(matches!(
        verify(&broken, Typ::Policy, &source),
        Err(VerifyError::Header(_))
    ));
}

const REJECTED_KIDS: &[&str] = &[
    "endpoint-0F8FAD5B-D9CB-469F-A165-70867728950E:1",
    "endpoint-{0f8fad5b-d9cb-469f-a165-70867728950e}:1",
    "endpoint-0f8fad5bd9cb469fa16570867728950e:1",
    "endpoint-0f8fad5b-d9cb-469f-a165-70867728950e:0",
    "endpoint-0f8fad5b-d9cb-469f-a165-70867728950e:01",
    "endpoint-0f8fad5b-d9cb-469f-a165-70867728950e:9007199254740992",
    "endpoint-0f8fad5b-d9cb-469f-a165-70867728950e",
    "install-acme",
    "recovery-acme:",
    "vendor-other-1",
    "vendor-release-1:1",
    "vendor-release-",
    "vendor-test-",
    "",
];

#[test]
fn kids_outside_the_grammar_are_kid_errors_inside_and_outside_a_jws() {
    let signer = key(1);
    for &kid in REJECTED_KIDS {
        let source = Source::default().with(kid, &signer, KeyKind::Customer);
        let outside = Kid::parse(kid).unwrap_err();
        let jws = signer.sign(Typ::Keyset, kid, PAYLOAD);
        let expected = VerifyError::Kid {
            source: outside,
            header: diagnostics("senta-keyset", kid),
        };
        assert_eq!(verify(&jws, Typ::Keyset, &source).unwrap_err(), expected);
        assert_eq!(inspect(&jws, Typ::Keyset).unwrap_err(), expected);
        assert_eq!(source.calls.get(), 0, "{kid}");
    }
}

#[test]
fn a_kid_parses_the_same_inside_and_outside_a_jws() {
    for kind in KeyKind::ALL {
        let kid = kid_of(kind);
        let (jws, source) = signed(Typ::Keyset, &kid, kind);
        let inspected = inspect(&jws, Typ::Keyset);
        let outside = Kid::parse(&kid).unwrap();
        if let Ok(inspected) = inspected {
            assert_eq!(inspected.kid(), &outside);
            assert_eq!(inspected.kid().kind(), outside.kind());
            assert_eq!(inspected.kid().key_name(), outside.key_name());
            assert_eq!(inspected.kid().version(), outside.version());
            let verified = verify(&jws, Typ::Keyset, &source).unwrap();
            assert_eq!(verified.kid(), &outside);
        }
    }
}

#[test]
fn vendor_test_kids_verify_like_vendor_release_kids() {
    for kid in ["vendor-release-7", "vendor-test-7", "vendor-release-001"] {
        let (jws, source) = signed(Typ::DeploymentCert, kid, KeyKind::Vendor);
        let verified = verify(&jws, Typ::DeploymentCert, &source).unwrap();
        assert_eq!(verified.kid().as_str(), kid);
        assert_eq!(verified.header().kid(), kid);
        assert!(inspect(&jws, Typ::DeploymentCert).is_ok());
    }
    let (jws, source) = signed(Typ::DeploymentCert, "vendor-test-7", KeyKind::Vendor);
    let verified = verify(&jws, Typ::DeploymentCert, &source).unwrap();
    assert_eq!(verified.kid().vendor_class(), Some(VendorKeyClass::Test));
    assert_eq!(verified.kid().vendor_number(), Some("7"));
}

#[test]
fn vendor_release_with_leading_zeros_keeps_its_spelling() {
    let kid = "vendor-release-001";
    let (jws, source) = signed(Typ::DeploymentCert, kid, KeyKind::Vendor);
    let verified = verify(&jws, Typ::DeploymentCert, &source).unwrap();
    assert_eq!(verified.kid().as_str(), kid);
    assert_eq!(verified.kid().vendor_number(), Some("001"));
    assert_eq!(verified.header().kid(), kid);
    // Registered as `vendor-release-1`, it is another kid.
    let other = Source::default().with("vendor-release-1", &key(1), KeyKind::Vendor);
    assert!(matches!(
        verify(&jws, Typ::DeploymentCert, &other),
        Err(VerifyError::UnknownKid { .. })
    ));
}

#[test]
fn unknown_and_revoked_kids() {
    let kid = customer_kid();
    let jws = key(1).sign(Typ::Policy, &kid, PAYLOAD);
    let header = diagnostics("senta-policy", &kid);
    assert_eq!(
        verify(&jws, Typ::Policy, &Source::default()).unwrap_err(),
        VerifyError::UnknownKid {
            header: header.clone()
        }
    );
    assert_eq!(
        verify(&jws, Typ::Policy, &Source::default().revoked(&kid)).unwrap_err(),
        VerifyError::RevokedKid { header }
    );
}

#[test]
fn another_version_of_the_same_key_name_is_unknown() {
    let signer = key(1);
    let jws = signer.sign(Typ::Policy, &format!("endpoint-{UUID}:2"), PAYLOAD);
    let source = Source::default()
        .with(&format!("endpoint-{UUID}:1"), &signer, KeyKind::Customer)
        .with(&format!("endpoint-{UUID}:3"), &signer, KeyKind::Customer);
    assert!(matches!(
        verify(&jws, Typ::Policy, &source),
        Err(VerifyError::UnknownKid { .. })
    ));
}

#[test]
fn a_key_registered_as_another_kind_is_a_key_kind_error() {
    let kid = customer_kid();
    // The signature is good; the registered kind is not.
    for (typ, registered) in [
        (Typ::Policy, KeyKind::Recovery),
        (Typ::Policy, KeyKind::Vendor),
        (Typ::Keyset, KeyKind::Recovery),
    ] {
        let (jws, source) = signed(typ, &kid, registered);
        let error = verify(&jws, typ, &source).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("the key under a customer key kid is registered as a {registered}")
        );
        assert_eq!(
            error,
            VerifyError::KeyKind {
                typ,
                kid_kind: KeyKind::Customer,
                registered_kind: Some(registered),
                header: diagnostics(typ.as_str(), &kid),
            }
        );
        assert_eq!(source.calls.get(), 1);
    }
}

#[test]
fn success_carries_the_header_values() {
    let (jws, source) = policy();
    let verified = verify(&jws, Typ::Policy, &source).unwrap();
    assert_eq!(
        verified.header(),
        &diagnostics("senta-policy", &customer_kid())
    );
    let inspected = inspect(&jws, Typ::Policy).unwrap();
    assert_eq!(inspected.header(), verified.header());
}

/// Whether the diagnostics are present, stage by stage.
#[test]
fn diagnostics_by_stage() {
    let signer = key(1);
    let kid = customer_kid();
    let good = Source::default().with(&kid, &signer, KeyKind::Customer);
    let jws = signer.sign(Typ::Policy, &kid, PAYLOAD);
    let parts = segments(&jws);
    let bad_signature = join(parts[0], parts[1], &flip_bit(parts[2], 0));
    let bad_alg = signer.sign_raw(
        format!(r#"{{"alg":"none","typ":"senta-policy","kid":"{kid}"}}"#).as_bytes(),
        PAYLOAD,
    );
    let bad_kid = signer.sign(Typ::Policy, "endpoint-x:1", PAYLOAD);
    let recovery = signer.sign(Typ::Policy, "recovery-acme:1", PAYLOAD);

    let policy = diagnostics("senta-policy", &kid);
    let cases: [(&str, &str, Typ, &Source, Option<HeaderDiagnostics>); 9] = [
        ("1 format", "a.b", Typ::Policy, &good, None),
        ("2 header", &bad_alg, Typ::Policy, &good, None),
        ("3 typ", &jws, Typ::Command, &good, Some(policy.clone())),
        (
            "4 kid",
            &bad_kid,
            Typ::Policy,
            &good,
            Some(diagnostics("senta-policy", "endpoint-x:1")),
        ),
        (
            "5 key kind",
            &recovery,
            Typ::Policy,
            &good,
            Some(diagnostics("senta-policy", "recovery-acme:1")),
        ),
        (
            "6 unknown",
            &jws,
            Typ::Policy,
            &Source::default(),
            Some(policy.clone()),
        ),
        (
            "6 revoked",
            &jws,
            Typ::Policy,
            &Source::default().revoked(&kid),
            Some(policy.clone()),
        ),
        (
            "6 registered kind",
            &jws,
            Typ::Policy,
            &Source::default().with(&kid, &signer, KeyKind::Recovery),
            Some(policy.clone()),
        ),
        (
            "7 signature",
            &bad_signature,
            Typ::Policy,
            &good,
            Some(policy.clone()),
        ),
    ];
    for (stage, jws, typ, source, expected) in cases {
        let error = verify(jws, typ, source).unwrap_err();
        assert_eq!(error.header(), expected.as_ref(), "{stage}: {error}");
        // `inspect` stops before the key lookup: stages 1–5 fail as `verify`
        // does, and 6–7 pass.
        let inspected = inspect(jws, typ);
        if stage.starts_with(['6', '7']) {
            assert!(inspected.is_ok(), "{stage}: inspect failed");
        } else {
            assert_eq!(inspected.unwrap_err(), error, "{stage}");
        }
    }
}

#[test]
fn checks_run_in_order() {
    let signer = key(1);
    let kid = customer_kid();
    let source = Source::default().with(&kid, &signer, KeyKind::Customer);

    // A wrong alg and a wrong signature: the header error.
    let bad_alg = signer.sign_raw(
        format!(r#"{{"alg":"HS256","typ":"senta-policy","kid":"{kid}"}}"#).as_bytes(),
        PAYLOAD,
    );
    let parts = segments(&bad_alg);
    let both = join(parts[0], parts[1], &flip_bit(parts[2], 0));
    assert!(matches!(
        verify(&both, Typ::Policy, &source),
        Err(VerifyError::Header(_))
    ));

    // A wrong typ and an unknown kid: the typ mismatch.
    let unknown = signer.sign(Typ::Policy, &format!("endpoint-{UUID}:9"), PAYLOAD);
    assert!(matches!(
        verify(&unknown, Typ::Command, &source),
        Err(VerifyError::TypMismatch { .. })
    ));

    // A wrong typ and a kid out of grammar: the typ mismatch.
    let bad_kid = signer.sign(Typ::Policy, "nope", PAYLOAD);
    assert!(matches!(
        verify(&bad_kid, Typ::Command, &source),
        Err(VerifyError::TypMismatch { .. })
    ));

    // A key kind not allowed and an unknown kid: the key kind error, without
    // asking the source.
    let recovery = signer.sign(Typ::Policy, "recovery-acme:1", PAYLOAD);
    assert!(matches!(
        verify(&recovery, Typ::Policy, &source),
        Err(VerifyError::KeyKind { .. })
    ));

    // A revoked kid and a wrong signature: the revoked kid.
    let jws = signer.sign(Typ::Policy, &kid, PAYLOAD);
    let parts = segments(&jws);
    let tampered = join(parts[0], parts[1], &flip_bit(parts[2], 0));
    assert!(matches!(
        verify(&tampered, Typ::Policy, &Source::default().revoked(&kid)),
        Err(VerifyError::RevokedKid { .. })
    ));
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn inspect_passes_a_wrong_signature() {
    let (jws, _) = policy();
    let parts = segments(&jws);
    let tampered = join(parts[0], parts[1], &flip_bit(parts[2], 5));
    let inspected = inspect(&tampered, Typ::Policy).unwrap();
    assert_eq!(inspected.payload(), PAYLOAD);
    assert_eq!(inspected.kid().as_str(), customer_kid());
    assert_eq!(inspected.typ(), Typ::Policy);
    assert_eq!(
        inspected.header(),
        &diagnostics("senta-policy", &customer_kid())
    );
    assert_eq!(inspected.payload_hash(), &sha256(PAYLOAD));
    assert_eq!(inspected.clone().into_payload(), PAYLOAD);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn the_payload_hash_is_the_sha256_of_the_payload() {
    // FIPS 180-2's "abc" vector.
    let abc = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let kid = customer_kid();
    let first = key(1).sign(Typ::Policy, &kid, b"abc");
    let second = key(2).sign(Typ::Policy, &format!("endpoint-{UUID}:2"), b"abc");
    let first = verify(
        &first,
        Typ::Policy,
        &Source::default().with(&kid, &key(1), KeyKind::Customer),
    )
    .unwrap();
    let second = verify(
        &second,
        Typ::Policy,
        &Source::default().with(&format!("endpoint-{UUID}:2"), &key(2), KeyKind::Customer),
    )
    .unwrap();
    assert_eq!(first.payload_hash(), &abc);
    assert_eq!(second.payload_hash(), &abc);
    assert_eq!(first.into_payload(), b"abc");
}

#[test]
fn test_keys_are_deterministic() {
    let first = key(7);
    let again = key(7);
    assert_eq!(first.public_key(), again.public_key());
    assert_eq!(first.public_key_bytes(), again.public_key_bytes());
    assert_eq!(first.jwk(), again.jwk());
    assert_eq!(first.public_key().to_bytes(), first.public_key_bytes());
    assert_ne!(first.public_key(), key(8).public_key());
    // Ed25519 signatures are deterministic too.
    assert_eq!(
        first.sign(Typ::Policy, "x", PAYLOAD),
        again.sign(Typ::Policy, "x", PAYLOAD)
    );
    // RFC 8032 section 7.1, test 1.
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    assert_eq!(
        b64::encode(&TestKey::from_seed(&seed).public_key_bytes()),
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
}

#[test]
fn jwk_reads_exactly_the_three_members() {
    // A key whose `x` has a character outside the standard base64 alphabet.
    let signer = (1..=u8::MAX)
        .map(key)
        .find(|k| b64::encode(&k.public_key_bytes()).contains(['-', '_']))
        .expect("some seed gives `-` or `_`");
    let x = b64::encode(&signer.public_key_bytes());
    let valid = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#);
    let jwk: Jwk = strict::from_slice(valid.as_bytes()).unwrap();
    assert_eq!(jwk, signer.jwk());
    assert_eq!(jwk.public_key(), signer.public_key());
    assert_eq!(serde_json::to_string(&signer.jwk()).unwrap(), valid);
    // Reordered members are the same JWK.
    let reordered = format!(r#"{{"x":"{x}","crv":"Ed25519","kty":"OKP"}}"#);
    assert_eq!(
        strict::from_slice::<Jwk>(reordered.as_bytes()).unwrap(),
        jwk
    );

    let short = b64::encode(&signer.public_key_bytes()[..31]);
    let long = b64::encode(&[&signer.public_key_bytes()[..], &[0]].concat());
    let rejected = [
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","kid":"a"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","use":"sig"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","d":"{x}"}}"#),
        format!(r#"{{"crv":"Ed25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","x":"{x}"}}"#),
        r#"{"kty":"OKP","crv":"Ed25519"}"#.to_owned(),
        format!(r#"{{"kty":"EC","crv":"Ed25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"okp","crv":"Ed25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{short}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{long}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}="}}"#),
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            x.replace('-', "+").replace('_', "/")
        ),
        format!(r#"{{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","x":"{x}"}}"#),
        r#"{"kty":"OKP","crv":"Ed25519","x":1}"#.to_owned(),
        format!(r#"["OKP","Ed25519","{x}"]"#),
    ];
    for json in &rejected {
        assert!(
            strict::from_slice::<Jwk>(json.as_bytes()).is_err(),
            "{json}"
        );
        // The checks are the JWK's own, not only the strict parser's.
        assert!(serde_json::from_str::<Jwk>(json).is_err(), "{json}");
    }
    // `x` whose last character carries unused bits.
    let mut bumped = x.clone();
    let last = bumped.pop().unwrap();
    assert!(!x.is_empty() && last != '_');
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let next = alphabet.chars().skip_while(|&c| c != last).nth(1).unwrap();
    bumped.push(next);
    let json = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{bumped}"}}"#);
    assert!(strict::from_slice::<Jwk>(json.as_bytes()).is_err());
}

#[test]
fn jwk_rejects_bytes_that_are_not_a_curve_point() {
    let not_a_point = (0..=u8::MAX)
        .map(|b| [b; 32])
        .find(|bytes| PublicKey::from_bytes(bytes).is_err())
        .expect("some repeated byte is not a point");
    let json = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        b64::encode(&not_a_point)
    );
    assert!(strict::from_slice::<Jwk>(json.as_bytes()).is_err());
}

#[test]
fn jwk_reads_as_a_content_field() {
    #[derive(Debug, Deserialize)]
    struct RecoveryKey {
        recovery_key_version: u64,
        recovery_key: Jwk,
    }
    let signer = key(3);
    let content = format!(
        r#"{{"recovery_key_version":2,"recovery_key":{}}}"#,
        serde_json::to_string(&signer.jwk()).unwrap()
    );
    let parsed: RecoveryKey = strict::from_slice(content.as_bytes()).unwrap();
    assert_eq!(parsed.recovery_key_version, 2);
    assert_eq!(parsed.recovery_key.public_key(), signer.public_key());
    // The key it yields verifies what the key signed.
    let kid = "recovery-acme:2";
    let jws = signer.sign(Typ::RecoveryKey, kid, PAYLOAD);
    let source = Source::default();
    let source = Source {
        entries: BTreeMap::from([(
            kid.to_owned(),
            Entry::Key(parsed.recovery_key.public_key(), KeyKind::Recovery),
        )]),
        ..source
    };
    assert!(verify(&jws, Typ::RecoveryKey, &source).is_ok());
}

/// A content type for the content-side rejections.
#[derive(Debug, Deserialize)]
struct Assign {
    recovery_epoch: u64,
    endpoint_id: strict::LowerUuid,
    version: u64,
    group_id: strict::LowerUuid,
    uninstall_token_sha256: Base64UrlArray<32>,
}

#[test]
fn content_rejections_are_schema_errors_after_verification() {
    let valid = format!(
        r#"{{"recovery_epoch":0,"endpoint_id":"{UUID}","version":1,"group_id":"{UUID}","uninstall_token_sha256":"{}"}}"#,
        b64::encode(&[7; 32])
    );
    let parse = |content: &str| -> Result<Assign, SchemaError> {
        let (jws, source) = {
            let signer = key(1);
            let kid = customer_kid();
            let jws = signer.sign(Typ::Assign, &kid, content.as_bytes());
            (
                jws,
                Source::default().with(&kid, &signer, KeyKind::Customer),
            )
        };
        let verified = verify(&jws, Typ::Assign, &source).expect("the signature verifies");
        strict::from_slice(verified.payload())
    };
    let assign = parse(&valid).unwrap();
    assert_eq!(assign.version, 1);
    assert_eq!(assign.recovery_epoch, 0);
    assert_eq!(assign.endpoint_id, assign.group_id);
    assert_eq!(assign.uninstall_token_sha256.get(), &[7; 32]);

    let rejected = [
        valid.replacen('{', r#"{"extra":1,"#, 1),
        valid.replacen("group_id", "groupId", 1),
        valid.replacen("group_id", "Group_id", 1),
        valid.replacen(r#""version":1,"#, "", 1),
        valid.replacen('{', r#"{"version":1,"#, 1),
        valid.replacen(r#""version":1"#, r#""version":9007199254740992"#, 1),
        valid.replacen(r#""version":1"#, r#""version":1.0"#, 1),
        valid.replacen(r#""version":1"#, r#""version":-1"#, 1),
        valid.replacen(r#""version":1"#, r#""version":1e0"#, 1),
    ];
    for content in &rejected {
        assert!(parse(content).is_err(), "{content}");
    }
    let max = valid.replacen(r#""version":1"#, r#""version":9007199254740991"#, 1);
    assert_eq!(parse(&max).unwrap().version, 9_007_199_254_740_991);
}

#[test]
fn a_key_source_can_be_a_trait_object() {
    let (jws, source) = policy();
    let source: &dyn KeySource = &source;
    assert!(verify(&jws, Typ::Policy, source).is_ok());
}
