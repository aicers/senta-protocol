//! The `jws` vector file: a valid document of each `typ`, and the
//! rejections of the JWS rules and the content schema.

use senta_protocol::auth::jws::Typ;

use crate::fixtures::{
    self, CommandSpec, ENDPOINT, EPOCH, EnrollResultSpec, INSTALL_ID, KeyRing, KeysetSpec,
    MAX_INTEGER, TOKEN, VENDOR_RELEASE, b64, b64_decode, customer_kid, install_kid, recovery_kid,
    sha256,
};
use crate::json::J;
use crate::model::{Category, FORMAT_VERSION, JwsCase, JwsInput, TrustedKey, VectorFile};
use crate::notation::{jws_verified, tag};

/// The integer field set to 2^53 in each `typ` that has one. A
/// `senta-deployment-cert` and a `senta-enroll` have no integer field.
fn integer_field(typ: Typ) -> Option<&'static str> {
    match typ {
        Typ::DeploymentCert | Typ::Enroll => None,
        Typ::InstallConfig | Typ::RecoveryKey => Some("recovery_key_version"),
        Typ::Keyset => Some("keyset_version"),
        Typ::EnrollResult => Some("recovery_epoch"),
        Typ::Policy | Typ::Assign | Typ::Addresses | Typ::Update => Some("version"),
        Typ::Command => Some("seq"),
    }
}

/// The kid that signs a valid document of `typ`.
fn signer(typ: Typ) -> String {
    match typ {
        Typ::DeploymentCert => VENDOR_RELEASE.to_owned(),
        Typ::InstallConfig => install_kid(INSTALL_ID),
        Typ::RecoveryKey => recovery_kid(INSTALL_ID, 1),
        _ => customer_kid(1),
    }
}

/// A kid of a kind `typ` does not allow.
fn wrong_class_signer(typ: Typ) -> String {
    match typ {
        Typ::DeploymentCert | Typ::InstallConfig | Typ::RecoveryKey => customer_kid(1),
        _ => install_kid(INSTALL_ID),
    }
}

/// A valid content of `typ`.
fn valid_content(ring: &mut KeyRing, typ: Typ) -> J {
    let mut issuer = fixtures::Issuer::new();
    match typ {
        Typ::DeploymentCert => fixtures::deployment_cert(ring, INSTALL_ID),
        Typ::InstallConfig => {
            let spec = fixtures::standard_install_spec(ring);
            fixtures::install_config_content(ring, &spec)
        }
        Typ::Keyset => fixtures::keyset(ring, &KeysetSpec::of(EPOCH, 1, &[1], 1, &[])),
        Typ::RecoveryKey => fixtures::recovery_key(ring, 2),
        Typ::Enroll => fixtures::enroll(TOKEN),
        Typ::EnrollResult => fixtures::enroll_result(&EnrollResultSpec::matching(EPOCH)),
        Typ::Policy => {
            let (_, version) = issuer.issue(&format!("{typ}:{}", fixtures::GROUP));
            fixtures::policy(EPOCH, version, "tray")
        }
        Typ::Assign => {
            let (_, version) = issuer.issue(&format!("{typ}:{ENDPOINT}"));
            fixtures::assign(EPOCH, version)
        }
        Typ::Addresses => {
            let (_, version) = issuer.issue(typ.as_str());
            fixtures::addresses(EPOCH, version)
        }
        Typ::Update => {
            let (at, version) = issuer.issue(&format!("{typ}:{}", fixtures::GROUP));
            fixtures::group_update(
                EPOCH,
                version,
                at,
                at + jiff::SignedDuration::from_hours(24),
            )
        }
        Typ::Command => {
            let id = fixtures::command_id(1);
            let at = issuer.tick();
            let seq = issuer.number(&format!("command:{ENDPOINT}"), at);
            fixtures::command(&CommandSpec {
                command_id: &id,
                endpoint_id: ENDPOINT,
                seq,
                issued_at: at,
                epoch: EPOCH,
            })
        }
    }
}

/// The content with its first member written twice.
fn with_duplicate_key(content: &J) -> J {
    match content {
        J::Obj(members) => {
            let mut members = members.clone();
            if let Some(first) = members.first().cloned() {
                members.push(first);
            }
            J::Obj(members)
        }
        other => other.clone(),
    }
}

/// The name of the first member, which every content requires.
fn first_member(content: &J) -> String {
    match content {
        J::Obj(members) => members
            .first()
            .map(|(name, _)| name.clone())
            .expect("every content has members"),
        _ => panic!("every content is an object"),
    }
}

fn header(alg: &str, typ: &str, kid: &str, extra: &str) -> String {
    format!(
        r#"{{"alg":{},"typ":{},"kid":{}{extra}}}"#,
        J::str(alg),
        J::str(typ),
        J::str(kid)
    )
}

/// Returns the segments of a compact JWS.
fn segments(jws: &str) -> (&str, &str, &str) {
    let mut parts = jws.splitn(3, '.');
    let header = parts.next().expect("a compact JWS has a header");
    let payload = parts.next().expect("a compact JWS has a payload");
    let signature = parts.next().expect("a compact JWS has a signature");
    (header, payload, signature)
}

/// Decodes a segment and reads it as UTF-8, if it is.
fn readable(segment: &str) -> Option<String> {
    b64_decode(segment).and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Flips the lowest bit of the first signature byte.
fn flip_signature_bit(jws: &str) -> String {
    let (header, payload, signature) = segments(jws);
    let mut bytes = b64_decode(signature).expect("the signature is base64url");
    if let Some(first) = bytes.first_mut() {
        *first ^= 1;
    }
    format!("{header}.{payload}.{}", b64(&bytes))
}

/// The JWS JSON serialization (flattened) of the same parts.
fn json_serialization(jws: &str) -> String {
    let (header, payload, signature) = segments(jws);
    J::obj([
        ("protected", J::str(header)),
        ("payload", J::str(payload)),
        ("signature", J::str(signature)),
    ])
    .to_text()
}

fn trusted_keys() -> Vec<TrustedKey> {
    [
        VENDOR_RELEASE.to_owned(),
        install_kid(INSTALL_ID),
        customer_kid(1),
        recovery_kid(INSTALL_ID, 1),
    ]
    .into_iter()
    .map(|kid| TrustedKey {
        kind: fixtures::kind_of(&kid),
        kid,
    })
    .collect()
}

fn case(
    typ: Typ,
    variant: &str,
    description: String,
    jws: String,
    signed_by: Option<String>,
    expected: J,
) -> JwsCase {
    let (header_json, payload_json) = if jws.starts_with('{') {
        let parsed: serde_json::Value =
            serde_json::from_str(&jws).expect("the JSON serialization is JSON");
        let member = |name: &str| {
            parsed
                .get(name)
                .and_then(|value| value.as_str())
                .and_then(readable)
        };
        (member("protected"), member("payload"))
    } else {
        let (header, payload, _) = segments(&jws);
        (readable(header), readable(payload))
    };
    JwsCase {
        name: format!("{typ}:{variant}"),
        description,
        signed_by,
        input: JwsInput {
            jws,
            header_json,
            payload_json,
            expected_typ: typ.as_str().to_owned(),
            trusted_keys: trusted_keys(),
            revoked_kids: Vec::new(),
        },
        expected,
    }
}

fn cases_of(ring: &mut KeyRing, typ: Typ, index: usize) -> Vec<JwsCase> {
    let content = valid_content(ring, typ);
    let payload = content.to_text();
    let kid = signer(typ);
    let typ_text = typ.as_str();
    let mut cases = Vec::new();

    let valid = ring.sign(typ, &kid, &content);
    cases.push(case(
        typ,
        "valid",
        format!("A valid {typ_text} signed by {kid}."),
        valid.clone(),
        Some(kid.clone()),
        jws_verified(&b64(&sha256(payload.as_bytes()))),
    ));

    let signed_raw = |ring: &mut KeyRing, header: &str| {
        ring.sign_raw(&kid, header.as_bytes(), payload.as_bytes())
    };
    cases.push(case(
        typ,
        "alg_not_eddsa",
        "The header's alg is ES256, not EdDSA.".to_owned(),
        signed_raw(ring, &header("ES256", typ_text, &kid, "")),
        Some(kid.clone()),
        tag("schema_error"),
    ));

    let other = Typ::ALL
        .get((index + 1) % Typ::ALL.len())
        .copied()
        .expect("the index is within the eleven typs");
    cases.push(case(
        typ,
        "typ_mismatch",
        format!("The header's typ is {other}, not the expected {typ_text}."),
        ring.sign(other, &kid, &content),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    cases.push(case(
        typ,
        "crit_header",
        "The header carries crit.".to_owned(),
        signed_raw(ring, &header("EdDSA", typ_text, &kid, r#","crit":["b64"]"#)),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    cases.push(case(
        typ,
        "unknown_header_member",
        "The header carries a member other than alg, typ and kid.".to_owned(),
        signed_raw(
            ring,
            &header("EdDSA", typ_text, &kid, r#","extra":"value""#),
        ),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    cases.push(case(
        typ,
        "unknown_content_field",
        "The content carries a field its schema does not define.".to_owned(),
        ring.sign(typ, &kid, &content.with("unknown_field", J::str("value"))),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    let missing = first_member(&content);
    cases.push(case(
        typ,
        "missing_content_field",
        format!("The content lacks its required field {missing}."),
        ring.sign(typ, &kid, &content.without(&missing)),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    cases.push(case(
        typ,
        "duplicate_content_key",
        format!("The content writes its field {missing} twice."),
        ring.sign(typ, &kid, &with_duplicate_key(&content)),
        Some(kid.clone()),
        tag("schema_error"),
    ));
    if let Some(field) = integer_field(typ) {
        let too_large = (MAX_INTEGER + 1).to_string();
        cases.push(case(
            typ,
            "integer_2_pow_53",
            format!("The content's {field} is 2^53, one above the largest integer accepted."),
            ring.sign(typ, &kid, &content.with(field, J::Raw(too_large))),
            Some(kid.clone()),
            tag("schema_error"),
        ));
    }
    cases.push(case(
        typ,
        "signature_bit_flipped",
        "The valid document with the lowest bit of the first signature byte flipped.".to_owned(),
        flip_signature_bit(&valid),
        None,
        tag("bad_signature"),
    ));
    cases.push(case(
        typ,
        "json_serialization",
        "The valid document in the flattened JWS JSON serialization.".to_owned(),
        json_serialization(&valid),
        None,
        tag("schema_error"),
    ));
    let wrong = wrong_class_signer(typ);
    cases.push(case(
        typ,
        "wrong_key_class",
        format!("Signed by {wrong}, a kind of key {typ_text} does not allow."),
        ring.sign(typ, &wrong, &content),
        Some(wrong),
        tag("wrong_key_class"),
    ));
    cases
}

pub fn file() -> VectorFile<JwsCase> {
    let mut ring = KeyRing::default();
    let mut cases = Vec::new();
    for (index, typ) in Typ::ALL.into_iter().enumerate() {
        cases.extend(cases_of(&mut ring, typ, index));
    }
    // Every trusted key is in the key list, whether or not a case signs
    // with it.
    for key in trusted_keys() {
        ring.key(&key.kid);
    }
    VectorFile {
        format_version: FORMAT_VERSION,
        category: Category::Jws,
        keys: ring.entries(),
        cases,
    }
}
