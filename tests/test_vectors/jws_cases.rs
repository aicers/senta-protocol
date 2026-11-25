//! The `jws` vector file: a valid document of each `typ`, and the
//! rejections of the JWS rules and the content schema.

use senta_protocol::auth::jws::Typ;

use crate::fixtures::{
    self, CommandSpec, ENDPOINT, EPOCH, EnrollResultSpec, INSTALL_ID, KeyRing, KeysetSpec,
    LINUX_DEB, MAX_INTEGER, TOKEN, VENDOR_RELEASE, WINDOWS_MSI, b64, b64_decode, bytes32,
    customer_kid, install_kid, recovery_kid, sha256, sysmon_config, update_package,
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

/// A content of `senta-policy` or `senta-update` that changes the valid
/// one in a field those two carry, and whether it is still valid.
struct FieldVariant {
    name: &'static str,
    description: &'static str,
    content: J,
    valid: bool,
}

fn valid_variant(name: &'static str, description: &'static str, content: J) -> FieldVariant {
    FieldVariant {
        name,
        description,
        content,
        valid: true,
    }
}

fn invalid_variant(name: &'static str, description: &'static str, content: J) -> FieldVariant {
    FieldVariant {
        name,
        description,
        content,
        valid: false,
    }
}

/// The variants of the valid policy `content` in `sysmon_configs`,
/// `existing_sysmon` and `windows_sysmon_package`.
fn policy_variants(content: &J) -> Vec<FieldVariant> {
    let package = content
        .get("windows_sysmon_package")
        .cloned()
        .expect("the valid policy has a windows_sysmon_package");
    let configs = |items: Vec<J>| content.with("sysmon_configs", J::arr(items));
    let windows = sysmon_config("windows");
    let linux = sysmon_config("linux");
    let with_package = |package: J| content.with("windows_sysmon_package", package);
    vec![
        valid_variant(
            "valid_without_windows_sysmon_package",
            "A valid senta-policy without windows_sysmon_package, which deploys no standalone Sysmon.",
            content.without("windows_sysmon_package"),
        ),
        valid_variant(
            "valid_empty_sysmon_configs",
            "A valid senta-policy whose sysmon_configs is empty.",
            configs(Vec::new()),
        ),
        valid_variant(
            "valid_unknown_os",
            "A valid senta-policy with a Sysmon configuration for macos, an os the endpoint may not know.",
            configs(vec![windows.clone(), sysmon_config("macos")]),
        ),
        valid_variant(
            "valid_existing_sysmon_take_over",
            "A valid senta-policy whose existing_sysmon is take_over.",
            content.with("existing_sysmon", J::str("take_over")),
        ),
        invalid_variant(
            "sysmon_configs_repeated_os",
            "Two entries of sysmon_configs have the os windows.",
            configs(vec![windows.clone(), linux.with("os", J::str("windows"))]),
        ),
        invalid_variant(
            "sysmon_configs_empty_os",
            "An entry of sysmon_configs has an empty os.",
            configs(vec![windows.clone(), linux.with("os", J::str(""))]),
        ),
        invalid_variant(
            "sysmon_configs_empty_sources",
            "An entry of sysmon_configs has an empty sources.",
            configs(vec![windows.with("sources", J::arr([])), linux.clone()]),
        ),
        invalid_variant(
            "sysmon_configs_unknown_field",
            "An entry of sysmon_configs carries a field its schema does not define.",
            configs(vec![windows.with("unknown_field", J::str("value")), linux]),
        ),
        invalid_variant(
            "existing_sysmon_missing",
            "The content lacks existing_sysmon.",
            content.without("existing_sysmon"),
        ),
        invalid_variant(
            "existing_sysmon_unknown",
            "existing_sysmon is replace, neither keep nor take_over.",
            content.with("existing_sysmon", J::str("replace")),
        ),
        invalid_variant(
            "windows_sysmon_package_null",
            "windows_sysmon_package is null rather than left out.",
            with_package(J::Null),
        ),
        invalid_variant(
            "windows_sysmon_package_empty_version",
            "windows_sysmon_package has an empty version.",
            with_package(package.with("version", J::str(""))),
        ),
        invalid_variant(
            "windows_sysmon_package_sha256_31_bytes",
            "The sha256 of windows_sysmon_package is 31 bytes.",
            with_package(package.with("sha256", J::str(b64(&[7; 31])))),
        ),
        invalid_variant(
            "windows_sysmon_package_size_0",
            "The size of windows_sysmon_package is 0.",
            with_package(package.with("size", J::Int(0))),
        ),
        invalid_variant(
            "windows_sysmon_package_empty_sources",
            "windows_sysmon_package has an empty sources.",
            with_package(package.with("sources", J::arr([]))),
        ),
        invalid_variant(
            "windows_sysmon_package_unknown_field",
            "windows_sysmon_package carries a field its schema does not define.",
            with_package(package.with("unknown_field", J::str("value"))),
        ),
        invalid_variant(
            "sysmon_config_present",
            "The content also carries sysmon_config, the field sysmon_configs replaced.",
            content.with("sysmon_config", windows.without("os")),
        ),
    ]
}

/// The variants of the valid group update `content` in `target_version`
/// and `packages`; `release` is a valid update of an endpoint whose
/// `target_version` is `null`.
fn update_variants(content: &J, release: J) -> Vec<FieldVariant> {
    let packages = |items: Vec<J>| content.with("packages", J::arr(items));
    let msi = update_package(WINDOWS_MSI);
    let deb = update_package(LINUX_DEB);
    vec![
        valid_variant(
            "valid_null_target_version",
            "A valid senta-update of an endpoint whose target_version is null, without packages.",
            release.clone(),
        ),
        valid_variant(
            "valid_one_platform",
            "A valid senta-update with a package for one platform.",
            packages(vec![msi.clone()]),
        ),
        valid_variant(
            "valid_unknown_platform",
            "A valid senta-update with a package for macos-aarch64-pkg, a platform the endpoint may not know.",
            packages(vec![msi.clone(), update_package("macos-aarch64-pkg")]),
        ),
        invalid_variant(
            "packages_missing",
            "The target_version is a version and the content lacks packages.",
            content.without("packages"),
        ),
        invalid_variant("packages_empty", "packages is empty.", packages(Vec::new())),
        invalid_variant(
            "packages_repeated_platform",
            "Two entries of packages have the platform windows-x86_64-msi.",
            packages(vec![msi.clone(), deb.with("platform", J::str(WINDOWS_MSI))]),
        ),
        invalid_variant(
            "packages_empty_platform",
            "An entry of packages has an empty platform.",
            packages(vec![msi.clone(), deb.with("platform", J::str(""))]),
        ),
        invalid_variant(
            "packages_empty_sources",
            "An entry of packages has an empty sources.",
            packages(vec![msi.clone(), deb.with("sources", J::arr([]))]),
        ),
        invalid_variant(
            "packages_size_0",
            "An entry of packages has the size 0.",
            packages(vec![msi.clone(), deb.with("size", J::Int(0))]),
        ),
        invalid_variant(
            "packages_sha256_33_bytes",
            "The sha256 of an entry of packages is 33 bytes.",
            packages(vec![msi.with("sha256", J::str(b64(&[7; 33]))), deb.clone()]),
        ),
        invalid_variant(
            "packages_unknown_field",
            "An entry of packages carries a field its schema does not define.",
            packages(vec![
                msi.clone(),
                deb.with("unknown_field", J::str("value")),
            ]),
        ),
        invalid_variant(
            "null_target_version_with_packages",
            "The target_version is null and the content has packages.",
            release.with("packages", J::arr([msi.clone()])),
        ),
        invalid_variant(
            "package_sha256_present",
            "The content also carries package_sha256, a field packages replaced.",
            content.with("package_sha256", J::str(b64(&bytes32("package")))),
        ),
        invalid_variant(
            "package_size_present",
            "The content also carries package_size, a field packages replaced.",
            content.with("package_size", J::Int(1_048_576)),
        ),
        invalid_variant(
            "sources_present",
            "The content also carries sources, a field packages replaced.",
            content.with(
                "sources",
                J::arr([J::str("https://dist.example/senta-1.2.0.msi")]),
            ),
        ),
    ]
}

/// The cases of the fields `senta-policy` and `senta-update` carry beyond
/// the cases every `typ` has; none for another `typ`.
fn field_cases(ring: &mut KeyRing, typ: Typ, content: &J) -> Vec<JwsCase> {
    let variants = match typ {
        Typ::Policy => policy_variants(content),
        Typ::Update => {
            let mut issuer = fixtures::Issuer::new();
            let (at, version) = issuer.issue(&format!("{typ}:{ENDPOINT}"));
            let release = fixtures::endpoint_release(
                EPOCH,
                version,
                at,
                at + jiff::SignedDuration::from_hours(24),
            );
            update_variants(content, release)
        }
        _ => return Vec::new(),
    };
    let kid = signer(typ);
    variants
        .into_iter()
        .map(|variant| {
            let expected = if variant.valid {
                jws_verified(&b64(&sha256(variant.content.to_text().as_bytes())))
            } else {
                tag("schema_error")
            };
            case(
                typ,
                variant.name,
                variant.description.to_owned(),
                ring.sign(typ, &kid, &variant.content),
                Some(kid.clone()),
                expected,
            )
        })
        .collect()
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
        Some(kid.clone()),
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
    cases.extend(field_cases(ring, typ, &content));
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
