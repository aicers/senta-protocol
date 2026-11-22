//! Tests of `senta_protocol::auth::tls`: generated certificates, SPKI hashes,
//! and in-memory handshakes between the helpers' configurations and peers
//! built here.
#![cfg(feature = "auth")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey, Verifier};
use jiff::Timestamp;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::client::ResolvesClientCert;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::internal::msgs::codec::Codec;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, alg_id,
};
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, HandshakeKind, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme,
};
use senta_protocol::auth::tls::{
    CONTROL_ALPN, CertificateGenerationError, ClientConfigError, ClientVerifierError,
    EndpointClientVerifier, ExpectedNameError, PeerIdentityError, ServerConfigError,
    TELEMETRY_ALPN, alpn_matches, endpoint_certificate, endpoint_client_config,
    endpoint_private_key, expected_server_name, ingress_server_config, peer_spki_hash,
    spki_hash_from_certificate, spki_hash_from_ed25519_public_key,
};
use sha2::Digest as _;
use x509_parser::prelude::{FromDer, X509Certificate, X509Version};

/// The secret key of RFC 8032, section 7.1, test 1.
const SEED: [u8; 32] = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

/// The public key of RFC 8032, section 7.1, test 1.
const PUBLIC_KEY: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

/// `openssl pkey -pubout -outform DER` of the PKCS#8 key holding [`SEED`].
const SPKI_DER: &str = "302a300506032b6570032100\
                        d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// `openssl dgst -sha256` of [`SPKI_DER`].
const SPKI_SHA256: [u8; 32] =
    hex32("06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9");

const OTHER_SEED: [u8; 32] = [7; 32];

const SERVER_NAME: &str = "ingress.example";

const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let bytes = s.as_bytes();
    assert!(bytes.len() == 64, "not 32 bytes of hex");
    let mut out = [0_u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn now() -> Timestamp {
    ts("2026-11-23T05:06:07Z")
}

// ---------------------------------------------------------------------------
// Certificate authorities and peers
// ---------------------------------------------------------------------------

struct Ca {
    cert: CertificateDer<'static>,
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = name(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn root_ca(common_name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.self_signed(&key).unwrap();
    Ca {
        cert: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

fn intermediate_ca(parent: &Ca, common_name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    Ca {
        cert: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

/// A server certificate whose SAN holds `sans`, issued by `issuer`.
fn server_leaf(issuer: &Ca, sans: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let sans: Vec<String> = sans.iter().map(|s| (*s).to_owned()).collect();
    let mut params = CertificateParams::new(sans).unwrap();
    params.distinguished_name = name("ingress");
    let cert = params.signed_by(&key, &issuer.issuer).unwrap();
    (cert.der().clone(), pkcs8(&key))
}

fn pkcs8(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

/// The endpoint's own certificate and key, made by the crate.
fn endpoint_identity(seed: &[u8; 32]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (
        endpoint_certificate(seed, now()).unwrap(),
        endpoint_private_key(seed).unwrap().into(),
    )
}

/// An ingress whose server certificate is issued directly by a root.
struct Ingress {
    root: Ca,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn ingress() -> Ingress {
    let root = root_ca("root");
    let (cert, key) = server_leaf(&root, &[SERVER_NAME]);
    Ingress {
        root,
        chain: vec![cert],
        key,
    }
}

impl Ingress {
    fn server_config(&self, alpn: &[u8]) -> ServerConfig {
        ingress_server_config(provider(), self.chain.clone(), self.key.clone_key(), alpn).unwrap()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.cert.clone()).unwrap();
        roots
    }

    /// A client built here, not by the crate, trusting this ingress's root.
    fn client_builder(
        &self,
    ) -> rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert> {
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(self.roots())
    }

    fn endpoint_config(&self, seed: &[u8; 32], alpn: &[u8]) -> ClientConfig {
        let (cert, key) = endpoint_identity(seed);
        endpoint_client_config(provider(), &[self.root.pem.as_str()], cert, key, alpn).unwrap()
    }
}

fn server_name() -> ServerName<'static> {
    expected_server_name(SERVER_NAME).unwrap()
}

/// A plain server, built here, that does not ask for a client certificate.
fn plain_server(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    version: &'static rustls::SupportedProtocolVersion,
    alpn: &[u8],
) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

/// Presents a fixed certificate chain with a fixed signing key, which need
/// not belong to the certificate, as rustls' own resolver insists.
#[derive(Debug)]
struct Presents {
    keys: Vec<Arc<CertifiedKey>>,
    next: AtomicUsize,
}

impl Presents {
    /// Presents `cert` signed with the key of `seeds[i]` on the `i`th
    /// connection.
    fn new(cert: &CertificateDer<'static>, seeds: &[[u8; 32]]) -> Arc<Self> {
        let keys = seeds
            .iter()
            .map(|seed| {
                let key = provider()
                    .key_provider
                    .load_private_key(endpoint_private_key(seed).unwrap().into())
                    .unwrap();
                Arc::new(CertifiedKey::new(vec![cert.clone()], key))
            })
            .collect();
        Arc::new(Self {
            keys,
            next: AtomicUsize::new(0),
        })
    }
}

impl ResolvesClientCert for Presents {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let i = self.next.fetch_add(1, Ordering::SeqCst);
        self.keys.get(i).cloned()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// In-memory handshakes
// ---------------------------------------------------------------------------

/// Moves TLS records between the two sides until neither has more to send.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), String> {
    loop {
        let mut moved = false;
        while client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            let mut rest = buf.as_slice();
            while !rest.is_empty() {
                server.read_tls(&mut rest).unwrap();
            }
            server
                .process_new_packets()
                .map_err(|e| format!("server: {e}"))?;
            moved = true;
        }
        while server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            let mut rest = buf.as_slice();
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
            }
            client
                .process_new_packets()
                .map_err(|e| format!("client: {e}"))?;
            moved = true;
        }
        if !moved {
            break;
        }
    }
    if client.is_handshaking() || server.is_handshaking() {
        return Err("the handshake stalled".to_owned());
    }
    Ok(())
}

fn connect(
    client: &Arc<ClientConfig>,
    name: ServerName<'static>,
    server: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection, Result<(), String>) {
    let mut client = ClientConnection::new(client.clone(), name).unwrap();
    let mut server = ServerConnection::new(server.clone()).unwrap();
    let result = handshake(&mut client, &mut server);
    (client, server, result)
}

fn try_connect(client: ClientConfig, server: ServerConfig) -> Result<ServerConnection, String> {
    let (_, server, result) = connect(&Arc::new(client), server_name(), &Arc::new(server));
    result.map(|()| server)
}

// ---------------------------------------------------------------------------
// ALPN
// ---------------------------------------------------------------------------

#[test]
fn alpn_constants() {
    assert_eq!(CONTROL_ALPN, b"senta-control/1");
    assert_eq!(TELEMETRY_ALPN, b"senta-telemetry/1");
}

#[test]
fn alpn_matches_only_the_ports_value() {
    for (port, other) in [
        (CONTROL_ALPN, TELEMETRY_ALPN),
        (TELEMETRY_ALPN, CONTROL_ALPN),
    ] {
        assert!(alpn_matches(Some(port), port));
        assert!(!alpn_matches(Some(other), port));
        assert!(!alpn_matches(None, port));
        assert!(!alpn_matches(Some(b""), port));
        assert!(!alpn_matches(Some(b"h2"), port));
        assert!(!alpn_matches(Some(b"senta-control/2"), port));
    }
}

#[test]
fn alpn_of_the_other_port_fails() {
    let ingress = ingress();
    let client = ingress.endpoint_config(&SEED, CONTROL_ALPN);
    let server = ingress.server_config(TELEMETRY_ALPN);
    match try_connect(client, server) {
        Err(_) => {}
        Ok(server) => assert!(!alpn_matches(server.alpn_protocol(), CONTROL_ALPN)),
    }
}

#[test]
fn alpn_absent_on_the_client_is_a_mismatch() {
    let ingress = ingress();
    let mut client = ingress.endpoint_config(&SEED, CONTROL_ALPN);
    client.alpn_protocols.clear();
    let server = try_connect(client, ingress.server_config(CONTROL_ALPN)).unwrap();
    assert_eq!(server.alpn_protocol(), None);
    assert!(!alpn_matches(server.alpn_protocol(), CONTROL_ALPN));
}

#[test]
fn alpn_negotiated_on_both_ports() {
    let ingress = ingress();
    for alpn in [CONTROL_ALPN, TELEMETRY_ALPN] {
        let client = Arc::new(ingress.endpoint_config(&SEED, alpn));
        let server = Arc::new(ingress.server_config(alpn));
        let (client, server, result) = connect(&client, server_name(), &server);
        result.unwrap();
        assert!(alpn_matches(server.alpn_protocol(), alpn));
        assert!(alpn_matches(client.alpn_protocol(), alpn));
    }
}

// ---------------------------------------------------------------------------
// The self-signed certificate
// ---------------------------------------------------------------------------

/// Splits one DER TLV off `input`: its tag, its contents, the whole TLV, and
/// what follows.
fn tlv(input: &[u8]) -> (u8, &[u8], &[u8], &[u8]) {
    let tag = input[0];
    let (len, header) = match input[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let count = usize::from(n & 0x7f);
            let len = input[2..2 + count]
                .iter()
                .fold(0, |acc, b| (acc << 8) | usize::from(*b));
            (len, 2 + count)
        }
    };
    (
        tag,
        &input[header..header + len],
        &input[..header + len],
        &input[header + len..],
    )
}

/// The tags of `notBefore` and `notAfter`.
fn validity_tags(der: &[u8]) -> (u8, u8) {
    let (_, cert, _, _) = tlv(der);
    let (_, tbs, _, _) = tlv(cert);
    // version, serialNumber, signature, issuer
    let mut rest = tbs;
    for _ in 0..4 {
        rest = tlv(rest).3;
    }
    let (_, validity, _, _) = tlv(rest);
    let (not_before, _, _, rest) = tlv(validity);
    let (not_after, _, _, _) = tlv(rest);
    (not_before, not_after)
}

fn validity(der: &[u8]) -> (i64, i64) {
    let (_, cert) = X509Certificate::from_der(der).unwrap();
    (
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    )
}

#[test]
fn certificate_parses_as_x509_v3() {
    let der = endpoint_certificate(&SEED, now()).unwrap();
    let (rest, cert) = X509Certificate::from_der(&der).unwrap();
    assert!(rest.is_empty());
    assert_eq!(cert.version(), X509Version::V3);
    assert!(cert.extensions().is_empty());
    // rustls-webpki, which rejects anything but v3, parses it too.
    webpki::EndEntityCert::try_from(&der).unwrap();
}

#[test]
fn certificate_is_deterministic() {
    let a = endpoint_certificate(&SEED, now()).unwrap();
    let b = endpoint_certificate(&SEED, now()).unwrap();
    assert_eq!(a.as_ref(), b.as_ref());
    let other_key = endpoint_certificate(&OTHER_SEED, now()).unwrap();
    assert_ne!(a.as_ref(), other_key.as_ref());
    let other_time = endpoint_certificate(&SEED, ts("2026-11-23T05:06:08Z")).unwrap();
    assert_ne!(a.as_ref(), other_time.as_ref());
}

#[test]
fn certificate_spki_is_the_keys_ed25519_public_key() {
    let der = endpoint_certificate(&SEED, now()).unwrap();
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    assert_eq!(cert.public_key().raw, hex(SPKI_DER).as_slice());
    assert_eq!(
        cert.public_key().algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert!(cert.public_key().algorithm.parameters.is_none());
    assert_eq!(cert.public_key().subject_public_key.data, &PUBLIC_KEY[..]);
}

#[test]
fn certificate_signature_verifies_with_its_own_key() {
    let der = endpoint_certificate(&SEED, now()).unwrap();
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert_eq!(
        cert.tbs_certificate.signature.algorithm.to_id_string(),
        "1.3.101.112"
    );
    let key: [u8; 32] = cert
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
    let signature: [u8; 64] = cert.signature_value.data.as_ref().try_into().unwrap();
    key.verify(
        cert.tbs_certificate.as_ref(),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .unwrap();
    assert_eq!(cert.issuer(), cert.subject());
}

#[test]
fn not_before_is_rounded_down_to_the_second() {
    let der = endpoint_certificate(&SEED, ts("2026-11-23T05:06:07.999999999Z")).unwrap();
    assert_eq!(validity(&der).0, ts("2026-11-23T05:06:07Z").as_second());

    let der = endpoint_certificate(&SEED, ts("2026-11-23T05:06:07.000000001Z")).unwrap();
    assert_eq!(validity(&der).0, ts("2026-11-23T05:06:07Z").as_second());

    // Before the epoch, rounding down moves away from zero.
    let der = endpoint_certificate(&SEED, ts("1969-12-31T23:59:59.5Z")).unwrap();
    assert_eq!(validity(&der).0, ts("1969-12-31T23:59:59Z").as_second());
}

#[test]
fn not_after_is_100_years_later_on_the_same_day_and_time() {
    for (now, not_before, not_after) in [
        (
            "2026-11-23T05:06:07.5Z",
            "2026-11-23T05:06:07Z",
            "2126-11-23T05:06:07Z",
        ),
        (
            "1950-01-01T00:00:00Z",
            "1950-01-01T00:00:00Z",
            "2050-01-01T00:00:00Z",
        ),
        (
            "2049-12-31T23:59:59Z",
            "2049-12-31T23:59:59Z",
            "2149-12-31T23:59:59Z",
        ),
        (
            "2023-03-01T00:00:00Z",
            "2023-03-01T00:00:00Z",
            "2123-03-01T00:00:00Z",
        ),
        // February 29 to a leap year stays February 29.
        (
            "1996-02-29T12:00:00Z",
            "1996-02-29T12:00:00Z",
            "2096-02-29T12:00:00Z",
        ),
        (
            "2024-02-29T12:34:56Z",
            "2024-02-29T12:34:56Z",
            "2124-02-29T12:34:56Z",
        ),
        (
            "2023-02-28T01:02:03Z",
            "2023-02-28T01:02:03Z",
            "2123-02-28T01:02:03Z",
        ),
        // February 29 to a common year (a century not divisible by 400)
        // becomes February 28.
        (
            "2000-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "2100-02-28T00:00:00Z",
        ),
        (
            "2400-02-29T23:59:59Z",
            "2400-02-29T23:59:59Z",
            "2500-02-28T23:59:59Z",
        ),
        (
            "2800-02-29T08:00:00Z",
            "2800-02-29T08:00:00Z",
            "2900-02-28T08:00:00Z",
        ),
        (
            "9899-12-30T21:59:59Z",
            "9899-12-30T21:59:59Z",
            "9999-12-30T21:59:59Z",
        ),
        // The latest notAfter there is.
        (
            "9899-12-31T23:59:59.999Z",
            "9899-12-31T23:59:59Z",
            "9999-12-31T23:59:59Z",
        ),
    ] {
        let der = endpoint_certificate(&SEED, ts(now)).unwrap();
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let (before, after) = (cert.validity().not_before, cert.validity().not_after);
        assert_eq!(before.timestamp(), ts(not_before).as_second(), "{now}");
        // `jiff` stops short of 9999-12-31, so compare the notAfter as text.
        let after = after.to_datetime();
        let after = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            after.year(),
            u8::from(after.month()),
            after.day(),
            after.hour(),
            after.minute(),
            after.second()
        );
        assert_eq!(after, not_after, "{now}");
    }
}

#[test]
fn validity_times_use_the_rfc_5280_encodings() {
    for (now, not_before, not_after) in [
        ("1950-01-01T00:00:00Z", TAG_UTC_TIME, TAG_GENERALIZED_TIME),
        ("1969-12-31T23:59:59Z", TAG_UTC_TIME, TAG_GENERALIZED_TIME),
        ("2026-11-23T05:06:07Z", TAG_UTC_TIME, TAG_GENERALIZED_TIME),
        ("2049-12-31T23:59:59Z", TAG_UTC_TIME, TAG_GENERALIZED_TIME),
        (
            "2050-01-01T00:00:00Z",
            TAG_GENERALIZED_TIME,
            TAG_GENERALIZED_TIME,
        ),
        (
            "9899-01-01T00:00:00Z",
            TAG_GENERALIZED_TIME,
            TAG_GENERALIZED_TIME,
        ),
    ] {
        let der = endpoint_certificate(&SEED, ts(now)).unwrap();
        assert_eq!(validity_tags(&der), (not_before, not_after), "{now}");
    }
    // 1949 + 100 lands in UTCTime's range only for notAfter, and 1949 itself
    // is rejected below, so a notAfter in UTCTime means a notBefore in 1950
    // or earlier: none is generated.
}

#[test]
fn validity_out_of_range_is_an_error() {
    for now in [
        "1949-12-31T23:59:59Z",
        "1949-12-31T23:59:59.999Z",
        "1900-06-01T00:00:00Z",
    ] {
        assert!(
            matches!(
                endpoint_certificate(&SEED, ts(now)),
                Err(CertificateGenerationError::NotBeforeTooEarly { .. })
            ),
            "{now}"
        );
    }
    for now in [
        "9900-01-01T00:00:00Z",
        "9950-06-15T00:00:00Z",
        "9999-12-30T00:00:00Z",
    ] {
        assert!(
            matches!(
                endpoint_certificate(&SEED, ts(now)),
                Err(CertificateGenerationError::NotAfterTooLate { .. })
            ),
            "{now}"
        );
    }
    assert!(matches!(
        endpoint_certificate(&SEED, Timestamp::MIN),
        Err(CertificateGenerationError::NotBeforeTooEarly { .. })
    ));
    assert!(matches!(
        endpoint_certificate(&SEED, Timestamp::MAX),
        Err(CertificateGenerationError::NotAfterTooLate { .. })
    ));
}

#[test]
fn private_key_is_the_seeds_pkcs8_and_redacted() {
    let key = endpoint_private_key(&SEED).unwrap();
    // The PKCS#8 holds the seed, and rustls loads it as an Ed25519 signer.
    assert!(
        key.secret_pkcs8_der()
            .windows(SEED.len())
            .any(|w| w == SEED)
    );
    let signer = provider()
        .key_provider
        .load_private_key(key.clone_key().into())
        .unwrap();
    assert_eq!(signer.algorithm(), rustls::SignatureAlgorithm::ED25519);
    let debug = format!("{key:?}");
    assert!(!debug.contains("9d61"), "{debug}");
    assert!(!debug.contains("157"), "{debug}");
    // The rustls signer and the seed sign alike.
    let message = b"senta";
    let signed = signer
        .choose_scheme(&[SignatureScheme::ED25519])
        .unwrap()
        .sign(message)
        .unwrap();
    assert_eq!(
        signed,
        SigningKey::from_bytes(&SEED).sign(message).to_bytes()
    );
}

// ---------------------------------------------------------------------------
// SPKI hashes
// ---------------------------------------------------------------------------

#[test]
fn spki_hashes_agree_with_an_independent_tool() {
    let der = endpoint_certificate(&SEED, now()).unwrap();
    assert_eq!(spki_hash_from_certificate(&der).unwrap(), SPKI_SHA256);
    assert_eq!(spki_hash_from_ed25519_public_key(&PUBLIC_KEY), SPKI_SHA256);
    assert_eq!(
        SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        PUBLIC_KEY
    );
}

#[test]
fn spki_hash_covers_any_key_algorithm() {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let hash = spki_hash_from_certificate(cert.der()).unwrap();
    let (_, parsed) = X509Certificate::from_der(cert.der()).unwrap();
    let expected: [u8; 32] = sha2::Sha256::digest(parsed.public_key().raw).into();
    assert_eq!(hash, expected);
}

#[test]
fn spki_hash_of_garbage_is_an_error() {
    for bytes in [
        &b""[..],
        b"not a certificate",
        &[0x30, 0x03, 0x02, 0x01, 0x01],
    ] {
        assert!(spki_hash_from_certificate(&CertificateDer::from(bytes.to_vec())).is_err());
    }
}

// ---------------------------------------------------------------------------
// The ingress: handshakes and the client verifier
// ---------------------------------------------------------------------------

#[test]
fn handshake_succeeds_and_yields_the_clients_spki_hash() {
    let ingress = ingress();
    let server = try_connect(
        ingress.endpoint_config(&SEED, CONTROL_ALPN),
        ingress.server_config(CONTROL_ALPN),
    )
    .unwrap();
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(peer_spki_hash(&server).unwrap(), SPKI_SHA256);
    assert_eq!(
        peer_spki_hash(&server).unwrap(),
        spki_hash_from_ed25519_public_key(&PUBLIC_KEY)
    );
}

#[test]
fn peer_identity_before_the_handshake_finishes_is_an_error() {
    let ingress = ingress();
    let server = ServerConnection::new(Arc::new(ingress.server_config(CONTROL_ALPN))).unwrap();
    assert!(matches!(
        peer_spki_hash(&server),
        Err(PeerIdentityError::Handshaking)
    ));

    // Midway: the server has the ClientHello but not the client's Finished.
    let mut client = ClientConnection::new(
        Arc::new(ingress.endpoint_config(&SEED, CONTROL_ALPN)),
        server_name(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(ingress.server_config(CONTROL_ALPN))).unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut buf.as_slice()).unwrap();
    server.process_new_packets().unwrap();
    assert!(server.is_handshaking());
    assert!(matches!(
        peer_spki_hash(&server),
        Err(PeerIdentityError::Handshaking)
    ));
}

#[test]
fn peer_identity_without_a_client_certificate_is_an_error() {
    let ingress = ingress();
    let server = plain_server(
        ingress.chain.clone(),
        ingress.key.clone_key(),
        &rustls::version::TLS13,
        CONTROL_ALPN,
    );
    let server = try_connect(ingress.endpoint_config(&SEED, CONTROL_ALPN), server).unwrap();
    assert!(matches!(
        peer_spki_hash(&server),
        Err(PeerIdentityError::NoPeerCertificate)
    ));
}

#[test]
fn peer_identity_of_a_resumed_connection_is_an_error() {
    let ingress = ingress();
    // A server built here that resumes, unlike the ingress configuration.
    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(EndpointClientVerifier::new(&provider()).unwrap()))
        .with_single_cert(ingress.chain.clone(), ingress.key.clone_key())
        .unwrap();
    let server = Arc::new(server);
    let client = Arc::new(ingress.endpoint_config(&SEED, CONTROL_ALPN));

    let (_, first, result) = connect(&client, server_name(), &server);
    result.unwrap();
    assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(peer_spki_hash(&first).unwrap(), SPKI_SHA256);

    let (_, second, result) = connect(&client, server_name(), &server);
    result.unwrap();
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
    assert!(matches!(
        peer_spki_hash(&second),
        Err(PeerIdentityError::Resumed)
    ));
}

#[test]
fn rsa_client_certificate_is_rejected() {
    let key = KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
    rejects_client_key(&key);
}

#[test]
fn ecdsa_p256_client_certificate_is_rejected() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    rejects_client_key(&key);
}

fn rejects_client_key(key: &KeyPair) {
    let cert = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(key)
        .unwrap();
    let cert = cert.der().clone();

    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    assert!(
        verifier
            .verify_client_cert(&cert, &[], UnixTime::now())
            .is_err()
    );

    let ingress = ingress();
    let client = ingress
        .client_builder()
        .with_client_auth_cert(vec![cert], pkcs8(key))
        .unwrap();
    assert!(try_connect(client, ingress.server_config(CONTROL_ALPN)).is_err());
}

#[test]
fn verifier_rejects_unparsable_and_non_ed25519_certificates() {
    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    for bytes in [&b""[..], b"garbage"] {
        let cert = CertificateDer::from(bytes.to_vec());
        assert!(
            verifier
                .verify_client_cert(&cert, &[], UnixTime::now())
                .is_err()
        );
    }
    // A certificate the issuer would have to verify: ignored, the key is
    // what counts.
    let root = root_ca("root");
    assert!(
        verifier
            .verify_client_cert(&root.cert, &[], UnixTime::now())
            .is_err()
    );
    let own = endpoint_certificate(&SEED, now()).unwrap();
    assert!(
        verifier
            .verify_client_cert(&own, &[], UnixTime::now())
            .is_ok()
    );
    // Intermediates and the time are not looked at.
    let far_future = UnixTime::since_unix_epoch(std::time::Duration::from_secs(u64::MAX / 4));
    assert!(
        verifier
            .verify_client_cert(&own, &[CertificateDer::from(b"junk".to_vec())], far_future)
            .is_ok()
    );
}

/// DER-encodes the TLV of `tag` and `contents`.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(contents.len()) {
        Ok(len) if len < 0x80 => out.push(len),
        _ => {
            let len: Vec<u8> = contents
                .len()
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | u8::try_from(len.len()).unwrap());
            out.extend(len);
        }
    }
    out.extend(contents);
    out
}

/// `cert` with its SubjectPublicKeyInfo replaced by `spki`. The signature no
/// longer matches, which the verifier does not look at.
fn with_spki(cert: &[u8], spki: &[u8]) -> CertificateDer<'static> {
    let (_, cert_contents, _, _) = tlv(cert);
    let (_, tbs, _, after_tbs) = tlv(cert_contents);
    // version, serialNumber, signature, issuer, validity, subject
    let mut new_tbs = Vec::new();
    let mut rest = tbs;
    for _ in 0..6 {
        let (_, _, whole, next) = tlv(rest);
        new_tbs.extend(whole);
        rest = next;
    }
    new_tbs.extend(spki);
    new_tbs.extend(tlv(rest).3);
    let mut contents = der(0x30, &new_tbs);
    contents.extend(after_tbs);
    CertificateDer::from(der(0x30, &contents))
}

/// An SPKI of `algorithm` (the AlgorithmIdentifier's contents) over `key`.
fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bit_string = vec![0];
    bit_string.extend(key);
    let mut contents = der(0x30, algorithm);
    contents.extend(der(0x03, &bit_string));
    der(0x30, &contents)
}

#[test]
fn verifier_accepts_exactly_the_ed25519_spki() {
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    const X25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x6e];
    const ED448_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];
    const NULL: &[u8] = &[0x05, 0x00];

    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    let own = endpoint_certificate(&SEED, now()).unwrap();

    let ed25519 = spki(ED25519_OID, &PUBLIC_KEY);
    assert_eq!(ed25519, hex(SPKI_DER));
    let rebuilt = with_spki(&own, &ed25519);
    assert_eq!(rebuilt.as_ref(), own.as_ref());

    let ed25519_with_null = [ED25519_OID, NULL].concat();
    for (case, spki) in [
        ("X25519, same length", spki(X25519_OID, &PUBLIC_KEY)),
        ("Ed448", spki(ED448_OID, &[0x11; 57])),
        ("NULL parameters", spki(&ed25519_with_null, &PUBLIC_KEY)),
        ("31-byte key", spki(ED25519_OID, &PUBLIC_KEY[..31])),
        (
            "33-byte key",
            spki(ED25519_OID, &[PUBLIC_KEY.as_slice(), &[0]].concat()),
        ),
    ] {
        let cert = with_spki(&own, &spki);
        // rustls-webpki parses it, so the rejection is the SPKI check's.
        webpki::EndEntityCert::try_from(&cert).unwrap_or_else(|e| panic!("{case}: {e}"));
        let error = verifier
            .verify_client_cert(&cert, &[], UnixTime::now())
            .unwrap_err();
        assert!(
            !matches!(
                error,
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            ),
            "{case}: {error}"
        );
        // The hash is computed whatever the key.
        let expected: [u8; 32] = sha2::Sha256::digest(&spki).into();
        assert_eq!(
            spki_hash_from_certificate(&cert).unwrap(),
            expected,
            "{case}"
        );
    }
}

#[test]
fn verifier_properties() {
    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    assert!(verifier.offer_client_auth());
    assert!(verifier.client_auth_mandatory());
    assert!(verifier.root_hint_subjects().is_empty());
    assert_eq!(
        verifier.supported_verify_schemes(),
        vec![SignatureScheme::ED25519]
    );
    assert!(!verifier.requires_raw_public_keys());
}

/// Builds a `DigitallySignedStruct` by decoding its wire form, through
/// rustls' unstable `internal` codec: rustls offers no public constructor,
/// and the verifier's signature methods take nothing else.
fn dss(scheme: SignatureScheme, signature: &[u8]) -> DigitallySignedStruct {
    let mut bytes = u16::from(scheme).to_be_bytes().to_vec();
    bytes.extend(u16::try_from(signature.len()).unwrap().to_be_bytes());
    bytes.extend(signature);
    DigitallySignedStruct::read_bytes(&bytes).unwrap()
}

#[test]
fn verify_tls12_signature_is_always_an_error() {
    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    let cert = endpoint_certificate(&SEED, now()).unwrap();
    let message = b"message";
    let signature = SigningKey::from_bytes(&SEED).sign(message).to_bytes();
    for scheme in [
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ] {
        assert!(
            verifier
                .verify_tls12_signature(message, &cert, &dss(scheme, &signature))
                .is_err()
        );
    }
}

#[test]
fn verify_tls13_signature_checks_ed25519_against_the_certificate() {
    let verifier = EndpointClientVerifier::new(&provider()).unwrap();
    let cert = endpoint_certificate(&SEED, now()).unwrap();
    let message = b"message";
    let good = SigningKey::from_bytes(&SEED).sign(message).to_bytes();
    let other = SigningKey::from_bytes(&OTHER_SEED).sign(message).to_bytes();
    assert!(
        verifier
            .verify_tls13_signature(message, &cert, &dss(SignatureScheme::ED25519, &good))
            .is_ok()
    );
    assert!(
        verifier
            .verify_tls13_signature(
                b"other message",
                &cert,
                &dss(SignatureScheme::ED25519, &good)
            )
            .is_err()
    );
    assert!(
        verifier
            .verify_tls13_signature(message, &cert, &dss(SignatureScheme::ED25519, &other))
            .is_err()
    );
    assert!(
        verifier
            .verify_tls13_signature(
                message,
                &cert,
                &dss(SignatureScheme::ECDSA_NISTP256_SHA256, &good)
            )
            .is_err()
    );
}

/// The aws-lc-rs provider with the Ed25519 mapping removed, or pointed at
/// `replacement`'s algorithms.
fn provider_without_ed25519(replacement: Option<SignatureScheme>) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let replacement = replacement.map(|scheme| {
        algorithms
            .mapping
            .iter()
            .find(|(s, _)| *s == scheme)
            .unwrap()
            .1
    });
    let mapping: Vec<_> = algorithms
        .mapping
        .iter()
        .filter_map(|&(scheme, algs)| match (scheme, replacement) {
            (SignatureScheme::ED25519, None) => None,
            (SignatureScheme::ED25519, Some(replacement)) => Some((scheme, replacement)),
            _ => Some((scheme, algs)),
        })
        .collect();
    let all: Vec<_> = algorithms
        .all
        .iter()
        .copied()
        .filter(|alg| alg.public_key_alg_id() != alg_id::ED25519)
        .collect();
    provider.signature_verification_algorithms = WebPkiSupportedAlgorithms {
        all: Box::leak(all.into_boxed_slice()),
        mapping: Box::leak(mapping.into_boxed_slice()),
    };
    provider
}

#[test]
fn verifier_without_ed25519_is_an_error() {
    for replacement in [None, Some(SignatureScheme::ECDSA_NISTP256_SHA256)] {
        let provider = provider_without_ed25519(replacement);
        assert!(matches!(
            EndpointClientVerifier::new(&provider),
            Err(ClientVerifierError::NoEd25519)
        ));
        let ingress = ingress();
        assert!(matches!(
            ingress_server_config(
                Arc::new(provider),
                ingress.chain.clone(),
                ingress.key.clone_key(),
                CONTROL_ALPN
            ),
            Err(ServerConfigError::Verifier(ClientVerifierError::NoEd25519))
        ));
    }
}

#[test]
fn client_without_a_certificate_is_rejected() {
    let ingress = ingress();
    let client = ingress.client_builder().with_no_client_auth();
    assert!(try_connect(client, ingress.server_config(CONTROL_ALPN)).is_err());
}

#[test]
fn client_signing_with_a_key_not_its_certificates_is_rejected() {
    let ingress = ingress();
    // Someone else's genuine Ed25519 certificate, signed for with our key.
    let theirs = endpoint_certificate(&OTHER_SEED, now()).unwrap();
    let client = ingress
        .client_builder()
        .with_client_cert_resolver(Presents::new(&theirs, &[SEED]));
    let error = try_connect(client, ingress.server_config(CONTROL_ALPN)).unwrap_err();
    assert!(error.starts_with("server:"), "{error}");
}

#[test]
fn tls12_only_client_is_rejected() {
    let ingress = ingress();
    let (cert, key) = endpoint_identity(&SEED);
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(ingress.roots())
        .with_client_auth_cert(vec![cert], key)
        .unwrap();
    assert!(try_connect(client, ingress.server_config(CONTROL_ALPN)).is_err());
}

/// An Ed25519 client certificate made here with `params` and signed by
/// `issuer`, or self-signed.
fn ed25519_client(
    params: &CertificateParams,
    issuer: Option<&Ca>,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>, [u8; 32]) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = match issuer {
        Some(issuer) => params.signed_by(&key, &issuer.issuer).unwrap(),
        None => params.self_signed(&key).unwrap(),
    };
    let public_key: [u8; 32] = rcgen::PublicKeyData::der_bytes(&key).try_into().unwrap();
    (cert.der().clone(), pkcs8(&key), public_key)
}

#[test]
fn unchecked_fields_do_not_matter() {
    let ingress = ingress();
    let other_ca = root_ca("someone else");

    let mut other_subject = CertificateParams::new(Vec::<String>::new()).unwrap();
    other_subject.distinguished_name = name("not an endpoint at all");

    let mut expired = CertificateParams::new(Vec::<String>::new()).unwrap();
    expired.not_before = rcgen::date_time_ymd(1990, 1, 1);
    expired.not_after = rcgen::date_time_ymd(2000, 1, 1);

    let issued = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();

    for (case, params, issuer) in [
        ("other subject", &other_subject, None),
        ("expired", &expired, None),
        ("signed by another key", &issued, Some(&other_ca)),
    ] {
        let (cert, key, public_key) = ed25519_client(params, issuer);
        let client = ingress
            .client_builder()
            .with_client_auth_cert(vec![cert], key)
            .unwrap();
        let server = try_connect(client, ingress.server_config(CONTROL_ALPN))
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(
            peer_spki_hash(&server).unwrap(),
            spki_hash_from_ed25519_public_key(&public_key),
            "{case}"
        );
    }
}

#[test]
fn ingress_never_resumes_and_verifies_every_certificate_verify() {
    let ingress = ingress();
    let server = Arc::new(ingress.server_config(CONTROL_ALPN));
    assert_eq!(server.send_tls13_tickets, 0);
    assert!(!server.session_storage.can_cache());
    assert!(!server.ticketer.enabled());

    // A client with resumption on, which the crate's configuration has.
    let client = Arc::new(ingress.endpoint_config(&SEED, CONTROL_ALPN));
    for _ in 0..2 {
        let (client_conn, server_conn, result) = connect(&client, server_name(), &server);
        result.unwrap();
        assert_eq!(server_conn.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(client_conn.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(peer_spki_hash(&server_conn).unwrap(), SPKI_SHA256);
    }

    // The second connection signs its CertificateVerify with the wrong key:
    // had it been resumed, nothing would have been signed or checked.
    let cert = endpoint_certificate(&SEED, now()).unwrap();
    let client = Arc::new(
        ingress
            .client_builder()
            .with_client_cert_resolver(Presents::new(&cert, &[SEED, OTHER_SEED])),
    );
    let (_, first, result) = connect(&client, server_name(), &server);
    result.unwrap();
    assert_eq!(peer_spki_hash(&first).unwrap(), SPKI_SHA256);
    let (_, _, result) = connect(&client, server_name(), &server);
    let error = result.unwrap_err();
    assert!(error.starts_with("server:"), "{error}");
}

#[test]
fn ingress_takes_no_early_data() {
    let ingress = ingress();
    let server = Arc::new(ingress.server_config(CONTROL_ALPN));
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.send_half_rtt_data);

    let mut client = ingress.endpoint_config(&SEED, CONTROL_ALPN);
    client.enable_early_data = true;
    let client = Arc::new(client);
    for _ in 0..2 {
        let mut client_conn = ClientConnection::new(client.clone(), server_name()).unwrap();
        assert!(client_conn.early_data().is_none());
        let mut server_conn = ServerConnection::new(server.clone()).unwrap();
        handshake(&mut client_conn, &mut server_conn).unwrap();
        assert!(!client_conn.is_early_data_accepted());
        assert!(server_conn.early_data().is_none());
    }
}

// ---------------------------------------------------------------------------
// The endpoint: server verification
// ---------------------------------------------------------------------------

#[test]
fn endpoint_accepts_a_server_issued_by_a_root() {
    let ingress = ingress();
    let server = try_connect(
        ingress.endpoint_config(&SEED, CONTROL_ALPN),
        plain_server(
            ingress.chain.clone(),
            ingress.key.clone_key(),
            &rustls::version::TLS13,
            CONTROL_ALPN,
        ),
    );
    server.unwrap();
}

#[test]
fn endpoint_rejects_a_tls12_only_server() {
    let ingress = ingress();
    let server = plain_server(
        ingress.chain.clone(),
        ingress.key.clone_key(),
        &rustls::version::TLS12,
        CONTROL_ALPN,
    );
    assert!(try_connect(ingress.endpoint_config(&SEED, CONTROL_ALPN), server).is_err());
}

#[test]
fn endpoint_accepts_a_chain_through_an_intermediate() {
    let root = root_ca("root");
    let intermediate = intermediate_ca(&root, "intermediate");
    let (leaf, key) = server_leaf(&intermediate, &[SERVER_NAME]);
    let (cert, client_key) = endpoint_identity(&SEED);
    let client = endpoint_client_config(
        provider(),
        &[root.pem.as_str()],
        cert,
        client_key,
        CONTROL_ALPN,
    )
    .unwrap();
    let chain = vec![leaf, intermediate.cert.clone()];
    try_connect(
        client.clone(),
        ingress_server_config(provider(), chain, key.clone_key(), CONTROL_ALPN).unwrap(),
    )
    .unwrap();

    // Without the intermediate, the chain does not reach the root.
    let (leaf, key) = server_leaf(&intermediate, &[SERVER_NAME]);
    assert!(
        try_connect(
            client,
            ingress_server_config(provider(), vec![leaf], key, CONTROL_ALPN).unwrap(),
        )
        .is_err()
    );
}

fn connects_with_roots(roots: &[&str], server_issuer: &Ca) -> Result<ServerConnection, String> {
    let (leaf, key) = server_leaf(server_issuer, &[SERVER_NAME]);
    let (cert, client_key) = endpoint_identity(&SEED);
    let client = endpoint_client_config(provider(), roots, cert, client_key, CONTROL_ALPN).unwrap();
    try_connect(
        client,
        ingress_server_config(provider(), vec![leaf], key, CONTROL_ALPN).unwrap(),
    )
}

#[test]
fn endpoint_accepts_servers_under_any_listed_root() {
    let old = root_ca("old root");
    let new = root_ca("new root");
    let both_in_one = format!("{}{}", old.pem, new.pem);
    for roots in [
        vec![old.pem.as_str(), new.pem.as_str()],
        vec![both_in_one.as_str()],
    ] {
        connects_with_roots(&roots, &old).unwrap();
        connects_with_roots(&roots, &new).unwrap();
    }
}

#[test]
fn endpoint_rejects_a_server_under_an_unlisted_root() {
    let listed = root_ca("listed");
    let unlisted = root_ca("unlisted");
    assert!(connects_with_roots(&[listed.pem.as_str()], &unlisted).is_err());
}

#[test]
fn endpoint_rejects_a_server_whose_san_is_another_name() {
    let root = root_ca("root");
    let (leaf, key) = server_leaf(&root, &["other.example"]);
    let (cert, client_key) = endpoint_identity(&SEED);
    let client = endpoint_client_config(
        provider(),
        &[root.pem.as_str()],
        cert,
        client_key,
        CONTROL_ALPN,
    )
    .unwrap();
    let server = ingress_server_config(provider(), vec![leaf], key, CONTROL_ALPN).unwrap();
    let error = try_connect(client, server).unwrap_err();
    assert!(error.starts_with("client:"), "{error}");
}

#[test]
fn endpoint_matches_a_dns_only_san_by_name_not_by_ip() {
    let ingress = ingress();
    let client = Arc::new(ingress.endpoint_config(&SEED, CONTROL_ALPN));
    let server = Arc::new(ingress.server_config(CONTROL_ALPN));

    let (_, _, result) = connect(&client, server_name(), &server);
    result.unwrap();

    // The address the endpoint dialled, given as the name, does not match.
    let ip = ServerName::try_from("127.0.0.1").unwrap();
    let (_, _, result) = connect(&client, ip, &server);
    let error = result.unwrap_err();
    assert!(error.starts_with("client:"), "{error}");
    assert!(matches!(
        expected_server_name("127.0.0.1"),
        Err(ExpectedNameError::IpAddress)
    ));
}

// ---------------------------------------------------------------------------
// Trust root PEM lists
// ---------------------------------------------------------------------------

fn roots_result(roots: &[&str]) -> Result<ClientConfig, ClientConfigError> {
    let (cert, key) = endpoint_identity(&SEED);
    endpoint_client_config(provider(), roots, cert, key, CONTROL_ALPN)
}

/// The PEM of a good certificate relabelled `label`: well-formed, with a
/// body that is valid base64.
fn relabel(pem: &str, label: &str) -> String {
    pem.replace("CERTIFICATE", label)
}

/// A `CERTIFICATE` block holding `30 03 02 01 01`, which parses as DER but is
/// no certificate.
const UNUSABLE_CERTIFICATE: &str =
    "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";

#[test]
fn empty_root_list_is_an_error() {
    assert!(matches!(
        roots_result(&[]),
        Err(ClientConfigError::NoTrustRoots)
    ));
}

#[test]
fn bad_root_elements_are_errors_even_beside_good_ones() {
    let good = root_ca("good");
    let body: String = good
        .pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    let no_end = format!("-----BEGIN CERTIFICATE-----\n{body}\n");
    let bad_base64 =
        "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n".to_owned();
    let mismatched_end = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END FOO-----\n");
    let stray_end = format!("{}-----END CERTIFICATE-----\n", good.pem);
    let nested = format!("-----BEGIN CERTIFICATE-----\n{}", good.pem);
    let no_certificate = "just some text\nand no PEM at all\n".to_owned();
    let private_key = relabel(&good.pem, "PRIVATE KEY");
    let unknown = relabel(&good.pem, "FOO");
    let unusable = UNUSABLE_CERTIFICATE.to_owned();

    type Check = fn(&ClientConfigError) -> bool;
    let malformed: Check = |e| matches!(e, ClientConfigError::MalformedPem { .. });
    let empty: Check = |e| matches!(e, ClientConfigError::NoCertificate { .. });
    let not_cert: Check = |e| matches!(e, ClientConfigError::NotCertificate { .. });
    let unusable_root: Check = |e| matches!(e, ClientConfigError::UnusableRoot { .. });

    let cases: [(&str, &str, Check); 9] = [
        ("missing END", &no_end, malformed),
        ("bad base64", &bad_base64, malformed),
        ("mismatched END", &mismatched_end, malformed),
        ("stray END", &stray_end, malformed),
        ("nested BEGIN", &nested, malformed),
        ("no certificate", &no_certificate, empty),
        ("private key block", &private_key, not_cert),
        ("unknown block", &unknown, not_cert),
        ("unusable certificate", &unusable, unusable_root),
    ];
    for (case, bad, check) in cases {
        let alone = roots_result(&[bad]).unwrap_err();
        assert!(check(&alone), "{case}: {alone:?}");
        for list in [[good.pem.as_str(), bad], [bad, good.pem.as_str()]] {
            let error = roots_result(&list).unwrap_err();
            assert!(check(&error), "{case}: {error:?}");
        }
        // In the same element as a good block, before or after it. Text
        // with no block beside a good block is only explanatory text.
        if case == "no certificate" {
            continue;
        }
        for combined in [format!("{}{bad}", good.pem), format!("{bad}\n{}", good.pem)] {
            let error = roots_result(&[combined.as_str()]).unwrap_err();
            assert!(
                check(&error) || malformed(&error),
                "{case} combined: {error:?}"
            );
        }
    }

    let label = match roots_result(&[unknown.as_str()]).unwrap_err() {
        ClientConfigError::NotCertificate { index, label } => (index, label),
        other => panic!("{other:?}"),
    };
    assert_eq!(label, (0, "FOO".to_owned()));
    match roots_result(&[good.pem.as_str(), unusable.as_str()]).unwrap_err() {
        ClientConfigError::UnusableRoot { index, .. } => assert_eq!(index, 1),
        other => panic!("{other:?}"),
    }
}

#[test]
fn explanatory_text_around_blocks_is_ignored() {
    let root = root_ca("root");
    let other = root_ca("other");
    let annotated = format!(
        "Subject: CN=root\nIssuer: CN=root\n\n{}\n  some notes between blocks  \n\n{}\ntrailing words\n",
        root.pem.trim_end(),
        other.pem
    );
    roots_result(&[annotated.as_str()]).unwrap();
    connects_with_roots(&[annotated.as_str()], &root).unwrap();
    connects_with_roots(&[annotated.as_str()], &other).unwrap();

    // CRLF line endings and surrounding whitespace on lines are fine too.
    let crlf = root.pem.replace('\n', "\r\n");
    connects_with_roots(&[crlf.as_str()], &root).unwrap();

    // So are CR-only line endings, and mixed ones.
    let cr = root.pem.replace('\n', "\r");
    connects_with_roots(&[cr.as_str()], &root).unwrap();
    let mixed = format!("notes\r{}\r\n{}", cr, other.pem.replace('\n', "\r\n"));
    connects_with_roots(&[mixed.as_str()], &root).unwrap();
    connects_with_roots(&[mixed.as_str()], &other).unwrap();
}

#[test]
fn cr_separated_bad_blocks_are_errors() {
    let good = root_ca("good");
    let good_cr = good.pem.replace('\n', "\r");
    let body: String = good
        .pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\r");

    // A block after a good one, set off only by CRs, is still a block.
    let unknown = format!(
        "{}notes\r-----BEGIN FOO-----\rAQ==\r-----END FOO-----\r",
        good.pem
    );
    assert!(matches!(
        roots_result(&[unknown.as_str()]),
        Err(ClientConfigError::NotCertificate { label, .. }) if label == "FOO"
    ));
    let unknown_cr = format!("{good_cr}notes\r-----BEGIN FOO-----\rAQ==\r-----END FOO-----\r");
    assert!(matches!(
        roots_result(&[unknown_cr.as_str()]),
        Err(ClientConfigError::NotCertificate { label, .. }) if label == "FOO"
    ));

    let no_end = format!("{good_cr}-----BEGIN CERTIFICATE-----\r{body}\r");
    let bad_base64 = format!(
        "{good_cr}-----BEGIN CERTIFICATE-----\r!!!not base64!!!\r-----END CERTIFICATE-----\r"
    );
    let mismatched_end =
        format!("{good_cr}-----BEGIN CERTIFICATE-----\r{body}\r-----END FOO-----\r");
    for (case, bad) in [
        ("missing END", no_end),
        ("bad base64", bad_base64),
        ("mismatched END", mismatched_end),
    ] {
        assert!(
            matches!(
                roots_result(&[bad.as_str()]),
                Err(ClientConfigError::MalformedPem { index: 0 })
            ),
            "{case}"
        );
    }

    let unusable = format!("{good_cr}{}", UNUSABLE_CERTIFICATE.replace('\n', "\r"));
    assert!(matches!(
        roots_result(&[unusable.as_str()]),
        Err(ClientConfigError::UnusableRoot { index: 0, .. })
    ));
}

// ---------------------------------------------------------------------------
// The expected name
// ---------------------------------------------------------------------------

#[test]
fn expected_name_is_a_dns_name() {
    assert_eq!(
        expected_server_name("ingress.example").unwrap(),
        ServerName::try_from("ingress.example").unwrap()
    );
    assert!(matches!(
        expected_server_name("ingress.example").unwrap(),
        ServerName::DnsName(_)
    ));
    for ip in ["127.0.0.1", "10.0.0.255", "::1", "fe80::1", "2001:db8::1"] {
        assert!(
            matches!(expected_server_name(ip), Err(ExpectedNameError::IpAddress)),
            "{ip}"
        );
    }
    for bad in [
        "",
        "bad name",
        "ingress..example",
        "-.example",
        "a/b",
        "[::1]",
        "1.2.3.4.5",
    ] {
        assert!(
            matches!(
                expected_server_name(bad),
                Err(ExpectedNameError::InvalidDnsName)
            ),
            "{bad}"
        );
    }
}
