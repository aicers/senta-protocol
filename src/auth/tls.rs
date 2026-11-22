//! TLS helpers for the endpoint ports of REview and the event store.
//!
//! An endpoint has no certificate authority. Its identity is an Ed25519 key
//! it made itself, presented as a self-signed certificate
//! ([`endpoint_certificate`], [`endpoint_private_key`]), and the
//! CertificateVerify of each connection proves it holds that key. The
//! ingress takes the SHA-256 of the certificate's SubjectPublicKeyInfo after
//! the handshake ([`peer_spki_hash`]) and looks it up in its active list;
//! that lookup is not done here.
//!
//! The ingress side is built with [`ingress_server_config`], whose client
//! verifier is [`EndpointClientVerifier`]. The endpoint side is built with
//! [`endpoint_client_config`], which checks the server against the trust
//! roots of the signed address document with rustls' own
//! `WebPkiServerVerifier`, under the name [`expected_server_name`] returns.
//! After either handshake, [`alpn_matches`] decides whether the negotiated
//! protocol is the one the port expects.
//!
//! Every helper takes the [`CryptoProvider`] from the caller; none reads or
//! installs the process default.
//!
//! This module is the crate's certificate verification module: all
//! certificate verification in the crate lives here.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    SignatureVerificationAlgorithm, UnixTime, alg_id,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ServerConnection};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, HandshakeKind,
    OtherError, RootCertStore, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// The ALPN protocol of REview's endpoint port, which carries the control
/// connection.
pub const CONTROL_ALPN: &[u8] = b"senta-control/1";

/// The ALPN protocol of the event store's endpoint port, which carries the
/// telemetry connection.
pub const TELEMETRY_ALPN: &[u8] = b"senta-telemetry/1";

/// The DER of an Ed25519 SubjectPublicKeyInfo up to the public key:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }`,
/// with no algorithm parameters (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The length of an Ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The length of an Ed25519 SubjectPublicKeyInfo DER.
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN;

/// How many years after `notBefore` the self-signed certificate's `notAfter`
/// lies.
const VALIDITY_YEARS: i16 = 100;

/// The earliest `notBefore` the self-signed certificate accepts: before it,
/// RFC 5280 gives the time no encoding.
const MIN_VALIDITY_YEAR: i16 = 1950;

/// The latest year a `notAfter` may fall in: GeneralizedTime has four year
/// digits.
const MAX_VALIDITY_YEAR: i16 = 9999;

/// The subject and issuer common name of the self-signed certificate.
const ENDPOINT_COMMON_NAME: &str = "senta endpoint";

/// The length of the self-signed certificate's serial number, in bytes.
const SERIAL_LEN: usize = 16;

/// The PEM label of a certificate.
const PEM_CERTIFICATE_LABEL: &str = "CERTIFICATE";
/// What a line looking like a PEM boundary starts with, once trimmed.
const PEM_BEGIN_MARK: &str = "-----BEGIN";
const PEM_END_MARK: &str = "-----END";
/// What a well-formed boundary line starts with before its label.
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
/// What a well-formed boundary line ends with after its label.
const PEM_DASHES: &str = "-----";

/// Returns whether the negotiated ALPN protocol is the one the port expects.
///
/// `negotiated` is the value of `alpn_protocol()` on the connection, which is
/// `None` when no protocol was negotiated; `expected` is the port's constant,
/// [`CONTROL_ALPN`] or [`TELEMETRY_ALPN`]. Anything but an exact match,
/// including `None`, is a mismatch, and the caller closes the connection.
#[must_use]
pub fn alpn_matches(negotiated: Option<&[u8]>, expected: &[u8]) -> bool {
    negotiated == Some(expected)
}

/// An error generating the endpoint's self-signed certificate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CertificateGenerationError {
    /// `notBefore` would fall before 1950-01-01T00:00:00Z.
    #[error("notBefore {year} is before {MIN_VALIDITY_YEAR}")]
    NotBeforeTooEarly {
        /// The UTC year of `notBefore`.
        year: i16,
    },
    /// `notAfter` would fall after 9999-12-31T23:59:59Z.
    #[error("notAfter {year} is after {MAX_VALIDITY_YEAR}")]
    NotAfterTooLate {
        /// The UTC year `notAfter` would fall in.
        year: i16,
    },
    /// The certificate could not be encoded.
    #[error("encoding the self-signed certificate")]
    Encoding(#[source] rcgen::Error),
}

/// An error encoding the endpoint's private key as PKCS#8.
#[derive(Debug, thiserror::Error)]
#[error("encoding the Ed25519 private key as PKCS#8")]
pub struct PrivateKeyEncodingError(#[source] ed25519_dalek::pkcs8::Error);

/// Returns the DER of an X.509 v3 certificate for the Ed25519 key `seed`,
/// self-signed with that key.
///
/// `notBefore` is `now` rounded down to the second, in UTC; `notAfter` is the
/// same month, day and time of day 100 years later in the UTC calendar, or
/// February 28 when `notBefore` is February 29 and that year is not a leap
/// year. Validity times in 1950 through 2049 are encoded as UTCTime and later
/// ones as GeneralizedTime, as RFC 5280 requires.
///
/// The subject and issuer are both `CN=senta endpoint`, the serial number is
/// derived from the public key and `notBefore`, and the certificate carries
/// no extensions. Nothing is random: the same key and time give the same
/// bytes.
///
/// # Errors
///
/// Returns [`CertificateGenerationError::NotBeforeTooEarly`] if `notBefore`
/// would be before 1950-01-01T00:00:00Z,
/// [`CertificateGenerationError::NotAfterTooLate`] if `notAfter` would be
/// after 9999-12-31T23:59:59Z, and
/// [`CertificateGenerationError::Encoding`] if the certificate could not be
/// encoded.
pub fn endpoint_certificate(
    seed: &[u8; 32],
    now: Timestamp,
) -> Result<CertificateDer<'static>, CertificateGenerationError> {
    let year = TimeZone::UTC.to_datetime(now).year();
    if year < MIN_VALIDITY_YEAR {
        return Err(CertificateGenerationError::NotBeforeTooEarly { year });
    }
    let after_year = year + VALIDITY_YEARS;
    if after_year > MAX_VALIDITY_YEAR {
        return Err(CertificateGenerationError::NotAfterTooLate { year: after_year });
    }

    // `as_second` truncates toward zero and a time before the epoch carries a
    // negative fraction, so stepping back one second there rounds down.
    let second = now.as_second() - i64::from(now.subsec_nanosecond() < 0);
    // Both conversions are within range by the checks above: `time` covers
    // years up to 9999, and February 29 is moved to the 28th before the year
    // changes.
    let not_before = time::OffsetDateTime::from_unix_timestamp(second)
        .map_err(|_| CertificateGenerationError::NotBeforeTooEarly { year })?;
    let not_after = if not_before.month() == time::Month::February
        && not_before.day() == 29
        && !time::util::is_leap_year(i32::from(after_year))
    {
        not_before.replace_day(28)
    } else {
        Ok(not_before)
    }
    .and_then(|date_time| date_time.replace_year(i32::from(after_year)))
    .map_err(|_| CertificateGenerationError::NotAfterTooLate { year: after_year })?;

    let key = Ed25519Signer::new(seed);
    let spki = ed25519_spki(&key.public_key);

    let mut params = rcgen::CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(serial_number(&spki, second));
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, ENDPOINT_COMMON_NAME);
    params.distinguished_name = name;

    let certificate = params
        .self_signed(&key)
        .map_err(CertificateGenerationError::Encoding)?;
    Ok(certificate.der().clone())
}

/// Returns the Ed25519 key `seed` as the PKCS#8 DER rustls loads a private
/// key from.
///
/// # Errors
///
/// Returns [`PrivateKeyEncodingError`] if the key could not be encoded.
pub fn endpoint_private_key(
    seed: &[u8; 32],
) -> Result<PrivatePkcs8KeyDer<'static>, PrivateKeyEncodingError> {
    let document = SigningKey::from_bytes(seed)
        .to_pkcs8_der()
        .map_err(PrivateKeyEncodingError)?;
    Ok(PrivatePkcs8KeyDer::from(document.as_bytes().to_vec()))
}

/// An Ed25519 key that signs the certificate rcgen encodes.
struct Ed25519Signer {
    key: SigningKey,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519Signer {
    fn new(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let public_key = key.verifying_key().to_bytes();
        Self { key, public_key }
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Signer(<redacted>)")
    }
}

impl rcgen::PublicKeyData for Ed25519Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.key.sign(msg).to_bytes().to_vec())
    }
}

/// Derives a positive, minimally encoded 16-byte serial number from the
/// certificate's inputs.
fn serial_number(spki: &[u8; ED25519_SPKI_LEN], not_before: i64) -> rcgen::SerialNumber {
    let digest = Sha256::new()
        .chain_update(spki)
        .chain_update(not_before.to_be_bytes())
        .finalize();
    let mut serial = [0_u8; SERIAL_LEN];
    serial.copy_from_slice(&digest[..SERIAL_LEN]);
    // Clear the sign bit so the INTEGER is positive, and set the next one so
    // it needs no leading zero octet.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    rcgen::SerialNumber::from_slice(&serial)
}

/// An error computing an SPKI hash from a certificate.
#[derive(Debug, thiserror::Error)]
#[error("parsing the certificate")]
pub struct SpkiHashError(#[source] webpki::Error);

/// Returns the SHA-256 of the SubjectPublicKeyInfo DER, tag and length
/// included, of the X.509 certificate `cert`.
///
/// The certificate is parsed with rustls-webpki's `EndEntityCert`, the parse
/// rustls verifies the CertificateVerify signature with, so the SPKI hashed
/// is the one whose key that signature was checked against. The hash is
/// computed for any key algorithm; it is a computation, not an identity
/// decision.
///
/// # Errors
///
/// Returns [`SpkiHashError`] if `cert` is not a certificate rustls-webpki
/// parses.
pub fn spki_hash_from_certificate(cert: &CertificateDer<'_>) -> Result<[u8; 32], SpkiHashError> {
    let parsed = webpki::EndEntityCert::try_from(cert).map_err(SpkiHashError)?;
    Ok(sha256(parsed.subject_public_key_info().as_ref()))
}

/// Returns the SHA-256 of the SubjectPublicKeyInfo DER of the Ed25519 public
/// key `public_key`.
#[must_use]
pub fn spki_hash_from_ed25519_public_key(public_key: &[u8; 32]) -> [u8; 32] {
    sha256(&ed25519_spki(public_key))
}

fn ed25519_spki(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> [u8; ED25519_SPKI_LEN] {
    let mut spki = [0_u8; ED25519_SPKI_LEN];
    let (prefix, key) = spki.split_at_mut(ED25519_SPKI_PREFIX.len());
    prefix.copy_from_slice(&ED25519_SPKI_PREFIX);
    key.copy_from_slice(public_key);
    spki
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// An error taking the endpoint identity out of a connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerIdentityError {
    /// The handshake has not finished.
    #[error("the handshake has not finished")]
    Handshaking,
    /// The connection was resumed, so no CertificateVerify proved the key on
    /// it.
    #[error("the connection was resumed")]
    Resumed,
    /// The peer presented no certificate.
    #[error("the peer presented no certificate")]
    NoPeerCertificate,
    /// The peer's certificate does not parse.
    #[error("hashing the peer certificate's SPKI")]
    Spki(#[source] SpkiHashError),
}

/// Returns the SPKI hash of the first certificate the client presented on
/// `conn`.
///
/// The hash is the endpoint's identity only when `conn` was made from a
/// configuration [`ingress_server_config`] returned: then the connection's
/// Ed25519 CertificateVerify was verified against that certificate's key in
/// a full handshake. On a connection made any other way it is just a hash.
///
/// # Errors
///
/// Returns [`PeerIdentityError::Handshaking`] if the handshake has not
/// finished, [`PeerIdentityError::Resumed`] if the connection was resumed,
/// [`PeerIdentityError::NoPeerCertificate`] if the client presented no
/// certificate, and [`PeerIdentityError::Spki`] if its certificate does not
/// parse.
pub fn peer_spki_hash(conn: &ServerConnection) -> Result<[u8; 32], PeerIdentityError> {
    if conn.is_handshaking() {
        return Err(PeerIdentityError::Handshaking);
    }
    match conn.handshake_kind() {
        Some(HandshakeKind::Resumed) => return Err(PeerIdentityError::Resumed),
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest) => {}
        None => return Err(PeerIdentityError::Handshaking),
    }
    let cert = conn
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .ok_or(PeerIdentityError::NoPeerCertificate)?;
    spki_hash_from_certificate(cert).map_err(PeerIdentityError::Spki)
}

/// An error building an [`EndpointClientVerifier`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientVerifierError {
    /// The provider maps no algorithm to the Ed25519 signature scheme, or
    /// maps one that is not Ed25519.
    #[error("the crypto provider has no Ed25519 signature verification")]
    NoEd25519,
}

/// The ingress's verifier of endpoint client certificates.
///
/// An endpoint's certificate is self-signed and chains to nothing, so no
/// chain is verified, deliberately. The verifier accepts any end-entity
/// certificate that parses as X.509 and whose SubjectPublicKeyInfo is exactly
/// an Ed25519 key (OID 1.3.101.112, no parameters, a 32-byte key). It does
/// not look at the certificate's signature, issuer, intermediates, validity
/// period or subject, nor at the active list.
///
/// What it does verify is the CertificateVerify of the handshake, with
/// Ed25519 only: that is the proof the client holds the certificate's key.
/// The identity is the SPKI hash ([`peer_spki_hash`]), and the active list
/// decides what that identity may do after the handshake.
#[derive(Debug)]
pub struct EndpointClientVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl EndpointClientVerifier {
    /// Creates a verifier that verifies signatures with the Ed25519
    /// algorithm of `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientVerifierError::NoEd25519`] if `provider` maps no
    /// signature verification algorithm to the Ed25519 signature scheme, or
    /// maps one that is not Ed25519.
    pub fn new(provider: &CryptoProvider) -> Result<Self, ClientVerifierError> {
        let mapping = provider.signature_verification_algorithms.mapping;
        let index = mapping
            .iter()
            .position(|(scheme, _)| *scheme == SignatureScheme::ED25519)
            .ok_or(ClientVerifierError::NoEd25519)?;
        // A subslice of the provider's `'static` mapping: rustls' algorithm
        // list needs `'static` slices, and this one holds only Ed25519.
        let ed25519_mapping = mapping
            .get(index..=index)
            .ok_or(ClientVerifierError::NoEd25519)?;
        let &[(_, algorithms)] = ed25519_mapping else {
            return Err(ClientVerifierError::NoEd25519);
        };
        if algorithms.is_empty() || !algorithms.iter().all(|alg| is_ed25519(*alg)) {
            return Err(ClientVerifierError::NoEd25519);
        }
        Ok(Self {
            algorithms: WebPkiSupportedAlgorithms {
                all: algorithms,
                mapping: ed25519_mapping,
            },
        })
    }
}

fn is_ed25519(alg: &dyn SignatureVerificationAlgorithm) -> bool {
    alg.public_key_alg_id() == alg_id::ED25519 && alg.signature_alg_id() == alg_id::ED25519
}

/// The client certificate's key is not Ed25519.
#[derive(Debug, thiserror::Error)]
#[error("the client certificate's key is not Ed25519")]
struct NotEd25519;

impl ClientCertVerifier for EndpointClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let parsed = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let spki = parsed.subject_public_key_info();
        let spki = spki.as_ref();
        if spki.len() != ED25519_SPKI_LEN || !spki.starts_with(&ED25519_SPKI_PREFIX) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(NotEd25519)),
            )));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not supported on an endpoint port".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// An error building the ingress's TLS configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerConfigError {
    /// The client verifier could not be built.
    #[error("building the endpoint client verifier")]
    Verifier(#[source] ClientVerifierError),
    /// rustls rejected the configuration, such as a provider without TLS 1.3
    /// or a key that does not match the certificate.
    #[error("building the TLS server configuration")]
    Rustls(#[source] rustls::Error),
}

/// Returns the TLS configuration of an ingress's endpoint port.
///
/// The configuration speaks TLS 1.3 only, offers `alpn` (the port's
/// [`CONTROL_ALPN`] or [`TELEMETRY_ALPN`]) as its only ALPN protocol, and
/// verifies clients with [`EndpointClientVerifier`]. It neither resumes
/// sessions nor accepts 0-RTT data, so every connection is a full handshake
/// whose CertificateVerify is verified. `cert_chain` is the server's
/// certificate followed by its intermediates, and `key` its private key.
///
/// # Errors
///
/// Returns [`ServerConfigError::Verifier`] if `provider` has no Ed25519
/// signature verification, and [`ServerConfigError::Rustls`] if rustls
/// rejects the provider, the chain or the key.
pub fn ingress_server_config(
    provider: Arc<CryptoProvider>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Result<ServerConfig, ServerConfigError> {
    let verifier = EndpointClientVerifier::new(&provider).map_err(ServerConfigError::Verifier)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(ServerConfigError::Rustls)?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, key)
        .map_err(ServerConfigError::Rustls)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    // No session resumption: a resumed connection carries no
    // CertificateVerify, so it would prove nothing about the client's key.
    // Without storage and with the builder's ticketer, which produces no
    // tickets, no ticket is ever sent.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}

/// An error reading the trust roots or building the endpoint's TLS
/// configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientConfigError {
    /// The trust root list is empty.
    #[error("the trust root list is empty")]
    NoTrustRoots,
    /// A list element is not well-formed PEM: a `BEGIN` line without its
    /// `END` line, a stray or malformed boundary line, or a body that is not
    /// base64.
    #[error("trust root {index} is malformed PEM")]
    MalformedPem {
        /// The position of the element in the list.
        index: usize,
    },
    /// A list element holds no PEM block.
    #[error("trust root {index} holds no certificate")]
    NoCertificate {
        /// The position of the element in the list.
        index: usize,
    },
    /// A list element holds a PEM block that is not a `CERTIFICATE`.
    #[error("trust root {index} holds a {label} block, not a certificate")]
    NotCertificate {
        /// The position of the element in the list.
        index: usize,
        /// The label of the block.
        label: String,
    },
    /// A certificate could not be added to the root store.
    #[error("trust root {index} is not a usable trust anchor")]
    UnusableRoot {
        /// The position of the element in the list.
        index: usize,
        /// Why the root store rejected it.
        #[source]
        source: rustls::Error,
    },
    /// The server verifier could not be built.
    #[error("building the server certificate verifier")]
    Verifier(#[source] rustls::client::VerifierBuilderError),
    /// rustls rejected the configuration, such as a provider without TLS 1.3
    /// or a key that does not match the certificate.
    #[error("building the TLS client configuration")]
    Rustls(#[source] rustls::Error),
}

/// Returns the TLS configuration with which an endpoint connects to an
/// ingress's endpoint port.
///
/// The configuration speaks TLS 1.3 only, offers `alpn` (the port's
/// [`CONTROL_ALPN`] or [`TELEMETRY_ALPN`]) as its only ALPN protocol, and
/// presents `cert` with `key` as its client certificate. It verifies the
/// server with rustls' `WebPkiServerVerifier` over `trust_roots`, unchanged.
///
/// Each element of `trust_roots` is PEM holding one or more `CERTIFICATE`
/// blocks, every one of which becomes a root; during a rotation the old and
/// new roots arrive together. Text outside the blocks is ignored. The list is
/// taken whole or not at all: a single bad element or block fails it.
///
/// # Errors
///
/// Returns [`ClientConfigError::NoTrustRoots`] if `trust_roots` is empty;
/// [`ClientConfigError::MalformedPem`], [`ClientConfigError::NoCertificate`]
/// or [`ClientConfigError::NotCertificate`] if an element is malformed PEM,
/// holds no block, or holds a block that is not a `CERTIFICATE`;
/// [`ClientConfigError::UnusableRoot`] if a certificate cannot be a trust
/// anchor; and [`ClientConfigError::Verifier`] or
/// [`ClientConfigError::Rustls`] if rustls rejects the verifier, the
/// provider, the certificate or the key.
pub fn endpoint_client_config<S: AsRef<str>>(
    provider: Arc<CryptoProvider>,
    trust_roots: &[S],
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Result<ClientConfig, ClientConfigError> {
    let roots = root_store(trust_roots)?;
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(ClientConfigError::Verifier)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(ClientConfigError::Rustls)?
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(ClientConfigError::Rustls)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

fn root_store<S: AsRef<str>>(trust_roots: &[S]) -> Result<RootCertStore, ClientConfigError> {
    if trust_roots.is_empty() {
        return Err(ClientConfigError::NoTrustRoots);
    }
    let mut store = RootCertStore::empty();
    for (index, pem) in trust_roots.iter().enumerate() {
        let certificates = pem_certificates(pem.as_ref()).map_err(|error| match error {
            PemElementError::Malformed => ClientConfigError::MalformedPem { index },
            PemElementError::NoCertificate => ClientConfigError::NoCertificate { index },
            PemElementError::NotCertificate { label } => {
                ClientConfigError::NotCertificate { index, label }
            }
        })?;
        for der in certificates {
            store
                .add(der)
                .map_err(|source| ClientConfigError::UnusableRoot { index, source })?;
        }
    }
    Ok(store)
}

/// Why one trust root element is not PEM of certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PemElementError {
    /// A `BEGIN` line without its `END` line, a stray or malformed boundary
    /// line, or a body that is not base64.
    Malformed,
    /// The element holds no PEM block.
    NoCertificate,
    /// The element holds a block that is not a `CERTIFICATE`.
    NotCertificate {
        /// The label of the first such block.
        label: String,
    },
}

/// Decodes one trust root element: PEM of one or more `CERTIFICATE` blocks,
/// with any text outside the blocks ignored.
///
/// This is the one PEM rule for trust roots: [`endpoint_client_config`]
/// reads each element with it, and the address document's schema checks
/// each element with it, so the two cannot disagree on what is PEM. Whether
/// a certificate can be a trust anchor is not looked at here.
pub(crate) fn pem_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, PemElementError> {
    let blocks = pem_blocks(pem).ok_or(PemElementError::Malformed)?;
    if blocks.is_empty() {
        return Err(PemElementError::NoCertificate);
    }
    blocks
        .into_iter()
        .map(|block| {
            if block.label != PEM_CERTIFICATE_LABEL {
                return Err(PemElementError::NotCertificate {
                    label: block.label.to_owned(),
                });
            }
            CertificateDer::from_pem_slice(block.text.as_bytes())
                .map_err(|_| PemElementError::Malformed)
        })
        .collect()
}

/// A PEM block: its label, and its text from the `BEGIN` line through the
/// `END` line, each line trimmed.
struct PemBlock<'a> {
    label: &'a str,
    text: String,
}

/// Splits `pem` into its blocks, whatever their labels, or returns `None` if
/// it is malformed.
///
/// Unlike the iterator of `rustls-pki-types`, this keeps blocks whose label
/// it does not know, so the caller rejects them instead of skipping them.
/// Lines outside a block are ignored unless they look like a boundary: a
/// trimmed line starting with `-----BEGIN` or `-----END` must be one that
/// opens a block outside one, or closes the open block with its own label.
/// Lines end at CRLF, CR or LF, as RFC 7468 allows.
fn pem_blocks(pem: &str) -> Option<Vec<PemBlock<'_>>> {
    let mut blocks = Vec::new();
    let mut open: Option<PemBlock<'_>> = None;
    for line in pem_lines(pem).map(str::trim) {
        let is_begin = line.starts_with(PEM_BEGIN_MARK);
        let is_end = line.starts_with(PEM_END_MARK);
        match open.as_mut() {
            None if is_begin => {
                let label = boundary_label(line, PEM_BEGIN)?;
                open = Some(PemBlock {
                    label,
                    text: format!("{line}\n"),
                });
            }
            None if is_end => return None,
            None => {}
            Some(_) if is_begin => return None,
            Some(block) if is_end => {
                if boundary_label(line, PEM_END)? != block.label {
                    return None;
                }
                block.text.push_str(line);
                block.text.push('\n');
                blocks.extend(open.take());
            }
            Some(block) => {
                block.text.push_str(line);
                block.text.push('\n');
            }
        }
    }
    if open.is_some() {
        return None;
    }
    Some(blocks)
}

/// Splits `text` into lines ending at CRLF, CR or LF.
///
/// `str::lines` ends a line only at LF or CRLF, so a CR-only document would
/// read as one line and every block in it as explanatory text.
fn pem_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'))
}

/// Returns the label of the boundary line `line` that starts with `prefix`,
/// or `None` if the line is not `<prefix><label>-----` with a non-empty label.
fn boundary_label<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let label = line.strip_prefix(prefix)?.strip_suffix(PEM_DASHES)?;
    (!label.is_empty()).then_some(label)
}

/// An error reading an ingress entry's expected name.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExpectedNameError {
    /// The name is an IP address; the server's SAN is a DNS name.
    #[error("the expected name is an IP address, not a DNS name")]
    IpAddress,
    /// The name is not a valid DNS name.
    #[error("the expected name is not a valid DNS name")]
    InvalidDnsName,
}

/// Returns the ingress entry's `expected_name` as the DNS server name to
/// verify the server's certificate against.
///
/// The caller opens TCP to the entry's address and passes this name to the
/// `ClientConnection`.
///
/// # Errors
///
/// Returns [`ExpectedNameError::IpAddress`] if `expected_name` is an IP
/// address, and [`ExpectedNameError::InvalidDnsName`] if it is not a valid
/// DNS name.
pub fn expected_server_name(expected_name: &str) -> Result<ServerName<'static>, ExpectedNameError> {
    if expected_name.parse::<IpAddr>().is_ok() {
        return Err(ExpectedNameError::IpAddress);
    }
    let name = DnsName::try_from(expected_name.to_owned())
        .map_err(|_| ExpectedNameError::InvalidDnsName)?;
    Ok(ServerName::DnsName(name))
}
