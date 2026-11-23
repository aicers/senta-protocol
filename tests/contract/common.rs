//! The harness both ports share: a test PKI, in-memory TLS 1.3 links
//! between rustls peers configured by the crate, and an ingress composed
//! from the crate's TLS helpers, active list and server-side connection
//! helper.
//!
//! Nothing here touches the network, the disk or a real clock: TLS bytes
//! move between the two rustls connections in memory, rustls reads the
//! time from [`FixedTime`], and every wall-clock and monotonic time handed
//! to the crate is a constant or a value the test sets.

use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use ed25519_dalek::SigningKey;
use jiff::Timestamp;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ConnectionCommon, RootCertStore, SideData, SignatureScheme};
use senta_protocol::auth::active_list::{
    ActiveList, ConnectionChange, ConnectionId, EntryState, Lease, ListEntry, ListUpdate, Standing,
};
use senta_protocol::auth::tls::{
    alpn_matches, endpoint_certificate, endpoint_client_config, endpoint_private_key,
    expected_server_name, ingress_server_config, peer_spki_hash, spki_hash_from_ed25519_public_key,
};
use senta_protocol::connection::{
    CloseReason, ENDPOINT_RECEIVE_LIMIT, EndpointAction, EndpointChannel, EndpointConfig,
    EndpointConnection, EndpointHandshake, Envelope, Frame, FrameTooLarge, Hello, HelloAck,
    Message, Ping, Pong, SERVER_ACTIVE_RECEIVE_LIMIT, ServerAction, ServerChannel, ServerConfig,
    ServerConnection, ServerHandshake, StandingVerdict, Unsupported, VersionRange,
};
use senta_protocol::standing::SuspendReason;
use uuid::Uuid;

/// The DNS name the ingress's certificate carries and the endpoint expects.
const SERVER_NAME: &str = "ingress.example";

/// The source address every connection is registered from.
const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// The crate version the endpoint's `hello` carries.
pub(crate) const CRATE_VERSION: &str = "0.1.0";

/// A message kind neither side knows.
pub(crate) const UNKNOWN_T: &str = "x_unknown_kind";

/// How much plaintext is handed to rustls at a time: well under its 64 KiB
/// buffer of TLS to send and its 16 KiB buffer of plaintext received.
const CHUNK: usize = 16 * 1024;

/// The key seed of an endpoint listed `active`.
pub(crate) const ACTIVE: u8 = 1;
/// The key seed of an endpoint listed `license_pending`.
pub(crate) const PENDING: u8 = 2;
/// The key seed of an endpoint listed `suspended` for
/// [`LISTED_SUSPEND_REASON`].
pub(crate) const SUSPENDED: u8 = 3;
/// The key seed of an endpoint not on the list.
pub(crate) const NOT_LISTED: u8 = 4;
/// The key seed of a second endpoint listed `active`.
pub(crate) const OTHER_ACTIVE: u8 = 5;

/// Why the endpoint of [`SUSPENDED`] is suspended in [`full_list`].
pub(crate) const LISTED_SUSPEND_REASON: SuspendReason = SuspendReason::Operator;

/// The version of [`full_list`].
pub(crate) const LIST_VERSION: u64 = 1;

/// The wall clock the endpoint reads, and the time rustls verifies
/// certificates at: 2026-11-23T05:06:07Z.
pub(crate) fn endpoint_wall() -> Timestamp {
    Timestamp::from_second(1_795_410_367).unwrap()
}

/// The wall clock the ingress reads, two seconds ahead of the endpoint's.
pub(crate) fn ingress_wall() -> Timestamp {
    Timestamp::from_second(1_795_410_369).unwrap()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// rustls' clock, stopped at [`endpoint_wall`].
#[derive(Debug)]
struct FixedTime;

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        let second = u64::try_from(endpoint_wall().as_second()).ok()?;
        Some(UnixTime::since_unix_epoch(Duration::from_secs(second)))
    }
}

// ---------------------------------------------------------------------------
// Keys, certificates and TLS configurations
// ---------------------------------------------------------------------------

/// The 32-byte Ed25519 seed of the endpoint numbered `n`.
fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// The SHA-256 of the SubjectPublicKeyInfo of the endpoint numbered `n`,
/// from its public key.
pub(crate) fn spki(n: u8) -> [u8; 32] {
    let public_key = SigningKey::from_bytes(&seed(n)).verifying_key().to_bytes();
    spki_hash_from_ed25519_public_key(&public_key)
}

fn name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

/// Makes `params` valid from 2026-01-01 to 2027-12-31, around
/// [`endpoint_wall`].
fn valid_around_wall(params: &mut CertificateParams) {
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2027, 12, 31);
}

/// A root the test made, and the ingress's server certificate it issued.
pub(crate) struct Pki {
    root: CertificateDer<'static>,
    root_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Pki {
    fn new() -> Self {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.distinguished_name = name("contract test root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        valid_around_wall(&mut root_params);
        let root = root_params.self_signed(&root_key).unwrap();
        let issuer = Issuer::new(root_params, root_key);

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec![SERVER_NAME.to_owned()]).unwrap();
        leaf_params.distinguished_name = name("ingress");
        valid_around_wall(&mut leaf_params);
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        Self {
            root: root.der().clone(),
            root_pem: root.pem(),
            chain: vec![leaf.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    /// The ingress's configuration for the port of `alpn`, by the crate.
    fn server_config(&self, alpn: &[u8]) -> Arc<rustls::ServerConfig> {
        let mut config =
            ingress_server_config(provider(), self.chain.clone(), self.key.clone_key(), alpn)
                .unwrap();
        config.time_provider = Arc::new(FixedTime);
        Arc::new(config)
    }

    /// The configuration of the endpoint numbered `n` offering `alpn`, by
    /// the crate, with the certificate the crate makes for its key.
    pub(crate) fn endpoint_client(&self, n: u8, alpn: &[u8]) -> ClientConfig {
        let cert = endpoint_certificate(&seed(n), endpoint_wall()).unwrap();
        let key = endpoint_private_key(&seed(n)).unwrap().into();
        let mut config =
            endpoint_client_config(provider(), &[self.root_pem.as_str()], cert, key, alpn).unwrap();
        config.time_provider = Arc::new(FixedTime);
        config
    }

    /// A client built here, not by the crate, presenting the certificate of
    /// the endpoint numbered `cert_of` and signing its CertificateVerify
    /// with the key of `signed_by`.
    fn foreign_client(&self, cert_of: u8, signed_by: u8, alpn: &[u8]) -> ClientConfig {
        let cert = endpoint_certificate(&seed(cert_of), endpoint_wall()).unwrap();
        let key = provider()
            .key_provider
            .load_private_key(endpoint_private_key(&seed(signed_by)).unwrap().into())
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(Presents(Arc::new(CertifiedKey::new(
                vec![cert],
                key,
            )))));
        config.alpn_protocols = vec![alpn.to_vec()];
        config.time_provider = Arc::new(FixedTime);
        config
    }
}

/// Presents a fixed certificate with a fixed signing key, which need not
/// belong to the certificate, as rustls' own resolver insists.
#[derive(Debug)]
struct Presents(Arc<CertifiedKey>);

impl ResolvesClientCert for Presents {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// The active list
// ---------------------------------------------------------------------------

/// The list entry of the endpoint numbered `n`.
fn entry(n: u8, state: EntryState) -> ListEntry {
    ListEntry {
        endpoint_id: Uuid::from_u128(u128::from(n)),
        spki_sha256: spki(n),
        customer_endpoint_id: Uuid::from_u128(0x1000 + u128::from(n)),
        state,
    }
}

/// The full list at [`LIST_VERSION`]: [`ACTIVE`] and [`OTHER_ACTIVE`]
/// active, [`PENDING`] waiting for its license, [`SUSPENDED`] suspended,
/// and [`NOT_LISTED`] absent.
fn full_list() -> ListUpdate {
    ListUpdate::Full {
        version: LIST_VERSION,
        entries: vec![
            entry(ACTIVE, EntryState::Active),
            entry(PENDING, EntryState::LicensePending),
            entry(
                SUSPENDED,
                EntryState::Suspended {
                    reason: LISTED_SUSPEND_REASON,
                },
            ),
            entry(OTHER_ACTIVE, EntryState::Active),
        ],
    }
}

/// The diff from [`full_list`] that puts the endpoint numbered `n` in
/// `state`.
pub(crate) fn diff(n: u8, state: EntryState) -> ListUpdate {
    ListUpdate::Diff {
        base_version: LIST_VERSION,
        version: LIST_VERSION + 1,
        upserts: vec![entry(n, state)],
        removals: vec![],
    }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// A `ping` from the endpoint.
pub(crate) fn ping() -> Frame {
    Frame::from_message(&Ping {
        sent_at: endpoint_wall(),
    })
    .unwrap()
}

/// A `pong` from the endpoint.
pub(crate) fn pong() -> Frame {
    Frame::from_message(&Pong {
        ping_sent_at: ingress_wall(),
        sent_at: endpoint_wall(),
    })
    .unwrap()
}

/// A frame of [`UNKNOWN_T`] with an empty map for its body.
pub(crate) fn unknown() -> Frame {
    Frame::new(UNKNOWN_T, &Value::Map(vec![])).unwrap()
}

/// A frame of `t` whose body is the map of `fields` and a byte string
/// `pad`, sized so that the frame's length prefix holds exactly `size`.
pub(crate) fn padded(t: &str, fields: &[(&str, Value)], size: u32) -> Frame {
    let encode = |pad: usize| {
        let mut body: Vec<(Value, Value)> = fields
            .iter()
            .map(|(key, value)| (Value::Text((*key).to_owned()), value.clone()))
            .collect();
        body.push((Value::Text("pad".to_owned()), Value::Bytes(vec![0; pad])));
        Frame::new(t, &Value::Map(body)).unwrap()
    };
    let size = usize::try_from(size).unwrap();
    // The byte string's header is as long for the guess as for the answer
    // at every size used here, so one correction lands on `size`.
    let guess = size - 256;
    let pad = guess + size - encode(guess).payload().len();
    let frame = encode(pad);
    assert_eq!(frame.payload().len(), size);
    let prefix: [u8; 4] = frame.as_bytes()[..4].try_into().unwrap();
    assert_eq!(usize::try_from(u32::from_be_bytes(prefix)).unwrap(), size);
    frame
}

/// A frame of [`UNKNOWN_T`] whose length prefix holds `size`.
pub(crate) fn unknown_of(size: u32) -> Frame {
    padded(UNKNOWN_T, &[], size)
}

/// Returns the `t` of a frame's payload.
pub(crate) fn t_of(payload: &[u8]) -> String {
    Envelope::parse(payload).unwrap().t().to_owned()
}

/// Returns the `t`s of frames' payloads.
pub(crate) fn ts(payloads: &[Vec<u8>]) -> Vec<String> {
    payloads.iter().map(|payload| t_of(payload)).collect()
}

/// Asserts that `payload` is `unsupported { kind }`.
pub(crate) fn assert_unsupported(payload: &[u8], kind: &str) {
    let envelope = Envelope::parse(payload).unwrap();
    assert_eq!(envelope.t(), Unsupported::T);
    let unsupported: Unsupported = envelope.body().decode().unwrap();
    assert_eq!(unsupported.kind, kind);
}

/// Returns the text keys of the map a frame's body holds, sorted.
pub(crate) fn body_keys(payload: &[u8]) -> Vec<String> {
    let envelope = Envelope::parse(payload).unwrap();
    let Value::Map(fields) = envelope.body().decode::<Value>().unwrap() else {
        panic!("the body of {:?} is not a map", envelope.t());
    };
    let mut keys: Vec<String> = fields
        .into_iter()
        .map(|(key, _)| key.into_text().unwrap())
        .collect();
    keys.sort_unstable();
    keys
}

// ---------------------------------------------------------------------------
// A port's composition
// ---------------------------------------------------------------------------

/// What one port's ingress and endpoint are composed of.
pub(crate) trait Port: 'static {
    /// The port's ALPN protocol.
    const ALPN: &'static [u8];
    /// The message kinds both sides hand their connection helper.
    const KINDS: &'static [&'static str];

    /// The lease the ingress holds its active list under, if any.
    fn lease() -> Option<Lease>;

    /// The ingress's channel.
    fn server_channel() -> ServerChannel;

    /// The endpoint's channel, expecting the ingress's own entry.
    fn endpoint_channel() -> EndpointChannel;

    /// The standing check's verdict on a message `t` from an endpoint of
    /// `standing`.
    fn verdict(standing: &Standing, t: &str) -> StandingVerdict;

    /// Decodes a delivered message by the port's own messages, and encodes
    /// it again; `None` when its body does not decode.
    fn decode(envelope: &Envelope) -> Option<Frame>;

    /// The notice the ingress sends an endpoint as its connection takes
    /// `standing`, if any.
    fn notice(standing: &Standing) -> Option<Frame>;

    /// The frame sent on a connection the lease's expiry closes.
    fn lease_expired() -> Frame;
}

/// The endpoint's configuration for port `P`.
pub(crate) fn endpoint_config<P: Port>() -> EndpointConfig {
    EndpointConfig::new(P::endpoint_channel(), CRATE_VERSION).with_known_kinds(P::KINDS.to_vec())
}

// ---------------------------------------------------------------------------
// In-memory TLS
// ---------------------------------------------------------------------------

/// The side of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Endpoint,
    Ingress,
}

/// A TLS handshake that failed.
#[derive(Debug)]
pub(crate) struct TlsFailure {
    /// The side whose rustls refused the handshake; `None` when it stalled.
    pub(crate) by: Option<Side>,
    /// What rustls said.
    pub(crate) error: String,
}

/// Moves TLS records between the two sides until the handshake ends or one
/// side refuses it.
fn tls_handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Result<(), TlsFailure> {
    let refused = |by, error: rustls::Error| TlsFailure {
        by: Some(by),
        error: error.to_string(),
    };
    loop {
        let mut moved = false;
        while client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            let mut rest = buf.as_slice();
            while !rest.is_empty() {
                server.read_tls(&mut rest).unwrap();
                server
                    .process_new_packets()
                    .map_err(|error| refused(Side::Ingress, error))?;
            }
            moved = true;
        }
        while server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            let mut rest = buf.as_slice();
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
                client
                    .process_new_packets()
                    .map_err(|error| refused(Side::Endpoint, error))?;
            }
            moved = true;
        }
        if !moved {
            break;
        }
    }
    if client.is_handshaking() || server.is_handshaking() {
        return Err(TlsFailure {
            by: None,
            error: "the handshake stalled".to_owned(),
        });
    }
    Ok(())
}

/// Plaintext one side has to send, and whether it ends the connection
/// after it.
#[derive(Default)]
struct Outbox {
    bytes: Vec<u8>,
    sent: usize,
    close: bool,
    close_sent: bool,
}

impl Outbox {
    fn push(&mut self, frame: &Frame) {
        assert!(!self.close, "a frame queued after the connection's end");
        self.bytes.extend_from_slice(frame.as_bytes());
    }

    fn close(&mut self) {
        self.close = true;
    }
}

/// What one round of moving plaintext brought the receiving side.
#[derive(Default)]
struct Moved {
    any: bool,
    chunks: Vec<Vec<u8>>,
    eof: bool,
}

/// Moves `out` from `from` to `to` through TLS a chunk at a time, then the
/// close_notify if `out` asks for one, taking the plaintext out of `to` as
/// it arrives so that neither rustls buffer fills.
fn transfer<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
    out: &mut Outbox,
) -> Moved {
    let mut moved = Moved::default();
    loop {
        if out.sent < out.bytes.len() {
            let end = out.bytes.len().min(out.sent + CHUNK);
            out.sent += from.writer().write(&out.bytes[out.sent..end]).unwrap();
        } else if out.close && !out.close_sent {
            from.send_close_notify();
            out.close_sent = true;
        }
        if !from.wants_write() {
            break;
        }
        while from.wants_write() {
            let mut tls = Vec::new();
            from.write_tls(&mut tls).unwrap();
            let mut rest = tls.as_slice();
            while !rest.is_empty() {
                to.read_tls(&mut rest).unwrap();
                to.process_new_packets().unwrap();
                drain(to, &mut moved);
            }
            moved.any = true;
        }
    }
    if out.sent == out.bytes.len() {
        out.bytes.clear();
        out.sent = 0;
    }
    moved
}

/// Takes every byte of plaintext `to` holds, noting the close_notify.
fn drain<B: SideData>(to: &mut ConnectionCommon<B>, moved: &mut Moved) {
    let mut buf = vec![0; CHUNK];
    loop {
        match to.reader().read(&mut buf) {
            Ok(0) => {
                moved.eof = true;
                break;
            }
            Ok(n) => moved.chunks.push(buf[..n].to_vec()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("reading plaintext: {error}"),
        }
    }
}

/// Splits received plaintext into frame payloads, whatever their length:
/// what the peer sent, independently of the connection helper.
#[derive(Default)]
struct Tap {
    buf: Vec<u8>,
    frames: Vec<Vec<u8>>,
}

impl Tap {
    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while let Some(prefix) = self.buf.first_chunk::<4>() {
            let len = usize::try_from(u32::from_be_bytes(*prefix)).unwrap();
            if self.buf.len() < 4 + len {
                break;
            }
            self.frames.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
    }
}

// ---------------------------------------------------------------------------
// Either side of a connection
// ---------------------------------------------------------------------------

/// The endpoint's side: the crate's endpoint connection helper, with what
/// it received and decided.
pub(crate) struct EndpointSide {
    helper: EndpointConnection,
    hello: Option<Frame>,
    out: Outbox,
    tap: Tap,
    /// The handshake the helper completed.
    pub(crate) handshake: Option<EndpointHandshake>,
    /// The messages the helper delivered, in order.
    pub(crate) delivered: Vec<Envelope>,
    /// The `kind`s of the refusals the helper reported.
    pub(crate) unsupported: Vec<String>,
    /// Why the helper closed the connection.
    pub(crate) closed: Option<CloseReason>,
    /// Whether the ingress ended the connection.
    pub(crate) peer_closed: bool,
}

impl EndpointSide {
    /// The payloads of the frames the ingress sent, in order.
    pub(crate) fn frames(&self) -> &[Vec<u8>] {
        &self.tap.frames
    }

    fn receive(&mut self, bytes: &[u8], now: Duration) {
        if self.closed.is_some() {
            return;
        }
        self.tap.push(bytes);
        let wall = endpoint_wall();
        let mut actions = self.helper.receive(bytes, wall, now);
        loop {
            let mut accept = false;
            for action in actions {
                match action {
                    EndpointAction::Handshake(handshake) => self.handshake = Some(handshake),
                    EndpointAction::ClockMeasured(_) => {}
                    EndpointAction::Deliver(envelope) => {
                        self.delivered.push(envelope);
                        accept = self.helper.is_body_pending();
                    }
                    EndpointAction::Unsupported(unsupported) => {
                        self.unsupported.push(unsupported.kind);
                    }
                    EndpointAction::Send(frame) => self.out.push(&frame),
                    EndpointAction::Close(reason) => {
                        self.closed = Some(reason);
                        self.out.close();
                    }
                }
            }
            if !accept {
                break;
            }
            actions = self.helper.accept_body(wall, now);
        }
    }
}

/// Why the ingress ended a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IngressClose {
    /// The negotiated ALPN was not the port's.
    Alpn,
    /// The connection helper closed it.
    Helper(CloseReason),
    /// The lease expired while it was open.
    LeaseExpired,
    /// A connection with the same key replaced it.
    Replaced,
    /// The entry its key matched is gone, or another endpoint's.
    EntryChanged,
}

/// The ingress's side: the crate's server connection helper, set up once
/// the TLS handshake and the ALPN check are done, with what it received
/// and decided.
pub(crate) struct IngressSide {
    helper: Option<ServerConnection>,
    standing: Arc<Mutex<Standing>>,
    out: Outbox,
    tap: Tap,
    /// The SPKI hash taken from the peer's certificate.
    pub(crate) spki: Option<[u8; 32]>,
    /// The handshake the helper completed.
    pub(crate) handshake: Option<ServerHandshake>,
    /// The messages delivered and decoded by the port's own messages,
    /// encoded again.
    pub(crate) delivered: Vec<Frame>,
    /// The `kind`s of the refusals the helper reported.
    pub(crate) unsupported: Vec<String>,
    /// Why the ingress ended the connection.
    pub(crate) closed: Option<IngressClose>,
    /// Whether the endpoint ended the connection.
    pub(crate) peer_closed: bool,
}

impl IngressSide {
    fn new() -> Self {
        Self {
            helper: None,
            standing: Arc::new(Mutex::new(Standing::Unready)),
            out: Outbox::default(),
            tap: Tap::default(),
            spki: None,
            handshake: None,
            delivered: Vec::new(),
            unsupported: Vec::new(),
            closed: None,
            peer_closed: false,
        }
    }

    /// The payloads of the frames the endpoint sent, in order, from the
    /// moment the connection was registered.
    pub(crate) fn frames(&self) -> &[Vec<u8>] {
        &self.tap.frames
    }

    /// Sets up the connection helper for a registered connection whose
    /// standing is `standing`: its receive limit and its standing check
    /// both follow the connection's standing as it changes.
    fn admit<P: Port>(&mut self, spki: [u8; 32], standing: Standing, now: Duration) {
        let limit = standing.receive_limit();
        *self.standing.lock().unwrap() = standing;
        let shared = Arc::clone(&self.standing);
        let config = ServerConfig::new(P::server_channel(), limit)
            .with_known_kinds(P::KINDS.to_vec())
            .with_standing(move |t| P::verdict(&shared.lock().unwrap(), t));
        self.helper = Some(ServerConnection::new(config, now));
        self.spki = Some(spki);
    }

    /// Takes the standing an applied update gave the connection.
    fn restand<P: Port>(&mut self, standing: Standing) {
        if self.closed.is_some() {
            return;
        }
        let helper = self.helper.as_mut().unwrap();
        helper.set_receive_limit(standing.receive_limit());
        if helper.is_established()
            && let Some(notice) = P::notice(&standing)
        {
            self.out.push(&notice);
        }
        *self.standing.lock().unwrap() = standing;
    }

    fn close(&mut self, why: IngressClose) {
        if self.closed.is_none() {
            self.closed = Some(why);
            self.out.close();
        }
    }

    fn receive<P: Port>(&mut self, bytes: &[u8], now: Duration) {
        if self.closed.is_some() {
            return;
        }
        let helper = self
            .helper
            .as_mut()
            .expect("an open connection the ingress took is registered");
        self.tap.push(bytes);
        let wall = ingress_wall();
        let mut actions = helper.receive(bytes, wall, now);
        loop {
            let mut accept = false;
            for action in actions {
                match action {
                    ServerAction::Handshake(handshake) => {
                        self.handshake = Some(handshake);
                        let standing = self.standing.lock().unwrap().clone();
                        if let Some(notice) = P::notice(&standing) {
                            self.out.push(&notice);
                        }
                    }
                    ServerAction::Deliver(envelope) => match P::decode(&envelope) {
                        Some(frame) => {
                            self.delivered.push(frame);
                            accept = true;
                        }
                        None => {
                            let ServerAction::Close(reason) = helper.reject_body() else {
                                panic!("rejecting a body closes the connection");
                            };
                            self.closed = Some(IngressClose::Helper(reason));
                            self.out.close();
                        }
                    },
                    ServerAction::Unsupported(unsupported) => {
                        self.unsupported.push(unsupported.kind);
                    }
                    ServerAction::Send(frame) => self.out.push(&frame),
                    ServerAction::SendThenClose { frame, reason } => {
                        self.out.push(&frame);
                        self.closed = Some(IngressClose::Helper(reason));
                        self.out.close();
                    }
                    ServerAction::Close(reason) => {
                        self.closed = Some(IngressClose::Helper(reason));
                        self.out.close();
                    }
                }
            }
            if !accept {
                break;
            }
            actions = helper.accept_body(wall, now);
        }
    }
}

/// One connection: both rustls peers and both sides above them.
pub(crate) struct Conn {
    pub(crate) id: ConnectionId,
    client: rustls::ClientConnection,
    server: rustls::ServerConnection,
    /// How the TLS handshake ended.
    pub(crate) tls: Result<(), TlsFailure>,
    pub(crate) endpoint: EndpointSide,
    pub(crate) ingress: IngressSide,
}

impl Conn {
    /// The ALPN protocol each side negotiated: the endpoint's, then the
    /// ingress's.
    pub(crate) fn alpn(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        (self.client.alpn_protocol(), self.server.alpn_protocol())
    }

    /// Moves bytes both ways until neither side has anything to send.
    fn pump<P: Port>(&mut self, now: Duration) {
        if self.tls.is_err() {
            return;
        }
        loop {
            let up = transfer(&mut self.client, &mut self.server, &mut self.endpoint.out);
            for chunk in &up.chunks {
                self.ingress.receive::<P>(chunk, now);
            }
            if up.eof {
                self.ingress.peer_closed = true;
            }
            let down = transfer(&mut self.server, &mut self.client, &mut self.ingress.out);
            for chunk in &down.chunks {
                self.endpoint.receive(chunk, now);
            }
            if down.eof {
                self.endpoint.peer_closed = true;
            }
            if !up.any && !down.any {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The ingress
// ---------------------------------------------------------------------------

/// An ingress of port `P` composed from the crate: the TLS configuration,
/// the active list, and a server connection helper per connection, with
/// the endpoints that connect to it.
///
/// A connection's identity is taken, and the connection registered, only
/// after its TLS handshake and ALPN check. Its helper's receive limit and
/// standing check follow its standing, which the list gives it at
/// registration and applied updates change.
pub(crate) struct Ingress<P: Port> {
    pki: Pki,
    tls: Arc<rustls::ServerConfig>,
    /// The active list the ingress judges connections by.
    pub(crate) list: ActiveList,
    /// The monotonic clock, since the ingress started.
    pub(crate) now: Duration,
    next: u64,
    conns: Vec<Conn>,
    port: PhantomData<P>,
}

impl<P: Port> Ingress<P> {
    /// An ingress that has had no list yet: unready.
    pub(crate) fn unready() -> Self {
        let pki = Pki::new();
        let tls = pki.server_config(P::ALPN);
        Self {
            pki,
            tls,
            list: ActiveList::new(P::lease()),
            now: Duration::ZERO,
            next: 1,
            conns: Vec::new(),
            port: PhantomData,
        }
    }

    /// An ingress holding [`full_list`], applied at its start.
    pub(crate) fn listed() -> Self {
        let mut ingress = Self::unready();
        ingress.apply(full_list());
        ingress
    }

    pub(crate) fn pki(&self) -> &Pki {
        &self.pki
    }

    pub(crate) fn conn(&self, id: ConnectionId) -> &Conn {
        self.conns
            .iter()
            .find(|conn| conn.id == id)
            .expect("a connection of this ingress")
    }

    fn conn_mut(&mut self, id: ConnectionId) -> &mut Conn {
        self.conns
            .iter_mut()
            .find(|conn| conn.id == id)
            .expect("a connection of this ingress")
    }

    /// Connects an endpoint with these TLS and helper configurations, and
    /// returns its connection once the handshake is over and the ingress
    /// has taken it or refused it; the endpoint has sent nothing yet.
    pub(crate) fn connect(
        &mut self,
        client: ClientConfig,
        endpoint: EndpointConfig,
    ) -> ConnectionId {
        let id = ConnectionId(self.next);
        self.next += 1;
        let server_name = expected_server_name(SERVER_NAME).unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(client), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::clone(&self.tls)).unwrap();
        let tls = tls_handshake(&mut client, &mut server);
        let (helper, hello) = EndpointConnection::new(endpoint, endpoint_wall(), self.now).unwrap();
        let mut conn = Conn {
            id,
            client,
            server,
            tls,
            endpoint: EndpointSide {
                helper,
                hello: Some(hello),
                out: Outbox::default(),
                tap: Tap::default(),
                handshake: None,
                delivered: Vec::new(),
                unsupported: Vec::new(),
                closed: None,
                peer_closed: false,
            },
            ingress: IngressSide::new(),
        };
        let mut register = None;
        if conn.tls.is_ok() {
            if alpn_matches(conn.server.alpn_protocol(), P::ALPN) {
                let spki = peer_spki_hash(&conn.server).unwrap();
                let outcome = self.list.register(id, &spki, ADDRESS, self.now);
                let standing = self.list.standing(&spki, self.now).standing;
                conn.ingress.admit::<P>(spki, standing, self.now);
                register = Some(outcome);
            } else {
                conn.ingress.close(IngressClose::Alpn);
            }
        }
        self.conns.push(conn);
        if let Some(outcome) = register {
            if let Some(expired) = outcome.expired {
                self.expire(&expired);
            }
            if let Some(replaced) = outcome.replaced {
                self.conn_mut(replaced)
                    .ingress
                    .close(IngressClose::Replaced);
            }
        }
        self.pump_all();
        id
    }

    /// Connects the endpoint numbered `n`, configured by the crate for this
    /// port, and sends its `hello`.
    pub(crate) fn open(&mut self, n: u8) -> ConnectionId {
        let client = self.pki.endpoint_client(n, P::ALPN);
        let id = self.connect(client, endpoint_config::<P>());
        self.hello(id);
        id
    }

    /// Sends the `hello` the endpoint's helper made.
    pub(crate) fn hello(&mut self, id: ConnectionId) {
        let hello = self.conn_mut(id).endpoint.hello.take().unwrap();
        self.endpoint_send(id, &hello);
    }

    /// Sends a frame from the endpoint, and lets both sides answer.
    pub(crate) fn endpoint_send(&mut self, id: ConnectionId, frame: &Frame) {
        let conn = self.conn_mut(id);
        assert!(conn.tls.is_ok(), "no TLS connection to send on");
        assert!(conn.endpoint.closed.is_none(), "the endpoint closed");
        conn.endpoint.out.push(frame);
        self.pump_all();
    }

    /// Sends a frame from the ingress, and lets both sides answer.
    pub(crate) fn ingress_send(&mut self, id: ConnectionId, frame: &Frame) {
        let conn = self.conn_mut(id);
        assert!(conn.ingress.closed.is_none(), "the ingress closed");
        conn.ingress.out.push(frame);
        self.pump_all();
    }

    /// Applies an update to the list, and acts on what it changed.
    pub(crate) fn apply(&mut self, update: ListUpdate) {
        let outcome = self.list.apply(update, self.now);
        if let Some(expired) = outcome.expired {
            self.expire(&expired);
        }
        for change in outcome.result.unwrap().changes {
            self.change(change);
        }
        self.pump_all();
    }

    fn change(&mut self, change: ConnectionChange) {
        let ingress = &mut self.conn_mut(change.connection).ingress;
        if change.close {
            ingress.close(IngressClose::EntryChanged);
        } else {
            ingress.restand::<P>(change.standing);
        }
    }

    /// Ends the connections a lease expiry returned, each after the port's
    /// expiry frame.
    pub(crate) fn expire(&mut self, ids: &[ConnectionId]) {
        for &id in ids {
            let ingress = &mut self.conn_mut(id).ingress;
            if ingress.closed.is_none() {
                ingress.out.push(&P::lease_expired());
                ingress.close(IngressClose::LeaseExpired);
            }
        }
        self.pump_all();
    }

    fn pump_all(&mut self) {
        for conn in &mut self.conns {
            conn.pump::<P>(self.now);
            if conn.ingress.closed.is_some() || conn.ingress.peer_closed {
                self.list.remove(conn.id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Assertions both ports share
// ---------------------------------------------------------------------------

/// Asserts that the connection is open both ways: a `ping` from the
/// endpoint is answered with exactly one `pong`.
pub(crate) fn assert_kept<P: Port>(ingress: &mut Ingress<P>, id: ConnectionId) {
    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &ping());
    let conn = ingress.conn(id);
    let replies = &conn.endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Pong::T], "a ping on {id:?}");
    let pong: Pong = Envelope::parse(&replies[0])
        .unwrap()
        .body()
        .decode()
        .unwrap();
    assert_eq!(pong.ping_sent_at, endpoint_wall());
    assert_eq!(conn.ingress.closed, None);
    assert_eq!(conn.endpoint.closed, None);
    assert!(!conn.ingress.peer_closed && !conn.endpoint.peer_closed);
}

/// Asserts that the ingress ended the connection without sending anything
/// after the first `seen` frames, for `why`.
pub(crate) fn assert_ended_silently<P: Port>(
    ingress: &Ingress<P>,
    id: ConnectionId,
    seen: usize,
    why: &IngressClose,
) {
    let conn = ingress.conn(id);
    assert_eq!(ts(&conn.endpoint.frames()[seen..]), Vec::<String>::new());
    assert_eq!(conn.ingress.closed.as_ref(), Some(why));
    assert!(conn.endpoint.peer_closed, "the endpoint saw the end");
}

/// Sends each of `samples` on an established connection, and asserts what
/// becomes of it: those whose `t` is in `accepted` are taken (a `ping` is
/// answered with a `pong`, a `pong` with nothing, and anything else is
/// delivered to the ingress as sent), and the rest are refused with
/// `unsupported`. Either way the connection stays open.
pub(crate) fn assert_row<P: Port>(
    ingress: &mut Ingress<P>,
    id: ConnectionId,
    samples: &[(&str, Frame)],
    accepted: &[&str],
) {
    for (t, frame) in samples {
        let conn = ingress.conn(id);
        let seen = conn.endpoint.frames().len();
        let delivered = conn.ingress.delivered.len();
        let refused = conn.endpoint.unsupported.len();
        ingress.endpoint_send(id, frame);
        let conn = ingress.conn(id);
        let replies = &conn.endpoint.frames()[seen..];
        let new_deliveries: Vec<&[u8]> = conn.ingress.delivered[delivered..]
            .iter()
            .map(Frame::as_bytes)
            .collect();
        if !accepted.contains(t) {
            assert_eq!(ts(replies), [Unsupported::T], "{t} is refused");
            assert_unsupported(&replies[0], t);
            assert_eq!(conn.endpoint.unsupported[refused..], [*t]);
            assert!(new_deliveries.is_empty(), "{t} is not delivered");
        } else if *t == Ping::T {
            assert_eq!(ts(replies), [Pong::T], "{t} is answered");
        } else {
            assert_eq!(ts(replies), Vec::<String>::new(), "{t} is taken quietly");
            if *t == Pong::T {
                assert!(new_deliveries.is_empty());
            } else {
                assert_eq!(
                    new_deliveries,
                    [frame.as_bytes()],
                    "{t} is delivered as sent"
                );
            }
        }
        assert_kept(ingress, id);
    }
}

/// The samples of the framing's own messages an endpoint sends.
pub(crate) fn framing_samples() -> Vec<(&'static str, Frame)> {
    vec![(Ping::T, ping()), (Pong::T, pong())]
}

// ---------------------------------------------------------------------------
// Cases both ports share
// ---------------------------------------------------------------------------

/// The handshake of an active endpoint on port `P`: TLS 1.3 with the port's
/// ALPN, the endpoint's key as the identity, and version 1 negotiated.
/// Returns the ingress and the connection for the port's own checks.
pub(crate) fn active_handshake<P: Port>() -> (Ingress<P>, ConnectionId) {
    let mut ingress = Ingress::<P>::listed();
    let id = ingress.open(ACTIVE);
    let conn = ingress.conn(id);
    assert!(conn.tls.is_ok());
    assert_eq!(conn.alpn(), (Some(P::ALPN), Some(P::ALPN)));
    assert_eq!(conn.ingress.spki, Some(spki(ACTIVE)));
    assert_eq!(ingress.list.connections().collect::<Vec<_>>(), [id]);

    let handshake = conn.endpoint.handshake.as_ref().unwrap();
    assert_eq!(handshake.version, 1);
    assert_eq!(handshake.server_time, ingress_wall());
    let handshake = conn.ingress.handshake.as_ref().unwrap();
    assert_eq!(handshake.version, 1);
    assert_eq!(
        handshake.hello,
        Hello {
            crate_version: CRATE_VERSION.to_owned(),
            versions: VersionRange::new(1, 1),
            sent_at: endpoint_wall(),
        }
    );
    assert_eq!(ts(conn.endpoint.frames()), [HelloAck::T]);
    assert_eq!(conn.endpoint.closed, None);
    assert_eq!(conn.ingress.closed, None);
    (ingress, id)
}

/// An endpoint offering only `alpn`, another port's, at port `P`: the TLS
/// handshake fails, or the ALPN check does; either way nothing is
/// registered and no `hello` handled.
pub(crate) fn other_ports_alpn<P: Port>(alpn: &[u8]) {
    let mut ingress = Ingress::<P>::listed();
    let client = ingress.pki().endpoint_client(ACTIVE, alpn);
    let id = ingress.connect(client, endpoint_config::<P>());
    if ingress.conn(id).tls.is_ok() {
        let (_, negotiated) = ingress.conn(id).alpn();
        assert!(!alpn_matches(negotiated, P::ALPN));
        ingress.hello(id);
        assert_eq!(ingress.conn(id).ingress.closed, Some(IngressClose::Alpn));
    }
    let conn = ingress.conn(id);
    assert_eq!(conn.ingress.spki, None, "no identity taken");
    assert_eq!(ingress.list.connections().count(), 0, "nothing registered");
    assert_eq!(conn.ingress.handshake, None, "no hello handled");
    assert_eq!(conn.endpoint.frames().len(), 0);
    assert_eq!(conn.endpoint.handshake, None);
}

/// An active connection takes a frame of [`SERVER_ACTIVE_RECEIVE_LIMIT`]
/// and ends at one byte more.
pub(crate) fn active_receive_limit<P: Port>() {
    let mut ingress = Ingress::<P>::listed();
    let id = ingress.open(ACTIVE);

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_ACTIVE_RECEIVE_LIMIT));
    let replies = &ingress.conn(id).endpoint.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], UNKNOWN_T);
    assert_kept(&mut ingress, id);

    let seen = ingress.conn(id).endpoint.frames().len();
    ingress.endpoint_send(id, &unknown_of(SERVER_ACTIVE_RECEIVE_LIMIT + 1));
    assert_ended_silently(
        &ingress,
        id,
        seen,
        &IngressClose::Helper(CloseReason::FrameTooLarge(FrameTooLarge {
            length: SERVER_ACTIVE_RECEIVE_LIMIT + 1,
            limit: SERVER_ACTIVE_RECEIVE_LIMIT,
        })),
    );
}

/// The endpoint on an established connection answers a frame of
/// [`ENDPOINT_RECEIVE_LIMIT`] of an unknown kind with `unsupported`, and
/// ends the connection at one byte more.
pub(crate) fn endpoint_receive_limit<P: Port>(ingress: &mut Ingress<P>, id: ConnectionId) {
    let seen = ingress.conn(id).ingress.frames().len();
    ingress.ingress_send(id, &unknown_of(ENDPOINT_RECEIVE_LIMIT));
    let conn = ingress.conn(id);
    let replies = &conn.ingress.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], UNKNOWN_T);
    assert_kept(ingress, id);

    let seen = ingress.conn(id).ingress.frames().len();
    ingress.ingress_send(id, &unknown_of(ENDPOINT_RECEIVE_LIMIT + 1));
    let conn = ingress.conn(id);
    assert_eq!(ts(&conn.ingress.frames()[seen..]), Vec::<String>::new());
    assert_eq!(
        conn.endpoint.closed,
        Some(CloseReason::FrameTooLarge(FrameTooLarge {
            length: ENDPOINT_RECEIVE_LIMIT + 1,
            limit: ENDPOINT_RECEIVE_LIMIT,
        }))
    );
    assert!(conn.ingress.peer_closed, "the ingress saw the end");
}

/// Connects the endpoint numbered `n` speaking versions 2 to 2 alone, and
/// sends its `hello`.
pub(crate) fn open_speaking_version_2<P: Port>(ingress: &mut Ingress<P>, n: u8) -> ConnectionId {
    let client = ingress.pki().endpoint_client(n, P::ALPN);
    let endpoint = endpoint_config::<P>().with_versions(VersionRange::new(2, 2));
    let id = ingress.connect(client, endpoint);
    ingress.hello(id);
    id
}

/// An active endpoint speaking version 2 alone is refused with
/// `unsupported { kind: "version" }` and no `hello_ack`, and both sides end
/// the connection.
pub(crate) fn no_common_version<P: Port>() {
    let mut ingress = Ingress::<P>::listed();
    let id = open_speaking_version_2(&mut ingress, ACTIVE);
    let conn = ingress.conn(id);
    assert_eq!(ts(conn.endpoint.frames()), [Unsupported::T]);
    assert_unsupported(&conn.endpoint.frames()[0], Unsupported::VERSION);
    assert_eq!(conn.endpoint.handshake, None);
    assert_eq!(conn.endpoint.closed, Some(CloseReason::NoCommonVersion));
    assert_eq!(
        conn.ingress.closed,
        Some(IngressClose::Helper(CloseReason::NoCommonVersion))
    );
    assert!(conn.endpoint.peer_closed);
}

/// An active endpoint answers a message kind it does not know, from the
/// ingress, with `unsupported`, and the connection stays open.
pub(crate) fn unknown_kind_from_the_ingress<P: Port>() {
    let mut ingress = Ingress::<P>::listed();
    let id = ingress.open(ACTIVE);
    let seen = ingress.conn(id).ingress.frames().len();
    ingress.ingress_send(id, &unknown());
    let conn = ingress.conn(id);
    let replies = &conn.ingress.frames()[seen..];
    assert_eq!(ts(replies), [Unsupported::T]);
    assert_unsupported(&replies[0], UNKNOWN_T);
    assert_eq!(conn.ingress.unsupported, [UNKNOWN_T]);
    assert_kept(&mut ingress, id);
}

/// A client presenting the certificate of the active endpoint X and
/// signing with another key is refused in the TLS handshake: nothing is
/// taken from it or registered, and X's own connection stays open.
pub(crate) fn someone_elses_certificate<P: Port>() {
    let mut ingress = Ingress::<P>::listed();
    let attempt = |ingress: &mut Ingress<P>| {
        let client = ingress.pki().foreign_client(ACTIVE, NOT_LISTED, P::ALPN);
        let id = ingress.connect(client, endpoint_config::<P>());
        let conn = ingress.conn(id);
        let failure = conn.tls.as_ref().unwrap_err();
        assert_eq!(failure.by, Some(Side::Ingress), "{}", failure.error);
        assert_eq!(conn.ingress.spki, None, "no identity taken");
        assert_eq!(conn.ingress.handshake, None, "no hello handled");
    };

    attempt(&mut ingress);
    assert_eq!(ingress.list.connections().count(), 0, "nothing registered");

    let x = ingress.open(ACTIVE);
    attempt(&mut ingress);
    assert_eq!(ingress.list.connections().collect::<Vec<_>>(), [x]);
    assert_kept(&mut ingress, x);
}
