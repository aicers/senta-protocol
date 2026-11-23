//! Tests of the command state machine.
//!
//! Every command is signed with the deterministic test keys of `test_util`
//! and goes through the public API. The store records each batch it writes,
//! so every test can check what a call wrote, and fails the operations a
//! test names.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use serde_json::json;

use super::*;
use crate::auth::documents::{InstallId, Integer, PositiveInteger, verify_keyset};
use crate::auth::jws::test_util::TestKey;
use crate::auth::jws::{KeyKind, KeyLookup, KeySource, Kid, PublicKey, Typ};

const INSTALL: &str = "install-a";
const CUSTOMER: &str = "c0000000-0000-4000-8000-000000000001";
/// Customer key names, one per recovery epoch of the tests.
const NAME_A: &str = "a0000000-0000-4000-8000-00000000000a";
const NAME_B: &str = "b0000000-0000-4000-8000-00000000000b";
const ENDPOINT: &str = "e0000000-0000-4000-8000-0000000000e1";
const OTHER_ENDPOINT: &str = "e0000000-0000-4000-8000-0000000000e2";

// --- keys and trust states ---------------------------------------------------

fn seed(class: u8, tag: u8, version: u64) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[0] = class;
    seed[1] = tag;
    seed[2..10].copy_from_slice(&version.to_be_bytes());
    seed
}

/// The customer key of version `version` under the key name `name`.
fn ck(name: &str, version: u64) -> TestKey {
    TestKey::from_seed(&seed(1, name.as_bytes()[0], version))
}

fn ckid(name: &str, version: u64) -> String {
    format!("endpoint-{name}:{version}")
}

/// The recovery key of version `version`.
fn rk(version: u64) -> TestKey {
    TestKey::from_seed(&seed(2, 0, version))
}

fn rkid(version: u64) -> String {
    format!("recovery-{INSTALL}:{version}")
}

/// A key no test trusts, to make bad signatures with.
fn stranger() -> TestKey {
    TestKey::from_seed(&[9; 32])
}

/// A key set of the customer key name `name`.
struct Ks {
    name: &'static str,
    epoch: u64,
    version: u64,
    keys: Vec<(&'static str, u64)>,
    current: u64,
    revoked: Vec<String>,
}

impl Ks {
    fn first(epoch: u64, name: &'static str) -> Self {
        Self {
            name,
            epoch,
            version: 1,
            keys: vec![(name, 1)],
            current: 1,
            revoked: Vec::new(),
        }
    }

    fn payload(&self) -> Vec<u8> {
        let keys: Vec<_> = self
            .keys
            .iter()
            .map(|&(name, v)| json!({"kid": ckid(name, v), "key": ck(name, v).jwk()}))
            .collect();
        serde_json::to_vec(&json!({
            "customer_endpoint_id": CUSTOMER,
            "customer_key_name": format!("endpoint-{}", self.name),
            "recovery_epoch": self.epoch,
            "keyset_version": self.version,
            "keys": keys,
            "current_kid": ckid(self.name, self.current),
            "revoked_kids": self.revoked,
        }))
        .unwrap()
    }

    fn resigned(&self) -> String {
        ck(self.name, self.current).sign(
            Typ::Keyset,
            &ckid(self.name, self.current),
            &self.payload(),
        )
    }

    fn rotated(&self) -> String {
        ck(self.name, self.version - 1).sign(
            Typ::Keyset,
            &ckid(self.name, self.version - 1),
            &self.payload(),
        )
    }

    fn recovery_signed(&self, version: u64) -> String {
        rk(version).sign(Typ::Keyset, &rkid(version), &self.payload())
    }
}

struct OneKey {
    kid: String,
    key: PublicKey,
}

impl KeySource for OneKey {
    fn find_key(&self, kid: &Kid, _: &[KeyKind]) -> KeyLookup {
        if kid.as_str() == self.kid {
            KeyLookup::Found {
                key: self.key,
                kind: kid.kind(),
            }
        } else {
            KeyLookup::Unknown
        }
    }
}

fn trust_at(ks: &Ks) -> TrustState {
    let source = OneKey {
        kid: ckid(ks.name, ks.current),
        key: ck(ks.name, ks.current).public_key(),
    };
    let verified = verify_keyset(&ks.resigned(), &source).unwrap();
    TrustState::new(
        verified,
        InstallId::parse(INSTALL).unwrap(),
        rk(1).jwk(),
        PositiveInteger::new(1).unwrap(),
    )
}

/// The trust state of an endpoint just installed: epoch 1, the key
/// `NAME_A:1`.
fn installed() -> TrustState {
    trust_at(&Ks::first(1, NAME_A))
}

/// The key set of epoch 2 the recovery key signs, whose keys are `NAME_B:1`
/// and `extra`.
fn recovery_keyset(extra: &[(&'static str, u64)]) -> Ks {
    let mut ks = Ks::first(2, NAME_B);
    ks.keys.extend_from_slice(extra);
    ks
}

/// Moves `trust` to epoch 2 with the recovery key, returning the change.
fn recover(trust: &mut TrustState, extra: &[(&'static str, u64)]) -> EpochChange {
    let receipt = trust.receive_keyset(&recovery_keyset(extra).recovery_signed(1));
    assert_eq!(receipt.result(), &DocumentResult::Applied);
    let change = receipt.epoch_change().unwrap();
    assert_eq!(
        change,
        EpochChange {
            old_epoch: 1,
            new_epoch: 2
        }
    );
    change
}

// --- times and commands ------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-23T00:00:00Z".parse().unwrap()
}

fn hours(n: i64) -> SignedDuration {
    SignedDuration::from_hours(n)
}

fn minutes(n: i64) -> SignedDuration {
    SignedDuration::from_mins(n)
}

const NS: SignedDuration = SignedDuration::from_nanos(1);

/// The time commands are received at unless a test says otherwise: well
/// inside the default window.
fn now() -> Timestamp {
    t0() + minutes(10)
}

fn id(text: &str) -> LowerUuid {
    LowerUuid::parse(text).unwrap()
}

fn cid_text(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn cid(n: u32) -> LowerUuid {
    id(&cid_text(n))
}

/// A `senta-command`, by default a `diagnose` for `ENDPOINT` at epoch 1,
/// issued at `t0` and expiring an hour later.
#[derive(Clone)]
struct Cmd {
    command_id: String,
    endpoint_id: &'static str,
    seq: u64,
    issued_at: Timestamp,
    expires_at: Timestamp,
    epoch: u64,
    signer: (&'static str, u64),
}

impl Cmd {
    fn new(n: u32, seq: u64) -> Self {
        Self {
            command_id: cid_text(n),
            endpoint_id: ENDPOINT,
            seq,
            issued_at: t0(),
            expires_at: t0() + hours(1),
            epoch: 1,
            signer: (NAME_A, 1),
        }
    }

    fn id(&self) -> LowerUuid {
        id(&self.command_id)
    }

    fn to(mut self, endpoint_id: &'static str) -> Self {
        self.endpoint_id = endpoint_id;
        self
    }

    fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    fn signer(mut self, name: &'static str, version: u64) -> Self {
        self.signer = (name, version);
        self
    }

    fn window(mut self, issued_at: Timestamp, expires_at: Timestamp) -> Self {
        self.issued_at = issued_at;
        self.expires_at = expires_at;
        self
    }

    fn payload(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "command_id": self.command_id,
            "endpoint_id": self.endpoint_id,
            "seq": self.seq,
            "issued_at": self.issued_at.to_string(),
            "expires_at": self.expires_at.to_string(),
            "recovery_epoch": self.epoch,
            "kind": "diagnose",
            "args": {},
        }))
        .unwrap()
    }

    fn jws(&self) -> String {
        let (name, version) = self.signer;
        ck(name, version).sign(Typ::Command, &ckid(name, version), &self.payload())
    }
}

// --- the recording store -----------------------------------------------------

/// A batch the store wrote, or the read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Load,
    Create,
    Accept,
    Finish,
    Reject,
    ResetEpoch,
    Prune,
}

#[derive(Debug, PartialEq, Eq)]
struct Down;

impl fmt::Display for Down {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the store is down")
    }
}

impl std::error::Error for Down {}

#[derive(Debug, Default)]
struct Control {
    failing: Vec<Op>,
    written: Vec<Op>,
}

/// A memory store that logs the batches it writes and fails the operations
/// its control names, writing nothing for them.
#[derive(Debug, Default)]
struct TestStore {
    inner: MemoryCommandStore,
    control: Rc<RefCell<Control>>,
}

impl TestStore {
    fn control(&self) -> Ctl {
        Ctl(Rc::clone(&self.control))
    }

    fn check(&self, op: Op) -> Result<(), Down> {
        let mut control = self.control.borrow_mut();
        if control.failing.contains(&op) {
            return Err(Down);
        }
        if op != Op::Load {
            control.written.push(op);
        }
        Ok(())
    }
}

/// The test's handle on a store's control.
#[derive(Clone)]
struct Ctl(Rc<RefCell<Control>>);

impl Ctl {
    fn fail(&self, ops: &[Op]) {
        self.0.borrow_mut().failing = ops.to_vec();
    }

    fn recover(&self) {
        self.0.borrow_mut().failing.clear();
    }

    /// Returns the batches written since the last call.
    fn take(&self) -> Vec<Op> {
        std::mem::take(&mut self.0.borrow_mut().written)
    }
}

impl CommandStore for TestStore {
    type Error = Down;

    fn load(&self) -> Result<Option<StoredCommandState>, Down> {
        self.check(Op::Load)?;
        Ok(self.inner.load().unwrap())
    }

    fn create(&mut self, endpoint_id: LowerUuid, epoch: u64) -> Result<(), Down> {
        self.check(Op::Create)?;
        self.inner.create(endpoint_id, epoch).unwrap();
        Ok(())
    }

    fn accept(
        &mut self,
        seq: u64,
        command_id: LowerUuid,
        expires_at: Timestamp,
    ) -> Result<(), Down> {
        self.check(Op::Accept)?;
        self.inner.accept(seq, command_id, expires_at).unwrap();
        Ok(())
    }

    fn finish(&mut self, command_id: LowerUuid, result: &CommandResultKind) -> Result<(), Down> {
        self.check(Op::Finish)?;
        self.inner.finish(command_id, result).unwrap();
        Ok(())
    }

    fn reject(
        &mut self,
        command_id: LowerUuid,
        expires_at: Timestamp,
        result: &CommandResultKind,
    ) -> Result<(), Down> {
        self.check(Op::Reject)?;
        self.inner.reject(command_id, expires_at, result).unwrap();
        Ok(())
    }

    fn reset_epoch(&mut self, epoch: u64) -> Result<(), Down> {
        self.check(Op::ResetEpoch)?;
        self.inner.reset_epoch(epoch).unwrap();
        Ok(())
    }

    fn prune(&mut self, command_ids: &[LowerUuid]) -> Result<(), Down> {
        self.check(Op::Prune)?;
        self.inner.prune(command_ids).unwrap();
        Ok(())
    }
}

type Machine = CommandStateMachine<TestStore>;

/// A state machine just created for `ENDPOINT` over `trust`, and its store's
/// control, with the creation already taken from the log.
fn machine(trust: &TrustState) -> (Machine, Ctl) {
    let store = TestStore::default();
    let ctl = store.control();
    let machine = Machine::create(store, id(ENDPOINT), trust).unwrap();
    assert_eq!(ctl.take(), [Op::Create]);
    (machine, ctl)
}

/// The state the store holds.
fn stored(machine: &Machine) -> StoredCommandState {
    machine.store().inner.state().unwrap().clone()
}

/// Makes the state machine again from its own store.
fn restart(machine: Machine) -> Machine {
    let machine = Machine::restore(machine.into_store()).unwrap();
    assert_eq!(machine.state(), &stored(&machine));
    machine
}

fn rejected(result: DocumentResult) -> CommandResultKind {
    CommandResultKind::Rejected(result)
}

fn report(cmd: &Cmd, result: CommandResultKind) -> CommandVerdict {
    CommandVerdict::Report {
        command_id: cmd.id(),
        result,
    }
}

fn failed(reason: &str) -> CommandResultKind {
    CommandResultKind::Failed {
        reason: reason.to_owned(),
    }
}

/// Receives `cmd` at `now()`, asserting that it is to be run.
#[track_caller]
fn execute(machine: &mut Machine, trust: &TrustState, cmd: &Cmd) {
    execute_at(machine, trust, cmd, now());
}

#[track_caller]
fn execute_at(machine: &mut Machine, trust: &TrustState, cmd: &Cmd, at: Timestamp) {
    let verdict = machine.receive(&cmd.jws(), trust, at).unwrap();
    assert_eq!(verdict.command_id(), Some(cmd.id()));
    assert_eq!(verdict.result(), None);
    match verdict {
        CommandVerdict::Execute(content) => assert_eq!(content.command_id(), cmd.id()),
        other => panic!("expected Execute, got {other:?}"),
    }
}

/// Receives `cmd` at `at`, asserting the verdict, and that the state
/// machine and its store agree afterwards.
#[track_caller]
fn receive_at(
    machine: &mut Machine,
    trust: &TrustState,
    cmd: &Cmd,
    at: Timestamp,
) -> CommandVerdict {
    let verdict = machine.receive(&cmd.jws(), trust, at).unwrap();
    assert_eq!(machine.state(), &stored(machine));
    verdict
}

#[track_caller]
fn receive(machine: &mut Machine, trust: &TrustState, cmd: &Cmd) -> CommandVerdict {
    receive_at(machine, trust, cmd, now())
}

fn record(expires_at: Timestamp, status: RecordStatus) -> CommandRecord {
    CommandRecord { expires_at, status }
}

// --- acceptance and results --------------------------------------------------

#[test]
fn diagnose_runs_and_its_result_is_recorded() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 7);
    let verdict = receive(&mut m, &trust, &cmd);
    let CommandVerdict::Execute(content) = &verdict else {
        panic!("expected Execute, got {verdict:?}");
    };
    assert_eq!(content.seq().get(), 7);
    assert_eq!(content.endpoint_id(), id(ENDPOINT));
    assert_eq!(verdict.command_id(), Some(cmd.id()));
    assert_eq!(ctl.take(), [Op::Accept]);
    assert_eq!(m.last_seq(), Some(7));
    assert_eq!(
        m.record(cmd.id()),
        Some(&record(cmd.expires_at, RecordStatus::Running))
    );

    m.finish(cmd.id(), CommandResultKind::Done).unwrap();
    assert_eq!(ctl.take(), [Op::Finish]);
    assert_eq!(
        m.record(cmd.id()),
        Some(&record(
            cmd.expires_at,
            RecordStatus::Finished(CommandResultKind::Done)
        ))
    );
    assert_eq!(m.state(), &stored(&m));

    let other = Cmd::new(2, 8);
    execute(&mut m, &trust, &other);
    m.finish(other.id(), failed("disk full")).unwrap();
    assert_eq!(
        m.record(other.id()).unwrap().status,
        RecordStatus::Finished(failed("disk full"))
    );
}

#[test]
fn a_running_command_received_again_is_already_done() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 1);
    execute(&mut m, &trust, &cmd);
    ctl.take();
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, CommandResultKind::AlreadyDone)
    );
    assert!(ctl.take().is_empty());
}

#[test]
fn a_recorded_command_returns_its_stored_result_whatever_it_is() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let done = Cmd::new(1, 1);
    let fail = Cmd::new(2, 2);
    // Rejected as expired: its window passed long before `now()`.
    let expired = Cmd::new(3, 50).window(t0() - hours(5), t0() - hours(4));
    execute(&mut m, &trust, &done);
    execute(&mut m, &trust, &fail);
    m.finish(done.id(), CommandResultKind::Done).unwrap();
    m.finish(fail.id(), failed("boom")).unwrap();
    assert_eq!(
        receive(&mut m, &trust, &expired),
        report(&expired, rejected(DocumentResult::Expired))
    );
    ctl.take();
    let floor = m.last_seq();

    // Received again past their windows, and below the floor for the
    // first two: the stored result, nothing run, nothing written.
    let later = t0() + hours(3);
    assert_eq!(
        receive_at(&mut m, &trust, &done, later),
        report(&done, CommandResultKind::Done)
    );
    assert_eq!(
        receive_at(&mut m, &trust, &fail, later),
        report(&fail, failed("boom"))
    );
    assert_eq!(
        receive_at(&mut m, &trust, &expired, later),
        report(&expired, rejected(DocumentResult::Expired))
    );
    assert!(ctl.take().is_empty());
    assert_eq!(m.last_seq(), floor);
}

// --- the order of the checks ---------------------------------------------------

#[test]
fn each_step_ends_the_judgement_and_writes_only_its_batch() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 10));
    ctl.take();
    let before = stored(&m);

    // Step 1: verification, then the epoch. Nothing written.
    let forged = Cmd::new(2, 11);
    let jws = stranger().sign(Typ::Command, &ckid(NAME_A, 1), &forged.payload());
    let verdict = m.receive(&jws, &trust, now()).unwrap();
    assert_eq!(
        verdict,
        CommandVerdict::Unverified {
            result: DocumentResult::BadSignature,
            kid: Some(ckid(NAME_A, 1)),
        }
    );
    let epoch = Cmd::new(3, 11).epoch(2);
    assert_eq!(
        receive(&mut m, &trust, &epoch),
        report(&epoch, rejected(DocumentResult::EpochMismatch))
    );
    // Step 2: the target. Nothing written.
    let target = Cmd::new(4, 11).to(OTHER_ENDPOINT);
    assert_eq!(
        receive(&mut m, &trust, &target),
        report(&target, rejected(DocumentResult::WrongTarget))
    );
    // Step 3: the record. Nothing written.
    assert_eq!(
        receive(&mut m, &trust, &Cmd::new(1, 10)),
        report(&Cmd::new(1, 10), CommandResultKind::AlreadyDone)
    );
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);

    // Step 4: the sequence floor. A rejection record only.
    let stale = Cmd::new(5, 10);
    assert_eq!(
        receive(&mut m, &trust, &stale),
        report(&stale, rejected(DocumentResult::Stale))
    );
    assert_eq!(ctl.take(), [Op::Reject]);
    assert_eq!(m.last_seq(), Some(10));
    assert_eq!(
        m.record(stale.id()),
        Some(&record(
            stale.expires_at,
            RecordStatus::Finished(rejected(DocumentResult::Stale))
        ))
    );

    // Step 5: the window. A rejection record only.
    let early = Cmd::new(6, 12).window(t0() + hours(2), t0() + hours(3));
    assert_eq!(
        receive(&mut m, &trust, &early),
        report(&early, rejected(DocumentResult::NotYetValid))
    );
    assert_eq!(ctl.take(), [Op::Reject]);
    assert_eq!(m.last_seq(), Some(10));

    // Step 6: the acceptance only.
    execute(&mut m, &trust, &Cmd::new(7, 11));
    assert_eq!(ctl.take(), [Op::Accept]);
    assert_eq!(m.last_seq(), Some(11));
    assert_eq!(m.state(), &stored(&m));
}

#[test]
fn a_command_breaking_two_rules_gets_the_earlier_steps_result() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let known = Cmd::new(1, 10);
    execute(&mut m, &trust, &known);
    ctl.take();
    let before = stored(&m);

    // Epoch and target: the epoch.
    let cmd = Cmd::new(2, 11).epoch(5).to(OTHER_ENDPOINT);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::EpochMismatch))
    );
    // Another endpoint and a known command_id: the target.
    let cmd = known.clone().to(OTHER_ENDPOINT);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::WrongTarget))
    );
    // Another endpoint and a low seq: the target.
    let cmd = Cmd::new(3, 1).to(OTHER_ENDPOINT);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::WrongTarget))
    );
    // A known command_id with a low seq: the stored result.
    let mut cmd = known.clone();
    cmd.seq = 3;
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, CommandResultKind::AlreadyDone)
    );
    // A known command_id, expired: the stored result.
    let cmd = known.clone().window(t0() - hours(5), t0() - hours(4));
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, CommandResultKind::AlreadyDone)
    );
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);

    // A low seq, expired: stale.
    let cmd = Cmd::new(4, 9).window(t0() - hours(5), t0() - hours(4));
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::Stale))
    );
    assert_eq!(ctl.take(), [Op::Reject]);
    // Too long a lifetime, issued in the future: expired.
    let cmd = Cmd::new(5, 20).window(t0() + hours(3), t0() + hours(28));
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::Expired))
    );
    assert_eq!(ctl.take(), [Op::Reject]);
    assert_eq!(m.last_seq(), Some(10));
}

#[test]
fn verification_failures_carry_no_command_id() {
    let mut ks = Ks::first(1, NAME_A);
    ks.version = 3;
    ks.keys = vec![(NAME_A, 2), (NAME_A, 3)];
    ks.current = 3;
    ks.revoked = vec![ckid(NAME_A, 1)];
    let trust = trust_at(&ks);
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 1);

    let cases = [
        (
            stranger().sign(Typ::Command, &ckid(NAME_A, 3), &cmd.payload()),
            DocumentResult::BadSignature,
            ckid(NAME_A, 3),
        ),
        (
            ck(NAME_A, 1).sign(Typ::Command, &ckid(NAME_A, 1), &cmd.payload()),
            DocumentResult::RevokedKid,
            ckid(NAME_A, 1),
        ),
        (
            ck(NAME_A, 9).sign(Typ::Command, &ckid(NAME_A, 9), &cmd.payload()),
            DocumentResult::UnknownKid,
            ckid(NAME_A, 9),
        ),
        (
            rk(1).sign(Typ::Command, &rkid(1), &cmd.payload()),
            DocumentResult::WrongKeyClass,
            rkid(1),
        ),
    ];
    for (jws, result, kid) in cases {
        let verdict = m.receive(&jws, &trust, now()).unwrap();
        assert_eq!(verdict.command_id(), None);
        assert_eq!(verdict.result(), Some(rejected(result.clone())));
        assert_eq!(
            verdict,
            CommandVerdict::Unverified {
                result,
                kid: Some(kid)
            }
        );
    }
    assert!(ctl.take().is_empty());
    assert_eq!(m.last_seq(), None);
    assert!(m.state().records.is_empty());
}

#[test]
fn the_diagnostic_kid_is_the_raw_header_kid_when_the_header_reads() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 1);

    // A good header, a bad signature: the kid as written.
    let kid = ckid(NAME_A, 1);
    let jws = stranger().sign(Typ::Command, &kid, &cmd.payload());
    let verdict = m.receive(&jws, &trust, now()).unwrap();
    let CommandVerdict::Unverified {
        kid: Some(seen), ..
    } = &verdict
    else {
        panic!("expected a diagnostic kid, got {verdict:?}");
    };
    assert_eq!(seen, &kid);

    // A JWS that is not one, and a header that is not JSON: no kid.
    let not_json = ck(NAME_A, 1).sign_raw(b"{not json", &cmd.payload());
    for jws in ["not-a-jws", "a.b", not_json.as_str()] {
        assert_eq!(
            m.receive(jws, &trust, now()).unwrap(),
            CommandVerdict::Unverified {
                result: DocumentResult::SchemaError,
                kid: None,
            }
        );
    }
    assert!(ctl.take().is_empty());
}

#[test]
fn every_verdict_past_verification_carries_the_command_id() {
    let trust = installed();
    let (mut m, _) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 10));
    let cases = [
        Cmd::new(2, 11).epoch(3),
        Cmd::new(3, 11).to(OTHER_ENDPOINT),
        Cmd::new(4, 10),
        Cmd::new(5, 11).window(t0() - hours(5), t0() - hours(4)),
        Cmd::new(6, 11).window(t0() + hours(2), t0() + hours(3)),
        Cmd::new(1, 10),
        Cmd::new(7, 11),
    ];
    for cmd in cases {
        assert_eq!(receive(&mut m, &trust, &cmd).command_id(), Some(cmd.id()));
    }
}

// --- the sequence floor --------------------------------------------------------

#[test]
fn the_floor_rejects_equal_and_lower_seqs_and_admits_skips() {
    let trust = installed();
    let (mut m, _) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 5));
    for (n, seq) in [(2, 5), (3, 4), (4, 0)] {
        let cmd = Cmd::new(n, seq);
        assert_eq!(
            receive(&mut m, &trust, &cmd),
            report(&cmd, rejected(DocumentResult::Stale))
        );
        assert_eq!(m.last_seq(), Some(5));
    }
    execute(&mut m, &trust, &Cmd::new(5, 9));
    assert_eq!(m.last_seq(), Some(9));
}

#[test]
fn a_window_rejection_does_not_move_the_floor() {
    let trust = installed();
    let (mut m, _) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 10));
    let expired = Cmd::new(2, 20).window(t0() - hours(5), t0() - hours(4));
    let early = Cmd::new(3, 30).window(t0() + hours(2), t0() + hours(3));
    assert_eq!(
        receive(&mut m, &trust, &expired),
        report(&expired, rejected(DocumentResult::Expired))
    );
    assert_eq!(
        receive(&mut m, &trust, &early),
        report(&early, rejected(DocumentResult::NotYetValid))
    );
    assert_eq!(m.last_seq(), Some(10));
    execute(&mut m, &trust, &Cmd::new(4, 15));
    assert_eq!(m.last_seq(), Some(15));
}

// --- the validity window -------------------------------------------------------

#[test]
fn the_window_bounds_are_strict() {
    let trust = installed();
    // Issued at t0, expiring at t0 + 1 hour.
    let base = Cmd::new(1, 1);
    let late_edge = base.expires_at + hours(1);
    let early_edge = base.issued_at - hours(1);
    let cases = [
        (late_edge, None),
        (late_edge + NS, Some(DocumentResult::Expired)),
        (early_edge, None),
        (early_edge - NS, Some(DocumentResult::NotYetValid)),
    ];
    for (at, expected) in cases {
        let (mut m, _) = machine(&trust);
        match expected {
            None => execute_at(&mut m, &trust, &base, at),
            Some(result) => assert_eq!(
                receive_at(&mut m, &trust, &base, at),
                report(&base, rejected(result))
            ),
        }
    }

    // Lifetimes, received in the middle of the window.
    let full = Cmd::new(2, 1).window(t0(), t0() + hours(24));
    let (mut m, _) = machine(&trust);
    execute_at(&mut m, &trust, &full, t0() + hours(12));
    let over = Cmd::new(3, 1).window(t0(), t0() + hours(24) + SignedDuration::from_millis(1));
    let (mut m, _) = machine(&trust);
    assert_eq!(
        receive_at(&mut m, &trust, &over, t0() + hours(12)),
        report(&over, rejected(DocumentResult::Expired))
    );
    // Over the lifetime and issued in the future: the lifetime decides.
    let future = Cmd::new(4, 1).window(t0() + hours(5), t0() + hours(30));
    assert_eq!(
        receive_at(&mut m, &trust, &future, t0()),
        report(&future, rejected(DocumentResult::Expired))
    );
}

// --- restarts ------------------------------------------------------------------

#[test]
fn a_restored_state_machine_does_not_run_a_command_again() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 1);
    let stale = Cmd::new(2, 1);

    // After the acceptance alone.
    execute(&mut m, &trust, &cmd);
    let mut m = restart(m);
    assert_eq!(m.last_seq(), Some(1));
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, CommandResultKind::AlreadyDone)
    );

    // After the result.
    m.finish(cmd.id(), failed("no space")).unwrap();
    let mut m = restart(m);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, failed("no space"))
    );

    // After a rejection record.
    assert_eq!(
        receive(&mut m, &trust, &stale),
        report(&stale, rejected(DocumentResult::Stale))
    );
    let mut m = restart(m);
    ctl.take();
    assert_eq!(
        receive(&mut m, &trust, &stale),
        report(&stale, rejected(DocumentResult::Stale))
    );
    assert!(ctl.take().is_empty());
}

#[test]
fn a_restored_state_after_reconciliation_has_the_new_epoch_and_no_floor() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 1000);
    execute(&mut m, &trust, &cmd);
    // The new key set keeps `NAME_A:1`, so the old command still verifies.
    let change = recover(&mut trust, &[(NAME_A, 1)]);
    m.apply_epoch_change(change).unwrap();
    assert_eq!(ctl.take(), [Op::Accept, Op::ResetEpoch]);
    let mut m = restart(m);
    assert_eq!(m.epoch(), 2);
    assert_eq!(m.last_seq(), None);
    assert_eq!(
        m.record(cmd.id()),
        Some(&record(cmd.expires_at, RecordStatus::Running))
    );

    // The same command again: of the old epoch, so not run, and nothing
    // written. A command of the new epoch under the old floor runs.
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::EpochMismatch))
    );
    assert!(ctl.take().is_empty());
    execute(&mut m, &trust, &Cmd::new(2, 3).epoch(2).signer(NAME_B, 1));
    assert_eq!(ctl.take(), [Op::Accept]);
}

#[test]
fn create_and_restore() {
    let trust = installed();
    let (m, _) = machine(&trust);
    let m = restart(m);
    assert_eq!(m.endpoint_id(), id(ENDPOINT));
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.last_seq(), None);
    assert!(m.state().records.is_empty());

    // Creating over a created store: refused, nothing written.
    let store = m.into_store();
    let ctl = store.control();
    let before = store.inner.clone();
    let mut store = store;
    let other = id(OTHER_ENDPOINT);
    assert!(matches!(
        CommandStateMachine::create(&mut store, other, &trust),
        Err(CommandError::AlreadyCreated)
    ));
    assert!(ctl.take().is_empty());
    assert_eq!(store.inner, before);

    // Restoring an empty store.
    assert!(matches!(
        Machine::restore(TestStore::default()),
        Err(CommandError::NotCreated)
    ));
    assert!(matches!(
        CommandStateMachine::restore(MemoryCommandStore::new()),
        Err(CommandError::NotCreated)
    ));

    // A failed creation.
    let store = TestStore::default();
    let ctl = store.control();
    ctl.fail(&[Op::Create]);
    assert!(matches!(
        Machine::create(store, id(ENDPOINT), &trust),
        Err(CommandError::Store(Down))
    ));
    let store = TestStore::default();
    store.control().fail(&[Op::Load]);
    assert!(matches!(
        Machine::restore(store),
        Err(CommandError::Store(Down))
    ));

    // Enrolling again: the caller empties the store first.
    let mut memory = MemoryCommandStore::new();
    CommandStateMachine::create(&mut memory, id(ENDPOINT), &trust).unwrap();
    memory.clear();
    let m = CommandStateMachine::create(&mut memory, other, &trust).unwrap();
    assert_eq!(m.endpoint_id(), other);
}

#[test]
fn a_state_restored_under_a_later_trust_state_reconciles_without_an_event() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 1000));
    recover(&mut trust, &[]);
    let mut m = restart(m);
    ctl.take();
    let cmd = Cmd::new(2, 10).epoch(2).signer(NAME_B, 1);
    execute(&mut m, &trust, &cmd);
    assert_eq!(ctl.take(), [Op::ResetEpoch, Op::Accept]);
    assert_eq!((m.epoch(), m.last_seq()), (2, Some(10)));
}

// --- store failures ------------------------------------------------------------

#[test]
fn a_failed_acceptance_runs_nothing_and_changes_nothing() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 1));
    ctl.take();
    let before = stored(&m);
    let cmd = Cmd::new(2, 2);
    ctl.fail(&[Op::Accept]);
    assert!(matches!(
        m.receive(&cmd.jws(), &trust, now()),
        Err(CommandError::Store(Down))
    ));
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);
    assert_eq!(m.state(), &before);
    assert_eq!(m.last_seq(), Some(1));
    assert_eq!(m.record(cmd.id()), None);

    ctl.recover();
    execute(&mut m, &trust, &cmd);
    assert_eq!(m.last_seq(), Some(2));
}

#[test]
fn a_failed_acceptance_after_reconciliation_keeps_the_reconciliation() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    let old = Cmd::new(1, 1000);
    execute(&mut m, &trust, &old);
    recover(&mut trust, &[]);
    ctl.take();

    let cmd = Cmd::new(2, 5).epoch(2).signer(NAME_B, 1);
    ctl.fail(&[Op::Accept]);
    assert!(matches!(
        m.receive(&cmd.jws(), &trust, now()),
        Err(CommandError::Store(Down))
    ));
    assert_eq!(ctl.take(), [Op::ResetEpoch]);
    for state in [stored(&m), m.state().clone()] {
        assert_eq!(state.epoch, 2);
        assert_eq!(state.last_seq, None);
        assert_eq!(
            state.records.get(&old.id()),
            Some(&record(old.expires_at, RecordStatus::Running))
        );
        assert_eq!(state.records.get(&cmd.id()), None);
    }
    ctl.recover();
    let mut m = restart(m);
    assert_eq!((m.epoch(), m.last_seq()), (2, None));
    execute(&mut m, &trust, &cmd);
    assert_eq!(ctl.take(), [Op::Accept]);
}

#[test]
fn failed_writes_of_the_other_batches_change_nothing() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    let cmd = Cmd::new(1, 10);
    execute(&mut m, &trust, &cmd);
    ctl.take();
    let before = stored(&m);
    ctl.fail(&[Op::Reject, Op::Finish, Op::Prune, Op::ResetEpoch]);

    assert!(matches!(
        m.receive(&Cmd::new(2, 1).jws(), &trust, now()),
        Err(CommandError::Store(Down))
    ));
    assert!(matches!(
        m.finish(cmd.id(), CommandResultKind::Done),
        Err(CommandError::Store(Down))
    ));
    assert!(matches!(
        m.prune(t0() + hours(10)),
        Err(CommandError::Store(Down))
    ));
    let change = recover(&mut trust, &[]);
    assert!(matches!(
        m.apply_epoch_change(change),
        Err(CommandError::Store(Down))
    ));
    assert!(matches!(
        m.receive(&Cmd::new(3, 1).jws(), &trust, now()),
        Err(CommandError::Store(Down))
    ));
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);
    assert_eq!(m.state(), &before);
}

// --- finishing -----------------------------------------------------------------

#[test]
fn finishing_needs_a_running_command_and_a_completion() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    let running = Cmd::new(1, 1);
    let done = Cmd::new(2, 2);
    let stale = Cmd::new(3, 1);
    execute(&mut m, &trust, &running);
    execute(&mut m, &trust, &done);
    m.finish(done.id(), CommandResultKind::Done).unwrap();
    receive(&mut m, &trust, &stale);
    ctl.take();
    let before = stored(&m);

    for command_id in [cid(99), done.id(), stale.id()] {
        let error = m.finish(command_id, failed("late")).unwrap_err();
        assert!(
            matches!(error, CommandError::NotRunning { command_id: seen } if seen == command_id)
        );
    }
    for result in [
        CommandResultKind::AlreadyDone,
        rejected(DocumentResult::Stale),
        CommandResultKind::Other("paused".to_owned()),
    ] {
        assert!(matches!(
            m.finish(running.id(), result),
            Err(CommandError::NotACompletion)
        ));
    }
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);
    assert_eq!(
        m.record(running.id()).unwrap().status,
        RecordStatus::Running
    );
}

// --- retention -----------------------------------------------------------------

#[test]
fn pruning_removes_only_records_past_retention() {
    let trust = installed();
    let (mut m, ctl) = machine(&trust);
    // Expiring at t0 + 1h, t0 + 2h and t0 + 3h; the first stays running.
    let first = Cmd::new(1, 1);
    let second = Cmd::new(2, 2).window(t0(), t0() + hours(2));
    let third = Cmd::new(3, 3).window(t0(), t0() + hours(3));
    for cmd in [&first, &second, &third] {
        execute(&mut m, &trust, cmd);
    }
    m.finish(second.id(), CommandResultKind::Done).unwrap();
    ctl.take();

    // Nothing past retention: nothing written.
    assert!(m.prune(first.expires_at + hours(1)).unwrap().is_empty());
    assert!(ctl.take().is_empty());

    // At exactly t0 + 3h the second is on its edge and stays.
    let at = second.expires_at + hours(1);
    assert_eq!(m.prune(at).unwrap(), [first.id()]);
    assert_eq!(ctl.take(), [Op::Prune]);
    assert_eq!(m.record(first.id()), None);
    assert!(m.record(second.id()).is_some());
    assert_eq!(m.prune(at + NS).unwrap(), [second.id()]);
    assert!(m.record(third.id()).is_some());
    assert_eq!(m.state(), &stored(&m));
    assert_eq!(m.last_seq(), Some(3));
}

#[test]
fn a_pruned_command_received_again_is_not_run() {
    let trust = installed();
    let (mut m, _) = machine(&trust);
    // Accepted and done.
    let done = Cmd::new(1, 100);
    execute(&mut m, &trust, &done);
    m.finish(done.id(), CommandResultKind::Done).unwrap();
    // 120 expired, then 121 accepted: 120 sits under the floor.
    let at = t0() + minutes(30);
    let expired_low = Cmd::new(2, 120).window(t0() - hours(5), t0() - hours(4));
    assert_eq!(
        receive_at(&mut m, &trust, &expired_low, at),
        report(&expired_low, rejected(DocumentResult::Expired))
    );
    execute_at(
        &mut m,
        &trust,
        &Cmd::new(3, 121).window(t0(), t0() + hours(20)),
        at,
    );
    // Expired with a seq above the floor.
    let expired_high = Cmd::new(4, 500).window(t0() - hours(5), t0() - hours(4));
    assert_eq!(
        receive_at(&mut m, &trust, &expired_high, at),
        report(&expired_high, rejected(DocumentResult::Expired))
    );

    let pruned_at = t0() + hours(3);
    let mut pruned = m.prune(pruned_at).unwrap();
    pruned.sort_unstable();
    let mut expected = vec![done.id(), expired_low.id(), expired_high.id()];
    expected.sort_unstable();
    assert_eq!(pruned, expected);
    assert_eq!(m.last_seq(), Some(121));

    for at in [pruned_at, pruned_at + hours(1)] {
        assert_eq!(
            receive_at(&mut m, &trust, &done, at),
            report(&done, rejected(DocumentResult::Stale))
        );
        assert_eq!(
            receive_at(&mut m, &trust, &expired_low, at),
            report(&expired_low, rejected(DocumentResult::Stale))
        );
        assert_eq!(
            receive_at(&mut m, &trust, &expired_high, at),
            report(&expired_high, rejected(DocumentResult::Expired))
        );
        m.prune(at + hours(1)).unwrap();
    }
    assert_eq!(m.last_seq(), Some(121));
}

// --- recovery epochs -----------------------------------------------------------

#[test]
fn an_epoch_change_restarts_the_floor() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    let old = Cmd::new(1, 1000);
    execute(&mut m, &trust, &old);
    // The new key set keeps `NAME_A:1` among its keys.
    let change = recover(&mut trust, &[(NAME_A, 1)]);
    ctl.take();
    m.apply_epoch_change(change).unwrap();
    assert_eq!(ctl.take(), [Op::ResetEpoch]);
    assert_eq!((m.epoch(), m.last_seq()), (2, None));

    execute(&mut m, &trust, &Cmd::new(2, 5).epoch(2).signer(NAME_B, 1));
    assert_eq!(m.last_seq(), Some(5));
    // The old command again, its kid still trusted: the epoch.
    assert_eq!(
        receive(&mut m, &trust, &old),
        report(&old, rejected(DocumentResult::EpochMismatch))
    );
    let older = Cmd::new(3, 1001);
    assert_eq!(
        receive(&mut m, &trust, &older),
        report(&older, rejected(DocumentResult::EpochMismatch))
    );

    // Late and repeated events do nothing.
    m.apply_epoch_change(change).unwrap();
    m.apply_epoch_change(EpochChange {
        old_epoch: 0,
        new_epoch: 1,
    })
    .unwrap();
    assert_eq!(ctl.take(), [Op::Accept]);
    assert_eq!((m.epoch(), m.last_seq()), (2, Some(5)));
}

#[test]
fn receiving_reconciles_first_and_the_reconciliation_stays() {
    for case in 0..3 {
        let mut trust = installed();
        let (mut m, ctl) = machine(&trust);
        execute(&mut m, &trust, &Cmd::new(1, 1000));
        recover(&mut trust, &[]);
        ctl.take();

        let verdict = match case {
            // Rejected at step 1, by verification.
            0 => {
                let jws = Cmd::new(2, 1).jws();
                m.receive(&jws, &trust, now()).unwrap()
            }
            // Rejected at step 1, by the epoch.
            1 => receive(&mut m, &trust, &Cmd::new(2, 1).signer(NAME_B, 1)),
            // Rejected at step 2.
            _ => receive(
                &mut m,
                &trust,
                &Cmd::new(2, 1).epoch(2).signer(NAME_B, 1).to(OTHER_ENDPOINT),
            ),
        };
        assert!(verdict.result().is_some(), "{verdict:?}");
        assert_eq!(ctl.take(), [Op::ResetEpoch]);
        assert_eq!((m.epoch(), m.last_seq()), (2, None));
        assert_eq!(m.state(), &stored(&m));
    }
}

#[test]
fn a_trust_state_behind_the_stored_epoch_is_an_error() {
    let old_trust = installed();
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    let change = recover(&mut trust, &[]);
    m.apply_epoch_change(change).unwrap();
    ctl.take();
    let before = stored(&m);
    let error = m
        .receive(&Cmd::new(1, 1).jws(), &old_trust, now())
        .unwrap_err();
    assert!(matches!(
        error,
        CommandError::TrustStateBehind {
            trust_epoch: 1,
            stored_epoch: 2
        }
    ));
    assert!(ctl.take().is_empty());
    assert_eq!(stored(&m), before);
}

#[test]
fn a_leaked_key_is_contained_by_the_epoch() {
    let mut trust = installed();
    let (mut m, _) = machine(&trust);
    let max = Integer::MAX.get();

    // A far future epoch: rejected.
    let cmd = Cmd::new(1, 1).epoch(max);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::EpochMismatch))
    );
    // A huge seq in the current epoch: accepted, and it raises the floor.
    execute(&mut m, &trust, &Cmd::new(2, max));
    let normal = Cmd::new(3, 5);
    assert_eq!(
        receive(&mut m, &trust, &normal),
        report(&normal, rejected(DocumentResult::Stale))
    );

    // The recovery key moves the epoch on, revoking the leaked key.
    let mut ks = recovery_keyset(&[]);
    ks.revoked = vec![ckid(NAME_A, 1)];
    let receipt = trust.receive_keyset(&ks.recovery_signed(1));
    m.apply_epoch_change(receipt.epoch_change().unwrap())
        .unwrap();
    execute(&mut m, &trust, &Cmd::new(4, 1).epoch(2).signer(NAME_B, 1));

    // The leaked key no longer signs anything.
    let leaked = Cmd::new(5, max).epoch(2);
    assert_eq!(
        m.receive(&leaked.jws(), &trust, now()).unwrap(),
        CommandVerdict::Unverified {
            result: DocumentResult::RevokedKid,
            kid: Some(ckid(NAME_A, 1)),
        }
    );
}

#[test]
fn a_rotation_within_the_epoch_keeps_the_floor() {
    let mut trust = installed();
    let (mut m, ctl) = machine(&trust);
    execute(&mut m, &trust, &Cmd::new(1, 10));
    let mut ks = Ks::first(1, NAME_A);
    ks.version = 2;
    ks.keys = vec![(NAME_A, 1), (NAME_A, 2)];
    ks.current = 2;
    assert_eq!(
        trust.receive_keyset(&ks.rotated()).result(),
        &DocumentResult::Applied
    );
    ctl.take();
    let cmd = Cmd::new(2, 10).signer(NAME_A, 2);
    assert_eq!(
        receive(&mut m, &trust, &cmd),
        report(&cmd, rejected(DocumentResult::Stale))
    );
    assert_eq!(ctl.take(), [Op::Reject]);
    assert_eq!(m.epoch(), 1);
}
