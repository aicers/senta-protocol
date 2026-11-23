//! The sequence vector files: `keyset`, `leak`, `document_versions`,
//! `enroll_result` and `commands`. Every case starts from the standard
//! installation and takes its steps in order.

use jiff::SignedDuration;
use senta_protocol::auth::jws::Typ;
use senta_protocol::control::{
    ControlMessage, Documents, EnrollOutcome as ControlEnrollOutcome, EnrollResult,
};

use crate::fixtures::{
    self, ATTEMPT, CommandSpec, ENDPOINT, EPOCH, EnrollResultSpec, GROUP, INSTALL_ID, Issuer,
    KeyRing, KeysetSpec, MAX_INTEGER, OTHER_ATTEMPT, OTHER_CUSTOMER, OTHER_ENDPOINT, OTHER_TOKEN,
    SENTA_VERSION, TOKEN, VENDOR_RELEASE, b64, command_id, customer_kid, now, recovery_kid,
    rfc3339, spki,
};
use crate::json::J;
use crate::model::{
    Action, Attempt, Category, ChainInput, FORMAT_VERSION, KeysetPosition, SequenceCase,
    SlotSummary, StateSummary, Step, StepEnv, StepInput, VectorFile,
};
use crate::notation::{
    self, enroll_failed, enrolled, execute, keyset_gap, ok, rejected, repeat, tag,
};

/// The epoch a leaked document claims, far above any real one.
const FAR_EPOCH: u64 = 1000;

// --- state summaries ------------------------------------------------------------

fn keyset_state(recovery_epoch: u64, keyset_version: u64) -> StateSummary {
    StateSummary {
        keyset: Some(KeysetPosition {
            recovery_epoch,
            keyset_version,
        }),
        ..StateSummary::default()
    }
}

fn keys_state(recovery_epoch: u64, keyset_version: u64, recovery_key_version: u64) -> StateSummary {
    StateSummary {
        recovery_key_version: Some(recovery_key_version),
        ..keyset_state(recovery_epoch, keyset_version)
    }
}

fn enrolled_state(endpoint_id: Option<&str>) -> StateSummary {
    StateSummary {
        endpoint_id: Some(endpoint_id.map(str::to_owned)),
        ..StateSummary::default()
    }
}

fn seq_state(last_seq: Option<u64>) -> StateSummary {
    StateSummary {
        last_seq: Some(last_seq),
        ..StateSummary::default()
    }
}

fn policy_slot() -> J {
    J::tagged("policy", J::str(GROUP))
}

fn group_update_slot() -> J {
    J::tagged("group_update", J::str(GROUP))
}

fn slot_state(slot: J, verified: Option<u64>, applied: Option<u64>) -> StateSummary {
    StateSummary {
        slot: Some(SlotSummary {
            slot,
            verified_version: verified,
            applied_version: applied,
        }),
        ..StateSummary::default()
    }
}

// --- steps ------------------------------------------------------------------------

fn attempt() -> Attempt {
    Attempt {
        spki_sha256: b64(&spki()),
        attempt_id: ATTEMPT.to_owned(),
        token_id: TOKEN.to_owned(),
    }
}

fn document_env() -> StepEnv {
    StepEnv {
        now: Some(rfc3339(now())),
        senta_version: Some(SENTA_VERSION.to_owned()),
        attempt: None,
    }
}

fn step(action: Action, input: StepInput, env: StepEnv, expected: J, state: StateSummary) -> Step {
    Step {
        action,
        input,
        env,
        expected,
        state: Some(state),
    }
}

fn receive_keyset(jws: String, expected: J, state: StateSummary) -> Step {
    step(
        Action::ReceiveKeyset,
        StepInput {
            jws: Some(jws),
            ..StepInput::default()
        },
        StepEnv::default(),
        expected,
        state,
    )
}

fn receive_chain(documents: Vec<String>, expected: Vec<J>, state: StateSummary) -> Step {
    step(
        Action::ReceiveChain,
        StepInput {
            documents: Some(documents),
            ..StepInput::default()
        },
        StepEnv::default(),
        J::Arr(expected),
        state,
    )
}

fn receive_enroll_result(
    chain: Vec<String>,
    enroll_result: String,
    expected: J,
    state: StateSummary,
) -> Step {
    step(
        Action::ReceiveEnrollResult,
        StepInput {
            chain: Some(chain),
            enroll_result: Some(enroll_result),
            ..StepInput::default()
        },
        StepEnv {
            attempt: Some(attempt()),
            ..StepEnv::default()
        },
        expected,
        state,
    )
}

fn receive_enroll_result_message(message: String, expected: J, state: StateSummary) -> Step {
    step(
        Action::ReceiveEnrollResultMessage,
        StepInput {
            message: Some(message),
            ..StepInput::default()
        },
        StepEnv {
            attempt: Some(attempt()),
            ..StepEnv::default()
        },
        expected,
        state,
    )
}

fn receive_documents_message(message: String, expected: Vec<J>, state: StateSummary) -> Step {
    step(
        Action::ReceiveDocumentsMessage,
        StepInput {
            message: Some(message),
            ..StepInput::default()
        },
        document_env(),
        J::Arr(expected),
        state,
    )
}

fn receive_document(jws: String, expected: J, state: StateSummary) -> Step {
    step(
        Action::ReceiveDocument,
        StepInput {
            jws: Some(jws),
            ..StepInput::default()
        },
        document_env(),
        expected,
        state,
    )
}

fn receive_command(jws: String, expected: J, last_seq: Option<u64>) -> Step {
    step(
        Action::ReceiveCommand,
        StepInput {
            jws: Some(jws),
            ..StepInput::default()
        },
        StepEnv {
            now: Some(rfc3339(now())),
            ..StepEnv::default()
        },
        expected,
        seq_state(last_seq),
    )
}

fn finish_command(id: &str, last_seq: Option<u64>) -> Step {
    step(
        Action::FinishCommand,
        StepInput {
            command_id: Some(id.to_owned()),
            result: Some(tag("done")),
            ..StepInput::default()
        },
        StepEnv::default(),
        ok(),
        seq_state(last_seq),
    )
}

/// The control message bytes of an approved `EnrollResult`: the payload of
/// its frame, the envelope `[t, b]` without the 4-byte length prefix.
fn enroll_result_message(enroll_result: &str, chain: &[String]) -> String {
    let message = ControlMessage::from(EnrollResult {
        outcome: ControlEnrollOutcome::Approved {
            enroll_result: enroll_result.to_owned(),
            chain: chain.to_vec(),
        },
    });
    let frame = message
        .to_frame()
        .expect("an enroll_result message encodes");
    b64(frame.payload())
}

/// The control message bytes of a `Documents` message.
fn documents_message(documents: &[String]) -> String {
    let message = ControlMessage::from(Documents {
        documents: documents.to_vec(),
    });
    let frame = message.to_frame().expect("a documents message encodes");
    b64(frame.payload())
}

// --- case building ------------------------------------------------------------------

/// Builds one sequence case: its documents, from its own issuer, and its
/// steps.
struct Seq<'r> {
    ring: &'r mut KeyRing,
    issuer: Issuer,
    initial: ChainInput,
    steps: Vec<Step>,
}

impl<'r> Seq<'r> {
    fn new(ring: &'r mut KeyRing) -> Self {
        let install_config = fixtures::standard_install(ring);
        Self {
            ring,
            issuer: Issuer::new(),
            initial: ChainInput {
                install_config,
                vendor_keys: vec![VENDOR_RELEASE.to_owned()],
                trust_test_keys: false,
            },
            steps: Vec::new(),
        }
    }

    fn push(&mut self, step: Step) -> &mut Self {
        self.steps.push(step);
        self
    }

    fn finish(self, name: &str, description: &str) -> SequenceCase {
        SequenceCase {
            name: name.to_owned(),
            description: description.to_owned(),
            initial: self.initial,
            steps: self.steps,
        }
    }

    fn sign(&mut self, typ: Typ, kid: &str, content: &J) -> String {
        self.ring.sign(typ, kid, content)
    }

    fn enroll_result(&mut self, kid: &str, spec: &EnrollResultSpec<'_>) -> String {
        self.sign(Typ::EnrollResult, kid, &fixtures::enroll_result(spec))
    }

    /// Enrolls at epoch 1 with an enrollment result signed by the customer
    /// key version 1, without a chain.
    fn enroll(&mut self) -> &mut Self {
        let result = self.enroll_result(&customer_kid(1), &EnrollResultSpec::matching(EPOCH));
        self.push(receive_enroll_result(
            Vec::new(),
            result,
            notation::enroll(Vec::new(), enrolled(ENDPOINT)),
            enrolled_state(Some(ENDPOINT)),
        ))
    }

    fn keyset(&mut self, signer: &str, spec: &KeysetSpec<'_>) -> String {
        let content = fixtures::keyset(self.ring, spec);
        self.sign(Typ::Keyset, signer, &content)
    }

    fn recovery_key(&mut self, version: u64) -> String {
        let content = fixtures::recovery_key(self.ring, version);
        self.sign(
            Typ::RecoveryKey,
            &recovery_kid(INSTALL_ID, version - 1),
            &content,
        )
    }

    /// An assignment of the endpoint to the group at `epoch`, by the
    /// issuing side's rule.
    fn assign(&mut self, epoch: u64, signer: &str) -> (String, u64) {
        let (_, version) = self.issuer.issue(&format!("{}:{ENDPOINT}", Typ::Assign));
        let jws = self.sign(Typ::Assign, signer, &fixtures::assign(epoch, version));
        (jws, version)
    }

    fn policy(&mut self, epoch: u64, signer: &str) -> (String, u64) {
        let (_, version) = self.issuer.issue(&format!("{}:{GROUP}", Typ::Policy));
        let jws = self.sign(
            Typ::Policy,
            signer,
            &fixtures::policy(epoch, version, "tray"),
        );
        (jws, version)
    }

    /// A command by the issuing side's rule, for `endpoint_id`.
    fn command(&mut self, n: u8, endpoint_id: &str, epoch: u64, signer: &str) -> (String, u64) {
        let at = self.issuer.tick();
        let seq = self.issuer.number(&format!("command:{endpoint_id}"), at);
        let jws = self.command_with_seq(n, endpoint_id, epoch, seq, signer, at);
        (jws, seq)
    }

    /// A command with a `seq` set by the case, against the issuing rule.
    fn command_with_seq(
        &mut self,
        n: u8,
        endpoint_id: &str,
        epoch: u64,
        seq: u64,
        signer: &str,
        at: jiff::Timestamp,
    ) -> String {
        let id = command_id(n);
        let content = fixtures::command(&CommandSpec {
            command_id: &id,
            endpoint_id,
            seq,
            issued_at: at,
            epoch,
        });
        self.sign(Typ::Command, signer, &content)
    }

    /// Enrolls, then has the assignment and a policy of epoch 1 applied;
    /// returns the policy's version.
    fn enroll_assign_policy(&mut self) -> u64 {
        self.enroll();
        let (assign, assign_version) = self.assign(EPOCH, &customer_kid(1));
        self.push(receive_document(
            assign,
            tag("applied"),
            slot_state(J::str("assign"), Some(assign_version), Some(assign_version)),
        ));
        let (policy, version) = self.policy(EPOCH, &customer_kid(1));
        self.push(receive_document(
            policy,
            tag("applied"),
            slot_state(policy_slot(), Some(version), Some(version)),
        ));
        version
    }
}

// --- keyset -----------------------------------------------------------------------------

/// The documents of the R1 → R2 → R3 recovery: the two recovery key
/// replacements, the key set (2, 1) the recovery key version 3 signed, and
/// the key set (2, 2) after it.
fn recovery_chain(seq: &mut Seq<'_>) -> Vec<String> {
    let r2 = seq.recovery_key(2);
    let r3 = seq.recovery_key(3);
    let k21 = seq.keyset(
        &recovery_kid(INSTALL_ID, 3),
        &KeysetSpec::of(EPOCH + 1, 1, &[4], 4, &[1]),
    );
    let k22 = seq.keyset(
        &customer_kid(4),
        &KeysetSpec::of(EPOCH + 1, 2, &[4, 5], 5, &[1]),
    );
    vec![r2, r3, k21, k22]
}

/// The `EnrollResult` message of an endpoint that missed the R1 → R2 → R3
/// recovery: the chain, and a result signed by the customer key version 5,
/// which only the chain makes trusted.
fn recovery_enroll_message(seq: &mut Seq<'_>, chain: &[String]) -> String {
    let result = seq.enroll_result(&customer_kid(5), &EnrollResultSpec::matching(EPOCH + 1));
    enroll_result_message(&result, chain)
}

fn recovered_state() -> StateSummary {
    StateSummary {
        endpoint_id: Some(Some(ENDPOINT.to_owned())),
        ..keys_state(EPOCH + 1, 2, 3)
    }
}

fn keyset_cases(ring: &mut KeyRing) -> Vec<SequenceCase> {
    let mut cases = Vec::new();

    let mut seq = Seq::new(ring);
    let k2 = seq.keyset(&customer_kid(1), &KeysetSpec::of(EPOCH, 2, &[1, 2], 2, &[]));
    let k3 = seq.keyset(
        &customer_kid(2),
        &KeysetSpec::of(EPOCH, 3, &[2, 3], 3, &[1]),
    );
    seq.push(receive_keyset(k2, tag("applied"), keyset_state(EPOCH, 2)))
        .push(receive_keyset(k3, tag("applied"), keyset_state(EPOCH, 3)));
    cases.push(seq.finish(
        "rotation_v1_v2_v3",
        "Two ordinary rotations, each signed by the current_kid of the key set before it.",
    ));

    let mut seq = Seq::new(ring);
    let chain = recovery_chain(&mut seq);
    let message = recovery_enroll_message(&mut seq, &chain);
    seq.push(receive_enroll_result_message(
        message,
        notation::enroll(repeat(&tag("applied"), 4), enrolled(ENDPOINT)),
        recovered_state(),
    ));
    cases.push(seq.finish(
        "recovery_chain_in_enroll_result",
        "An endpoint trusting recovery key 1 missed the replacements by keys 2 and 3 and a recovery: the approved EnrollResult carries the replacement R2 signed by R1, R3 signed by R2, the key set (2, 1) signed by R3 and the key set (2, 2), and a result signed by a key only the chain makes trusted.",
    ));

    let mut seq = Seq::new(ring);
    let chain = recovery_chain(&mut seq);
    seq.enroll().push(receive_documents_message(
        documents_message(&chain),
        repeat(&tag("applied"), 4),
        recovered_state(),
    ));
    cases.push(seq.finish(
        "recovery_chain_in_documents",
        "An enrolled endpoint trusting recovery key 1 reconnects and receives the same recovery chain in a Documents message.",
    ));

    let mut seq = Seq::new(ring);
    let chain = recovery_chain(&mut seq);
    let message = recovery_enroll_message(&mut seq, &chain);
    seq.push(receive_enroll_result_message(
        message.clone(),
        notation::enroll(repeat(&tag("applied"), 4), enrolled(ENDPOINT)),
        recovered_state(),
    ))
    .push(receive_enroll_result_message(
        message,
        notation::enroll(repeat(&tag("duplicate"), 4), enrolled(ENDPOINT)),
        recovered_state(),
    ));
    cases.push(seq.finish(
        "enroll_result_queried_again",
        "The same EnrollResult received twice: the second time every chain document is a duplicate and the enrollment succeeds again.",
    ));

    let mut seq = Seq::new(ring);
    let chain = recovery_chain(&mut seq);
    let message = recovery_enroll_message(&mut seq, &chain);
    let head: Vec<String> = chain.iter().take(2).cloned().collect();
    seq.push(receive_chain(
        head,
        repeat(&tag("applied"), 2),
        keys_state(EPOCH, 1, 3),
    ))
    .push(receive_enroll_result_message(
        message,
        notation::enroll(
            [repeat(&tag("duplicate"), 2), repeat(&tag("applied"), 2)].concat(),
            enrolled(ENDPOINT),
        ),
        recovered_state(),
    ));
    cases.push(seq.finish(
        "enroll_result_after_part_of_chain",
        "The endpoint has already taken the two recovery key replacements, then receives the EnrollResult with the whole chain.",
    ));

    let mut seq = Seq::new(ring);
    let k2 = seq.keyset(&customer_kid(1), &KeysetSpec::of(EPOCH, 2, &[1, 2], 2, &[]));
    let k3 = seq.keyset(
        &customer_kid(1),
        &KeysetSpec::of(EPOCH, 3, &[2, 3], 3, &[1]),
    );
    seq.push(receive_keyset(k2, tag("applied"), keyset_state(EPOCH, 2)))
        .push(receive_keyset(
            k3,
            tag("unknown_kid"),
            keyset_state(EPOCH, 2),
        ));
    cases.push(seq.finish(
        "next_version_signed_by_non_current_key",
        "Key set (1, 3) signed by customer key version 1, which is in the keys of (1, 2) but not its current_kid.",
    ));

    let mut seq = Seq::new(ring);
    let k2 = seq.keyset(&customer_kid(1), &KeysetSpec::of(EPOCH, 2, &[1, 2], 2, &[]));
    let k3 = seq.keyset(
        &customer_kid(2),
        &KeysetSpec::of(EPOCH, 3, &[2, 3], 3, &[1]),
    );
    let k5 = seq.keyset(
        &customer_kid(4),
        &KeysetSpec::of(EPOCH, 5, &[4, 5], 5, &[1]),
    );
    seq.push(receive_keyset(k2, tag("applied"), keyset_state(EPOCH, 2)))
        .push(receive_keyset(k3, tag("applied"), keyset_state(EPOCH, 3)))
        .push(receive_keyset(
            k5,
            keyset_gap(EPOCH, 3),
            keyset_state(EPOCH, 3),
        ));
    cases.push(seq.finish(
        "keyset_gap",
        "Key set (1, 5) arrives at an endpoint holding (1, 3).",
    ));

    let mut seq = Seq::new(ring);
    let foreign = seq.keyset(
        &recovery_kid(INSTALL_ID, 1),
        &KeysetSpec {
            customer: OTHER_CUSTOMER,
            epoch: EPOCH + 1,
            version: 1,
            keys: &[1],
            current: 1,
            revoked: &[],
        },
    );
    seq.push(receive_keyset(
        foreign,
        tag("wrong_target"),
        keys_state(EPOCH, 1, 1),
    ));
    cases.push(seq.finish(
        "recovery_keyset_for_other_customer",
        "A key set of the next epoch signed by the trusted recovery key, whose customer_endpoint_id is another customer's.",
    ));

    cases
}

// --- leak ---------------------------------------------------------------------------------

/// The recovery key set (2, 1) after customer key version 1 leaked.
#[derive(Clone, Copy)]
enum LeakedKey {
    /// In `revoked_kids`.
    Revoked,
    /// Neither in `keys` nor in `revoked_kids`.
    Dropped,
    /// Still in `keys`.
    Kept,
}

fn leak_recovery(seq: &mut Seq<'_>, leaked: LeakedKey) -> String {
    let spec = match leaked {
        LeakedKey::Revoked => KeysetSpec::of(EPOCH + 1, 1, &[4], 4, &[1]),
        LeakedKey::Dropped => KeysetSpec::of(EPOCH + 1, 1, &[4], 4, &[]),
        LeakedKey::Kept => KeysetSpec::of(EPOCH + 1, 1, &[1, 4], 4, &[]),
    };
    seq.keyset(&recovery_kid(INSTALL_ID, 1), &spec)
}

/// A policy signed by the leaked key, claiming a far epoch and the largest
/// version.
fn leaked_policy(seq: &mut Seq<'_>) -> String {
    seq.sign(
        Typ::Policy,
        &customer_kid(1),
        &fixtures::policy(FAR_EPOCH, MAX_INTEGER, "hidden"),
    )
}

fn leak_cases(ring: &mut KeyRing) -> Vec<SequenceCase> {
    let mut cases = Vec::new();
    let leaked = customer_kid(1);

    let mut seq = Seq::new(ring);
    let version = seq.enroll_assign_policy();
    let policy = leaked_policy(&mut seq);
    seq.push(receive_document(
        policy,
        tag("epoch_mismatch"),
        slot_state(policy_slot(), Some(version), Some(version)),
    ));
    cases.push(seq.finish(
        "leaked_policy_far_epoch",
        "At epoch 1, a policy signed by the leaked customer key version 1 claims epoch 1000 and the largest version.",
    ));

    let mut seq = Seq::new(ring);
    seq.enroll();
    let (first, first_seq) = seq.command(1, ENDPOINT, EPOCH, &leaked);
    let at = seq.issuer.tick();
    let forged = seq.command_with_seq(2, ENDPOINT, FAR_EPOCH, MAX_INTEGER, &leaked, at);
    let (next, next_seq) = seq.command(3, ENDPOINT, EPOCH, &leaked);
    seq.push(receive_command(first, execute(), Some(first_seq)))
        .push(receive_command(
            forged,
            rejected("epoch_mismatch"),
            Some(first_seq),
        ))
        .push(receive_command(next, execute(), Some(next_seq)));
    cases.push(seq.finish(
        "leaked_command_far_epoch_and_seq",
        "At epoch 1, a command signed by the leaked key claims epoch 1000 and the largest seq; the epoch comparison rejects it before its seq is looked at, and the next ordinary command is accepted.",
    ));

    for (name, variant, rejection, about) in [
        (
            "after_recovery_leaked_key_revoked",
            LeakedKey::Revoked,
            "revoked_kid",
            "lists the leaked key in revoked_kids",
        ),
        (
            "after_recovery_leaked_key_dropped",
            LeakedKey::Dropped,
            "unknown_kid",
            "has the leaked key neither in keys nor in revoked_kids",
        ),
        (
            "after_recovery_leaked_key_kept",
            LeakedKey::Kept,
            "epoch_mismatch",
            "still has the leaked key in keys",
        ),
    ] {
        let mut seq = Seq::new(ring);
        let version = seq.enroll_assign_policy();
        let recovery = leak_recovery(&mut seq, variant);
        let policy = leaked_policy(&mut seq);
        let at = seq.issuer.tick();
        let forged = seq.command_with_seq(2, ENDPOINT, FAR_EPOCH, MAX_INTEGER, &leaked, at);
        let (assign, assign_version) = seq.assign(EPOCH + 1, &customer_kid(4));
        let (new_policy, policy_version) = seq.policy(EPOCH + 1, &customer_kid(4));
        let (command, command_seq) = seq.command(3, ENDPOINT, EPOCH + 1, &customer_kid(4));
        seq.push(receive_document(
            policy.clone(),
            tag("epoch_mismatch"),
            slot_state(policy_slot(), Some(version), Some(version)),
        ))
        .push(receive_command(
            forged.clone(),
            rejected("epoch_mismatch"),
            None,
        ))
        .push(receive_keyset(
            recovery,
            tag("applied"),
            StateSummary {
                slot: Some(SlotSummary {
                    slot: policy_slot(),
                    verified_version: None,
                    applied_version: None,
                }),
                ..keyset_state(EPOCH + 1, 1)
            },
        ))
        .push(receive_document(
            policy,
            tag(rejection),
            slot_state(policy_slot(), None, None),
        ))
        .push(receive_command(forged, rejected(rejection), None))
        .push(receive_document(
            assign,
            tag("applied"),
            slot_state(J::str("assign"), Some(assign_version), Some(assign_version)),
        ))
        .push(receive_document(
            new_policy,
            tag("applied"),
            slot_state(policy_slot(), Some(policy_version), Some(policy_version)),
        ))
        .push(receive_command(command, execute(), Some(command_seq)));
        cases.push(seq.finish(
            name,
            &format!(
                "At epoch 1 the leaked policy and command are rejected for their epoch. After the recovery key set (2, 1), which {about}, they come again; then the assignment, a policy and an ordinary command of epoch 2 are accepted."
            ),
        ));
    }

    let mut seq = Seq::new(ring);
    seq.enroll();
    let at = seq.issuer.tick();
    let raised = seq.command_with_seq(1, ENDPOINT, EPOCH, MAX_INTEGER, &leaked, at);
    let (stale, _) = seq.command(2, ENDPOINT, EPOCH, &customer_kid(1));
    let recovery = leak_recovery(&mut seq, LeakedKey::Revoked);
    let (after, after_seq) = seq.command(3, ENDPOINT, EPOCH + 1, &customer_kid(4));
    seq.push(receive_command(raised, execute(), Some(MAX_INTEGER)))
        .push(receive_command(stale, rejected("stale"), Some(MAX_INTEGER)))
        .push(receive_keyset(
            recovery,
            tag("applied"),
            StateSummary {
                last_seq: Some(None),
                ..keyset_state(EPOCH + 1, 1)
            },
        ))
        .push(receive_command(after, execute(), Some(after_seq)));
    cases.push(seq.finish(
        "seq_floor_raised_then_recovery",
        "At epoch 1 the leaked key signs a command with the largest seq that passes every check, raising the sequence floor; an ordinary command is then stale. The recovery key set (2, 1) restarts the floor, and an ordinary command of epoch 2 with a new command_id is accepted.",
    ));

    cases
}

// --- document versions --------------------------------------------------------------------

fn version_cases(ring: &mut KeyRing) -> Vec<SequenceCase> {
    let mut cases = Vec::new();

    let mut seq = Seq::new(ring);
    let version = seq.enroll_assign_policy();
    let other = seq.sign(
        Typ::Policy,
        &customer_kid(1),
        &fixtures::policy(EPOCH, version, "hidden"),
    );
    seq.push(receive_document(
        other,
        tag("conflict"),
        slot_state(policy_slot(), Some(version), Some(version)),
    ));
    cases.push(seq.finish(
        "same_version_other_content",
        "A policy of the version already verified and applied, with other content.",
    ));

    let mut seq = Seq::new(ring);
    seq.enroll();
    let (assign, assign_version) = seq.assign(EPOCH, &customer_kid(1));
    let (policy, version) = seq.policy(EPOCH, &customer_kid(1));
    let recovery = seq.keyset(
        &recovery_kid(INSTALL_ID, 1),
        &KeysetSpec::of(EPOCH + 1, 1, &[1, 4], 4, &[]),
    );
    seq.push(receive_document(
        assign,
        tag("applied"),
        slot_state(J::str("assign"), Some(assign_version), Some(assign_version)),
    ))
    .push(receive_document(
        policy.clone(),
        tag("applied"),
        slot_state(policy_slot(), Some(version), Some(version)),
    ))
    .push(receive_keyset(
        recovery,
        tag("applied"),
        StateSummary {
            slot: Some(SlotSummary {
                slot: policy_slot(),
                verified_version: None,
                applied_version: None,
            }),
            ..keyset_state(EPOCH + 1, 1)
        },
    ))
    .push(receive_document(
        policy,
        tag("epoch_mismatch"),
        slot_state(policy_slot(), None, None),
    ));
    cases.push(seq.finish(
        "previous_epoch_document",
        "A policy of epoch 1, signed by a key the recovery key set (2, 1) keeps, comes again after the epoch moved on to 2.",
    ));

    let mut seq = Seq::new(ring);
    seq.enroll();
    let (assign, assign_version) = seq.assign(EPOCH, &customer_kid(1));
    let issued_at = now() + SignedDuration::from_hours(1) + SignedDuration::from_mins(1);
    let version = seq
        .issuer
        .number(&format!("{}:{GROUP}", Typ::Update), issued_at);
    let update = seq.sign(
        Typ::Update,
        &customer_kid(1),
        &fixtures::group_update(
            EPOCH,
            version,
            issued_at,
            issued_at + SignedDuration::from_hours(24),
        ),
    );
    seq.push(receive_document(
        assign,
        tag("applied"),
        slot_state(J::str("assign"), Some(assign_version), Some(assign_version)),
    ))
    .push(receive_document(
        update,
        tag("not_yet_valid"),
        slot_state(group_update_slot(), None, None),
    ));
    cases.push(seq.finish(
        "update_issued_too_far_ahead",
        "A senta-update whose issued_at is 1 hour and 1 minute after the endpoint's clock.",
    ));

    let mut seq = Seq::new(ring);
    seq.enroll();
    let (assign, assign_version) = seq.assign(EPOCH, &customer_kid(1));
    let (issued_at, version) = seq.issuer.issue(&format!("{}:{GROUP}", Typ::Update));
    let too_long = seq.sign(
        Typ::Update,
        &customer_kid(1),
        &fixtures::group_update(
            EPOCH,
            version,
            issued_at,
            issued_at + SignedDuration::from_hours(30 * 24) + SignedDuration::from_secs(1),
        ),
    );
    let (issued_at, valid_version) = seq.issuer.issue(&format!("{}:{GROUP}", Typ::Update));
    let valid = seq.sign(
        Typ::Update,
        &customer_kid(1),
        &fixtures::group_update(
            EPOCH,
            valid_version,
            issued_at,
            issued_at + SignedDuration::from_hours(30 * 24),
        ),
    );
    seq.push(receive_document(
        assign,
        tag("applied"),
        slot_state(J::str("assign"), Some(assign_version), Some(assign_version)),
    ))
    .push(receive_document(
        too_long,
        tag("expired"),
        slot_state(group_update_slot(), None, None),
    ))
    .push(receive_document(
        valid,
        tag("applied"),
        slot_state(
            group_update_slot(),
            Some(valid_version),
            Some(valid_version),
        ),
    ));
    cases.push(seq.finish(
        "update_lifetime_over_30_days",
        "A senta-update whose expires_at is 30 days and 1 second after its issued_at; then one living exactly 30 days is applied.",
    ));

    cases
}

// --- enrollment results -------------------------------------------------------------------

fn enroll_cases(ring: &mut KeyRing) -> Vec<SequenceCase> {
    let mut seq = Seq::new(ring);
    let kid = customer_kid(1);
    let wrong_token = seq.enroll_result(
        &kid,
        &EnrollResultSpec {
            token_id: OTHER_TOKEN,
            ..EnrollResultSpec::matching(EPOCH)
        },
    );
    let wrong_attempt = seq.enroll_result(
        &kid,
        &EnrollResultSpec {
            attempt_id: OTHER_ATTEMPT,
            ..EnrollResultSpec::matching(EPOCH)
        },
    );
    let wrong_epoch = seq.enroll_result(&kid, &EnrollResultSpec::matching(EPOCH + 1));
    let matching = seq.enroll_result(&kid, &EnrollResultSpec::matching(EPOCH));
    for (result, comparison) in [
        (wrong_token, "token_id_mismatch"),
        (wrong_attempt, "attempt_id_mismatch"),
        (wrong_epoch, "recovery_epoch_mismatch"),
    ] {
        seq.push(receive_enroll_result(
            Vec::new(),
            result,
            notation::enroll(Vec::new(), enroll_failed(comparison)),
            enrolled_state(None),
        ));
    }
    seq.push(receive_enroll_result(
        Vec::new(),
        matching,
        notation::enroll(Vec::new(), enrolled(ENDPOINT)),
        enrolled_state(Some(ENDPOINT)),
    ));
    vec![seq.finish(
        "attempt_comparisons",
        "Enrollment results with the endpoint's own spki_sha256 that each differ from the attempt in one field, token_id, attempt_id or recovery_epoch, then one that matches.",
    )]
}

// --- commands -----------------------------------------------------------------------------

fn command_cases(ring: &mut KeyRing) -> Vec<SequenceCase> {
    let mut seq = Seq::new(ring);
    let kid = customer_kid(1);
    seq.enroll();
    let (first, first_seq) = seq.command(1, ENDPOINT, EPOCH, &kid);
    let (same_id, _) = seq.command(1, OTHER_ENDPOINT, EPOCH, &kid);
    let at = seq.issuer.tick();
    let far = seq.command_with_seq(2, OTHER_ENDPOINT, EPOCH, MAX_INTEGER, &kid, at);
    let (own, own_seq) = seq.command(3, ENDPOINT, EPOCH, &kid);
    seq.push(receive_command(first, execute(), Some(first_seq)))
        .push(finish_command(&command_id(1), Some(first_seq)))
        .push(receive_command(
            same_id,
            rejected("wrong_target"),
            Some(first_seq),
        ))
        .push(receive_command(
            far,
            rejected("wrong_target"),
            Some(first_seq),
        ))
        .push(receive_command(own, execute(), Some(own_seq)));
    vec![seq.finish(
        "other_endpoint_rejected_first",
        "Commands for another endpoint of the same customer are rejected as wrong_target before the stored result and the sequence floor are looked at: one reusing the command_id of a command run here, one with the largest seq.",
    )]
}

// --- files ---------------------------------------------------------------------------------

pub fn file(category: Category) -> VectorFile<SequenceCase> {
    let mut ring = KeyRing::default();
    let cases = match category {
        Category::Keyset => keyset_cases(&mut ring),
        Category::Leak => leak_cases(&mut ring),
        Category::DocumentVersions => version_cases(&mut ring),
        Category::EnrollResult => enroll_cases(&mut ring),
        Category::Commands => command_cases(&mut ring),
        other => panic!("{} is not a sequence category", other.as_str()),
    };
    ring.key(VENDOR_RELEASE);
    VectorFile {
        format_version: FORMAT_VERSION,
        category,
        keys: ring.entries(),
        cases,
    }
}
