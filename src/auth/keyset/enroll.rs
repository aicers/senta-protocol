//! Receiving an approved enrollment: the catch-up chain that comes with it,
//! then the `senta-enroll-result`.

use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::{ChainOutcome, EpochChange, TrustState};
use crate::auth::documents;
use crate::results::DocumentResult;

/// What the endpoint knows of the enrollment attempt it made, to hold the
/// enrollment result against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollAttempt {
    /// The SHA-256 of the endpoint's own SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
    /// The id of this enrollment attempt.
    pub attempt_id: Uuid,
    /// The `token_id` of the enrollment token the endpoint presented.
    pub token_id: Uuid,
}

/// Why an enrollment result was not accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnrollFailure {
    /// The catch-up chain stopped at a document, and the enrollment result
    /// was not looked at.
    #[error("the catch-up chain stopped at document {index} with {result:?}")]
    Chain {
        /// The index in the chain of the document it stopped at.
        index: usize,
        /// That document's result.
        result: DocumentResult,
    },
    /// The `senta-enroll-result` did not verify against the key set after
    /// the chain.
    #[error("the enrollment result was rejected with {0:?}")]
    Rejected(DocumentResult),
    /// The result is for another endpoint key: its `spki_sha256` is not the
    /// endpoint's.
    #[error("the enrollment result is for another endpoint key")]
    SpkiMismatch,
    /// The result's `attempt_id` is not this attempt's.
    #[error("the enrollment result is for another enrollment attempt")]
    AttemptIdMismatch,
    /// The result's `token_id` is not the token the endpoint presented.
    #[error("the enrollment result is for another enrollment token")]
    TokenIdMismatch,
    /// The result's `recovery_epoch` is not the epoch of the key set after
    /// the chain.
    #[error("the enrollment result's recovery epoch {result} is not the current {current}")]
    EpochMismatch {
        /// The result's `recovery_epoch`.
        result: u64,
        /// The epoch of the key set after the chain.
        current: u64,
    },
}

/// The outcome of [`receive_enroll_result`]: success with the endpoint id,
/// or the failure, and in either case the trust state after the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollOutcome {
    state: TrustState,
    chain: ChainOutcome,
    result: Result<Uuid, EnrollFailure>,
}

impl EnrollOutcome {
    /// Returns the endpoint id the enrollment gave, or `None` if it failed.
    #[must_use]
    pub fn endpoint_id(&self) -> Option<Uuid> {
        self.result.as_ref().ok().copied()
    }

    /// Returns why the enrollment failed, or `None` if it succeeded.
    #[must_use]
    pub fn failure(&self) -> Option<&EnrollFailure> {
        self.result.as_ref().err()
    }

    /// Returns the endpoint id, or why the enrollment failed.
    pub fn result(&self) -> Result<Uuid, &EnrollFailure> {
        self.result.as_ref().copied()
    }

    /// Returns the trust state after the chain, with whatever the chain
    /// applied, success or failure.
    #[must_use]
    pub fn state(&self) -> &TrustState {
        &self.state
    }

    /// Returns the trust state after the chain, consuming `self`.
    #[must_use]
    pub fn into_state(self) -> TrustState {
        self.state
    }

    /// Returns the outcome of the chain.
    #[must_use]
    pub fn chain(&self) -> &ChainOutcome {
        &self.chain
    }

    /// Returns the epoch changes the chain brought, success or failure.
    #[must_use]
    pub fn epoch_changes(&self) -> &[EpochChange] {
        self.chain.epoch_changes()
    }
}

/// Receives an approved enrollment: the catch-up chain `chain`, then the
/// `senta-enroll-result` JWS `enroll_result`, held against `attempt`.
///
/// 1. `chain` goes through [`TrustState::receive_chain`]. If it stops, the
///    enrollment fails with [`EnrollFailure::Chain`] and `enroll_result` is
///    not looked at, even if it would verify under a key `state` already
///    trusts.
/// 2. `enroll_result` is verified against the state after the chain, as a
///    [`KeySource`](crate::auth::jws::KeySource): a failure is
///    [`EnrollFailure::Rejected`].
/// 3. Its `spki_sha256` must be `attempt`'s (compared in constant time),
///    its `attempt_id` and `token_id` `attempt`'s, and its `recovery_epoch`
///    the epoch after the chain; the first that differs is the failure.
/// 4. Otherwise the enrollment succeeds with the result's `endpoint_id`.
///
/// Whatever the chain applied stays applied in the returned state, whether
/// the enrollment succeeds or fails.
#[must_use]
pub fn receive_enroll_result<S: AsRef<str>>(
    mut state: TrustState,
    chain: &[S],
    enroll_result: &str,
    attempt: &EnrollAttempt,
) -> EnrollOutcome {
    let chain = state.receive_chain(chain);
    let result = match chain.stopped_at() {
        Some((index, result)) => Err(EnrollFailure::Chain {
            index,
            result: result.clone(),
        }),
        None => check_result(&state, enroll_result, attempt),
    };
    EnrollOutcome {
        state,
        chain,
        result,
    }
}

fn check_result(
    state: &TrustState,
    enroll_result: &str,
    attempt: &EnrollAttempt,
) -> Result<Uuid, EnrollFailure> {
    let verified = documents::verify_enroll_result(enroll_result, state)
        .map_err(|error| EnrollFailure::Rejected(error.result()))?;
    let content = verified.content();
    let spki_matches: bool = content
        .spki_sha256
        .get()
        .as_slice()
        .ct_eq(attempt.spki_sha256.as_slice())
        .into();
    if !spki_matches {
        return Err(EnrollFailure::SpkiMismatch);
    }
    if content.attempt_id.get() != attempt.attempt_id {
        return Err(EnrollFailure::AttemptIdMismatch);
    }
    if content.token_id.get() != attempt.token_id {
        return Err(EnrollFailure::TokenIdMismatch);
    }
    let result_epoch = content.recovery_epoch.get();
    let current = state.recovery_epoch();
    if result_epoch != current {
        return Err(EnrollFailure::EpochMismatch {
            result: result_epoch,
            current,
        });
    }
    Ok(content.endpoint_id.get())
}
