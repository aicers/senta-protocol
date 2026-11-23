//! The result notation of the vector files, built by hand from what each
//! case defines. The README lays it out.

use crate::json::J;

/// A variant without content: its tag, as `"bad_signature"`.
pub fn tag(tag: &str) -> J {
    J::str(tag)
}

/// `{"keyset_gap": {"have_epoch": …, "have_version": …}}`.
pub fn keyset_gap(have_epoch: u64, have_version: u64) -> J {
    J::tagged(
        "keyset_gap",
        J::obj([
            ("have_epoch", J::Int(have_epoch)),
            ("have_version", J::Int(have_version)),
        ]),
    )
}

/// A command rejected for a document result: `{"rejected": "<tag>"}`.
pub fn rejected(result: &str) -> J {
    J::tagged("rejected", J::str(result))
}

/// A JWS that verified, with the SHA-256 of its decoded payload.
pub fn jws_verified(payload_sha256: &str) -> J {
    J::tagged(
        "verified",
        J::obj([("payload_sha256", J::str(payload_sha256))]),
    )
}

/// An install configuration whose trust chain verified, with the trust
/// state it starts from.
pub fn chain_verified(recovery_epoch: u64, keyset_version: u64, recovery_key_version: u64) -> J {
    J::tagged(
        "installed",
        J::obj([
            ("recovery_epoch", J::Int(recovery_epoch)),
            ("keyset_version", J::Int(keyset_version)),
            ("recovery_key_version", J::Int(recovery_key_version)),
        ]),
    )
}

/// An install configuration whose trust chain failed: the
/// `InstallConfigFailure`, the step number and the document's `typ`.
pub fn chain_failed(failure: &str, step: u64, document: &str) -> J {
    J::tagged(
        "install_failed",
        J::obj([
            ("failure", J::str(failure)),
            ("step", J::Int(step)),
            ("document", J::str(document)),
        ]),
    )
}

/// What receiving an enrollment result comes to: the result of each chain
/// document, then the enrollment's.
pub fn enroll(chain: Vec<J>, result: J) -> J {
    J::obj([("chain", J::Arr(chain)), ("result", result)])
}

/// An enrollment that succeeded with `endpoint_id`.
pub fn enrolled(endpoint_id: &str) -> J {
    J::tagged("enrolled", J::str(endpoint_id))
}

/// An enrollment that failed at a comparison with the attempt, by its
/// name.
pub fn enroll_failed(comparison: &str) -> J {
    J::tagged("enroll_failed", J::str(comparison))
}

/// A command accepted to be run.
pub fn execute() -> J {
    J::str("execute")
}

/// A step that has no result of its own and completed.
pub fn ok() -> J {
    J::str("ok")
}

/// A document of a list that was not processed.
pub fn not_processed() -> J {
    J::str("not_processed")
}

pub fn repeat(result: &J, count: usize) -> Vec<J> {
    vec![result.clone(); count]
}
