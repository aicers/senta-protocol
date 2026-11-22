//! Protocol, record formats and trust contracts shared by Clumit Endpoint,
//! REview and the event store.
//!
//! A consumer turns on the features for the parts it uses; none is on by
//! default, and any combination is supported:
//!
//! - `auth` turns on the `auth` module.
//! - `control` turns on the `control` module.
//! - `telemetry` turns on the `telemetry` module.
//! - `test-util`, together with `auth`, turns on `auth::jws::test_util`:
//!   deterministic Ed25519 test keys and a JWS signer, for tests that build
//!   signed documents. The crate signs nothing elsewhere. Without `auth` it
//!   adds nothing.

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "control")]
pub mod control;
#[cfg(feature = "telemetry")]
pub mod telemetry;

/// Doctests asserting that each feature-gated module exists exactly when its
/// feature is on. A module whose feature is off must not resolve.
#[cfg(doctest)]
mod feature_gates {
    #[cfg_attr(feature = "auth", doc = "```")]
    #[cfg_attr(not(feature = "auth"), doc = "```compile_fail,E0432")]
    #[doc = "use senta_protocol::auth;"]
    #[doc = "```"]
    struct Auth;

    #[cfg_attr(all(feature = "auth", feature = "test-util"), doc = "```")]
    #[cfg_attr(
        not(all(feature = "auth", feature = "test-util")),
        doc = "```compile_fail,E0432"
    )]
    #[doc = "use senta_protocol::auth::jws::test_util;"]
    #[doc = "```"]
    struct AuthTestUtil;

    #[cfg_attr(feature = "control", doc = "```")]
    #[cfg_attr(not(feature = "control"), doc = "```compile_fail,E0432")]
    #[doc = "use senta_protocol::control;"]
    #[doc = "```"]
    struct Control;

    #[cfg_attr(feature = "telemetry", doc = "```")]
    #[cfg_attr(not(feature = "telemetry"), doc = "```compile_fail,E0432")]
    #[doc = "use senta_protocol::telemetry;"]
    #[doc = "```"]
    struct Telemetry;
}
