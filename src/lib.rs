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
//!   signed documents. Without `auth` it adds nothing.
//!
//! Outside that test signer, which needs both `auth` and `test-util`, the
//! crate makes no signed documents. The one thing it signs under `auth`
//! alone is an endpoint's own certificate, which
//! `auth::tls::endpoint_certificate` self-signs with the endpoint's key.
//!
//! Whatever the features, the `connection` module is always public: the
//! framing, envelope, CBOR rules, version negotiation, liveness and clock
//! correction that control and telemetry connections share.
//!
//! The `results` module is public whatever the features: it holds the
//! result enums that the trust state machines produce and the control
//! channel carries.
//!
//! The `host` module is public whatever the features too: the operating
//! system and collection mode an endpoint reports about its host, which
//! telemetry record headers and control messages both carry.
//!
//! The `telemetry_codes` module is public whatever the features as well:
//! the telemetry errors and the reasons for dropping records that
//! telemetry messages carry, and with which the active list refuses an
//! endpoint.

#[cfg(feature = "auth")]
pub mod auth;
pub mod connection;
#[cfg(feature = "control")]
pub mod control;
pub mod host;
pub mod results;
#[cfg(feature = "telemetry")]
pub mod telemetry;
pub mod telemetry_codes;

/// Doctests asserting that each feature-gated module exists exactly when its
/// feature is on, and `connection` and `host` always. A module whose
/// feature is off must not resolve.
#[cfg(doctest)]
mod feature_gates {
    #[doc = "```"]
    #[doc = "use senta_protocol::connection;"]
    #[doc = "```"]
    struct Connection;

    #[doc = "```"]
    #[doc = "use senta_protocol::host;"]
    #[doc = "```"]
    struct Host;

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

    #[doc = "```"]
    #[doc = "use senta_protocol::telemetry_codes;"]
    #[doc = "```"]
    struct TelemetryCodes;
}
