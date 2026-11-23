#![cfg(all(feature = "auth", any(feature = "control", feature = "telemetry")))]
//! Contract tests: the crate's endpoint side and ingress side joined over
//! in-memory TLS 1.3 connections, exchanging frames through the connection
//! helpers, judged by the active list.
//!
//! `common` holds the harness both ports share: the test PKI, the
//! in-memory TLS link, and an ingress composed from the crate's helpers.
//! `control` and `telemetry` hold each port's composition and its cases.

mod common;
#[cfg(feature = "control")]
mod control;
#[cfg(feature = "telemetry")]
mod telemetry;
