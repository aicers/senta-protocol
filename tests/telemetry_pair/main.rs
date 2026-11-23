#![cfg(feature = "telemetry")]
//! The endpoint's `SenderStream` and the entries' `ReceiverStream`s run
//! against each other, every message through the envelope, with faults
//! mixed in: connections that break, answers that are lost, clocks that
//! run past the retention and the holds, buffers that fill, state lost at
//! either end, writes that fail, closed streams forgotten, entries that
//! accept fewer kinds and then more, and the endpoint moving between
//! entries. The judges then hold the run to the guarantees: nothing
//! missing, nothing stored twice without a reason, every loss reported,
//! and `A` never going back, judged by record, by entry and by recovery.
//!
//! The test keeps its own model of the endpoint (`model`), from which it
//! computes what it expects; every run is recorded in a trace (`trace`)
//! that the judges (`judge`) read alone. Fixed cases (`cases`) run named
//! scenarios one at a time, and mutation tests (`mutations`) check that
//! the judges catch each misbehaviour the issue names.
//!
//! The property test runs `DEFAULT_CASES` cases, or as many as the
//! `PROPTEST_CASES` environment variable says when it is set. A failing
//! case is reported as its minimal setup and list of operations, which can
//! be pasted into a fixed case as they are. Nothing is written to disk.

mod cases;
mod fixture;
mod harness;
mod ingress;
mod judge;
mod model;
mod mutations;
mod ops;
mod trace;

use proptest::prelude::*;
use proptest::test_runner::Config;

use crate::harness::World;
use crate::ops::{Op, Setup};

/// The cases the property test runs when `PROPTEST_CASES` is not set,
/// chosen so that a debug build runs this whole test binary in CI within
/// a minute.
const DEFAULT_CASES: u32 = 256;
/// The most shrinking steps proptest takes on a failure.
const MAX_SHRINK_ITERS: u32 = 2_000;

fn config() -> Config {
    let mut config = Config::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = DEFAULT_CASES;
    }
    config.max_shrink_iters = MAX_SHRINK_ITERS;
    config.failure_persistence = None;
    config
}

/// Runs `ops` from `setup`, drains, and judges the run.
pub fn run_case(setup: Setup, ops: &[Op]) -> Result<(), String> {
    let mut world = World::new(setup);
    for op in ops {
        world.run(*op);
    }
    let kinds = world.last_kinds;
    let trace = world.finish(kinds);
    judge::judge(&trace)
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn the_pair_keeps_its_guarantees_under_mixed_faults(
        setup in ops::setup(),
        ops in prop::collection::vec(ops::op(), 1..150),
    ) {
        if let Err(failures) = run_case(setup, &ops) {
            prop_assert!(false, "{}", failures);
        }
    }
}
