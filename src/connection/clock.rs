//! Clock correction: how far the server's wall clock is from the
//! endpoint's, measured from round trips the endpoint makes.
//!
//! The result is only ever recorded beside the original times, in a
//! record's header and in the clock state of a status report. Nothing here
//! adjusts a time, and nothing here takes part in deciding expiry.

use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// How far back from the most recent measurement [`ClockCorrection`] looks
/// when it picks one: ten minutes of the monotonic clock.
pub const SELECTION_WINDOW: Duration = Duration::from_secs(10 * 60);

const NANOS_PER_MILLI: u128 = 1_000_000;
const LARGE_OFFSET_NANOS: u128 = 3_600 * 1_000_000_000;

/// The server's wall clock minus the endpoint's, with the uncertainty of
/// the measurement and when it was made.
///
/// In CBOR it is a map of the three fields under their own names; the
/// record header carries it as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockOffset {
    /// Server minus endpoint, in milliseconds, truncated toward zero.
    pub offset_ms: i64,
    /// Half the round trip, in milliseconds, rounded up.
    pub uncertainty_ms: u32,
    /// The endpoint's wall clock when the answer arrived: the request's
    /// wall clock time plus the round trip.
    #[serde(with = "super::cbor::timestamp")]
    pub measured_at: Timestamp,
}

/// One measurement of the clock offset, from a `hello` and its
/// `hello_ack`, or a `ping` and its `pong`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockMeasurement {
    offset: ClockOffset,
    offset_nanos: i128,
    uncertainty_nanos: u64,
    received_mono: Duration,
}

impl ClockMeasurement {
    /// Measures the offset from one round trip.
    ///
    /// `request_wall` and `request_mono` are the endpoint's clocks as it
    /// sent the request, `response_mono` its monotonic clock as the answer
    /// arrived, and `server_wall` the server's wall clock in the answer.
    /// With the round trip `rtt = response_mono − request_mono` and its
    /// half rounded up to a whole nanosecond, the offset is
    /// `server_wall − (request_wall + half)` and the uncertainty is `half`.
    ///
    /// Returns `None` when the monotonic clock ran backwards, when the
    /// uncertainty exceeds `u32::MAX` milliseconds, or when a value falls
    /// outside the range of a [`Timestamp`] or an `i64` of milliseconds.
    pub(crate) fn from_round_trip(
        request_wall: Timestamp,
        request_mono: Duration,
        response_mono: Duration,
        server_wall: Timestamp,
    ) -> Option<Self> {
        let rtt = response_mono.checked_sub(request_mono)?.as_nanos();
        let half = rtt.div_ceil(2);
        let uncertainty_ms = u32::try_from(half.div_ceil(NANOS_PER_MILLI)).ok()?;
        let uncertainty_nanos = u64::try_from(half).ok()?;
        let request = request_wall.as_nanosecond();
        let offset_nanos = server_wall
            .as_nanosecond()
            .checked_sub(request.checked_add(i128::from(uncertainty_nanos))?)?;
        // Integer division truncates toward zero.
        let offset_ms = i64::try_from(offset_nanos / i128::from(1_000_000u32)).ok()?;
        let measured_at =
            Timestamp::from_nanosecond(request.checked_add(i128::try_from(rtt).ok()?)?).ok()?;
        Some(Self {
            offset: ClockOffset {
                offset_ms,
                uncertainty_ms,
                measured_at,
            },
            offset_nanos,
            uncertainty_nanos,
            received_mono: response_mono,
        })
    }

    /// Returns the offset as the record header carries it.
    #[must_use]
    pub fn offset(&self) -> ClockOffset {
        self.offset
    }

    /// Returns the offset in nanoseconds, before truncation to
    /// milliseconds.
    #[must_use]
    pub fn offset_nanos(&self) -> i128 {
        self.offset_nanos
    }

    /// Returns the uncertainty in nanoseconds: half the round trip, rounded
    /// up.
    #[must_use]
    pub fn uncertainty_nanos(&self) -> u64 {
        self.uncertainty_nanos
    }

    /// Returns the endpoint's monotonic clock as the answer arrived.
    #[must_use]
    pub fn received_mono(&self) -> Duration {
        self.received_mono
    }

    /// Reports whether the offset is more than an hour either way.
    ///
    /// The comparison uses the offset in nanoseconds: exactly an hour is
    /// not more, and an hour and a nanosecond is, even though both are
    /// 3,600,000 milliseconds.
    #[must_use]
    pub fn exceeds_one_hour(&self) -> bool {
        self.offset_nanos.unsigned_abs() > LARGE_OFFSET_NANOS
    }
}

/// The offset chosen from the measurements recorded so far.
///
/// It is kept apart from any connection, so it can outlive one and gather
/// measurements across reconnections. All the measurements given one value
/// must share the origin of their monotonic clock.
///
/// The choice is the measurement with the smallest uncertainty among those
/// within [`SELECTION_WINDOW`] of the most recent one, and of those the
/// most recent. A measurement older than the window is dropped as soon as
/// a newer one is recorded, and so is one that a newer measurement at
/// least as certain makes impossible to choose, so what is kept does not
/// grow over time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockCorrection {
    /// Ordered by arrival, oldest first, each strictly less uncertain than
    /// every one after it.
    kept: Vec<ClockMeasurement>,
}

impl ClockCorrection {
    /// Creates a correction with no measurement.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a measurement.
    pub fn record(&mut self, measurement: ClockMeasurement) {
        let at = self
            .kept
            .partition_point(|kept| kept.received_mono <= measurement.received_mono);
        self.kept.insert(at, measurement);
        let Some(latest) = self.kept.last().map(|kept| kept.received_mono) else {
            return;
        };
        let cutoff = latest.saturating_sub(SELECTION_WINDOW);
        let stale = self
            .kept
            .partition_point(|kept| kept.received_mono < cutoff);
        self.kept.drain(..stale);
        // Walking from the newest, keep only a measurement less uncertain
        // than every newer one: the others can never be chosen, because a
        // newer one at least as certain outlasts them in the window.
        let mut best_newer = u64::MAX;
        let mut kept: Vec<ClockMeasurement> = Vec::with_capacity(self.kept.len());
        for measurement in self.kept.iter().rev() {
            if kept.is_empty() || measurement.uncertainty_nanos < best_newer {
                best_newer = measurement.uncertainty_nanos;
                kept.push(*measurement);
            }
        }
        kept.reverse();
        self.kept = kept;
    }

    /// Returns the chosen measurement, or `None` before any is recorded.
    #[must_use]
    pub fn selected(&self) -> Option<&ClockMeasurement> {
        self.kept.first()
    }

    /// Returns the chosen offset, or `None` before any is recorded.
    #[must_use]
    pub fn offset(&self) -> Option<ClockOffset> {
        self.selected().map(ClockMeasurement::offset)
    }

    /// Reports whether the chosen offset is more than an hour either way;
    /// `false` before any measurement is recorded.
    #[must_use]
    pub fn exceeds_one_hour(&self) -> bool {
        self.selected()
            .is_some_and(ClockMeasurement::exceeds_one_hour)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i128 = 1_000_000_000;
    const HOUR: i128 = 3_600 * SECOND;

    fn at(nanos: i128) -> Timestamp {
        Timestamp::from_nanosecond(nanos).unwrap()
    }

    fn mono(nanos: u64) -> Duration {
        Duration::from_nanos(nanos)
    }

    /// A measurement whose offset is exactly `offset` nanoseconds with a
    /// round trip of `rtt` nanoseconds, arriving at `received` on the
    /// monotonic clock.
    fn measured(offset: i128, rtt: u64, received: u64) -> ClockMeasurement {
        let request = 1_700_000_000 * SECOND;
        let half = i128::from(rtt.div_ceil(2));
        ClockMeasurement::from_round_trip(
            at(request),
            mono(received - rtt),
            mono(received),
            at(request + half + offset),
        )
        .unwrap()
    }

    #[test]
    fn measurement_follows_the_formula() {
        // Request at wall 1000 s, mono 10 s; answer at mono 10.000_000_301 s,
        // server wall 1005.5 s. RTT 301 ns, half rounded up to 151 ns.
        let m = ClockMeasurement::from_round_trip(
            at(1_000 * SECOND),
            Duration::from_secs(10),
            Duration::new(10, 301),
            at(1_005 * SECOND + SECOND / 2),
        )
        .unwrap();
        assert_eq!(m.uncertainty_nanos(), 151);
        assert_eq!(m.offset_nanos(), 5 * SECOND + SECOND / 2 - 151);
        assert_eq!(
            m.offset(),
            ClockOffset {
                // 5_499_999_849 ns truncates to 5_499 ms.
                offset_ms: 5_499,
                // 151 ns rounds up to 1 ms.
                uncertainty_ms: 1,
                measured_at: at(1_000 * SECOND + 301),
            }
        );
        assert_eq!(m.received_mono(), Duration::new(10, 301));
    }

    #[test]
    fn negative_offsets_truncate_toward_zero() {
        // Server behind by 2.9999 ms with an even round trip of 4 ms.
        let m = ClockMeasurement::from_round_trip(
            at(0),
            mono(0),
            mono(4_000_000),
            at(2_000_000 - 2_999_900),
        )
        .unwrap();
        assert_eq!(m.offset_nanos(), -2_999_900);
        assert_eq!(m.offset().offset_ms, -2);
        assert_eq!(m.offset().uncertainty_ms, 2);
        // A zero round trip has no uncertainty.
        let m = ClockMeasurement::from_round_trip(at(0), mono(5), mono(5), at(0)).unwrap();
        assert_eq!(m.offset().uncertainty_ms, 0);
        assert_eq!(m.offset().offset_ms, 0);
    }

    #[test]
    fn unusable_measurements_are_refused() {
        // The monotonic clock ran backwards.
        assert!(ClockMeasurement::from_round_trip(at(0), mono(10), mono(9), at(0)).is_none());
        // Half the round trip is more than u32::MAX milliseconds.
        let max_ms = u64::from(u32::MAX) * 1_000_000;
        assert!(
            ClockMeasurement::from_round_trip(at(0), mono(0), mono(2 * max_ms), at(0)).is_some()
        );
        assert!(
            ClockMeasurement::from_round_trip(at(0), mono(0), mono(2 * max_ms + 1), at(0))
                .is_none()
        );
    }

    #[test]
    fn the_hour_boundary_is_judged_in_nanoseconds() {
        for (offset, exceeds) in [
            (HOUR, false),
            (-HOUR, false),
            (HOUR + 1, true),
            (-HOUR - 1, true),
        ] {
            let m = measured(offset, 0, 1);
            assert_eq!(m.offset_nanos(), offset);
            assert_eq!(m.offset().offset_ms.unsigned_abs(), 3_600_000);
            assert_eq!(m.exceeds_one_hour(), exceeds, "{offset}");
            let mut correction = ClockCorrection::new();
            correction.record(m);
            assert_eq!(correction.exceeds_one_hour(), exceeds);
        }
        assert!(!ClockCorrection::new().exceeds_one_hour());
    }

    #[test]
    fn the_least_uncertain_recent_measurement_is_chosen() {
        let minute = 60 * 1_000_000_000;
        let mut correction = ClockCorrection::new();
        assert_eq!(correction.selected(), None);
        correction.record(measured(1, 8_000_000, minute));
        correction.record(measured(2, 2_000_000, 2 * minute));
        correction.record(measured(3, 6_000_000, 3 * minute));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 2);
        // An equally certain later one wins the tie.
        correction.record(measured(4, 2_000_000, 4 * minute));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 4);
        assert_eq!(
            correction.offset(),
            Some(correction.selected().unwrap().offset())
        );
    }

    #[test]
    fn measurements_older_than_the_window_are_not_chosen() {
        let minute: u64 = 60 * 1_000_000_000;
        let window = u64::try_from(SELECTION_WINDOW.as_nanos()).unwrap();
        let mut correction = ClockCorrection::new();
        correction.record(measured(1, 0, minute));
        correction.record(measured(2, 10_000_000, 2 * minute));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 1);
        // Exactly the window after the first: it is still in.
        correction.record(measured(3, 20_000_000, minute + window));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 1);
        // A nanosecond more: the first falls out, however certain.
        correction.record(measured(4, 20_000_000, minute + window + 1));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 2);
        // Far later: only the newest is left.
        correction.record(measured(5, 30_000_000, 100 * minute));
        assert_eq!(correction.selected().unwrap().offset_nanos(), 5);
        assert_eq!(correction.kept.len(), 1);
    }

    #[test]
    fn what_is_kept_does_not_grow() {
        let mut correction = ClockCorrection::new();
        for step in 0..10_000u64 {
            correction.record(measured(0, 1_000 + step % 7, (step + 1) * 1_000_000_000));
        }
        // Strictly increasing uncertainty, so at most one per distinct value.
        assert!(correction.kept.len() <= 7, "{}", correction.kept.len());
    }

    #[test]
    fn clock_offset_is_a_map_of_its_fields() {
        let offset = ClockOffset {
            offset_ms: -5,
            uncertainty_ms: 7,
            measured_at: at(9),
        };
        let bytes = super::super::cbor::to_vec(&offset).unwrap();
        let mut expected = vec![0xa3, 0x69];
        expected.extend_from_slice(b"offset_ms");
        expected.push(0x24);
        expected.push(0x6e);
        expected.extend_from_slice(b"uncertainty_ms");
        expected.push(0x07);
        expected.push(0x6b);
        expected.extend_from_slice(b"measured_at");
        expected.push(0x09);
        assert_eq!(bytes, expected);
        assert_eq!(
            super::super::cbor::from_slice::<ClockOffset>(&bytes).unwrap(),
            offset
        );
    }
}
