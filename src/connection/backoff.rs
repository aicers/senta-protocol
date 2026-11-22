//! The wait before an endpoint reconnects.

use std::time::Duration;

/// The wait before the first reconnection attempt, before jitter: one
/// second.
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The longest wait between reconnection attempts, before jitter: five
/// minutes.
pub const BACKOFF_CAP: Duration = Duration::from_secs(5 * 60);

/// Returns the wait before reconnection attempt `attempt`, counted from 0,
/// given a random number `r` in `[0, 1]`.
///
/// The wait is `r × min(1 s × 2^attempt, 5 min)`: the ceiling doubles from
/// one second up to five minutes, and `r` spreads the wait anywhere from
/// nothing up to that ceiling. It never overflows, however large
/// `attempt` is. An `r` below 0 counts as 0 and one above 1 as 1; a NaN
/// counts as 1, the longest wait.
#[must_use]
pub fn reconnect_delay(attempt: u32, r: f64) -> Duration {
    let ceiling = 1u64
        .checked_shl(attempt)
        .and_then(|factor| BACKOFF_BASE.checked_mul(u32::try_from(factor).ok()?))
        .map_or(BACKOFF_CAP, |ceiling| ceiling.min(BACKOFF_CAP));
    let r = if r.is_nan() { 1.0 } else { r.clamp(0.0, 1.0) };
    ceiling.mul_f64(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_doubles_from_a_second_up_to_five_minutes() {
        let expected = [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300];
        for (attempt, seconds) in (0u32..).zip(expected) {
            assert_eq!(
                reconnect_delay(attempt, 1.0),
                Duration::from_secs(seconds),
                "{attempt}"
            );
        }
        for attempt in [31, 32, 63, 64, 1_000, u32::MAX] {
            assert_eq!(reconnect_delay(attempt, 1.0), BACKOFF_CAP);
            assert!(reconnect_delay(attempt, 0.7) <= BACKOFF_CAP);
        }
    }

    #[test]
    fn r_scales_the_wait() {
        assert_eq!(reconnect_delay(0, 0.0), Duration::ZERO);
        assert_eq!(reconnect_delay(0, 0.5), Duration::from_millis(500));
        assert_eq!(reconnect_delay(3, 0.25), Duration::from_secs(2));
        assert_eq!(reconnect_delay(20, 0.5), Duration::from_secs(150));
        assert_eq!(reconnect_delay(20, 0.0), Duration::ZERO);
    }

    #[test]
    fn r_out_of_range_is_clamped_and_nan_is_the_longest_wait() {
        assert_eq!(reconnect_delay(2, -0.5), Duration::ZERO);
        assert_eq!(reconnect_delay(2, f64::NEG_INFINITY), Duration::ZERO);
        assert_eq!(reconnect_delay(2, 1.5), Duration::from_secs(4));
        assert_eq!(reconnect_delay(2, f64::INFINITY), Duration::from_secs(4));
        assert_eq!(reconnect_delay(2, f64::NAN), Duration::from_secs(4));
        assert_eq!(reconnect_delay(40, f64::NAN), BACKOFF_CAP);
    }
}
