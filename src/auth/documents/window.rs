//! The validity window of commands and updates.

use jiff::{SignedDuration, Timestamp};

use crate::results::DocumentResult;

/// How far the receiver's clock may be from the issuer's: a document is
/// valid from one hour before its `issued_at` to one hour after its
/// `expires_at`.
pub const CLOCK_SKEW: SignedDuration = SignedDuration::from_hours(1);

/// The longest a `senta-command` may live, from `issued_at` to
/// `expires_at`: 24 hours.
pub const MAX_COMMAND_LIFETIME: SignedDuration = SignedDuration::from_hours(24);

/// The longest a `senta-update` may live, from `issued_at` to `expires_at`:
/// 30 × 24 hours, not a calendar month.
pub const MAX_UPDATE_LIFETIME: SignedDuration = SignedDuration::from_hours(30 * 24);

/// Checks a document's validity window against the receiver's own clock
/// `now`.
///
/// The checks run in this order, and the first to fail decides the result;
/// every bound is strict, so a time exactly on one passes:
///
/// 1. `expires_at − issued_at > max_lifetime` is [`DocumentResult::Expired`];
/// 2. `issued_at − CLOCK_SKEW > now` is [`DocumentResult::NotYetValid`];
/// 3. `expires_at + CLOCK_SKEW < now` is [`DocumentResult::Expired`].
///
/// `max_lifetime` is [`MAX_COMMAND_LIFETIME`] or [`MAX_UPDATE_LIFETIME`].
/// No time a server reported is taken. Every comparison is between the
/// differences of two times, which cannot overflow, so this never panics,
/// whatever the timestamps, [`Timestamp::MIN`] and [`Timestamp::MAX`]
/// included.
///
/// # Errors
///
/// Returns [`DocumentResult::Expired`] or [`DocumentResult::NotYetValid`]
/// from the first check that failed.
pub fn check_validity_window(
    now: Timestamp,
    issued_at: Timestamp,
    expires_at: Timestamp,
    max_lifetime: SignedDuration,
) -> Result<(), DocumentResult> {
    if expires_at.duration_since(issued_at) > max_lifetime {
        return Err(DocumentResult::Expired);
    }
    if issued_at.duration_since(now) > CLOCK_SKEW {
        return Err(DocumentResult::NotYetValid);
    }
    if now.duration_since(expires_at) > CLOCK_SKEW {
        return Err(DocumentResult::Expired);
    }
    Ok(())
}
