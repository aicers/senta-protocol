//! Unit tests of what the public API does not show.

use super::SpkiKey;

#[test]
fn spki_keys_compare_by_value() {
    assert_eq!(SpkiKey([1; 32]), SpkiKey([1; 32]));
    let mut other = [1; 32];
    other[31] = 2;
    assert_ne!(SpkiKey([1; 32]), SpkiKey(other));
}

#[cfg(feature = "control")]
#[test]
fn control_kinds_are_known() {
    use super::admission::{LICENSE_PENDING_CONTROL, NOT_LISTED_CONTROL, SUSPENDED_CONTROL};
    use crate::connection::{Hello, HelloAck, Message, Ping, Pong, Unsupported};
    use crate::control::MESSAGE_KINDS;

    let builtin = [Hello::T, HelloAck::T, Ping::T, Pong::T, Unsupported::T];
    for t in NOT_LISTED_CONTROL
        .iter()
        .chain(&LICENSE_PENDING_CONTROL)
        .chain(&SUSPENDED_CONTROL)
    {
        assert!(
            MESSAGE_KINDS.contains(t) || builtin.contains(t),
            "{t} is not a control message"
        );
    }
}
