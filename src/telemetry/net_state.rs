//! Deciding where a record header's network state comes from, without
//! doing any I/O.
//!
//! The sender keeps the record of its network state, the IP addresses and
//! the default route's address and when they changed; this module only
//! decides, from what the caller found in that record around an event's
//! time, which state the header carries and with which
//! [`NetStateSource`].

use std::{collections::BTreeSet, net::IpAddr};

use jiff::{SignedDuration, Timestamp};

use super::NetStateSource;

/// The longest gap across which an unchanged state is carried over.
const MAX_INFERRED_GAP: SignedDuration = SignedDuration::from_mins(10);

/// A host's network state: its IP addresses and the address of its
/// default route.
#[derive(Debug, Clone, Default)]
pub struct NetState {
    /// The host's IP addresses.
    pub ips: Vec<IpAddr>,
    /// The IP address of the default route, if there is one.
    pub default_route_ip: Option<IpAddr>,
}

impl NetState {
    /// Returns whether two states are the same: their IP addresses are the
    /// same set, regardless of order and repetition, and their default
    /// route addresses are equal, both absent included.
    #[must_use]
    pub fn is_same_as(&self, other: &Self) -> bool {
        self.default_route_ip == other.default_route_ip
            && self.ips.iter().collect::<BTreeSet<_>>() == other.ips.iter().collect::<BTreeSet<_>>()
    }
}

/// A stretch of time the sender recorded its network state over, during
/// which the state was `state`.
#[derive(Debug, Clone)]
pub struct NetStateSpan {
    /// When the stretch began.
    pub start: Timestamp,
    /// When the stretch ended.
    pub end: Timestamp,
    /// The state throughout.
    pub state: NetState,
}

/// A stretch of time the sender was not running, and so recorded nothing.
#[derive(Debug, Clone)]
pub struct NetStateGap {
    /// When the gap began.
    pub start: Timestamp,
    /// When the gap ended.
    pub end: Timestamp,
    /// The state recorded just before the gap.
    pub before: NetState,
    /// The state recorded just after the gap.
    pub after: NetState,
    /// Whether the host suspended and resumed during the gap.
    pub suspended: bool,
}

/// The network state a record header carries, and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNetState {
    /// The header's `net_state_source`.
    pub source: NetStateSource,
    /// The header's `ips`.
    pub ips: Vec<IpAddr>,
    /// The header's `default_route_ip`.
    pub default_route_ip: Option<IpAddr>,
}

impl ResolvedNetState {
    fn from_state(source: NetStateSource, state: &NetState) -> Self {
        Self {
            source,
            ips: state.ips.clone(),
            default_route_ip: state.default_route_ip,
        }
    }

    fn unknown() -> Self {
        Self {
            source: NetStateSource::Unknown,
            ips: Vec::new(),
            default_route_ip: None,
        }
    }
}

/// Decides the network state a record header carries for an event at
/// `event_time`.
///
/// `span` is the recorded stretch the caller found around the event, and
/// `gap` the stretch without a record, each if there is one. In this
/// order:
///
/// 1. When `span` holds the event (`start ≤ event_time ≤ end`), the state
///    is [`NetStateSource::Observed`], the span's state.
/// 2. When `gap` holds the event (`start ≤ event_time ≤ end`), the states
///    before and after it are the same ([`NetState::is_same_as`]), it
///    lasted at most ten minutes (`end − start`, exactly ten included) and
///    the host did not suspend in it, the state is
///    [`NetStateSource::Inferred`], the state before the gap.
/// 3. Otherwise, a span or gap that ends before it starts and no record at
///    all included, the state is [`NetStateSource::Unknown`] with no
///    addresses. It is never filled in from the current state.
#[must_use]
pub fn resolve_net_state(
    event_time: Timestamp,
    span: Option<&NetStateSpan>,
    gap: Option<&NetStateGap>,
) -> ResolvedNetState {
    if let Some(span) = span
        && span.start <= event_time
        && event_time <= span.end
    {
        return ResolvedNetState::from_state(NetStateSource::Observed, &span.state);
    }
    if let Some(gap) = gap
        && gap.start <= event_time
        && event_time <= gap.end
        && gap.end.duration_since(gap.start) <= MAX_INFERRED_GAP
        && !gap.suspended
        && gap.before.is_same_as(&gap.after)
    {
        return ResolvedNetState::from_state(NetStateSource::Inferred, &gap.before);
    }
    ResolvedNetState::unknown()
}
