//! When a connection sends its next `ping`, and when it gives up on a
//! silent peer.

use std::time::Duration;

/// How long after the handshake the first `ping` goes, and how long after
/// each `ping` the next one does: 60 seconds.
pub const PING_INTERVAL: Duration = Duration::from_secs(60);

/// How long a connection waits without receiving a frame before it closes:
/// 180 seconds.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// What the liveness timer asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Due {
    Ping,
    Close,
}

#[derive(Debug, Clone)]
pub(super) struct Liveness {
    started: Duration,
    last_received: Option<Duration>,
    handshake_done: Option<Duration>,
    last_ping: Option<Duration>,
}

impl Liveness {
    pub(super) fn new(started: Duration) -> Self {
        Self {
            started,
            last_received: None,
            handshake_done: None,
            last_ping: None,
        }
    }

    pub(super) fn received(&mut self, now: Duration) {
        self.last_received = Some(now);
    }

    pub(super) fn handshake_done(&mut self, now: Duration) {
        self.handshake_done = Some(now);
    }

    pub(super) fn ping_sent(&mut self, now: Duration) {
        self.last_ping = Some(now);
    }

    fn close_at(&self) -> Duration {
        self.last_received
            .unwrap_or(self.started)
            .saturating_add(IDLE_TIMEOUT)
    }

    fn ping_at(&self) -> Option<Duration> {
        let since = self.last_ping.or(self.handshake_done)?;
        Some(since.saturating_add(PING_INTERVAL))
    }

    /// Returns what is due at `now`; closing wins when both are.
    pub(super) fn due(&self, now: Duration) -> Option<Due> {
        if now >= self.close_at() {
            Some(Due::Close)
        } else if self.ping_at().is_some_and(|at| now >= at) {
            Some(Due::Ping)
        } else {
            None
        }
    }

    /// Returns the earliest time at which something falls due.
    pub(super) fn next_deadline(&self) -> Duration {
        let close = self.close_at();
        self.ping_at().map_or(close, |ping| ping.min(close))
    }
}
