//! Per-connection federation quota and pause decisions.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::types::WindowKey;

/// Default distinct-window cap for one federated selector connection.
pub const DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION: usize = 64;
/// Default pause after a federated connection exceeds its quota.
pub const DEFAULT_FEDERATION_FLOOD_PAUSE_SECS: u64 = 30;

/// Decision returned by the federation quota gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowBlock {
    /// The request may proceed.
    Allow,
    /// The request is temporarily paused for this connection.
    Pause(FederationPauseReason),
    /// The request is permanently blocked by configuration.
    Block(FederationBlockReason),
}

/// Reason a federated connection entered or remains in pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationPauseReason {
    /// A new window would exceed the connection's distinct-window quota.
    WindowQuotaExceeded,
    /// A previous quota decision is still within its pause interval.
    FloodPauseActive,
}

/// Reason a federated connection is blocked rather than paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationBlockReason {
    /// The configured per-connection federated window quota is zero.
    WindowQuotaDisabled,
}

/// Tunables for one federated connection's quota state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederationQuotaConfig {
    /// Maximum distinct valid window keys one federated connection may touch.
    pub max_windows_per_connection: usize,
    /// Pause duration after quota overflow.
    pub flood_pause: Duration,
}

impl FederationQuotaConfig {
    /// Builds quota tunables from server config values.
    #[must_use]
    pub fn new(max_windows_per_connection: usize, flood_pause_secs: u64) -> Self {
        Self {
            max_windows_per_connection,
            flood_pause: Duration::from_secs(flood_pause_secs),
        }
    }
}

impl Default for FederationQuotaConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION,
            DEFAULT_FEDERATION_FLOOD_PAUSE_SECS,
        )
    }
}

/// Observable snapshot of a federated connection's quota state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationQuotaSnapshot {
    /// Number of distinct windows accepted on this connection.
    pub windows_touched: usize,
    /// Configured distinct-window cap.
    pub max_windows_per_connection: usize,
    /// Current allow/pause/block decision at the snapshot time.
    pub decision: AllowBlock,
    /// Remaining pause duration when paused.
    pub pause_remaining: Option<Duration>,
}

/// Mutable quota state for one federated selector connection.
#[derive(Debug, Clone)]
pub struct FederationConnectionQuota {
    config: FederationQuotaConfig,
    windows_touched: HashSet<WindowKey>,
    paused_until: Option<Instant>,
    last_decision: AllowBlock,
}

impl FederationConnectionQuota {
    /// Creates empty quota state for a single connection.
    #[must_use]
    pub fn new(config: FederationQuotaConfig) -> Self {
        Self {
            config,
            windows_touched: HashSet::new(),
            paused_until: None,
            last_decision: AllowBlock::Allow,
        }
    }

    /// Evaluates whether this connection may touch `key` at `now`.
    pub fn allow_window(&mut self, key: &WindowKey, now: Instant) -> AllowBlock {
        if self.config.max_windows_per_connection == 0 {
            return self.record(AllowBlock::Block(
                FederationBlockReason::WindowQuotaDisabled,
            ));
        }

        if self.pause_remaining(now).is_some() {
            return self.record(AllowBlock::Pause(FederationPauseReason::FloodPauseActive));
        }
        self.paused_until = None;

        if self.windows_touched.contains(key) {
            return self.record(AllowBlock::Allow);
        }

        if self.windows_touched.len() >= self.config.max_windows_per_connection {
            self.paused_until = now.checked_add(self.config.flood_pause).or(Some(now));
            return self.record(AllowBlock::Pause(
                FederationPauseReason::WindowQuotaExceeded,
            ));
        }

        self.windows_touched.insert(key.clone());
        self.record(AllowBlock::Allow)
    }

    /// Returns a snapshot suitable for logs, health surfaces, and tests.
    #[must_use]
    pub fn snapshot(&self, now: Instant) -> FederationQuotaSnapshot {
        let pause_remaining = self.pause_remaining(now);
        let decision = if self.config.max_windows_per_connection == 0 {
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        } else if pause_remaining.is_some() {
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        } else {
            self.last_decision
        };

        FederationQuotaSnapshot {
            windows_touched: self.windows_touched.len(),
            max_windows_per_connection: self.config.max_windows_per_connection,
            decision,
            pause_remaining,
        }
    }

    fn record(&mut self, decision: AllowBlock) -> AllowBlock {
        self.last_decision = decision;
        decision
    }

    fn pause_remaining(&self, now: Instant) -> Option<Duration> {
        self.paused_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|remaining| !remaining.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> WindowKey {
        WindowKey::new(value)
    }

    #[test]
    fn federation_quota_allows_known_windows_after_quota_is_reached() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(quota.snapshot(now).windows_touched, 1);
    }

    #[test]
    fn federation_quota_exceeded_enters_observable_pause() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(
            quota.allow_window(&key("2026-04"), now),
            AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
        );

        let snapshot = quota.snapshot(now);
        assert_eq!(
            snapshot.decision,
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        );
        assert_eq!(snapshot.pause_remaining, Some(Duration::from_secs(30)));
        assert_eq!(snapshot.windows_touched, 1);
    }

    #[test]
    fn federation_pause_resumes_after_pause_duration() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 1));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(
            quota.allow_window(&key("2026-04"), now),
            AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
        );
        assert_eq!(
            quota.allow_window(&key("2026-03"), now),
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        );

        let resumed = now + Duration::from_secs(1);
        assert_eq!(
            quota.allow_window(&key("2026-03"), resumed),
            AllowBlock::Allow
        );
    }

    #[test]
    fn zero_federation_quota_blocks_connection() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(0, 30));

        assert_eq!(
            quota.allow_window(&key("2026-03"), now),
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        );
        assert_eq!(
            quota.snapshot(now).decision,
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        );
    }
}
