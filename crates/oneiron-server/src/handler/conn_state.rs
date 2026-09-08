//! Per-connection budgets, quotas, rate limit, and sync-mode binding.

use std::collections::HashSet;
use std::time::Instant as StdInstant;

use tokio::time::{Duration, Instant};

use oneiron::sync::{AllowBlock, FederationConnectionQuota, FederationQuotaConfig, WindowKey};

use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError};

/// Per-connection mutable state. This is intentionally local to one socket:
/// Phase-1 auth has only a shared secret, so user-scoped limits are not sound.
pub(super) struct ConnState {
    windows_touched: HashSet<WindowKey>,
    federation_quota: FederationConnectionQuota,
    rate_limiter: MessageRateLimiter,
    pub(super) window_sync_mode: WindowSyncMode,
    pub(super) protocol_version: u8,
    /// App-tier authority is established only by a successful in-band bind.
    pub(super) bound_auth: Option<CoreAuth>,
}

impl ConnState {
    pub(super) fn new(
        max_messages_per_sec: u32,
        protocol_version: u8,
        federation_quota: FederationQuotaConfig,
    ) -> Self {
        Self {
            windows_touched: HashSet::new(),
            federation_quota: FederationConnectionQuota::new(federation_quota),
            rate_limiter: MessageRateLimiter::new(max_messages_per_sec),
            window_sync_mode: WindowSyncMode::Unbound,
            protocol_version,
            bound_auth: None,
        }
    }

    pub(super) fn record_inbound_message(&mut self) -> bool {
        self.rate_limiter.allow(Instant::now())
    }

    pub(super) fn touch_window(
        &mut self,
        key: WindowKey,
        max_windows_per_connection: usize,
    ) -> Result<WindowKey, ProtocolError> {
        if self.windows_touched.contains(&key) {
            return Ok(key);
        }

        if self.windows_touched.len() >= max_windows_per_connection {
            return Err(ProtocolError::InvalidPayload(
                "window creation limit exceeded",
            ));
        }

        self.windows_touched.insert(key.clone());
        Ok(key)
    }

    pub(super) fn allow_federation_window(&mut self, key: &WindowKey) -> AllowBlock {
        self.federation_quota.allow_window(key, StdInstant::now())
    }

    pub(super) fn federation_quota_snapshot(&self) -> oneiron::sync::FederationQuotaSnapshot {
        self.federation_quota.snapshot(StdInstant::now())
    }

    pub(super) fn bind_window_sync_mode(
        &mut self,
        mode: WindowSyncMode,
    ) -> Result<(), ProtocolError> {
        if mode == WindowSyncMode::Unbound {
            return Ok(());
        }
        match mode {
            WindowSyncMode::Selector
                if self.protocol_version != protocol::PROTOCOL_VERSION
                    && self.protocol_version != protocol::LEGACY_SELECTOR_PROTOCOL_VERSION =>
            {
                return Err(ProtocolError::InvalidPayload(
                    "selector sync requires the current selector protocol",
                ));
            }
            WindowSyncMode::FullWindow
                if self.protocol_version != protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION =>
            {
                return Err(ProtocolError::InvalidPayload(
                    "full-window sync requires the current full-window protocol",
                ));
            }
            _ => {}
        }

        match (self.window_sync_mode, mode) {
            (WindowSyncMode::Unbound, requested) => {
                self.window_sync_mode = requested;
                Ok(())
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::FullWindow)
            | (WindowSyncMode::Selector, WindowSyncMode::Selector) => Ok(()),
            (WindowSyncMode::Selector, WindowSyncMode::FullWindow) => {
                Err(ProtocolError::InvalidPayload(
                    "selector-scoped connection cannot use full-window sync",
                ))
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::Selector) => Err(
                ProtocolError::InvalidPayload("full-window connection cannot use selector sync"),
            ),
            (_, WindowSyncMode::Unbound) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowSyncMode {
    Unbound,
    FullWindow,
    Selector,
}

struct MessageRateLimiter {
    max_messages_per_sec: u32,
    window_start: Instant,
    messages_seen: u32,
}

impl MessageRateLimiter {
    fn new(max_messages_per_sec: u32) -> Self {
        Self {
            max_messages_per_sec,
            window_start: Instant::now(),
            messages_seen: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        if self.max_messages_per_sec == 0 {
            return false;
        }

        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.messages_seen = 0;
        }

        if self.messages_seen >= self.max_messages_per_sec {
            return false;
        }

        self.messages_seen += 1;
        true
    }
}
