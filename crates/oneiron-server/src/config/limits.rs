//! The `[limits]` section: the bounds on work a remote caller can start at
//! this server. Every bound is finite; an operator may move it but not remove
//! it.

use std::time::Duration;

use serde::Deserialize;

use crate::http_listener::ConnectionLimits;

/// Resolved limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitsConfig {
    /// Connections the listener holds open at once, from every peer together.
    pub max_connections: usize,
    /// Connections one off-device peer address may hold open. A loopback peer
    /// is bounded by `max_connections` only.
    pub max_connections_per_peer: usize,
    /// How long a request's headers may take to arrive, in milliseconds. It
    /// also bounds how long an idle keep-alive connection stays open.
    pub header_read_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_connections_per_peer: 64,
            header_read_timeout_ms: 30_000,
        }
    }
}

impl LimitsConfig {
    /// The listener's share of these limits.
    pub(crate) fn connections(&self) -> ConnectionLimits {
        ConnectionLimits {
            max_connections: self.max_connections,
            max_connections_per_peer: self.max_connections_per_peer,
            header_read_timeout: Duration::from_millis(self.header_read_timeout_ms),
        }
    }

    pub(super) fn apply_override(&mut self, over: LimitsConfigOverride) {
        let LimitsConfigOverride {
            max_connections,
            max_connections_per_peer,
            header_read_timeout_ms,
        } = over;
        if let Some(value) = max_connections {
            self.max_connections = value;
        }
        if let Some(value) = max_connections_per_peer {
            self.max_connections_per_peer = value;
        }
        if let Some(value) = header_read_timeout_ms {
            self.header_read_timeout_ms = value;
        }
    }

    /// A zero bound would refuse every caller, so it is a config error rather
    /// than a server that starts and serves nothing.
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        for (key, value) in [
            ("max_connections", self.max_connections as u64),
            (
                "max_connections_per_peer",
                self.max_connections_per_peer as u64,
            ),
            ("header_read_timeout_ms", self.header_read_timeout_ms),
        ] {
            if value == 0 {
                anyhow::bail!("limits.{key} must be at least 1");
            }
        }
        Ok(())
    }
}

/// One layer's `[limits]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct LimitsConfigOverride {
    pub(super) max_connections: Option<usize>,
    pub(super) max_connections_per_peer: Option<usize>,
    pub(super) header_read_timeout_ms: Option<u64>,
}
