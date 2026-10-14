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
    /// `git http-backend` exchanges at once, each one child process.
    pub git_exchanges: usize,
    /// Git exchanges one principal may hold at once.
    pub git_exchanges_per_principal: usize,
    /// LFS uploads and downloads at once, each one blocking worker.
    pub lfs_transfers: usize,
    /// LFS transfers one principal may hold at once.
    pub lfs_transfers_per_principal: usize,
    /// Bytes LFS uploads may bring the vault's stored objects to, counting
    /// what uploads in flight have reserved: each reserves its declared size,
    /// or the per-object cap when it declares none.
    pub lfs_quota_bytes: u64,
    /// How long a git or LFS transfer may go without moving a byte, in
    /// milliseconds, before it is ended and its worker and child freed.
    pub transfer_idle_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_connections_per_peer: 64,
            header_read_timeout_ms: 30_000,
            git_exchanges: 8,
            git_exchanges_per_principal: 4,
            lfs_transfers: 8,
            lfs_transfers_per_principal: 4,
            lfs_quota_bytes: 64 * 1024 * 1024 * 1024,
            // The door window's family (`DOOR_WINDOW_TIMEOUT`): long enough
            // for a slow link, short against a held-open socket.
            transfer_idle_timeout_ms: 300_000,
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
            git_exchanges,
            git_exchanges_per_principal,
            lfs_transfers,
            lfs_transfers_per_principal,
            lfs_quota_bytes,
            transfer_idle_timeout_ms,
        } = over;
        set(&mut self.max_connections, max_connections);
        set(&mut self.max_connections_per_peer, max_connections_per_peer);
        set(&mut self.header_read_timeout_ms, header_read_timeout_ms);
        set(&mut self.git_exchanges, git_exchanges);
        set(
            &mut self.git_exchanges_per_principal,
            git_exchanges_per_principal,
        );
        set(&mut self.lfs_transfers, lfs_transfers);
        set(
            &mut self.lfs_transfers_per_principal,
            lfs_transfers_per_principal,
        );
        set(&mut self.lfs_quota_bytes, lfs_quota_bytes);
        set(&mut self.transfer_idle_timeout_ms, transfer_idle_timeout_ms);
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
            ("git_exchanges", self.git_exchanges as u64),
            (
                "git_exchanges_per_principal",
                self.git_exchanges_per_principal as u64,
            ),
            ("lfs_transfers", self.lfs_transfers as u64),
            (
                "lfs_transfers_per_principal",
                self.lfs_transfers_per_principal as u64,
            ),
            ("lfs_quota_bytes", self.lfs_quota_bytes),
            ("transfer_idle_timeout_ms", self.transfer_idle_timeout_ms),
        ] {
            if value == 0 {
                anyhow::bail!("limits.{key} must be at least 1");
            }
        }
        Ok(())
    }
}

fn set<T>(field: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *field = value;
    }
}

/// One layer's `[limits]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct LimitsConfigOverride {
    pub(super) max_connections: Option<usize>,
    pub(super) max_connections_per_peer: Option<usize>,
    pub(super) header_read_timeout_ms: Option<u64>,
    pub(super) git_exchanges: Option<usize>,
    pub(super) git_exchanges_per_principal: Option<usize>,
    pub(super) lfs_transfers: Option<usize>,
    pub(super) lfs_transfers_per_principal: Option<usize>,
    pub(super) lfs_quota_bytes: Option<u64>,
    pub(super) transfer_idle_timeout_ms: Option<u64>,
}
