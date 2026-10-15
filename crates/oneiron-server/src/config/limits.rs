//! The `[limits]` section: the bounds on work a remote caller can start at
//! this server. Every bound is finite; an operator may move it but not remove
//! it.
//!
//! Most bounds are rows set far above fleet scale (ARCH-0079 plans for 100 to
//! 200 agents, many on one credential and one address; each count row is at
//! least ten times that). Past a row, work waits its turn in a fair queue and
//! the row asks whether everything is okay (OF-520); it never refuses. Only
//! the machine's own floors refuse or hold work back: the descriptor floor
//! (`max_connections`, sized from the open-file limit) and the disk floor
//! (`disk_reserve_bytes`), plus the anonymous surface's per-address share.

use std::time::Duration;

use serde::Deserialize;

use crate::http_listener::ConnectionLimits;

/// Resolved limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitsConfig {
    /// Connections the listener holds open at once, from every peer together:
    /// the descriptor floor. Past it, new sockets wait in the backlog.
    pub max_connections: usize,
    /// Connections one off-device peer address may hold before any of them
    /// has authenticated, and never more than half of `max_connections`. A
    /// connection leaves this share once a request on it authenticates; a
    /// loopback peer never holds one.
    pub max_unauthenticated_connections_per_peer: usize,
    /// How long a request's headers may take to arrive, in milliseconds. It
    /// also bounds how long an idle keep-alive connection stays open.
    pub header_read_timeout_ms: u64,
    /// How long a route may wait for the next piece of a request body, in
    /// milliseconds, before the body fails and the connection is closed.
    pub body_idle_timeout_ms: u64,
    /// `git http-backend` exchanges at once, each one child process. Past
    /// it, exchanges queue.
    pub git_exchanges: usize,
    /// LFS uploads and downloads at once, each one blocking worker. Past it,
    /// transfers queue.
    pub lfs_transfers: usize,
    /// Bytes stored LFS objects may come to, counting what uploads in flight
    /// have reserved: each reserves its declared size, or the per-object row
    /// when it declares none. Past it, an upload still lands and the row asks.
    pub lfs_quota_bytes: u64,
    /// How long a git or LFS transfer may go without moving a byte, in
    /// milliseconds, before it is ended and its worker and child freed.
    pub transfer_idle_timeout_ms: u64,
    /// How long work may wait for its turn, in milliseconds: a request
    /// timeout, not a limit. A wait that reaches it ends with nothing started.
    pub queue_wait_timeout_ms: u64,
    /// Free bytes the disk holding the vault keeps. An upload that would take
    /// the disk below it, counting the room every other upload in flight has
    /// claimed, is refused: before a byte is read when it declares its size,
    /// and as soon as it gets there when it does not.
    pub disk_reserve_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: descriptor_floor(),
            max_unauthenticated_connections_per_peer: 256,
            header_read_timeout_ms: 30_000,
            body_idle_timeout_ms: 60_000,
            git_exchanges: 2_048,
            lfs_transfers: 2_048,
            lfs_quota_bytes: 64 * 1024 * 1024 * 1024,
            // The door window's family (`DOOR_WINDOW_TIMEOUT`): long enough
            // for a slow link, short against a held-open socket.
            transfer_idle_timeout_ms: 300_000,
            queue_wait_timeout_ms: 300_000,
            disk_reserve_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Half the descriptors this process may open, for sockets; the other half
/// stays for the vault, spools and git children. Raising the open-file limit
/// (`LimitNOFILE=`) raises it.
fn descriptor_floor() -> usize {
    let limit = crate::machine::open_file_limit().unwrap_or(8_192);
    usize::try_from(limit / 2).unwrap_or(usize::MAX).max(64)
}

impl LimitsConfig {
    /// The listener's share of these limits.
    pub(crate) fn connections(&self) -> ConnectionLimits {
        ConnectionLimits {
            max_connections: self.max_connections,
            max_unauthenticated_per_peer: self.max_unauthenticated_connections_per_peer,
            header_read_timeout: Duration::from_millis(self.header_read_timeout_ms),
            body_idle_timeout: Duration::from_millis(self.body_idle_timeout_ms),
            queue_wait: self.queue_wait(),
        }
    }

    /// How long queued work waits for its turn.
    pub(crate) fn queue_wait(&self) -> Duration {
        Duration::from_millis(self.queue_wait_timeout_ms)
    }

    pub(super) fn apply_override(&mut self, over: LimitsConfigOverride) {
        let LimitsConfigOverride {
            max_connections,
            max_unauthenticated_connections_per_peer,
            header_read_timeout_ms,
            body_idle_timeout_ms,
            git_exchanges,
            lfs_transfers,
            lfs_quota_bytes,
            transfer_idle_timeout_ms,
            queue_wait_timeout_ms,
            disk_reserve_bytes,
        } = over;
        set(&mut self.max_connections, max_connections);
        set(
            &mut self.max_unauthenticated_connections_per_peer,
            max_unauthenticated_connections_per_peer,
        );
        set(&mut self.header_read_timeout_ms, header_read_timeout_ms);
        set(&mut self.body_idle_timeout_ms, body_idle_timeout_ms);
        set(&mut self.git_exchanges, git_exchanges);
        set(&mut self.lfs_transfers, lfs_transfers);
        set(&mut self.lfs_quota_bytes, lfs_quota_bytes);
        set(&mut self.transfer_idle_timeout_ms, transfer_idle_timeout_ms);
        set(&mut self.queue_wait_timeout_ms, queue_wait_timeout_ms);
        set(&mut self.disk_reserve_bytes, disk_reserve_bytes);
    }

    /// A zero bound would refuse every caller, so it is a config error rather
    /// than a server that starts and serves nothing. A zero disk reserve is a
    /// floor at the disk's last byte, which is allowed.
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        for (key, value) in [
            ("max_connections", self.max_connections as u64),
            (
                "max_unauthenticated_connections_per_peer",
                self.max_unauthenticated_connections_per_peer as u64,
            ),
            ("header_read_timeout_ms", self.header_read_timeout_ms),
            ("body_idle_timeout_ms", self.body_idle_timeout_ms),
            ("git_exchanges", self.git_exchanges as u64),
            ("lfs_transfers", self.lfs_transfers as u64),
            ("lfs_quota_bytes", self.lfs_quota_bytes),
            ("transfer_idle_timeout_ms", self.transfer_idle_timeout_ms),
            ("queue_wait_timeout_ms", self.queue_wait_timeout_ms),
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
    pub(super) max_unauthenticated_connections_per_peer: Option<usize>,
    pub(super) header_read_timeout_ms: Option<u64>,
    pub(super) body_idle_timeout_ms: Option<u64>,
    pub(super) git_exchanges: Option<usize>,
    pub(super) lfs_transfers: Option<usize>,
    pub(super) lfs_quota_bytes: Option<u64>,
    pub(super) transfer_idle_timeout_ms: Option<u64>,
    pub(super) queue_wait_timeout_ms: Option<u64>,
    pub(super) disk_reserve_bytes: Option<u64>,
}
