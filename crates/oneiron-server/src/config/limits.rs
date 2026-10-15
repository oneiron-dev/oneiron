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
    /// Bytes LFS transfers may hold in memory at once: half for reads (chunk
    /// exchanges, downloads and verifies), half for installing uploads. An
    /// exchange reads its request and builds its reply whole, so it takes a
    /// fixed room before it reads a byte; a download or a verify takes room
    /// for its object's manifest before it reads it; each keeps its room
    /// until its last byte is handed on. An upload takes room by its size
    /// once its body is spooled, for its install's credential scan and
    /// manifest, and keeps it until it is stored. Past either half, work
    /// queues, and work larger than its half waits to run alone. A memory
    /// bound sized from the machine (an eighth of its memory), not a count;
    /// each half holds at least one chunk exchange.
    pub lfs_memory_bytes: u64,
    /// Requests `embedder serve` holds at once, reading their bodies, waiting
    /// for the model or embedding. Past it, requests queue. The model itself
    /// works on a few at a time whatever this is; the rest wait their turn.
    pub embedder_requests: usize,
    /// Bytes `embedder serve`'s answers may hold at once: an answer takes
    /// room for its rows and their encoding before the model makes it, and
    /// keeps it until it is delivered. Past it, requests queue. A memory
    /// bound sized for the endpoint's machine, not a count.
    pub embedder_answer_bytes: u64,
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
    /// Live-query sessions held at once: one each socket attached to, and
    /// the ones kept for a reconnect after their socket went. Past it, the
    /// longest-kept detached session goes first (its reconnect gets a fresh
    /// snapshot); while every session is attached, the next waits its turn.
    pub live_sessions: usize,
    /// Live-query subscriptions open at once, every session's together.
    /// Past it, the next subscription waits its turn.
    pub live_subscriptions: usize,
    /// Message streams the vault holds open at once. Past it, the next
    /// stream waits its turn.
    pub message_streams: usize,
    /// Text documents the vault keeps resident at once. Past it, the next
    /// opener waits its turn.
    pub live_documents: usize,
    /// Bytes app-tier state kept between frames may hold at once: the
    /// presence hub, each live-query subscription's retained pushes and each
    /// socket's residence index projection. State larger than the whole of
    /// it runs alone. A memory bound sized from the machine (an eighth of
    /// its memory), not a count: past it, such state is the memory floor's
    /// one refusal, and a retained ring falls back to a resync.
    pub retained_memory_bytes: u64,
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
            lfs_memory_bytes: memory_floor(),
            embedder_requests: 2_048,
            embedder_answer_bytes: 256 * 1024 * 1024,
            lfs_quota_bytes: 64 * 1024 * 1024 * 1024,
            // The door window's family (`DOOR_WINDOW_TIMEOUT`): long enough
            // for a slow link, short against a held-open socket.
            transfer_idle_timeout_ms: 300_000,
            queue_wait_timeout_ms: 300_000,
            disk_reserve_bytes: 2 * 1024 * 1024 * 1024,
            live_sessions: 4_096,
            live_subscriptions: 65_536,
            message_streams: oneiron::live_rows::LiveRows::DEFAULT_MESSAGE_STREAMS,
            live_documents: oneiron::live_rows::LiveRows::DEFAULT_LIVE_DOCUMENTS,
            retained_memory_bytes: memory_floor(),
        }
    }
}

/// Half the descriptors this process may open, for sockets; the other half
/// stays for the vault, spools and git children, and the transfer rows are
/// held to what it leaves (`Transfers::new`). Raising the open-file limit
/// (`LimitNOFILE=`) raises it.
fn descriptor_floor() -> usize {
    let limit = crate::machine::open_file_limit().unwrap_or(8_192);
    usize::try_from(limit / 2).unwrap_or(usize::MAX).max(64)
}

/// An eighth of the machine's memory for what LFS transfers hold in memory,
/// and as much for app-tier state kept between frames, each at least 256
/// MiB; 2 GiB when the platform does not say.
fn memory_floor() -> u64 {
    const MIB: u64 = 1024 * 1024;
    crate::machine::memory_bytes().map_or(2_048 * MIB, |memory| (memory / 8).max(256 * MIB))
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
            lfs_memory_bytes,
            embedder_requests,
            embedder_answer_bytes,
            lfs_quota_bytes,
            transfer_idle_timeout_ms,
            queue_wait_timeout_ms,
            disk_reserve_bytes,
            live_sessions,
            live_subscriptions,
            message_streams,
            live_documents,
            retained_memory_bytes,
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
        set(&mut self.lfs_memory_bytes, lfs_memory_bytes);
        set(&mut self.embedder_requests, embedder_requests);
        set(&mut self.embedder_answer_bytes, embedder_answer_bytes);
        set(&mut self.lfs_quota_bytes, lfs_quota_bytes);
        set(&mut self.transfer_idle_timeout_ms, transfer_idle_timeout_ms);
        set(&mut self.queue_wait_timeout_ms, queue_wait_timeout_ms);
        set(&mut self.disk_reserve_bytes, disk_reserve_bytes);
        set(&mut self.live_sessions, live_sessions);
        set(&mut self.live_subscriptions, live_subscriptions);
        set(&mut self.message_streams, message_streams);
        set(&mut self.live_documents, live_documents);
        set(&mut self.retained_memory_bytes, retained_memory_bytes);
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
            ("lfs_memory_bytes", self.lfs_memory_bytes),
            ("embedder_requests", self.embedder_requests as u64),
            ("embedder_answer_bytes", self.embedder_answer_bytes),
            ("lfs_quota_bytes", self.lfs_quota_bytes),
            ("transfer_idle_timeout_ms", self.transfer_idle_timeout_ms),
            ("queue_wait_timeout_ms", self.queue_wait_timeout_ms),
            ("live_sessions", self.live_sessions as u64),
            ("live_subscriptions", self.live_subscriptions as u64),
            ("message_streams", self.message_streams as u64),
            ("live_documents", self.live_documents as u64),
            ("retained_memory_bytes", self.retained_memory_bytes),
        ] {
            if value == 0 {
                anyhow::bail!("limits.{key} must be at least 1");
            }
        }
        // A byte row is a claim on the machine: one too small for a single
        // chunk exchange would be held to one anyway, past what it says.
        let least = 2 * crate::api::LFS_MEMORY_ROOM;
        if self.lfs_memory_bytes < least {
            anyhow::bail!(
                "limits.lfs_memory_bytes must be at least {least}: room for one LFS chunk exchange in each half"
            );
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
    pub(super) lfs_memory_bytes: Option<u64>,
    pub(super) embedder_requests: Option<usize>,
    pub(super) embedder_answer_bytes: Option<u64>,
    pub(super) lfs_quota_bytes: Option<u64>,
    pub(super) transfer_idle_timeout_ms: Option<u64>,
    pub(super) queue_wait_timeout_ms: Option<u64>,
    pub(super) disk_reserve_bytes: Option<u64>,
    pub(super) live_sessions: Option<usize>,
    pub(super) live_subscriptions: Option<usize>,
    pub(super) message_streams: Option<usize>,
    pub(super) live_documents: Option<usize>,
    pub(super) retained_memory_bytes: Option<u64>,
}
