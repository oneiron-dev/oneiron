//! Results of releasing inference snapshot state before a vault lock.

use serde::Serialize;
use std::time::Duration;

/// How long past the runtime's own bound a lock still waits for its answer
/// before the key goes without one: the engine's bound on a host that hung
/// or crashed.
pub const LOCK_RELEASE_MARGIN: Duration = Duration::from_secs(2);

/// What a runtime did for a lock. Ids and outcomes only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SnapshotRelease {
    /// The copies released with their worker's acknowledgement.
    pub released: u64,
    /// The incarnations aborted because a release went unanswered.
    pub aborted: Vec<SnapshotWorkerAbort>,
    /// Whether a bound passed before every release was answered.
    pub timed_out: bool,
    pub elapsed_ms: u64,
    /// The host's plaintext copies of the vault's snapshots (snapshot
    /// regions and buffers in flight) when the lock began, and those still
    /// held when it answered.
    pub host_copies: u64,
    pub host_copies_left: u64,
}

/// One worker incarnation a lock aborted: killed, reaped and restarted by
/// its supervisor, its leases and handles revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotWorkerAbort {
    pub worker_id: String,
    /// The incarnation's epoch, as the worker named it.
    pub epoch: String,
    /// Whether the abort found it running and reaped it before the lock
    /// went on; `false` when that epoch had already ended on its own.
    pub reaped: bool,
}

/// What a vault lock did with its snapshot state, before the key went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotLockReceipt {
    /// The admission generation the lock closed.
    pub closed_generation: u64,
    /// The bound the lock waited for the runtime's answer, in milliseconds:
    /// its release bound and [`LOCK_RELEASE_MARGIN`]; `None` with no
    /// runtime attached.
    pub bound_ms: Option<u64>,
    /// The runtime's answer; `None` with no runtime attached.
    pub release: Option<SnapshotRelease>,
}
