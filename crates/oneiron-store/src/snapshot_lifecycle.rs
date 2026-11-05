//! A vault's inference snapshot lifecycle (DESIGN-V2 §7 "On vault lock",
//! V2-R3): the admission generation and closing gate every handle on one
//! open vault shares, its erase generation, its disk line, and the port to
//! the host's runtime, the process that holds what plaintext snapshot state
//! exists.
//!
//! A lock closes the gate first, so nothing new is admitted under the
//! generation that closed; then the attached runtime releases every copy of
//! this vault's state it holds (native sessions, host memory, transfer
//! buffers and mappings) under its own bound, aborting and restarting a
//! worker that does not answer; only then does the vault key go. The lock
//! always lands: a runtime that has not answered within its bound and
//! [`LOCK_RELEASE_MARGIN`] is recorded timed out, and the key goes anyway.
//! With no runtime attached the gate closes, the reservations in flight
//! drop and the key goes at once: this crate keeps no plaintext snapshot
//! buffer past a call, and a read whose admission a lock closed returns
//! none. An unlock opens a new generation; it makes nothing ready, and the
//! sealed catalog stays through both.
//!
//! The port is a boxed future: this crate names no server, and no executor
//! beyond the timer that bounds the wait.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, TryLockError};
use std::time::Duration;

use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::VaultRef;

pub use crate::snapshot_lock_result::LOCK_RELEASE_MARGIN;

/// A runtime's answer, in flight.
pub type SnapshotFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The host's runtime, as a vault asks it: the process that holds this
/// vault's plaintext snapshot state, native and in host memory. The vault
/// gives it no key, database or file.
pub trait SnapshotRuntime: Send + Sync {
    /// The bound `vault`'s release answers within: the owner's lock release
    /// timeout. The lock waits that long and [`LOCK_RELEASE_MARGIN`] more.
    /// It takes no lock the release path holds: a hung release never
    /// blocks it.
    fn release_bound(&self, vault: VaultRef) -> Duration;

    /// Releases every copy of `vault`'s snapshot state the host holds, for a
    /// lock: its sessions and their handles, host memory copies, transfer
    /// buffers and mappings. `closed` is the admission generation that just
    /// closed; nothing is admitted under it again. Resolves once each copy
    /// is released, or its worker's incarnation was aborted and reaped, and
    /// within the host's own bound.
    fn release_vault(&self, vault: VaultRef, closed: u64) -> SnapshotFuture<'_, SnapshotRelease>;

    /// Drops every copy of `vault`'s state that may depend on `ids`: an
    /// erase committed. Returns at once; the drops run on the host.
    fn invalidate(&self, vault: VaultRef, ids: &[EntityId]);
}

pub use crate::snapshot_lock_result::SnapshotLockReceipt;
pub use crate::snapshot_lock_result::SnapshotRelease;
pub use crate::snapshot_lock_result::SnapshotWorkerAbort;

/// One admission: the generation it was granted under and the erase
/// generation it saw. A publish or restore checks it still holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotAdmission {
    pub generation: u64,
    pub erase_generation: u64,
}

impl SnapshotAdmission {
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn erase_generation(&self) -> u64 {
        self.erase_generation
    }
}

#[derive(Debug)]
pub struct Gate {
    pub generation: u64,
    pub open: bool,
    pub erase_generation: u64,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            generation: 1,
            open: true,
            erase_generation: 0,
        }
    }
}
