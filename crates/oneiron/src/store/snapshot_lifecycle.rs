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

use crate::entity_id::EntityId;
use crate::store::snapshot_ledger::Ledger;
use oneiron_model::llm::VaultRef;

pub use crate::store::snapshot_lock_result::LOCK_RELEASE_MARGIN;

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

pub use crate::store::snapshot_lock_result::{
    SnapshotLockReceipt, SnapshotRelease, SnapshotWorkerAbort,
};

/// One admission: the generation it was granted under and the erase
/// generation it saw. A publish or restore checks it still holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotAdmission {
    generation: u64,
    erase_generation: u64,
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

/// The state every handle on one open vault shares (a [`crate::store::StoreCore`]
/// field). In memory only: an open starts generation 1, open.
#[derive(Default)]
pub(crate) struct SnapshotLifecycle {
    gate: Mutex<Gate>,
    pub(crate) runtime: RwLock<Option<Arc<dyn SnapshotRuntime>>>,
    ledger: Ledger,
    /// Held from a body file's write to its row's commit, and by every
    /// sweep of the body files, so a sweep never takes a body whose row is
    /// about to commit.
    files: Mutex<()>,
}

#[derive(Debug)]
struct Gate {
    generation: u64,
    open: bool,
    erase_generation: u64,
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

impl SnapshotLifecycle {
    fn gate(&self) -> MutexGuard<'_, Gate> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn attached(&self) -> Option<Arc<dyn SnapshotRuntime>> {
        self.runtime
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub(crate) fn files(&self) -> MutexGuard<'_, ()> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The body files' guard, or `None` while a publication or a sweep
    /// holds it.
    pub(crate) fn try_files(&self) -> Option<MutexGuard<'_, ()>> {
        match self.files.try_lock() {
            Ok(files) => Some(files),
            Err(TryLockError::Poisoned(files)) => Some(files.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Closes the gate: the generation it closed admits nothing again.
    pub(crate) fn close(&self) -> u64 {
        let mut gate = self.gate();
        let closed = gate.generation;
        gate.generation = gate.generation.wrapping_add(1);
        gate.open = false;
        closed
    }

    /// Opens a new generation, as an unlock does: nothing becomes ready.
    pub(crate) fn reopen(&self) {
        let mut gate = self.gate();
        if !gate.open {
            gate.generation = gate.generation.wrapping_add(1);
            gate.open = true;
        }
    }

    pub(crate) fn admission(&self) -> Option<SnapshotAdmission> {
        let gate = self.gate();
        gate.open.then_some(SnapshotAdmission {
            generation: gate.generation,
            erase_generation: gate.erase_generation,
        })
    }

    pub(crate) fn holds(&self, admission: &SnapshotAdmission) -> bool {
        let gate = self.gate();
        gate.open
            && gate.generation == admission.generation
            && gate.erase_generation == admission.erase_generation
    }

    /// Moves the erase generation: no admission granted before holds. An
    /// erase does this inside its own transaction, so a publish whose
    /// writer waits behind it sees it.
    pub(crate) fn erased(&self) {
        let mut gate = self.gate();
        gate.erase_generation = gate.erase_generation.wrapping_add(1);
    }
}
