//! Core half of `store::snapshot_lifecycle`: its store-layer items live in `oneiron_store::snapshot_lifecycle` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::snapshot_lifecycle::*;

use crate::entity_id::EntityId;
use crate::store::snapshot_ledger::Ledger;
pub use crate::store::snapshot_lock_result::LOCK_RELEASE_MARGIN;
pub use crate::store::snapshot_lock_result::{
    SnapshotLockReceipt, SnapshotRelease, SnapshotWorkerAbort,
};
use oneiron_model::llm::VaultRef;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, TryLockError};
use std::time::Duration;

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
    /// The data-key handoffs in flight ([`SnapshotAdmissionPause`]): while
    /// any is, no admission is granted. Read and changed under the gate.
    paused: AtomicU32,
}

/// Holds snapshot admission shut while the vault's data key changes hands, a
/// new data-key generation from its draft to its finish: no admission
/// granted before it holds, and none is granted while it lives, so no
/// snapshot sealed under the old key commits after the act. Dropping it
/// opens admission again only as far as the gate is open: a lock in between
/// keeps it shut.
pub(crate) struct SnapshotAdmissionPause<'a> {
    lifecycle: &'a SnapshotLifecycle,
}

impl Drop for SnapshotAdmissionPause<'_> {
    fn drop(&mut self) {
        let _gate = self.lifecycle.gate();
        self.lifecycle.paused.fetch_sub(1, Ordering::SeqCst);
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
        let paused = self.paused.load(Ordering::SeqCst) != 0;
        (gate.open && !paused).then_some(SnapshotAdmission {
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

    /// Pauses admission for a data-key handoff until the returned guard
    /// drops: every admission granted before stops holding, as after an
    /// erase, and none is granted meanwhile.
    pub(crate) fn pause_for_key_handoff(&self) -> SnapshotAdmissionPause<'_> {
        let mut gate = self.gate();
        gate.erase_generation = gate.erase_generation.wrapping_add(1);
        self.paused.fetch_add(1, Ordering::SeqCst);
        drop(gate);
        SnapshotAdmissionPause { lifecycle: self }
    }
}
