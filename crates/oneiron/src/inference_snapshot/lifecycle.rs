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
//! none. An unlock opens a new generation; it makes nothing
//! ready, and the sealed catalog stays through both.
//!
//! The port is a boxed future: this crate names no server, and no executor
//! beyond the timer that bounds the wait.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::retention::Ledger;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::llm::VaultRef;

/// How long past the runtime's own bound a lock still waits for its answer
/// before the key goes without one: the engine's bound on a host that hung
/// or crashed.
pub const LOCK_RELEASE_MARGIN: Duration = Duration::from_secs(2);

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
}

/// One worker incarnation a lock aborted: killed, reaped and restarted by
/// its supervisor, its leases and handles revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SnapshotWorkerAbort {
    pub worker_id: String,
    /// The incarnation's epoch, as the worker named it.
    pub epoch: String,
    /// Whether its process was reaped before the lock went on.
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
    runtime: RwLock<Option<Arc<dyn SnapshotRuntime>>>,
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

    fn attached(&self) -> Option<Arc<dyn SnapshotRuntime>> {
        self.runtime
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(super) fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub(super) fn files(&self) -> MutexGuard<'_, ()> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Closes the gate: the generation it closed admits nothing again.
    fn close(&self) -> u64 {
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

    fn admission(&self) -> Option<SnapshotAdmission> {
        let gate = self.gate();
        gate.open.then_some(SnapshotAdmission {
            generation: gate.generation,
            erase_generation: gate.erase_generation,
        })
    }

    fn holds(&self, admission: &SnapshotAdmission) -> bool {
        let gate = self.gate();
        gate.open
            && gate.generation == admission.generation
            && gate.erase_generation == admission.erase_generation
    }

    /// Moves the erase generation: no admission granted before holds. An
    /// erase does this inside its own transaction, so a publish whose
    /// writer waits behind it sees it.
    pub(super) fn erased(&self) {
        let mut gate = self.gate();
        gate.erase_generation = gate.erase_generation.wrapping_add(1);
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Vault {
    fn snapshot_vault_ref(&self) -> VaultRef {
        VaultRef(*self.vault_id().as_bytes())
    }

    /// Attaches the host's runtime to this vault's snapshot lifecycle: a
    /// lock waits for its release, within its bound and
    /// [`LOCK_RELEASE_MARGIN`], and an erase tells it what to drop. A later
    /// attach replaces it.
    pub fn attach_snapshot_runtime(&self, runtime: Arc<dyn SnapshotRuntime>) {
        *self
            .store
            .inference_snapshots
            .runtime
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(runtime);
    }

    /// An admission under the current generation, `None` while the vault
    /// is locked.
    #[must_use]
    pub fn snapshot_admission(&self) -> Option<SnapshotAdmission> {
        self.store.inference_snapshots.admission()
    }

    /// Whether `admission` still holds: no lock and no erase since.
    #[must_use]
    pub fn snapshot_admission_holds(&self, admission: &SnapshotAdmission) -> bool {
        self.store.inference_snapshots.holds(admission)
    }

    /// The snapshot half of a vault lock: closes admission, drops the
    /// reservations in flight, and waits for the attached runtime's release
    /// within its bound and [`LOCK_RELEASE_MARGIN`]. Never refuses: an
    /// answer that does not come in time is recorded timed out. Off a Tokio
    /// runtime, which the bound needs, the runtime is not asked and the
    /// release is recorded timed out.
    pub(crate) async fn release_inference_snapshots_for_lock(&self) -> SnapshotLockReceipt {
        let lifecycle = &self.store.inference_snapshots;
        let closed_generation = lifecycle.close();
        lifecycle.ledger().clear();
        let Some(runtime) = lifecycle.attached() else {
            return SnapshotLockReceipt {
                closed_generation,
                bound_ms: None,
                release: None,
            };
        };
        let started = Instant::now();
        let timed_out = || SnapshotRelease {
            timed_out: true,
            elapsed_ms: elapsed_ms(started),
            ..SnapshotRelease::default()
        };
        let vault = self.snapshot_vault_ref();
        let bound = runtime
            .release_bound(vault)
            .saturating_add(LOCK_RELEASE_MARGIN);
        let release = if tokio::runtime::Handle::try_current().is_ok() {
            let answer = runtime.release_vault(vault, closed_generation);
            match tokio::time::timeout(bound, answer).await {
                Ok(release) => release,
                Err(_) => timed_out(),
            }
        } else {
            timed_out()
        };
        if release.timed_out {
            tracing::warn!(
                aborted = release.aborted.len(),
                elapsed_ms = release.elapsed_ms,
                "a vault lock's snapshot release was not answered in time; the key drops anyway"
            );
        }
        SnapshotLockReceipt {
            closed_generation,
            bound_ms: Some(u64::try_from(bound.as_millis()).unwrap_or(u64::MAX)),
            release: Some(release),
        }
    }

    /// Carries out what retiring catalog rows leaves after their commit: the
    /// custody entries and the body files of every snapshot no row names
    /// any longer. A failure waits for the next housekeeping pass, which
    /// runs this again.
    pub(crate) fn finish_inference_snapshot_retirements_after_commit(&self) {
        if let Err(error) = self.finish_inference_snapshot_retirements() {
            tracing::warn!(
                kind = ?error.kind(),
                "inference snapshot retirement deferred to the next housekeeping pass"
            );
        }
    }

    /// After an erase commits (FIX 10466): admissions that saw the erase
    /// generation before it no longer hold, and the attached runtime drops
    /// every copy that may depend on `ids`.
    pub(crate) fn inference_snapshots_erased(&self, ids: &[EntityId]) {
        let lifecycle = &self.store.inference_snapshots;
        lifecycle.erased();
        if let Some(runtime) = lifecycle.attached() {
            runtime.invalidate(self.snapshot_vault_ref(), ids);
        }
    }
}
