//! Inference snapshot lifecycle vault doors.

use std::sync::{Arc, PoisonError};
use std::time::Instant;
use crate::Vault;
use crate::entity_id::EntityId;
use oneiron_model::llm::VaultRef;

pub use crate::store::snapshot_lifecycle::{LOCK_RELEASE_MARGIN, SnapshotFuture, SnapshotRuntime, SnapshotLockReceipt, SnapshotRelease, SnapshotWorkerAbort, SnapshotAdmission};
pub(crate) use crate::store::snapshot_lifecycle::SnapshotLifecycle;

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

    /// [`Self::finish_inference_snapshot_retirements_after_commit`] for a
    /// user delete, which never waits on a publication: while one holds the
    /// body files this does nothing, and housekeeping carries the
    /// retirements out. Their standing intents already deny every key read.
    pub(crate) fn try_finish_inference_snapshot_retirements_after_commit(&self) {
        if let Err(error) = self.try_finish_inference_snapshot_retirements() {
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
