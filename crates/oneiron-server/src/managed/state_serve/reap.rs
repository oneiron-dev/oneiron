//! The reap freeze: the write gate a frozen vault refuses at, and the
//! freeze, drain and export `prepare_reap` and `prepare_idle_reap` share.

/// The host-order legal holds a frozen source exports (`host_order_holds`).
mod host_holds;

use std::sync::atomic::Ordering;

use oneiron_vault_contract::{CtlResponse, validate_wake_entries};

use super::ManagedState;
use crate::managed::ManagedError;
use crate::managed::ledger::LedgerSnapshot;
use crate::owner::schedule::OwnerHost;

/// What a reap's freeze, drain and export found
/// ([`ManagedState::freeze_drain_export`]).
pub(super) struct Prepared {
    /// The admitted writes in flight once frozen, read before the drain and
    /// the export.
    pub(super) in_flight: u64,
    /// The owner host's backup jobs in flight, read just after: some of
    /// those writes.
    pub(super) backup_jobs: u64,
    /// Whether the lease table drained.
    pub(super) drained: bool,
    pub(super) ledger_rev: u64,
    /// The exported entries and training setting at `ledger_rev`.
    pub(super) report: LedgerSnapshot,
}

impl ManagedState {
    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    pub fn freeze(&self) -> Result<(), ManagedError> {
        self.frozen.store(true, Ordering::SeqCst);
        self.server
            .wire_telemetry
            .freeze_and_flush()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))
    }

    /// Lifts the process-local freeze on `reap_abort`. A new process starts
    /// unfrozen; shutdown must not reactivate observation writes.
    pub fn unfreeze(&self) -> Result<(), ManagedError> {
        self.server
            .wire_telemetry
            .unfreeze()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        self.frozen.store(false, Ordering::SeqCst);
        if self.background_waiting.swap(false, Ordering::SeqCst) {
            tracing::info!("the reap pause lifted; background passes run again");
        }
        Ok(())
    }

    /// The write gate a frozen vault refuses at. Typed, so a caller can tell
    /// "frozen for reap" from a storage failure and retry rather than
    /// surface an error to a user.
    pub fn guard_write(&self) -> Result<(), ManagedError> {
        if self.is_frozen() {
            return Err(ManagedError::WritesFrozen);
        }
        Ok(())
    }

    /// `quiescent` needs a third answer beyond "frozen" and "drained": the
    /// freeze refuses new requests and new upgrades, but a sync session
    /// upgraded before it rides past every per-request gate and can still
    /// commit. `PrepareReap` is not shutdown and closes nothing, so while one
    /// of those may be live this reports `false` and the supervisor reaps
    /// later rather than over a live writer.
    pub(super) async fn prepare_reap(&self) -> Result<CtlResponse, ManagedError> {
        let prepared = self.freeze_drain_export().await?;
        Ok(CtlResponse::PrepareReap {
            quiescent: self.quiescent(prepared.in_flight, prepared.drained),
            ledger_rev: prepared.ledger_rev,
            next_wake: prepared.report.entries,
            training: prepared.report.training,
        })
    }

    /// The strict quiescence `prepare_reap` reports, from `in_flight`, the
    /// admitted writes read once frozen, and whether the lease table
    /// `drained`: none in flight, drained, still frozen, and no sync session
    /// that could still commit. The idle reap's preparation judges its own,
    /// less its backup job.
    pub(super) fn quiescent(&self, in_flight: u64, drained: bool) -> bool {
        in_flight == 0 && drained && self.is_frozen() && !self.live_sync_writer()
    }

    /// Freeze, drain, export — in that order.
    ///
    /// The freeze goes first so nothing new enters the lease table while it is
    /// being drained, and the export runs last so the entries the supervisor
    /// gets describe the quiesced state rather than the one before it. The
    /// training setting rides the same report, read under the same revision.
    pub(super) async fn freeze_drain_export(&self) -> Result<Prepared, ManagedError> {
        self.freeze()?;
        // Check BEFORE drain/export. A writer finishing after export must not
        // turn a stale exported ledger into a quiescent reply.
        let in_flight = self.http_mutating_in_flight.load(Ordering::SeqCst);
        let backup_jobs = self
            .server
            .owner_host
            .as_deref()
            .map_or(0, OwnerHost::backup_jobs);
        let drained = self.drain_lease_table().await;
        let (ledger_rev, report) = self.ledger.export_at_freeze(&self.server).await?;
        // The reply carries the entries, so they are bounds-checked before
        // they are serialized rather than after a supervisor has trusted them,
        // and the training setting is shape-checked with them.
        validate_wake_entries(&report.entries)
            .and_then(|()| report.training.validate())
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        Ok(Prepared {
            in_flight,
            backup_jobs,
            drained,
            ledger_rev,
            report,
        })
    }

    /// Runs the lease table to completion once. A skipped run means a previous
    /// sweep is still in flight, which is exactly "not yet quiescent".
    async fn drain_lease_table(&self) -> bool {
        match self.server.expire_leases_once().await {
            Ok(report) => !report.skipped,
            Err(error) => {
                tracing::error!(kind = ?error.kind(), "lease table drain failed during prepare_reap");
                false
            }
        }
    }
}
