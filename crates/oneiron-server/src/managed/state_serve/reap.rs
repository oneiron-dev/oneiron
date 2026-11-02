//! The reap freeze: the write gate a frozen vault refuses at, and the
//! freeze, drain and export `prepare_reap` and `prepare_idle_reap` share.

/// The host-order legal holds a frozen source exports (`host_order_holds`).
mod host_holds;

use std::sync::atomic::Ordering;

use oneiron_vault_contract::{CtlResponse, validate_wake_entries};

use super::ManagedState;
use super::admission::InFlightCounts;
use crate::managed::ManagedError;
use crate::managed::ledger::FrozenReport;

/// How long `prepare_reap` waits, once frozen, for device sync to pause
/// (FIX 5127): within the supervisor's 2 s ctl call (a call). One still
/// running then reads as a live sync writer.
const DEVICE_SYNC_PAUSE_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// What a reap's freeze, drain and export found
/// ([`ManagedState::freeze_drain_export`]).
pub(super) struct Prepared {
    /// The admitted writes in flight at the freeze, by kind, read before
    /// the drain and the export.
    pub(super) at_freeze: InFlightCounts,
    /// Whether the lease table drained.
    pub(super) drained: bool,
    /// The exported entries and training setting, held whole for the
    /// supervisor's pull until `ledger_pulled` or `reap_abort` (FIX 9549).
    pub(super) report: FrozenReport,
}

impl ManagedState {
    pub fn is_frozen(&self) -> bool {
        self.admission.is_frozen()
    }

    pub fn freeze(&self) -> Result<(), ManagedError> {
        self.freeze_counted()?;
        Ok(())
    }

    /// Freezes, and returns the admitted writes in flight at that moment,
    /// by kind: read in the same hold of the admission's lock that sets the
    /// freeze, before the telemetry flush, so they are exactly the writes
    /// the freeze let in.
    pub(super) fn freeze_counted(&self) -> Result<InFlightCounts, ManagedError> {
        let at_freeze = self.admission.freeze();
        self.server
            .wire_telemetry
            .freeze_and_flush()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        Ok(at_freeze)
    }

    /// Lifts the process-local freeze on `reap_abort`. A new process starts
    /// unfrozen; shutdown must not reactivate observation writes.
    pub fn unfreeze(&self) -> Result<(), ManagedError> {
        self.server
            .wire_telemetry
            .unfreeze()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        self.admission.thaw();
        // A relay delete deferred `not_ready` while frozen asks again now.
        self.relay_delete.thawed();
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
            quiescent: self.quiescent(prepared.at_freeze.total(), prepared.drained),
            ledger: prepared.report.head,
        })
    }

    /// The strict quiescence `prepare_reap` reports, from `in_flight`, the
    /// counted writes read once frozen (a device sync run is judged through
    /// the sync session check instead), and whether the lease
    /// table `drained`: none in flight, drained, still frozen, and no sync
    /// session that could still commit. The idle reap's preparation judges
    /// its own.
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
        // Counted BEFORE drain/export. A writer finishing after export must
        // not turn a stale exported ledger into a quiescent reply.
        let at_freeze = self.freeze_counted()?;
        // Device sync is not counted; its last write lands before the
        // export, or it reads as live.
        self.device_sync_paused(tokio::time::Instant::now() + DEVICE_SYNC_PAUSE_WAIT)
            .await;
        self.drain_export(at_freeze, true, None).await
    }

    /// The drain and the export after a freeze that found `at_freeze`. With
    /// `drain_leases` false the lease table is not drained, and reads as not
    /// drained. A drain still under way at `deadline` is cut there and reads
    /// as not drained; the export then answers at once (FIX 11742). The
    /// sweep's job ends with the cut, so later sweeps run.
    pub(super) async fn drain_export(
        &self,
        at_freeze: InFlightCounts,
        drain_leases: bool,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Prepared, ManagedError> {
        let drained = drain_leases
            && match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, self.drain_lease_table())
                    .await
                    .unwrap_or(false),
                None => self.drain_lease_table().await,
            };
        let report = self.ledger.export_at_freeze(&self.server).await?;
        // The pages carry the entries, so they are bounds-checked before
        // they are served rather than after a supervisor has trusted them,
        // and the training setting is shape-checked with them.
        validate_wake_entries(&report.snapshot.entries)
            .and_then(|()| report.snapshot.training.validate())
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        Ok(Prepared {
            at_freeze,
            drained,
            report,
        })
    }

    /// Runs the lease table to completion once. A skipped run means a previous
    /// sweep is still in flight, which is exactly "not yet quiescent".
    async fn drain_lease_table(&self) -> bool {
        match self.server.expire_leases_once().await {
            Ok(report) => !report.skipped,
            Err(error) => {
                tracing::error!(kind = ?error.kind(), "lease table drain failed during a reap or export freeze");
                false
            }
        }
    }
}
