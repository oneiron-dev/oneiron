//! Core half of `store::retrieval_telemetry::retention`: its store-layer items live in `oneiron_store::retrieval_telemetry::retention` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::retrieval_telemetry::retention::*;

use super::RetrievalRunId;
#[cfg(target_os = "linux")]
use super::run_store::RETRIEVAL_RUN_PROVISIONAL;
use super::run_store::{RETRIEVAL_RUN, stage_retrieval_run_delete};
use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{ManifestDbs, Store};
use heed::RwTxn;

// Base-ledger retention only. Session overlay rows evaporate on close and
// cannot be evicted while an in-flight room assembly still owns them.
/// A published run's capture time, ordered for expiry and cap pruning; empty
/// value. Production run ids come from the store-local monotonic id source,
/// so the id breaks ties between captures in the same clock second. Key:
/// u64be (captured at) + run id.
const RETRIEVAL_AGE: SideTable<(u64, RetrievalRunId), (), Raw> =
    SideTable::new(&side_table::RETRIEVAL_AGE);

/// A run's capture time, locating its [`RETRIEVAL_AGE`] row. Key: run id.
const RETRIEVAL_AGE_BY_RUN: SideTable<RetrievalRunId, CapturedAt, Raw> =
    SideTable::new(&side_table::RETRIEVAL_AGE_BY_RUN);

/// Recover interrupted context-pack registrations and expire indexed runs.
/// Runs after the open gates, before handing the vault to a caller.
impl Store {
    pub(in crate::store) fn reconcile_retrieval_telemetry_on_open(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let (lease, sole_opener) =
                RetrievalTelemetryLease::acquire(self.owner.env.bound_root_dir()?)?;
            // Published age/cap entries are safe to prune under LMDB's
            // writer lock even if another process owns a shared lease.
            let mut wtxn = self.env.write_txn()?;
            if sole_opener {
                let orphans = RETRIEVAL_RUN_PROVISIONAL
                    .scan_keys(self, &wtxn, &[])
                    .map_err(corrupt_key("retrieval run telemetry"))?;
                for id in orphans {
                    stage_retrieval_run_delete(self, &mut wtxn, id)?;
                }
            }
            let _ = prune_retrieval_runs(self, &mut wtxn, 0)?;
            wtxn.commit()?;
            if sole_opener {
                lease.downgrade()?;
            }
            let mut guard = self.core.retrieval_telemetry_lease.lock().map_err(|_| {
                Error::InvariantViolation("retrieval telemetry lease lock poisoned")
            })?;
            *guard = Some(lease);
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // A pathname-opened LMDB cannot use the retained directory as
            // proof of orphanhood. Published rows have their own age index,
            // however, and can be pruned under LMDB's writer transaction.
            let mut wtxn = self.env.write_txn()?;
            let _ = prune_retrieval_runs(self, &mut wtxn, 0)?;
            wtxn.commit()?;
            Ok(())
        }
    }
}

impl Store {
    /// Deletes every stored retrieval run, with its index rows, in `wtxn`.
    ///
    /// The open that mints the vault's retrieval-trace key calls this, so
    /// every run it finds predates the key: its fork hash is unkeyed, which
    /// lets a telemetry reader test a guessed query against it, and a run
    /// stored before the owner ruling of 2026-10-14 (fix 6) may hold its
    /// pack's bytes. Telemetry is disposable, so none of them stays.
    pub(crate) fn delete_retrieval_runs_before_trace_key(
        &self,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<()> {
        let runs = RETRIEVAL_RUN
            .scan_keys(self, &*wtxn, &[])
            .map_err(corrupt_key("retrieval run telemetry"))?;
        for id in runs {
            stage_retrieval_run_delete(self, wtxn, id)?;
        }
        Ok(())
    }
}

pub(super) fn delete_retrieval_age(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: RetrievalRunId,
) -> Result<()> {
    if let Some(CapturedAt(at)) = RETRIEVAL_AGE_BY_RUN.get(target, &*txn, &id)? {
        RETRIEVAL_AGE.delete(target, txn, &(at, id))?;
        RETRIEVAL_AGE_BY_RUN.delete(target, txn, &id)?;
    }
    Ok(())
}

pub(super) fn put_retrieval_age(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: RetrievalRunId,
    at: u64,
) -> Result<()> {
    delete_retrieval_age(target, txn, id)?;
    RETRIEVAL_AGE.put(target, txn, &(at, id), &())?;
    RETRIEVAL_AGE_BY_RUN.put(target, txn, &id, &CapturedAt(at))?;
    Ok(())
}

pub(super) fn prune_retrieval_runs(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    reserve: usize,
) -> Result<bool> {
    let resolved = crate::gate::resolve_policy_manifest(store, txn)?;
    let Some(policy) = resolved.retrieval_retention_policy() else {
        // Opening a degraded vault stays possible, but no rejected policy
        // is permission to erase published runs.
        return Ok(false);
    };
    let (max_age_secs, max_runs) = policy.effective();
    let now = store.clock().now_recorded_at();
    let cutoff = now.saturating_sub(max_age_secs);
    // Collect keys before any delete; heed forbids mutating under an active cursor.
    let age_rows = RETRIEVAL_AGE
        .scan_keys(store, txn, &[])
        .map_err(corrupt_key("retrieval run retention"))?;
    let over = age_rows
        .len()
        .saturating_sub(max_runs.saturating_sub(reserve));
    for (index, (at, id)) in age_rows.into_iter().enumerate() {
        if index >= over && at >= cutoff {
            break;
        }
        stage_retrieval_run_delete(store, txn, id)?;
    }
    Ok(true)
}

/// Publication and finalization must refuse when the manifest is rejected;
/// unlike a healthy open they cannot use an invalid policy to admit a row.
pub(super) fn require_prune_retrieval_runs(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    reserve: usize,
) -> Result<()> {
    if prune_retrieval_runs(store, txn, reserve)? {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "retrieval retention policy unavailable".to_owned(),
        ))
    }
}
