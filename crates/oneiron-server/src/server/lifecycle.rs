//! Periodic lifecycle jobs: lease expiry, reassert-drain with debounce, and
//! the engine's housekeeping pass.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use loro::{ExportMode, VersionVector};
use oneiron::SyncEngineContext;
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::{self, WindowKey};
use tokio::task::JoinHandle;

use super::core::{SyncServer, unix_seconds_now};
use super::housekeeping::{
    AUTHORITY_CHECKPOINT_EVERY, HousekeepingAdmission, SERVED_REPOSITORY_MAINTENANCE_EVERY,
};
use super::leases::SERVER_LEASE_VAULT_ID;
use super::windows::SERVER_USER_ID;

const LEASE_LIFECYCLE_TICK_INTERVAL: Duration = Duration::from_secs(60);

pub(super) static NEXT_LIFECYCLE_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseExpiryReport {
    pub(crate) expired_rows: usize,
    pub(crate) skipped: bool,
    pub(crate) root_update: Option<Vec<u8>>,
}

impl LeaseExpiryReport {
    fn skipped() -> Self {
        Self {
            expired_rows: 0,
            skipped: true,
            root_update: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReassertDrainJobReport {
    pub(crate) report: sync::ReassertDrainReport,
    pub(crate) skipped: bool,
    pub(crate) window_updates: Vec<(String, Vec<u8>)>,
}

impl ReassertDrainJobReport {
    fn skipped() -> Self {
        Self {
            report: sync::ReassertDrainReport::default(),
            skipped: true,
            window_updates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum LifecycleJobKind {
    LeaseExpiry,
    ReassertDrain,
    Housekeeping,
    RepositoryMaintenance,
    MirrorPush,
    AuthorityCheckpoint,
}

/// The lifecycle loop, and the housekeeping pass it last started. Dropping it
/// stops the loop; [`Self::stop`] also waits out the pass.
pub(crate) struct LifecycleScheduler {
    tick: JoinHandle<()>,
    server: Arc<SyncServer>,
}

impl LifecycleScheduler {
    /// Stops the loop, then asks every housekeeping pass in flight, the
    /// owner's included, to start no further sweep or page, and waits for
    /// each, so nothing a pass writes lands after this returns.
    pub(crate) async fn stop(mut self) {
        self.tick.abort();
        let _ = (&mut self.tick).await;
        self.server.housekeeping_passes.stop().await;
    }
}

impl Drop for LifecycleScheduler {
    fn drop(&mut self) {
        self.tick.abort();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct LifecycleJobKey {
    kind: LifecycleJobKind,
    vault_id: u64,
    session_id: u64,
}

impl SyncServer {
    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

    /// Starts the periodic lifecycle loop. Each tick, the first at once,
    /// expires sync leases, drains reassert markers, finishes the dependent
    /// walks left past their first batch and starts a housekeeping pass
    /// through `admit`, the host's write gate.
    pub(crate) fn spawn_lifecycle_scheduler(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> LifecycleScheduler {
        self.spawn_lifecycle_scheduler_every(LEASE_LIFECYCLE_TICK_INTERVAL, admit)
    }

    pub(super) fn spawn_lifecycle_scheduler_every(
        self: &Arc<Self>,
        tick: Duration,
        admit: HousekeepingAdmission,
    ) -> LifecycleScheduler {
        let server = Arc::clone(self);
        let tick = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The served repositories' maintenance runs on the first tick and
            // then once an interval.
            let mut repositories_due = Instant::now();
            // So does this vault's authority checkpoint upkeep (OF-469).
            let mut checkpoint_due = Instant::now();
            loop {
                interval.tick().await;
                server.run_scheduled_lifecycle_tick().await;
                server.finish_dependent_walks_once().await;
                // The pass and the maintenance run on tasks of their own, so
                // neither holds back the next tick's lease expiry, nor one
                // the other.
                server.start_housekeeping_pass(&admit).await;
                if Instant::now() >= repositories_due
                    && server.start_repository_maintenance(&admit).await
                {
                    repositories_due = Instant::now() + SERVED_REPOSITORY_MAINTENANCE_EVERY;
                }
                // Each mirror target keeps its own cadence; the pass pushes
                // only the due ones.
                server.start_mirror_pushes(&admit).await;
                if Instant::now() >= checkpoint_due
                    && server.start_authority_checkpoint(&admit).await
                {
                    checkpoint_due = Instant::now() + AUTHORITY_CHECKPOINT_EVERY;
                }
            }
        });
        LifecycleScheduler {
            tick,
            server: Arc::clone(self),
        }
    }

    /// Finishes the dependent walks an erase, a purge or a changed source
    /// left past its first batch; reads honour them until then.
    async fn finish_dependent_walks_once(&self) {
        #[cfg(test)]
        self.housekeeping_passes.note_tick_step("dependent walks");
        let vault = std::sync::Arc::clone(self.vault());
        match tokio::task::spawn_blocking(move || vault.finish_dependent_walks()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "dependent walk pass failed");
            }
            Err(error) => tracing::warn!(panicked = error.is_panic(), "dependent walk task failed"),
        }
    }

    async fn run_scheduled_lifecycle_tick(&self) {
        let now_ms = unix_seconds_now().saturating_mul(1_000);
        self.dreamer_progress
            .lock()
            .await
            .remove_outdated(&self.ephemeral_store, now_ms);

        match self.expire_leases_once().await {
            Ok(report) => {
                if report.skipped {
                    tracing::debug!("lease expiry tick skipped: previous tick still in flight");
                } else {
                    tracing::debug!(
                        expired_rows = report.expired_rows,
                        "lease expiry tick complete"
                    );
                }
                if let Some(update) = report.root_update {
                    let msg = crate::protocol::encode_root_update(&update);
                    let _ = crate::broadcast::broadcast(&self.broadcast_tx, 0, msg);
                }
            }
            Err(err) => {
                tracing::error!(kind = ?err.kind(), "lease expiry tick failed");
            }
        }

        match self.drain_reassert_markers_once().await {
            Ok(report) => {
                if report.skipped {
                    tracing::debug!("ra drain tick skipped: previous tick still in flight");
                } else {
                    tracing::debug!(
                        drained = ?report.report.drained,
                        still_pending = ?report.report.still_pending,
                        "ra drain tick complete"
                    );
                }
                // Each socket's delivery judges the update for the machine it
                // serves (`window_delivery`).
                for (window_key, update) in report.window_updates {
                    match crate::protocol::encode_window_sync(
                        &window_key,
                        crate::protocol::window_sub_tags::UPDATE,
                        &update,
                    )
                    .into_result()
                    {
                        Ok(msg) => {
                            let _ = crate::broadcast::broadcast(&self.broadcast_tx, 0, msg);
                        }
                        Err(err) => {
                            tracing::error!(
                                window = %window_key,
                                error = crate::protocol::transport_err_msg(err),
                                "ra drain tick failed to encode window update"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                tracing::error!(kind = ?err.kind(), "ra drain tick failed");
            }
        }
    }

    pub(crate) async fn expire_leases_once(&self) -> Result<LeaseExpiryReport, oneiron::Error> {
        self.expire_leases_once_at(unix_seconds_now()).await
    }

    pub(super) async fn expire_leases_once_at(
        &self,
        now: u64,
    ) -> Result<LeaseExpiryReport, oneiron::Error> {
        if !self
            .begin_lifecycle_job(LifecycleJobKind::LeaseExpiry)
            .await
        {
            return Ok(LeaseExpiryReport::skipped());
        }

        let result = async {
            let _guard = self.lease_registrar.lock().await;
            let vv_before = self.root_doc.oplog_vv();
            let frontiers_before = self.root_doc.state_frontiers();
            let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
            let mut entries = self.root_lease_entries()?;

            let mut expired_rows = 0usize;
            for entry in &mut entries {
                let mut record = entry.record;
                if record.status == LeaseStatus::Active && record.expires_at < now {
                    record.status = LeaseStatus::Expired;
                    let scoped_key = lease::lease_registry_key(entry.vault_id, entry.client_id);
                    if entry.key != scoped_key {
                        leases.delete(entry.key.as_str()).map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                        })?;
                        entry.key = scoped_key;
                    }
                    leases
                        .insert(
                            entry.key.as_str(),
                            lease::encode_lease_record(&record).as_slice(),
                        )
                        .map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                        })?;
                    entry.record = record;
                    expired_rows += 1;
                }
            }

            let root_update =
                self.commit_lease_changes(expired_rows > 0, &vv_before, &frontiers_before)?;
            Ok(LeaseExpiryReport {
                expired_rows,
                skipped: false,
                root_update,
            })
        }
        .await;

        self.end_lifecycle_job(LifecycleJobKind::LeaseExpiry).await;
        result
    }

    pub(crate) async fn drain_reassert_markers_once(
        &self,
    ) -> Result<ReassertDrainJobReport, oneiron::Error> {
        if !self
            .begin_lifecycle_job(LifecycleJobKind::ReassertDrain)
            .await
        {
            return Ok(ReassertDrainJobReport::skipped());
        }

        let live_versions = self.live_window_versions();
        let result =
            sync::drain_reassert_markers(&self.vault, SERVER_USER_ID, &self.reassert_manager)
                .and_then(|report| {
                    let window_updates = self.collect_live_window_updates(live_versions)?;
                    Ok(ReassertDrainJobReport {
                        report,
                        skipped: false,
                        window_updates,
                    })
                });

        self.end_lifecycle_job(LifecycleJobKind::ReassertDrain)
            .await;
        result
    }

    fn live_window_versions(&self) -> HashMap<WindowKey, VersionVector> {
        self.reassert_manager
            .loaded_keys()
            .into_iter()
            .filter_map(|key| {
                self.reassert_manager
                    .window(&key)
                    .map(|window| (key, window.doc.oplog_vv()))
            })
            .collect()
    }

    fn collect_live_window_updates(
        &self,
        before: HashMap<WindowKey, VersionVector>,
    ) -> Result<Vec<(String, Vec<u8>)>, oneiron::Error> {
        let mut updates = Vec::new();
        for (key, vv_before) in before {
            let Some(window) = self.reassert_manager.window(&key) else {
                continue;
            };
            if window.doc.oplog_vv() == vv_before {
                continue;
            }
            let update = window
                .doc
                .export(ExportMode::updates(&vv_before))
                .map_err(|e| {
                    oneiron::Error::sync_engine(SyncEngineContext::LoroExportUpdates, e)
                })?;
            updates.push((key.as_str().to_string(), update));
        }
        Ok(updates)
    }

    pub(super) fn lifecycle_job_key(&self, kind: LifecycleJobKind) -> LifecycleJobKey {
        LifecycleJobKey {
            kind,
            vault_id: SERVER_LEASE_VAULT_ID,
            session_id: self.lifecycle_session_id,
        }
    }

    pub(super) async fn begin_lifecycle_job(&self, kind: LifecycleJobKind) -> bool {
        self.lifecycle_in_flight
            .lock()
            .await
            .insert(self.lifecycle_job_key(kind))
    }

    pub(super) async fn end_lifecycle_job(&self, kind: LifecycleJobKind) {
        self.lifecycle_in_flight
            .lock()
            .await
            .remove(&self.lifecycle_job_key(kind));
    }
}
