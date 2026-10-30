//! Periodic lifecycle jobs: lease expiry, reassert-drain with debounce, and
//! the engine's housekeeping pass.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use loro::{ExportMode, VersionVector};
use oneiron::SyncEngineContext;
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::{self, WindowKey};
use tokio::task::JoinHandle;

use super::core::{SyncServer, unix_seconds_now};
use super::housekeeping::{HousekeepingAdmission, SERVED_REPOSITORY_MAINTENANCE_EVERY};
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
    OwnerWork,
    MergeQueueChecks,
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
    /// walks left past their first batch and starts a housekeeping pass,
    /// each through `admit`, the host's write gate.
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
            loop {
                // A published-ref move or a green landing wakes the mirror
                // pushes alone, at once (FIX 6866); every other job keeps
                // the tick.
                let woken = tokio::select! {
                    _ = interval.tick() => false,
                    () = server.vault().origin_mirror_wake().notified() => true,
                    // A committed queue write wakes the merge queue checker
                    // alone (FIX 6868, G2 PR2), on its own wake, never on
                    // another attempt commit (FIX 7306).
                    () = server.vault().merge_queue_wake().notified() => {
                        server.wake_merge_queue_checker(&admit).await;
                        continue;
                    }
                };
                if woken {
                    server.start_mirror_pushes(&admit, true).await;
                    continue;
                }
                server.run_scheduled_lifecycle_tick(&admit).await;
                server.finish_dependent_walks_once(&admit).await;
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
                // only the due ones, and repairs a full-auto wake missed.
                server.start_mirror_pushes(&admit, false).await;
                // The authority checkpoint upkeep runs every tick; the engine
                // decides whether a cutoff is due (OF-469).
                server.start_authority_checkpoint(&admit).await;
                // The owner work naming this install as executor runs on the
                // same tick, with no interval of its own.
                server.start_owner_work_drain(&admit).await;
                server.start_merge_queue_checker(&admit).await;
            }
        });
        LifecycleScheduler {
            tick,
            server: Arc::clone(self),
        }
    }

    /// Finishes the dependent walks an erase, a purge or a changed source
    /// left past its first batch; reads honour them until then. First the
    /// sealed bundle uploads' disk claims follow their stages, so a stage that
    /// idled out gives its room back without a bundle call (FIX 4273).
    ///
    /// Both run under `admit`, the host's write gate, held by the blocking
    /// work itself, on a task held in the housekeeping passes from before
    /// this can yield, so the host's stop waits for them (FIX 9538). The tick
    /// still waits for them to end before it goes on. A tick the gate refuses,
    /// or one after the host began stopping, starts none and drops nothing:
    /// each walk keeps its row and the stages their headers, so the next
    /// admitted tick, or the next start, runs them.
    async fn finish_dependent_walks_once(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        #[cfg(test)]
        self.housekeeping_passes.note_tick_step("dependent walks");
        if self.housekeeping_passes.stopping() {
            return;
        }
        let Some(admission) = admit() else {
            tracing::debug!("dependent walks skipped: the host's gate refused the tick");
            return;
        };
        let server = Arc::clone(self);
        let walks = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            server.transfers.reconcile_sealed_stages(server.vault());
            server.vault().finish_dependent_walks()
        });
        let (ended, done) = tokio::sync::oneshot::channel::<()>();
        self.housekeeping_passes.hold(tokio::spawn(async move {
            match walks.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "dependent walk pass failed");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "dependent walk task failed");
                }
            }
            let _ = ended.send(());
        }));
        let _ = done.await;
    }

    /// Expires sync leases and drains reassert markers under `admit`, held
    /// through both (FIX 6955): a managed vault's reap freeze counts them, or
    /// refuses the tick, which leaves both for the next admitted one.
    async fn run_scheduled_lifecycle_tick(&self, admit: &HousekeepingAdmission) {
        let now_ms = unix_seconds_now().saturating_mul(1_000);
        self.dreamer_progress
            .lock()
            .await
            .remove_outdated(&self.ephemeral_store, now_ms);

        let Some(_admission) = admit() else {
            tracing::debug!("lease expiry and ra drain skipped: the host's gate refused the tick");
            return;
        };
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
        // The job ends when its guard drops: a sweep cut at an await (an idle
        // reap's deadline, FIX 11742) ends it as a finished one does.
        let Some(_job) = self.lifecycle_job(LifecycleJobKind::LeaseExpiry) else {
            return Ok(LeaseExpiryReport::skipped());
        };

        async {
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
        .await
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
        self.lifecycle_jobs().insert(self.lifecycle_job_key(kind))
    }

    pub(super) async fn end_lifecycle_job(&self, kind: LifecycleJobKind) {
        self.lifecycle_jobs().remove(&self.lifecycle_job_key(kind));
    }

    /// Begins the job `kind` as [`Self::begin_lifecycle_job`] does, held by
    /// the guard it answers, which ends it when dropped; `None` while one is
    /// in flight.
    pub(super) fn lifecycle_job(&self, kind: LifecycleJobKind) -> Option<LifecycleJob<'_>> {
        let key = self.lifecycle_job_key(kind);
        self.lifecycle_jobs()
            .insert(key)
            .then_some(LifecycleJob { server: self, key })
    }

    fn lifecycle_jobs(&self) -> std::sync::MutexGuard<'_, HashSet<LifecycleJobKey>> {
        self.lifecycle_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A begun lifecycle job ([`SyncServer::lifecycle_job`]), ended when it
/// drops: a sweep cut at an await, by a deadline's timeout or a dropped task,
/// ends its job as a finished one does, so the next sweep runs (FIX 11742).
pub(super) struct LifecycleJob<'a> {
    server: &'a SyncServer,
    key: LifecycleJobKey,
}

impl Drop for LifecycleJob<'_> {
    fn drop(&mut self) {
        self.server.lifecycle_jobs().remove(&self.key);
    }
}
