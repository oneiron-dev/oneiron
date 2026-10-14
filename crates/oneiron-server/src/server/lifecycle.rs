//! Periodic lifecycle jobs: lease expiry, reassert-drain with debounce, and
//! the engine's housekeeping pass.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use loro::{ExportMode, VersionVector};
use oneiron::SyncEngineContext;
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::{self, WindowKey};
use tokio::task::JoinHandle;

use super::core::{SyncServer, unix_seconds_now};
use super::housekeeping::HousekeepingAdmission;
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
}

/// The lifecycle loop, and the housekeeping pass it last started. Dropping it
/// stops the loop; [`Self::stop`] also waits out the pass.
pub(crate) struct LifecycleScheduler {
    tick: JoinHandle<()>,
    pass: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
    stop: Arc<AtomicBool>,
}

impl LifecycleScheduler {
    /// Stops the loop, asks a pass in flight to start no further sweep or
    /// page, and waits for it to end, so nothing it writes lands after this
    /// returns.
    pub(crate) async fn stop(mut self) {
        self.tick.abort();
        let _ = (&mut self.tick).await;
        self.stop.store(true, Ordering::Release);
        let pass = self
            .pass
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(pass) = pass {
            let _ = pass.await;
        }
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
    /// expires sync leases, drains reassert markers and starts a housekeeping
    /// pass through `admit`, the host's write gate.
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
        let pass: Arc<std::sync::Mutex<Option<JoinHandle<()>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let tick = tokio::spawn({
            let pass = Arc::clone(&pass);
            let stop = Arc::clone(&stop);
            async move {
                let mut interval = tokio::time::interval(tick);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    server.run_scheduled_lifecycle_tick().await;
                    // The pass runs on a task of its own, so a long sweep never
                    // holds back the next tick's lease expiry. Its handle is
                    // stored before this task can yield again, so a stop
                    // never misses it.
                    if let Some(started) = server.start_housekeeping_pass(&admit, &stop).await {
                        *pass.lock().unwrap_or_else(PoisonError::into_inner) = Some(started);
                    }
                }
            }
        });
        LifecycleScheduler { tick, pass, stop }
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
                for (window_key, update) in report.window_updates {
                    if super::windows::withheld_from_peers(
                        &self.reassert_manager,
                        &window_key,
                        &update,
                    ) {
                        continue;
                    }
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
