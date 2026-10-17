//! The host's half of the engine's housekeeping. Each lifecycle tick starts
//! the engine's pass ([`oneiron::Vault::housekeeping`]) on a blocking thread,
//! off the request path, unless the last pass is still running; the engine
//! decides which sweeps are due. After it, the host prunes what only the
//! process holds: MCP credentials that were revoked or have expired, and live
//! runs whose lease has gone. Hourly, on a task of its own, the host runs the
//! served repositories' git maintenance, each repository waiting for a git
//! exchange permit. The owner's "run now" is a pass of the same kind. Every
//! pass is held in [`HousekeepingPasses`], so stopping the host stops and
//! waits for each.
//!
//! Log lines carry a sweep's code, its counts and an error's kind, never row
//! text or an error's message.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use oneiron::housekeeping::{HousekeepingBudget, HousekeepingReport, SweepOutcome};
use oneiron::origin::smart_http::maintain_served_repositories;
use tokio::task::JoinHandle;

use super::core::SyncServer;
use super::lifecycle::LifecycleJobKind;
use crate::admission::Permit;

/// How long one scheduled pass may keep starting sweeps. Well inside a tick,
/// so a pass has ended before the next tick asks for another.
const HOUSEKEEPING_PASS_BUDGET: Duration = Duration::from_secs(20);

/// How long the owner's "run now" may keep starting sweeps.
const OWNER_PASS_BUDGET: Duration = Duration::from_secs(60);

/// How often the served repositories get their git maintenance.
pub(super) const SERVED_REPOSITORY_MAINTENANCE_EVERY: Duration = Duration::from_secs(60 * 60);

/// How often the host checks whether this vault's authority log grew past
/// its newest checkpoint image, and if so writes and attests a new one
/// (OF-469). The canon's default checkpoint cutoff is 24 hours.
pub(super) const AUTHORITY_CHECKPOINT_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How often repository maintenance waiting for a git exchange permit asks
/// again.
const GIT_PERMIT_POLL: Duration = Duration::from_millis(500);

/// The host's write gate for a pass. `None` skips the tick: a managed vault
/// frozen for reap writes nothing. What it returns is held until the pass
/// ends, so the host can see the write in flight.
pub(crate) type HousekeepingAdmission = Arc<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync>;

/// The gate of a host with no freeze: every tick is admitted.
pub(crate) fn admit_every_pass() -> HousekeepingAdmission {
    Arc::new(|| Some(Box::new(())))
}

/// The housekeeping passes in flight, whoever started them: the lifecycle
/// tick or the owner. A pass is held from before its starter can yield, so
/// [`Self::stop`] misses none.
#[derive(Debug, Default)]
pub(crate) struct HousekeepingPasses {
    stop: Arc<AtomicBool>,
    running: std::sync::Mutex<Vec<JoinHandle<()>>>,
    /// The lifecycle tick's steps, in the order it took them.
    #[cfg(test)]
    pub(super) tick_steps: std::sync::Mutex<Vec<&'static str>>,
}

impl HousekeepingPasses {
    /// Notes that the lifecycle tick took `step`.
    #[cfg(test)]
    pub(super) fn note_tick_step(&self, step: &'static str) {
        self.tick_steps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(step);
    }
}

impl HousekeepingPasses {
    fn budget(&self, time: Duration) -> HousekeepingBudget {
        HousekeepingBudget::within(time).stop_when(Arc::clone(&self.stop))
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn hold(&self, pass: JoinHandle<()>) {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        running.retain(|pass| !pass.is_finished());
        running.push(pass);
    }

    /// Asks every pass in flight to start no further sweep, page or
    /// repository, and waits for each to end.
    pub(crate) async fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        loop {
            let running =
                std::mem::take(&mut *self.running.lock().unwrap_or_else(PoisonError::into_inner));
            if running.is_empty() {
                return;
            }
            for pass in running {
                let _ = pass.await;
            }
        }
    }
}

impl SyncServer {
    /// Starts one scheduled pass on a task of its own, held for the host's
    /// stop, unless the last pass is still running, the host is stopping, or
    /// the host's gate refused the tick.
    pub(super) async fn start_housekeeping_pass(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        #[cfg(test)]
        self.housekeeping_passes.note_tick_step("housekeeping pass");
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::Housekeeping)
                .await
        {
            tracing::debug!("housekeeping tick skipped: the last pass is still running");
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::Housekeeping).await;
            return;
        };
        let server = Arc::clone(self);
        let budget = self.housekeeping_passes.budget(HOUSEKEEPING_PASS_BUDGET);
        let pass = tokio::spawn(async move {
            let _admission = admission;
            let vault = Arc::clone(server.vault());
            match tokio::task::spawn_blocking(move || vault.housekeeping(budget)).await {
                Ok(Ok(report)) => log_report(&report),
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "housekeeping pass could not read its schedule");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "housekeeping task failed");
                }
            }
            server.prune_mcp_credentials().await;
            // OF-181: a parked run cancelled, which no entry or call touches
            // again, leaves the host's live runs here.
            let live = Arc::clone(&server);
            if let Err(error) =
                tokio::task::spawn_blocking(move || live.live_runs.prune(live.vault())).await
            {
                tracing::warn!(panicked = error.is_panic(), "live-run prune failed");
            }
            let courier = Arc::clone(&server);
            if let Err(error) =
                tokio::task::spawn_blocking(move || courier.deliver_cooperative_deletions()).await
            {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "courtesy delete delivery failed"
                );
            }
            // Lapsed host orders, ended silences, owner erases no hold blocks
            // any more, queued refusals and expired hold-log rows (OF-470).
            let holds = Arc::clone(server.vault());
            match tokio::task::spawn_blocking(move || holds.maintain_legal_holds()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "legal-hold maintenance failed");
                }
                Err(error) => {
                    tracing::warn!(
                        panicked = error.is_panic(),
                        "legal-hold maintenance task failed"
                    );
                }
            }
            server
                .end_lifecycle_job(LifecycleJobKind::Housekeeping)
                .await;
        });
        self.housekeeping_passes.hold(pass);
    }

    /// Starts the served repositories' git maintenance on a task of its own,
    /// held for the host's stop, unless the last run is still going or the
    /// host is stopping. Returns whether a run started.
    pub(super) async fn start_repository_maintenance(
        self: &Arc<Self>,
        admit: &HousekeepingAdmission,
    ) -> bool {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::RepositoryMaintenance)
                .await
        {
            return false;
        }
        let server = Arc::clone(self);
        let admit = Arc::clone(admit);
        let run = tokio::spawn(async move {
            server.maintain_served_repositories(admit).await;
            server
                .end_lifecycle_job(LifecycleJobKind::RepositoryMaintenance)
                .await;
        });
        self.housekeeping_passes.hold(run);
        true
    }

    /// Starts a pass over the served repositories' mirror targets on a task
    /// of its own, held for the host's stop, unless the last pass is still
    /// going or the host is stopping. The engine pushes only the targets that
    /// are due and whose repository this host is the origin of.
    pub(super) async fn start_mirror_pushes(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        if self.housekeeping_passes.stopping()
            || !self.begin_lifecycle_job(LifecycleJobKind::MirrorPush).await
        {
            return;
        }
        let server = Arc::clone(self);
        let admit = Arc::clone(admit);
        let run = tokio::spawn(async move {
            server.push_due_mirrors(admit).await;
            server.end_lifecycle_job(LifecycleJobKind::MirrorPush).await;
        });
        self.housekeeping_passes.hold(run);
    }

    /// Starts this vault's authority checkpoint upkeep on a task of its own
    /// (OF-469), held for the host's stop, unless the last run is still
    /// going, the host is stopping, or the host's gate refused it. When the
    /// authority log grew past the newest image, the run writes a new one and
    /// attests it with the host root. Returns whether a run started.
    pub(super) async fn start_authority_checkpoint(
        self: &Arc<Self>,
        admit: &HousekeepingAdmission,
    ) -> bool {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::AuthorityCheckpoint)
                .await
        {
            return false;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::AuthorityCheckpoint)
                .await;
            return false;
        };
        let server = Arc::clone(self);
        let run = tokio::spawn(async move {
            let _admission = admission;
            let upkeep = Arc::clone(&server);
            match tokio::task::spawn_blocking(move || upkeep.upkeep_authority_checkpoint()).await {
                Ok(Ok(Some(_))) => tracing::info!("authority checkpoint written and attested"),
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "authority checkpoint upkeep failed");
                }
                Err(error) => {
                    tracing::warn!(
                        panicked = error.is_panic(),
                        "authority checkpoint task failed"
                    );
                }
            }
            server
                .end_lifecycle_job(LifecycleJobKind::AuthorityCheckpoint)
                .await;
        });
        self.housekeeping_passes.hold(run);
        true
    }

    /// The upkeep under this host's root: the managed issuer, or the one the
    /// configured host secret derives. A host with neither attests nothing.
    fn upkeep_authority_checkpoint(&self) -> oneiron::Result<Option<[u8; 32]>> {
        if let Some(issuer) = self.managed_issuer.as_ref() {
            return self.vault().upkeep_authority_checkpoint(issuer);
        }
        let Some(secret) = self.config.auth_secret.as_deref() else {
            return Ok(None);
        };
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
        self.vault().upkeep_authority_checkpoint(&issuer)
    }

    /// Pushes every due mirror. Each push waits for a git exchange permit,
    /// then takes the host's write gate, both held until it ends.
    async fn push_due_mirrors(self: &Arc<Self>, admit: HousekeepingAdmission) {
        let server = Arc::clone(self);
        let run = tokio::task::spawn_blocking(move || {
            server.vault().push_due_origin_mirrors(
                || {
                    let permit = server.wait_for_git_permit()?;
                    let admission = admit()?;
                    Some(Box::new((permit, admission)) as Box<dyn Send>)
                },
                || server.housekeeping_passes.stopping(),
            )
        })
        .await;
        match run {
            Ok(Ok(run)) if run.pushed + run.failed > 0 => {
                tracing::info!(
                    targets = run.targets,
                    pushed = run.pushed,
                    skipped = run.skipped,
                    failed = run.failed,
                    "origin mirror pushes ran"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "origin mirror pushes failed");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "origin mirror push task failed"
                );
            }
        }
    }

    /// Runs every engine sweep now, as the owner asked, on a pass the host
    /// holds: a caller that stops waiting does not end it, and stopping the
    /// host waits for it. `None` when the pass ended without a report.
    pub(crate) async fn housekeeping_now(&self) -> Option<oneiron::Result<HousekeepingReport>> {
        let (report, reported) = tokio::sync::oneshot::channel();
        let vault = Arc::clone(self.vault());
        let budget = self.housekeeping_passes.budget(OWNER_PASS_BUDGET);
        let pass = tokio::spawn(async move {
            if let Ok(done) =
                tokio::task::spawn_blocking(move || vault.housekeeping_all(budget)).await
            {
                let _ = report.send(done);
            }
        });
        self.housekeeping_passes.hold(pass);
        reported.await.ok()
    }

    /// Drops MCP credential records that were revoked or have expired, with
    /// their stream state. A live slip the registry no longer holds is learned
    /// again on its next use, so this takes nothing a caller still has.
    async fn prune_mcp_credentials(&self) {
        // Records expire with their slips, which run on the authority clock.
        let now = match self.vault().capability_slip_now() {
            Ok(now) => now,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "MCP credential prune skipped: no authority clock");
                return;
            }
        };
        let pruned = self.mcp_registry.lock().await.prune_revoked_or_expired(now);
        if pruned > 0 {
            tracing::info!(
                pruned,
                "housekeeping pruned revoked or expired MCP credentials"
            );
        }
    }

    /// `git gc --auto` over the served repositories. Each waits for a git
    /// exchange permit, then takes the host's write gate, both held until its
    /// maintenance ends; the engine gives the repository up to any push that
    /// asks for it.
    async fn maintain_served_repositories(self: &Arc<Self>, admit: HousekeepingAdmission) {
        let server = Arc::clone(self);
        let run = tokio::task::spawn_blocking(move || {
            maintain_served_repositories(
                server.vault(),
                || {
                    let permit = server.wait_for_git_permit()?;
                    let admission = admit()?;
                    Some(Box::new((permit, admission)) as Box<dyn Send>)
                },
                || server.housekeeping_passes.stopping(),
            )
        })
        .await;
        match run {
            Ok(Ok(run)) if run.maintained + run.deferred + run.failed + run.refused > 0 => {
                tracing::info!(
                    repositories = run.repositories,
                    maintained = run.maintained,
                    deferred = run.deferred,
                    failed = run.failed,
                    refused = run.refused,
                    "served repository maintenance ran"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "served repository maintenance failed");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "served repository maintenance task failed"
                );
            }
        }
    }

    /// Waits on this blocking thread for a git exchange permit, behind every
    /// exchange in line, each wait up to the queue deadline, until it is
    /// given one or the host stops.
    fn wait_for_git_permit(&self) -> Option<Permit> {
        loop {
            if self.housekeeping_passes.stopping() {
                return None;
            }
            if let Ok(permit) = self.transfers.admit_git_maintenance() {
                return Some(permit);
            }
            std::thread::sleep(GIT_PERMIT_POLL);
        }
    }
}

fn log_report(report: &HousekeepingReport) {
    for row in &report.sweeps {
        let sweep = row.sweep.code();
        match &row.outcome {
            SweepOutcome::Ran { work, complete } if work.is_idle() => {
                tracing::debug!(sweep, complete, "housekeeping sweep ran");
            }
            SweepOutcome::Ran { work, complete } => {
                tracing::info!(sweep, complete, work = ?work, "housekeeping sweep ran");
            }
            SweepOutcome::Failed { kind } => {
                tracing::warn!(sweep, kind = ?kind, "housekeeping sweep failed");
            }
            SweepOutcome::Panicked => {
                tracing::warn!(sweep, "housekeeping sweep panicked");
            }
            SweepOutcome::OutOfBudget => {
                tracing::debug!(sweep, "housekeeping sweep left for the next pass");
            }
            SweepOutcome::NotDue { .. } | SweepOutcome::HostOnly { .. } => {}
        }
    }
}
