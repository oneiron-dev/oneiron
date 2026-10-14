//! The host's half of the engine's housekeeping. Each lifecycle tick starts
//! the engine's pass ([`oneiron::Vault::housekeeping`]) on a blocking thread,
//! off the request path, unless the last pass is still running; the engine
//! decides which sweeps are due. After it, the host prunes what only the
//! process holds, MCP credentials that were revoked or have expired, and
//! hourly runs the served repositories' git maintenance under exchange
//! permits. The owner's "run now" is a pass of the same kind. Every pass is
//! held in [`HousekeepingPasses`], so stopping the host stops and waits for
//! each.
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

/// How long one scheduled pass may keep starting sweeps. Well inside a tick,
/// so a pass has ended before the next tick asks for another.
const HOUSEKEEPING_PASS_BUDGET: Duration = Duration::from_secs(20);

/// How long the owner's "run now" may keep starting sweeps.
const OWNER_PASS_BUDGET: Duration = Duration::from_secs(60);

/// How often the served repositories get their git maintenance.
pub(super) const SERVED_REPOSITORY_MAINTENANCE_EVERY: Duration = Duration::from_secs(60 * 60);

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
    /// the host's gate refused the tick. With `repositories`, the pass also
    /// runs the served repositories' git maintenance. Returns whether a pass
    /// started.
    pub(super) async fn start_housekeeping_pass(
        self: &Arc<Self>,
        admit: &HousekeepingAdmission,
        repositories: bool,
    ) -> bool {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::Housekeeping)
                .await
        {
            tracing::debug!("housekeeping tick skipped: the last pass is still running");
            return false;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::Housekeeping).await;
            return false;
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
            if repositories {
                server.maintain_served_repositories().await;
            }
            server
                .end_lifecycle_job(LifecycleJobKind::Housekeeping)
                .await;
        });
        self.housekeeping_passes.hold(pass);
        true
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

    /// `git gc --auto` over the served repositories, each under a git
    /// exchange permit and the repository coordinator, never waiting for
    /// either: a repository a push holds waits for the next run.
    async fn maintain_served_repositories(self: &Arc<Self>) {
        let server = Arc::clone(self);
        let run = tokio::task::spawn_blocking(move || {
            maintain_served_repositories(
                server.vault(),
                || {
                    server
                        .transfers
                        .admit_git_maintenance()
                        .ok()
                        .map(|permit| Box::new(permit) as Box<dyn Send>)
                },
                || server.housekeeping_passes.stopping(),
            )
        })
        .await;
        match run {
            Ok(Ok(run)) if run.maintained + run.deferred + run.failed > 0 => {
                tracing::info!(
                    repositories = run.repositories,
                    maintained = run.maintained,
                    deferred = run.deferred,
                    failed = run.failed,
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
