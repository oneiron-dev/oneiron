//! The host's half of the engine's housekeeping. Each lifecycle tick starts
//! the engine's pass ([`oneiron::Vault::housekeeping`]) on a blocking thread,
//! off the request path, unless the last pass is still running; the engine
//! decides which sweeps are due. After it, the host prunes what only the
//! process holds: MCP credentials that were revoked or have expired.
//!
//! Log lines carry a sweep's code, its counts and an error's kind, never row
//! text or an error's message.

use std::sync::Arc;
use std::time::Duration;

use oneiron::housekeeping::{HousekeepingBudget, HousekeepingReport, SweepOutcome};
use tokio::task::JoinHandle;

use super::core::SyncServer;
use super::lifecycle::LifecycleJobKind;

/// How long one pass may keep starting sweeps. Well inside a tick, so a pass
/// has ended before the next tick asks for another.
const HOUSEKEEPING_PASS_BUDGET: Duration = Duration::from_secs(20);

/// The host's write gate for a pass. `None` skips the tick: a managed vault
/// frozen for reap writes nothing. What it returns is held until the pass
/// ends, so the host can see the write in flight.
pub(crate) type HousekeepingAdmission = Arc<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync>;

/// The gate of a host with no freeze: every tick is admitted.
pub(crate) fn admit_every_pass() -> HousekeepingAdmission {
    Arc::new(|| Some(Box::new(())))
}

impl SyncServer {
    /// Starts one housekeeping pass on a task of its own and returns it, or
    /// returns `None` when the last pass is still running or the host's gate
    /// refused the tick.
    pub(super) async fn start_housekeeping_pass(
        self: &Arc<Self>,
        admit: &HousekeepingAdmission,
    ) -> Option<JoinHandle<()>> {
        if !self
            .begin_lifecycle_job(LifecycleJobKind::Housekeeping)
            .await
        {
            tracing::debug!("housekeeping tick skipped: the last pass is still running");
            return None;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::Housekeeping).await;
            return None;
        };
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            let vault = Arc::clone(server.vault());
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                vault.housekeeping(HousekeepingBudget::within(HOUSEKEEPING_PASS_BUDGET))
            })
            .await;
            match pass {
                Ok(Ok(report)) => log_report(&report),
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "housekeeping pass could not read its schedule");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "housekeeping task failed");
                }
            }
            server.prune_mcp_credentials().await;
            server
                .end_lifecycle_job(LifecycleJobKind::Housekeeping)
                .await;
        }))
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
