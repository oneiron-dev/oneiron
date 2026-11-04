//! The host's drain of retained transcript uploads (FIX 9654): an upload that
//! met its caller's open local session waits on the attempt queue, and this
//! worker lands each once that session has closed, oldest first, as its own
//! caller, until its deadline.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use oneiron::calendar::transcript::{
    TRANSCRIPT_PENDING_ATTEMPT_KIND, run_pending_transcript_ingests,
};

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often the worker looks for a retained upload that is due.
const DRAIN_TICK: Duration = Duration::from_secs(60);
/// Whom the worker claims retained uploads as.
const LEASE_OWNER: &str = "oneiron-serve.calendar-transcript";
/// Uploads one pass lands before it waits for the next tick.
const PASS_LIMIT: usize = 16;

/// Starts the drain. Each pass is admitted through `admit`, the way a
/// housekeeping pass is. Its first pass returns to the queue every row a
/// stopped host claimed and never settled: this worker is the kind's only one.
pub(crate) fn spawn_pending_transcript_drain(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DRAIN_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut recovered = false;
        loop {
            interval.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let recover = !std::mem::replace(&mut recovered, true);
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                let vault: &Vault = server.vault();
                if recover {
                    AttemptQueue::new(vault).cleanup_kind_leases(
                        TRANSCRIPT_PENDING_ATTEMPT_KIND,
                        CleanupAttemptLeases {
                            now: vault.now_recorded_at(),
                            lease_timeout_secs: 1,
                        },
                    )?;
                }
                run_pending_transcript_ingests(vault, LEASE_OWNER, PASS_LIMIT)
            })
            .await;
            match pass {
                Ok(Ok(pass)) if pass.landed + pass.failed > 0 => tracing::info!(
                    landed = pass.landed,
                    waiting = pass.waiting,
                    failed = pass.failed,
                    "retained transcript uploads drained"
                ),
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "retained transcript drain failed");
                }
                Err(error) => {
                    tracing::warn!(%error, "retained transcript drain pass panicked");
                }
            }
        }
    })
}
