//! The served connector reply worker (FIX 2405): the one consumer of the
//! `connector.reply` jobs a Dreamer pass hands an agent's reply off as.
//!
//! The pass only queues the job; this loop runs it off the pass, on a
//! blocking thread: generation (or the kept body), the recorded dispatch
//! and the job's result. It is shaped like the connector-send drain: run
//! every ready job, then wait for a commit to the attempt queue or an idle
//! tick. As it starts it returns to the queue any job a stopped process
//! left leased, so a restart picks the work up; a rerun reuses the kept
//! body and replays the logical send, never a second model call or send.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::TryRecvError;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;

/// How long an empty queue waits without a commit signal.
const IDLE: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

impl SyncServer {
    /// Starts the reply worker. Each pass is admitted through `admit`, the
    /// way a housekeeping pass is, so a vault frozen for reap runs nothing.
    pub(crate) fn spawn_connector_reply_worker(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move { server.run_connector_replies_forever(admit).await })
    }

    async fn run_connector_replies_forever(self: Arc<Self>, admit: HousekeepingAdmission) {
        // Subscribed before the first pass, so a job queued between that
        // pass and the first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let mut backoff = FIRST_BACKOFF;
        let mut reclaimed = false;
        loop {
            let Some(admission) = admit() else {
                tokio::time::sleep(IDLE).await;
                continue;
            };
            while let Ok(()) | Err(TryRecvError::Lagged(_)) = wake.try_recv() {}
            let server = Arc::clone(&self);
            let runtime = tokio::runtime::Handle::current();
            let reclaim = !reclaimed;
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                reply_pass(&server, &runtime, reclaim)
            })
            .await;
            let wait = match pass {
                Ok(Ok(())) => {
                    reclaimed = true;
                    backoff = FIRST_BACKOFF;
                    IDLE
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "connector reply worker failed; backing off");
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
                Err(error) => {
                    tracing::warn!(%error, "connector reply worker pass panicked; backing off");
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
            };
            tokio::select! {
                _ = wake.recv() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// One pass: on the worker's first pass, the leases a stopped process left;
/// then every ready job, each settled with its result.
fn reply_pass(
    server: &Arc<SyncServer>,
    runtime: &tokio::runtime::Handle,
    reclaim: bool,
) -> oneiron::Result<()> {
    let vault = server.vault();
    if reclaim {
        vault.reclaim_connector_reply_jobs(unix_now())?;
    }
    while let Some((claimed, job)) = vault.claim_connector_reply_job(unix_now())? {
        let result = crate::ai_host::run_connector_reply_job(server, runtime, &job);
        let result_ref = vault.settle_connector_reply_job(&claimed, &job, &result, unix_now())?;
        tracing::info!(
            agent = %job.agent.to_hex(),
            stage = ?result.stage,
            actual_units = result.actual_units,
            %result_ref,
            "connector reply job settled"
        );
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
