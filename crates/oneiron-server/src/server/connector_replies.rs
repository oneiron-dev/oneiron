//! The served connector reply worker (FIX 2405): the one consumer of the
//! `connector.reply` jobs a Dreamer pass hands an agent's reply off as.
//!
//! The pass only queues the job; this loop runs it off the pass, on a
//! blocking thread: generation (or the kept body), the recorded dispatch
//! and the job's result. It is shaped like the connector-send drain: run
//! every ready job, then wait for a commit to the attempt queue or an idle
//! tick. Each pass first returns to the queue any job left leased (by a
//! stopped process, or by a pass whose settle failed), so the work is picked
//! up again; a rerun reuses the kept body and replays the logical send, never
//! a second model call or send. A job body that panics settles as its fault.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use oneiron::outbound::{ConnectorReplyJobResult, ConnectorReplyStage};

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
        loop {
            let Some(admission) = admit() else {
                tokio::time::sleep(IDLE).await;
                continue;
            };
            while let Ok(()) | Err(TryRecvError::Lagged(_)) = wake.try_recv() {}
            let server = Arc::clone(&self);
            let runtime = tokio::runtime::Handle::current();
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                reply_pass(&server, &runtime)
            })
            .await;
            let wait = match pass {
                Ok(Ok(())) => {
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

/// One pass: the leases left behind (this worker holds none between
/// passes), then every ready job, each settled with its result.
fn reply_pass(server: &Arc<SyncServer>, runtime: &tokio::runtime::Handle) -> oneiron::Result<()> {
    let vault = server.vault();
    vault.reclaim_connector_reply_jobs(unix_now())?;
    while let Some((claimed, job)) = vault.claim_connector_reply_job(unix_now())? {
        let result = catch_unwind(AssertUnwindSafe(|| {
            crate::ai_host::run_connector_reply_job(server, runtime, &job)
        }))
        .unwrap_or_else(|_| {
            let mut fault = ConnectorReplyJobResult::at(ConnectorReplyStage::Fault);
            fault.reason = Some("connector reply job panicked".to_owned());
            fault
        });
        let result_ref = vault.settle_connector_reply_job(&claimed, &job, &result, unix_now())?;
        tracing::info!(
            agent = %job.agent.to_hex(),
            stage = ?result.stage,
            actual_units = result.actual_units,
            result_ref = result_ref.as_deref().unwrap_or("requeued"),
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
