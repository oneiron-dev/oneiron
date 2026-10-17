//! The served connector-send drain (OF-187): the one consumer of the
//! `bridge.outbound.schedule` queue that owner-approved sends wait in.
//!
//! The engine schedules a send as a connector-send TASK and its executor runs
//! each one through the common dispatch pipeline; it never starts a thread.
//! This loop is the host half, shaped like the surface-event drain: run the
//! executor until the queue is empty, then wait for a commit to the attempt
//! queue, the next scheduled retry or hold edge, or an idle tick, whichever
//! comes first. Every send goes out on the engine's served sink, which holds
//! the transports this engine drives; a channel it has none for fails the
//! attempt as not started. Everything the drain does is sync, so every pass
//! runs on a blocking thread.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::outbound::ServedChannelSink;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;

/// How long an empty queue waits without a commit signal.
const IDLE: Duration = Duration::from_secs(30);
/// The shortest wait between passes.
const MIN_WAIT: Duration = Duration::from_secs(1);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

impl SyncServer {
    /// Starts the drain. Each pass is admitted through `admit`, the way a
    /// housekeeping pass is, so a vault frozen for reap sends nothing.
    pub(crate) fn spawn_connector_send_worker(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move { server.drain_connector_sends_forever(admit).await })
    }

    async fn drain_connector_sends_forever(self: Arc<Self>, admit: HousekeepingAdmission) {
        // Subscribed before the first pass, so a send scheduled between that
        // pass and the first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let mut backoff = FIRST_BACKOFF;
        loop {
            let Some(admission) = admit() else {
                tokio::time::sleep(IDLE).await;
                continue;
            };
            let vault = Arc::clone(self.vault());
            let line_push_allowance = self.config.line.monthly_push_allowance();
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                send_pass(&vault, line_push_allowance)
            })
            .await;
            let wait = match pass {
                Ok(Ok(next)) => {
                    backoff = FIRST_BACKOFF;
                    // At least a second: a row the claim passes over cannot
                    // spin the loop.
                    next.map_or(IDLE, |at| {
                        Duration::from_secs(at.saturating_sub(unix_now())).clamp(MIN_WAIT, IDLE)
                    })
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "connector send drain failed; backing off");
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
                Err(error) => {
                    tracing::warn!(%error, "connector send drain pass panicked; backing off");
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

/// One pass: every claimable send, then the instant the next one is ready.
/// A LINE push is counted against the account plan's monthly allowance.
fn send_pass(vault: &Vault, line_push_allowance: u32) -> oneiron::Result<Option<u64>> {
    let mut sink = ServedChannelSink::new(vault)?.with_line_push_allowance(line_push_allowance);
    let delivered = vault
        .run_connector_task_executor(&mut sink, unix_now())
        .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
    if delivered > 0 {
        tracing::info!(delivered, "connector sends delivered");
    }
    vault.next_connector_send_ready_at()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
