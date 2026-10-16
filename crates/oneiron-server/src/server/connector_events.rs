//! The served surface-event drain (OF-218): the one thing that hands each
//! queued inbound event to its actor's standing connector subscriptions.
//!
//! The engine commits the handoff with the inbound write and settles each
//! attempt; it never starts a thread. This loop is the host half, shaped like
//! the tagging worker: drain a bounded pass, go again at once while the pass
//! was full, then wait for a commit to the attempt queue or an idle tick.
//! Pickup is level-triggered: every pass claims what is ready now, so work
//! larger than one pass drains in later passes and a missed signal costs one
//! idle tick, never a wake. Everything the drain does is sync, so every pass
//! runs on a blocking thread.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::surface_event::SurfaceEventWorkerOutcome;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;

/// Lease owner of every surface-event attempt this server claims.
const LEASE_OWNER: &str = "oneiron-server-surface-events";
/// Events one pass settles before the loop yields and goes again.
const PASS_LIMIT: usize = 64;
/// How long an empty queue waits without a commit signal.
const IDLE: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

impl SyncServer {
    /// Starts the drain. Each pass is admitted through `admit`, the way a
    /// housekeeping pass is, so a vault frozen for reap drains nothing.
    pub(crate) fn spawn_connector_event_worker(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move { server.drain_surface_events_forever(admit).await })
    }

    async fn drain_surface_events_forever(self: Arc<Self>, admit: HousekeepingAdmission) {
        // Subscribed before the first pass, so a commit between that pass and
        // the first wait still wakes the loop.
        let mut wake = oneiron::attempt_queue::AttemptQueue::new(self.vault()).subscribe();
        let mut backoff = FIRST_BACKOFF;
        loop {
            let Some(admission) = admit() else {
                tokio::time::sleep(IDLE).await;
                continue;
            };
            let vault = Arc::clone(self.vault());
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                drain_pass(&vault)
            })
            .await;
            let wait = match pass {
                Ok(Ok(full)) => {
                    backoff = FIRST_BACKOFF;
                    if full {
                        continue;
                    }
                    IDLE
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "surface event drain failed; backing off");
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
                Err(error) => {
                    tracing::warn!(%error, "surface event drain pass panicked; backing off");
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

/// One bounded pass. `Ok(true)`: the pass was full and more may be ready.
fn drain_pass(vault: &Vault) -> oneiron::Result<bool> {
    for _ in 0..PASS_LIMIT {
        if let SurfaceEventWorkerOutcome::Empty =
            vault.drain_surface_event_to_connector_wakes(LEASE_OWNER, unix_now())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
