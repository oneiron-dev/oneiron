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
use tokio::sync::broadcast::error::TryRecvError;

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
/// Whether a pass a timer starts (the idle, deadline or backoff wait, and the
/// first pass) opens the general Vault write door once before it claims.
/// Before FIX 5678 every claim went through that door, so its per-write work
/// (waiting scan checks, due found-key notices) ran at least once per idle
/// tick on a vault with no other writes; this keeps that cadence. Its commit
/// wakes every attempt observer once, and the pass that wake starts claims
/// through the kind's own door, which wakes no one when it finds nothing.
/// The connector-send drain shares it through [`carry_write_piggybacks`].
const IDLE_TICK_CARRIES_WRITE_PIGGYBACKS: bool = true;

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
        // Whether a timer started the pass about to run; the first pass
        // counts as one, since nothing has signalled yet.
        let mut tick = true;
        loop {
            let Some(admission) = admit() else {
                tokio::time::sleep(IDLE).await;
                tick = true;
                continue;
            };
            // The pass reads the queue as it is now, which answers every
            // signal already waiting; a commit after this point still wakes
            // the wait below.
            while let Ok(()) | Err(TryRecvError::Lagged(_)) = wake.try_recv() {}
            let vault = Arc::clone(self.vault());
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                drain_pass(&vault, tick)
            })
            .await;
            let wait = match pass {
                Ok(Ok(full)) => {
                    backoff = FIRST_BACKOFF;
                    if full {
                        tick = false;
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
            tick = tokio::select! {
                _ = wake.recv() => false,
                () = tokio::time::sleep(wait) => true,
            };
        }
    }
}

/// A timer pass's opening write, before its first claim: nothing of its own,
/// only the general write door's per-write work and its commit's wake, which
/// that pass's claim through the door carried before FIX 5678. With no
/// per-write work due the tick takes no write and sends that wake alone
/// (FIX 11664); a check that fails takes the write, so no work is skipped.
pub(super) fn carry_write_piggybacks(vault: &Vault, tick: bool) -> oneiron::Result<()> {
    if !(tick && IDLE_TICK_CARRIES_WRITE_PIGGYBACKS) {
        return Ok(());
    }
    if vault.write_door_work_due().unwrap_or(true) {
        vault.with_write_txn_grouped(|_| Ok(()))
    } else {
        vault.send_empty_commit_wakes();
        Ok(())
    }
}

/// One bounded pass. `Ok(true)`: the pass was full and more may be ready.
fn drain_pass(vault: &Vault, tick: bool) -> oneiron::Result<bool> {
    carry_write_piggybacks(vault, tick)?;
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
