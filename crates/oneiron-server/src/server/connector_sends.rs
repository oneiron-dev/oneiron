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

use crate::calendar_host::{CalendarChannelSink, CalendarSendClients};
use oneiron::Vault;
use tokio::sync::broadcast::error::TryRecvError;

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
        // The worker's send clients, built on the first pass's blocking
        // thread and kept across passes, so a pass that finds nothing to send
        // builds none. A pass that could not build them tries again next time.
        let mut clients: Option<CalendarSendClients> = None;
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
            let line_push_allowance = self.config.line.monthly_push_allowance();
            let mut kept = clients.take();
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                let next = send_pass(&vault, line_push_allowance, &mut kept, tick);
                (next, kept)
            })
            .await
            .map(|(next, kept)| {
                clients = kept;
                next
            });
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
            tick = tokio::select! {
                _ = wake.recv() => false,
                () = tokio::time::sleep(wait) => true,
            };
        }
    }
}

/// One pass: every claimable send, then the instant the next one is ready.
/// A LINE push is counted against the account plan's monthly allowance.
/// The worker's kept clients are built here, off the runtime, when it has
/// none yet. A pass a timer started (`tick`) opens with the general write
/// door's per-write work, as the surface-event drain's does.
fn send_pass(
    vault: &Vault,
    line_push_allowance: u32,
    clients: &mut Option<CalendarSendClients>,
    tick: bool,
) -> oneiron::Result<Option<u64>> {
    let clients = match clients {
        Some(clients) => clients,
        None => clients.insert(CalendarSendClients::new()?),
    };
    let mut sink = CalendarChannelSink::new(vault, line_push_allowance, clients);
    super::connector_events::carry_write_piggybacks(vault, tick)?;
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
