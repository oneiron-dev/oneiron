//! The served connector-send drain (OF-187): the one consumer of the
//! `bridge.outbound.schedule` queue that owner-approved sends wait in.
//! The member's told statements (`inquiry_push`, L7-03) go out here too,
//! on the host's HTTP inquiry transport, signed with the host's key.
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
//!
//! Beside the drain sit the send executor lease's two host calls (FIX 4747
//! slice 4): the release as serve stops, and the reaper pass the
//! housekeeping tick runs, which takes a send whose machine closed or
//! vanished when this machine holds what its channel needs.

use std::sync::Arc;
use std::time::Duration;

use crate::calendar_host::{CalendarChannelSink, CalendarSendClients};
use crate::inquiry_delivery::HttpInquiryTransport;
use oneiron::Vault;
use oneiron::authority::HostSlipIssuer;
use oneiron::outbound::ConnectorSendLeaseReap;
use oneiron_base::unix_seconds_now;
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
            let server = Arc::clone(&self);
            let line_push_allowance = self.config.line.monthly_push_allowance();
            let mut kept = clients.take();
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                let next = send_pass(&server, line_push_allowance, &mut kept, tick);
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
                        Duration::from_secs(at.saturating_sub(unix_seconds_now()))
                            .clamp(MIN_WAIT, IDLE)
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

    /// Releases the send executor leases this machine holds (FIX 4747 slice
    /// 4), as serve stops gracefully and before its device-sync link stops,
    /// so another machine's reaper may take them at once
    /// ([`oneiron::Vault::release_send_executor_leases`]). A release that
    /// fails leaves each lease to expire, logged with its kind.
    pub(crate) async fn release_send_executor_leases(&self) {
        let vault = Arc::clone(self.vault());
        match tokio::task::spawn_blocking(move || vault.release_send_executor_leases()).await {
            Ok(Ok(0)) => {}
            Ok(Ok(released)) => {
                tracing::info!(
                    released,
                    "send executor leases released for another machine"
                );
            }
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "send executor lease release failed");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "send executor lease release task failed"
                );
            }
        }
    }
}

/// One send lease reaper pass (FIX 4747 slice 4), on the housekeeping tick:
/// a connector send whose lease expired is taken here, in the ruled order,
/// when this machine holds what its channel needs, the check the worker's
/// sink makes before it sends ([`CalendarChannelSink::holds_channel`]); a
/// told statement needs the host's signing key `issuer`.
pub(super) fn reap_connector_send_leases(vault: &Vault, issuer: Option<&HostSlipIssuer>) {
    let holds_channel = |task: &oneiron::outbound::ConnectorSendTask| {
        CalendarChannelSink::holds_channel(vault, issuer, &task.intent)
    };
    match vault.reap_connector_send_leases(&holds_channel) {
        Ok(ConnectorSendLeaseReap {
            taken: 0,
            renewed: 0,
            waiting,
        }) => {
            if waiting > 0 {
                tracing::debug!(waiting, "send lease reaper left expired leases waiting");
            }
        }
        Ok(ConnectorSendLeaseReap {
            taken,
            waiting,
            renewed,
        }) => {
            tracing::info!(taken, renewed, waiting, "send lease reaper ran");
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "send lease reaper failed");
        }
    }
}

/// One pass: every claimable send, then the instant the next one is ready.
/// A LINE push is counted against the account plan's monthly allowance.
/// The worker's kept clients are built here, off the runtime, when it has
/// none yet. A pass a timer started (`tick`) opens with the general write
/// door's per-write work, as the surface-event drain's does. A told
/// statement is signed with the server's host key; a host that holds none
/// fails it as not sent.
fn send_pass(
    server: &SyncServer,
    line_push_allowance: u32,
    clients: &mut Option<CalendarSendClients>,
    tick: bool,
) -> oneiron::Result<Option<u64>> {
    let vault = server.vault();
    let clients = match clients {
        Some(clients) => clients,
        None => clients.insert(CalendarSendClients::new()?),
    };
    let inquiry_transport = server.host_issuer().map(HttpInquiryTransport::new);
    let mut sink = CalendarChannelSink::new(vault, line_push_allowance, clients);
    if let Some(transport) = inquiry_transport.as_ref() {
        sink = sink.with_inquiry_push(transport);
    }
    super::connector_events::carry_write_piggybacks(vault, tick)?;
    let delivered = vault
        .run_connector_task_executor(&mut sink, unix_seconds_now())
        .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
    if delivered > 0 {
        tracing::info!(delivered, "connector sends delivered");
    }
    vault.next_connector_send_ready_at()
}

#[cfg(oneiron_test_support)]
impl SyncServer {
    /// One connector-send pass now, as the drain runs it, with fresh send
    /// clients and no timer work: the test door
    /// `test_doors::connector_sends`. Blocking.
    pub(crate) fn run_connector_send_pass(&self) -> oneiron::Result<Option<u64>> {
        let mut clients = None;
        send_pass(
            self,
            self.config.line.monthly_push_allowance(),
            &mut clients,
            false,
        )
    }
}
