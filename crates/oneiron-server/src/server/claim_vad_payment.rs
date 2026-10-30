//! The host's claim VAD payment worker (FIX 11702, Engine 10-31 04:1x).
//!
//! The lifecycle scheduler attaches it to the served vault when it starts.
//! From then on the vault's write door answers before the claim VAD
//! consolidations its write owes: it hands them over and wakes this worker
//! ([`oneiron::Vault::claim_vad_payment_wake`]). Each wake starts one run at
//! once, on a blocking thread, under the host's write gate. Runs never
//! overlap: a wake that comes while one runs is kept and starts the next run
//! when it ends, and wakes that come together make one run. Each run is held
//! in the housekeeping passes, so stopping the host waits for it. A gate that
//! refuses a run, or a stopping host, leaves the debts, which are durable,
//! for the next wake or the housekeeping pass's `ClaimVadDebt` sweep.

use std::sync::Arc;

use tokio::task::JoinHandle;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;

impl SyncServer {
    /// Attaches the payment worker to this server's vault and starts its
    /// loop. Dropping or aborting the returned task detaches it, and the
    /// door pays on its calling thread again.
    pub(super) fn spawn_claim_vad_payment_worker(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> JoinHandle<()> {
        // Attached before this returns: every write from here on hands its
        // consolidations over and wakes the loop, which keeps a wake that
        // comes before it first waits.
        let attached = self.vault().attach_claim_vad_payment_worker();
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let _attached = attached;
            loop {
                server.vault().claim_vad_payment_wake().notified().await;
                if server.housekeeping_passes.stopping() {
                    return;
                }
                let Some(admission) = admit() else {
                    tracing::debug!("claim VAD payment skipped: the host's gate refused the run");
                    continue;
                };
                let vault = Arc::clone(server.vault());
                let run = tokio::task::spawn_blocking(move || {
                    let _admission = admission;
                    vault.pay_handed_claim_vads()
                });
                let (ended, done) = tokio::sync::oneshot::channel::<()>();
                server.housekeeping_passes.hold(tokio::spawn(async move {
                    match run.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(
                                kind = ?error.kind(),
                                "claim VAD payment failed; the debts stay for the housekeeping pass"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                panicked = error.is_panic(),
                                "claim VAD payment task failed"
                            );
                        }
                    }
                    let _ = ended.send(());
                }));
                let _ = done.await;
            }
        })
    }
}
