//! The served holder's owner work pickup. Each lifecycle tick runs the owner
//! work requests that name this install as their executor
//! ([`oneiron::Vault::run_pending_owner_work`]) on a blocking thread, off the
//! request path: the self-hosted serve and the managed one run the same
//! scheduler, so both pick it up. It has no interval of its own (CALLS
//! OWNER_WORK_PICKUP). The executor signs with its own install key; the host
//! root never signs owner work.
//!
//! Log lines carry counts and an error's kind, never a row's text.

use std::sync::Arc;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;

impl SyncServer {
    /// Starts this install's owner work pickup on a task of its own, held for
    /// the host's stop, unless the last one is still running, the host is
    /// stopping, or the host's gate refused it. A stopping host lets the
    /// request in hand commit and starts no other.
    pub(super) async fn start_owner_work_drain(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        if self.housekeeping_passes.stopping()
            || !self.begin_lifecycle_job(LifecycleJobKind::OwnerWork).await
        {
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::OwnerWork).await;
            return;
        };
        let server = Arc::clone(self);
        let run = tokio::spawn(async move {
            let _admission = admission;
            let drain = Arc::clone(&server);
            match tokio::task::spawn_blocking(move || {
                drain
                    .vault()
                    .run_pending_owner_work(|| !drain.housekeeping_passes.stopping())
            })
            .await
            {
                Ok(Ok(drained)) => {
                    if drained.enacted + drained.refused + drained.failed > 0 {
                        tracing::info!(
                            enacted = drained.enacted,
                            refused = drained.refused,
                            pending = drained.pending,
                            failed = drained.failed,
                            "owner work picked up"
                        );
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "owner work pickup failed");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "owner work task failed");
                }
            }
            server.end_lifecycle_job(LifecycleJobKind::OwnerWork).await;
        });
        self.housekeeping_passes.hold(run);
    }
}
