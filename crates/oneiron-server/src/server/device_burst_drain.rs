//! The home's drain of its own devices' retained bursts (L7-41). The UPDATE
//! arm answers a device's write that the burst core defers, or isolates and
//! proposes, as held. Each lifecycle tick lands every device's oldest
//! retained update whose device's rate is back at its baseline, with no human
//! step (arch-0023b `#decision-federation-26`: "Defer replays the burst
//! later"; "It never pauses for a human"). The owner's release of an isolated
//! batch lifts only its isolation. Expiry stays with housekeeping's
//! retained-work drain.
//!
//! Log lines carry counts, a batch's address and an error's kind, never a
//! row's text.

use std::sync::Arc;

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;
use crate::protocol::ProtocolError;

impl SyncServer {
    /// Starts one pass of [`Self::drain_device_bursts`] on a task of its own,
    /// held for the host's stop, unless the last one is still running, the
    /// host is stopping, or the host's gate refused it.
    pub(super) async fn start_device_burst_drain(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::DeviceBurstDrain)
                .await
        {
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::DeviceBurstDrain)
                .await;
            return;
        };
        let server = Arc::clone(self);
        let run = tokio::spawn(async move {
            let _admission = admission;
            match server.drain_device_bursts().await {
                Ok(0) => {}
                Ok(landed) => tracing::info!(landed, "own devices' held bursts landed"),
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "own device burst drain failed");
                }
            }
            server
                .end_lifecycle_job(LifecycleJobKind::DeviceBurstDrain)
                .await;
        });
        self.housekeeping_passes.hold(run);
    }

    /// One pass: lands each own device's oldest retained update that is due
    /// now, and ends its batch. A landed batch, or one held on a copy edit's
    /// ruled cause, is complete; one the window refuses as it is now is
    /// rejected; one whose load or persist failed stays for the next pass.
    /// Answers how many batches ended complete.
    ///
    /// # Errors
    /// A store error reading or ending the retained work.
    pub(crate) async fn drain_device_bursts(&self) -> oneiron::Result<usize> {
        let mut landed = 0;
        for work in oneiron::sync::federation_burst::ready_device_work(self.vault())? {
            match crate::handler::land_retained_device_update(self, &work).await {
                Ok(()) => {
                    work.complete(self.vault())?;
                    landed += 1;
                }
                Err(ProtocolError::Persistence(error)) => {
                    tracing::warn!(
                        batch_ref = %work.batch_ref(),
                        %error,
                        "an own device's held burst did not land; the next pass retries it"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        batch_ref = %work.batch_ref(),
                        %error,
                        "an own device's held burst is refused as it is now; its batch ends rejected"
                    );
                    work.reject(self.vault())?;
                }
            }
        }
        Ok(landed)
    }
}
