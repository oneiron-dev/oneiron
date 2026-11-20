//! The home's drain of its own devices' retained bursts (L7-41). The UPDATE
//! arm answers a device's write that the burst core defers, or isolates and
//! proposes, as held. Each lifecycle tick lands every device's oldest
//! retained update whose device's rate is back at its baseline, with no human
//! step (arch-0023b `#decision-federation-26`: "Defer replays the burst
//! later"; "It never pauses for a human"). The owner's release of an isolated
//! batch lifts only its isolation. Expiry stays with housekeeping's
//! retained-work drain.
//!
//! One batch has one landing at a time ([`DeviceBurstLandings`]): a socket's
//! UPDATE arm claims its batch before the burst core admits it, and the
//! drain each batch it takes, so the same bytes never persist twice and no
//! landing settles a batch another one ended (FIX
//! DEVICE-BURST-ALLOW-DRAIN-OVERLAP).
//!
//! Log lines carry counts, a batch's address and an error's kind, never a
//! row's text.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;
use crate::handler::DeviceBurstEnd;

/// The own devices' burst batches whose landing is claimed now, by batch
/// address ([`oneiron::sync::federation_burst::DeviceBurstWork::batch_ref`]).
/// In memory only: a restarted host holds no claim, and its drain takes
/// every retained batch again.
#[derive(Debug, Default)]
pub(crate) struct DeviceBurstLandings {
    claimed: Mutex<HashSet<String>>,
}

/// One landing's claim on its batch, given up when dropped.
#[derive(Debug)]
pub(crate) struct DeviceBurstLandingClaim<'a> {
    landings: &'a DeviceBurstLandings,
    batch_ref: String,
}

impl Drop for DeviceBurstLandingClaim<'_> {
    fn drop(&mut self) {
        self.landings
            .claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.batch_ref);
    }
}

impl SyncServer {
    /// Claims the landing of the own device's batch at `batch_ref`, or
    /// `None` while another landing holds it: a socket's UPDATE arm from
    /// before its burst admission until its batch ends, or the drain while it
    /// lands the batch.
    pub(crate) fn claim_device_burst_landing(
        &self,
        batch_ref: String,
    ) -> Option<DeviceBurstLandingClaim<'_>> {
        let landings = &self.housekeeping_passes.device_burst_landings;
        let fresh = landings
            .claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(batch_ref.clone());
        // No claim value exists for a refused claim: dropping one would end
        // the claim another landing holds.
        if !fresh {
            return None;
        }
        Some(DeviceBurstLandingClaim {
            landings,
            batch_ref,
        })
    }

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
    /// now, and ends its batch as [`DeviceBurstEnd::of`] reads the landing:
    /// landed, held on a copy edit's ruled cause, or durable, it is complete;
    /// one the window refuses as it is now is rejected; one whose load or
    /// persist failed stays for the next pass. A batch a socket's UPDATE arm
    /// claimed is that arm's to land and end: the pass leaves it, and takes it
    /// on a later pass if the arm gave up with it retained. Answers how many
    /// batches ended complete.
    ///
    /// # Errors
    /// A store error reading or ending the retained work.
    pub(crate) async fn drain_device_bursts(&self) -> oneiron::Result<usize> {
        let mut landed = 0;
        for work in oneiron::sync::federation_burst::ready_device_work(self.vault())? {
            let Some(claim) = self.claim_device_burst_landing(work.batch_ref()) else {
                continue;
            };
            let landing = crate::handler::land_retained_device_update(self, &work).await;
            let end = DeviceBurstEnd::of(&landing);
            if let Err(failure) = &landing {
                tracing::warn!(
                    batch_ref = %work.batch_ref(),
                    kind = failure.kind(),
                    end = ?end,
                    "an own device's held burst did not land as it was sent"
                );
            }
            end.settle(self.vault(), &work)?;
            drop(claim);
            if end == DeviceBurstEnd::Complete {
                landed += 1;
            }
        }
        Ok(landed)
    }
}
