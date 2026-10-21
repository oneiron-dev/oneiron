//! Accepted-push candidate intake in the checker's one drain (FIX 6869, G4
//! PR2). After the queues' own steps and before their checks, each enrolled
//! store matches its retained received refs once a drain, each store under
//! an admission of its own and the host's stop. Matching writes Proposed
//! work or a typed hold only: it never enqueues, approves or moves a ref.

use super::super::core::SyncServer;
use super::super::housekeeping::HousekeepingAdmission;

impl SyncServer {
    /// Each enrolled store's candidate intake, at most once a drain: how
    /// many durable transitions it wrote, or `None` when the host stops or
    /// its gate refuses.
    pub(super) fn intake_received_candidates(
        &self,
        admission: &mut Option<Box<dyn Send>>,
        admit: &HousekeepingAdmission,
        taken: &mut Vec<String>,
    ) -> oneiron::Result<Option<usize>> {
        let vault = self.vault();
        let mut moved = 0_usize;
        for config in vault.queue_driver_configurations()? {
            if taken.contains(&config.store) {
                continue;
            }
            if self.housekeeping_passes.stopping() {
                return Ok(None);
            }
            let Some(held) = admission.take().or_else(|| admit()) else {
                return Ok(None);
            };
            match vault
                .queue_driver_open(&config)
                .and_then(|queue| queue.intake_received_code_candidates())
            {
                Ok(written) => moved += written,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "received push intake did not settle");
                }
            }
            drop(held);
            taken.push(config.store);
        }
        Ok(Some(moved))
    }
}
