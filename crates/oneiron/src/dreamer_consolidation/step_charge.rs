//! Attempt-local step spend due to the shared wake ledger after memo replay.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_wake::{DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution};
use crate::error::Result;
use crate::{LlmUsage, Vault};

/// A checkpoint charges only steps without a durable paid receipt. An earlier
/// unbilled memo (for example, after a trap refunded its reservation) still
/// belongs in the next settlement; a paid checkpoint memo does not.
#[derive(Default)]
pub(super) struct StepChargeTally {
    pub(super) units: u64,
    pub(super) step_hashes: Vec<[u8; 32]>,
}

impl StepChargeTally {
    pub(super) fn checkpoint(&self) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkWithSpend {
            reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
            completed_units: self.units,
            step_hashes: self.step_hashes.clone(),
        }
    }

    pub(super) fn record_terminal(
        &mut self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        usage: &LlmUsage,
    ) -> Result<()> {
        if self.step_hashes.contains(&step_hash)
            || DreamerRunnerStore::new(vault).checkpoint_step_charged(attempt_id, &step_hash)?
        {
            return Ok(());
        }
        self.step_hashes.push(step_hash);
        self.record_usage(usage);
        Ok(())
    }

    /// Failed schema correction has paid provider usage but no terminal step
    /// claim to memoize or mark as previously charged on a later wake.
    pub(super) fn record_usage(&mut self, usage: &LlmUsage) {
        self.units = self
            .units
            .saturating_add(usage.input.total.saturating_add(usage.output.total));
    }
}
