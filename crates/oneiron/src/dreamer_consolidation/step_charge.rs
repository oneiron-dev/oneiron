//! Attempt-local step spend due to the shared wake ledger after memo replay.

use super::recipe_failure::RecipeFailure;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::{LlmResponse, LlmUsage, Vault};

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
        self.park_for(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
    }

    /// Parks with `reason` and settles what the attempt already spent, in a
    /// private park no later pass resumes.
    pub(super) fn park(&self, reason: &str) -> DreamerAttemptExecution {
        self.park_for(reason, DreamerParkCause::Other)
    }

    /// Parks on an engine `error` a recipe step met, with its text as the
    /// reason as before: privately when only an owner act clears it, else as
    /// a Retry a later pass resumes (OF-193a, [`RecipeFailure`]).
    pub(super) fn park_on_error(&self, error: &Error) -> DreamerAttemptExecution {
        self.park_for(
            &error.to_string(),
            RecipeFailure::of_error(error).park_cause(),
        )
    }

    /// [`Self::park`] with a typed cause, for a failed model call or step.
    pub(super) fn park_for(
        &self,
        reason: &str,
        cause: DreamerParkCause,
    ) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_hashes: self.step_hashes.clone(),
        }
    }

    /// Parks on a deterministic fallback's `response` to the step
    /// `step_hash`. A fallback that stood in for a provider outage parks as
    /// one, and the step's memo goes with it, so the attempt the offer's
    /// recovery resumes asks the model again rather than replaying the
    /// fallback (OF-305).
    pub(super) fn park_on_fallback(
        &self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        reason: &str,
        response: &LlmResponse,
    ) -> Result<DreamerAttemptExecution> {
        let cause = DreamerParkCause::of_response(response);
        if matches!(cause, DreamerParkCause::ProviderUnavailable) {
            crate::llm::forget_step_memo(vault, attempt_id, &step_hash)?;
        }
        Ok(self.park_for(reason, cause))
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

    /// [`Self::record_terminal`] for an attempt whose run line the driver
    /// meters: a step newly tallied is noted on `ctx`'s meter too, so a later
    /// engine error or park that settles the line's charge pins its paid
    /// receipt and a replay of its memo is not paid again (FIX 6100).
    pub(super) fn record_terminal_metered(
        &mut self,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        usage: &LlmUsage,
    ) -> Result<()> {
        let tallied = self.step_hashes.len();
        self.record_terminal(ctx.vault, attempt_id, step_hash, usage)?;
        if self.step_hashes.len() > tallied {
            ctx.note_terminal_step_charge(step_hash, usage_units(usage));
        }
        Ok(())
    }

    /// Failed schema correction has paid provider usage but no terminal step
    /// claim to memoize or mark as previously charged on a later wake.
    pub(super) fn record_usage(&mut self, usage: &LlmUsage) {
        self.units = self.units.saturating_add(usage_units(usage));
    }
}

/// The units one call's `usage` charges.
fn usage_units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}
