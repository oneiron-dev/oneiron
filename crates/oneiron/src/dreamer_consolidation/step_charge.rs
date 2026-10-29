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
    /// fallback (OF-305). A Retry's memo goes too (FIX 7431): a site's check
    /// refuses such a fallback inside its step, so only one stored before
    /// that check reaches here.
    ///
    /// The step's paid receipt goes with its memo, and this park pins none
    /// for it, so the call the resumed attempt asks again charges its own
    /// usage to the wake ledger's settlement (FIX 2851); the fallback's units
    /// stay in this park's spend. The receipt and the memo go in one write,
    /// so a crash leaves either both or neither (FIX 7489).
    pub(super) fn park_on_fallback(
        &self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        reason: &str,
        response: &LlmResponse,
    ) -> Result<DreamerAttemptExecution> {
        let cause = DreamerParkCause::of_response(response);
        if !matches!(
            cause,
            DreamerParkCause::ProviderUnavailable | DreamerParkCause::Retry
        ) {
            return Ok(self.park_for(reason, cause));
        }
        forget_charged_step(vault, attempt_id, &step_hash)?;
        Ok(DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_hashes: self
                .step_hashes
                .iter()
                .copied()
                .filter(|hash| *hash != step_hash)
                .collect(),
        })
    }

    /// Parks Retry on a memoized reply to the step `step_hash` that its site
    /// refuses for `reason` (FIX 7431, Engine 10-21): one stored before the
    /// site's check refused such replies inside the step. The memo and the
    /// charge mark go together in one write, so the next try asks the model
    /// again and its paid answer is tallied once as a fresh step (FIX 7489);
    /// this park pins none for it, while the refused call's units stay in its
    /// spend (that call was paid).
    pub(super) fn park_refused_reply(
        &self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        reason: &str,
    ) -> Result<DreamerAttemptExecution> {
        forget_charged_step(vault, attempt_id, &step_hash)?;
        Ok(DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause: DreamerParkCause::Retry,
            completed_units: self.units,
            step_hashes: self
                .step_hashes
                .iter()
                .copied()
                .filter(|hash| *hash != step_hash)
                .collect(),
        })
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

    /// Units a scoped agent's own generation spent on the attempt's guard
    /// (FIX 7508), charged once when its parent stops waiting on it.
    pub(super) fn record_units(&mut self, units: u64) {
        self.units = self.units.saturating_add(units);
    }
}

/// Forgets `step_hash`'s durable charge mark and its memo in ONE write, so
/// the next try's paid answer is tallied once as a fresh step and a crash
/// leaves either both or neither (FIX 7489).
fn forget_charged_step(vault: &Vault, attempt_id: AttemptId, step_hash: &[u8; 32]) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        DreamerRunnerStore::new(vault).forget_step_charge_in_txn(wtxn, attempt_id, step_hash)?;
        crate::llm::forget_step_memo_in_txn(vault, wtxn, attempt_id, step_hash)
    })
}

/// The units one call's `usage` charges.
pub(crate) fn usage_units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}

/// The text parts of a model `response`, joined, as each recipe site reads
/// its reply.
pub(super) fn reply_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            crate::llm::ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// Whether `response` is a deterministic fallback whose park a later pass
/// resumes as a Retry (FIX 7431, Engine 10-21): one that stood in for
/// neither a provider outage nor a failure only an owner act clears. A
/// site's step check refuses it, so it is paid, never memoized, and the next
/// try asks the model again. An outage's fallback still parks as one, its
/// memo dropped (OF-305); an owner-act wait keeps its private park.
pub(super) fn retry_fallback(response: &LlmResponse) -> bool {
    matches!(
        DreamerParkCause::of_response(response),
        DreamerParkCause::Retry
    )
}
