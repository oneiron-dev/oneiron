//! One judge call of a compaction check, as a durable step of the check's
//! own attempt. A check that judges in parts, a conversation turn read in
//! pieces (FIX-LIST COMPACTION-CHECK-JUDGES-PER-CHUNK), asks one per part,
//! and each call carries what the calls before it spent: a park, a settle or
//! a later booking then books each finished step once.

use super::{CompactionCheckModel, support};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::call_as_step;
use crate::model_step_context::{DurableStepContext, StepEffectBinding, StepOutcome};
use crate::model_step_error::DurableStepResult;
use crate::{EntityId, Error, Result};
use oneiron_model::llm::{LlmRequest, LlmResponse};

/// One judge call's answer, as a durable step of its attempt.
pub(super) struct Judging {
    pub(super) response: LlmResponse,
    pub(super) memoized: bool,
    pub(super) step_hash: [u8; 32],
    pub(super) binding: StepEffectBinding,
    /// What it spent: nothing when memoized, paid for by the pass that
    /// asked it.
    pub(super) units: u64,
    /// What the check's calls before it spent, booked with its own.
    pub(super) earlier: support::Spend,
}

impl Judging {
    /// The judge's model, step and usage, as a finding records them.
    pub(super) fn judge(&self, model: &CompactionCheckModel<'_>) -> serde_json::Value {
        serde_json::json!({
            "model": model.model.as_str(),
            "step_hash": bytes_to_hex_lower(&self.step_hash),
            "usage_in": self.response.usage.input.total,
            "usage_out": self.response.usage.output.total,
        })
    }
}

/// Asks the judge `request` about `subject`, as a durable step of
/// `attempt`, admitted on the host's role, after calls that spent
/// `earlier`: its answer, or how the attempt waits for one with `earlier`
/// kept. On an `Err` the caller hands `earlier` to the meter.
pub(super) async fn ask_judge(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: &CompactionCheckModel<'_>,
    request: LlmRequest,
    subject: EntityId,
    earlier: &support::Spend,
) -> Result<std::result::Result<Judging, DreamerAttemptExecution>> {
    let attempt_id = attempt.status.attempt.id;
    let request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    let step_hash = request
        .canonical_hash()
        .map_err(|_| Error::InvalidConfig("the check request did not hash".into()))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: ctx.vault.dreamer_actor_for_attempt(attempt_id)?,
        subject,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let outcome = call_as_step(&step_ctx, model.backend, model.guard, request).await;
    let (response, memoized, binding) = match step_answer(outcome, earlier)? {
        Ok(answer) => answer,
        Err(parked) => return Ok(Err(parked)),
    };
    let units = if memoized {
        0
    } else {
        response
            .usage
            .input
            .total
            .saturating_add(response.usage.output.total)
    };
    Ok(Ok(Judging {
        response,
        memoized,
        step_hash,
        binding,
        units,
        earlier: earlier.clone(),
    }))
}

/// The judge's answer and whether it was memoized, or how the attempt
/// waits for one.
type StepAnswer =
    std::result::Result<(LlmResponse, bool, StepEffectBinding), DreamerAttemptExecution>;

/// [`StepAnswer`] from the durable step's outcome: a step that did not
/// finish parks with what the calls before it spent, `earlier`, and its own
/// spend.
fn step_answer(
    outcome: DurableStepResult<StepOutcome>,
    earlier: &support::Spend,
) -> Result<StepAnswer> {
    match outcome {
        Ok(StepOutcome::Finished {
            response,
            memoized,
            binding,
            ..
        }) => Ok(Ok((response, memoized, binding))),
        Ok(StepOutcome::Trapped { .. }) => Ok(Err(earlier.clone().trapped())),
        Err(error) => earlier.clone().parked_on(error).map(Err),
    }
}
