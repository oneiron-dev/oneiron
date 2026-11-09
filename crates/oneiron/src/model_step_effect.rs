//! Durable model-step identity frozen into outbound effects.

use crate::attempt_queue::AttemptId;
use crate::model_step_error::DurableStepResult;
use oneiron_model::llm::LlmRequest;

#[doc(hidden)]
pub use oneiron_wake_contract::model_step_effect::StepEffectBinding;

pub(crate) fn step_effect_binding_for_request(
    attempt_id: AttemptId,
    request: &LlmRequest,
) -> DurableStepResult<StepEffectBinding> {
    Ok(StepEffectBinding {
        attempt_id,
        step_hash: request.canonical_hash()?,
    })
}
