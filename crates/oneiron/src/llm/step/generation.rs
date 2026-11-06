//! Optional logical-generation admission on the durable step's native attempt boundary.

use super::execute::durable_step_with_generation;
use super::types::DREAMER_STEP_RETRY_BACKOFF_MS;
use super::{DurableStepContext, DurableStepResult, StepOutcome};
use crate::llm::decision::DecisionGenerationAdmission;
use crate::llm::{BudgetGuard, FallbackRegistry, LlmBackend, LlmRequest, LlmUsage};

/// A completed step or an allowance cut, separate from a provider failure.
/// A cut before the first generation has no usage. A corrective cut carries
/// the actual answered and settled prefix, even if its reported usage is zero.
pub(crate) enum GenerationOutcome<T> {
    Completed(T),
    Cut { usage: Option<LlmUsage> },
}

/// The ordinary durable call with optional per-logical-generation admission.
/// Recovery consumes no start; transport retries share their attempt's start.
pub(crate) async fn call_as_step_with_generation(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    generation: Option<&dyn DecisionGenerationAdmission>,
) -> DurableStepResult<GenerationOutcome<StepOutcome>> {
    durable_step_with_generation(
        ctx,
        backend,
        guard,
        request,
        &FallbackRegistry::standard(),
        None,
        DREAMER_STEP_RETRY_BACKOFF_MS.len(),
        None,
        generation,
    )
    .await
}
