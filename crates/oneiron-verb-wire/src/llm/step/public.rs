//! Moved from `crates/oneiron/src/llm/step/public.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::model_step_submission::ModelStepRetryPolicy;
pub use crate::store::model_step_submission::ModelStepSubmit;
use oneiron_model::llm::LlmRequest;
use oneiron_store::model_step_record::DREAMER_STEP_RETRY_BACKOFF_MS;
pub(crate) use oneiron_store::model_step_record::MODEL_STEP_ATTEMPT_KIND;
pub use oneiron_store::model_step_record::ModelStepCheckpoint;
pub use oneiron_store::model_step_record::SettledStepRequest;
pub use oneiron_store::model_step_record::SettledStepView;
use oneiron_store::model_step_record::StepProgression;
pub use oneiron_store::model_step_submission::ModelStepFailure;
pub use oneiron_store::model_step_submission::ModelStepFailureClass;
pub use oneiron_store::model_step_submission::ModelStepResult;
pub use oneiron_store::model_step_submission::StepBudgetRefusal;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

impl Default for ModelStepRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: (DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1) as u8,
        }
    }
}

/// What `ai.steps.submit` takes: one step, and the live run a run's own
/// actor submits it on. The vault owner names no run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepSubmitRequest {
    /// The handle of the caller's attached live run. Absent: the call is
    /// the vault owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_run: Option<String>,
    pub step_key: String,
    pub request: LlmRequest,
    #[serde(default)]
    pub retry: ModelStepRetryPolicy,
}

impl ModelStepSubmitRequest {
    /// The live run the call names, and the step it freezes.
    #[must_use]
    pub fn into_parts(self) -> (Option<String>, ModelStepSubmit) {
        let step = ModelStepSubmit {
            step_key: self.step_key,
            request: self.request,
            retry: self.retry,
        };
        (self.live_run, step)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepReceiptRequest {
    /// The handle of the caller's attached live run, for a step that run
    /// submitted. Absent: the call is the vault owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_run: Option<String>,
    pub step_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepReceipt {
    pub step_ref: String,
    pub step_hash: String,
    pub model: super::super::ModelId,
    pub retry: ModelStepRetryPolicy,
    pub progression: Option<StepProgression>,
    /// None while an admitted request is running or recovering.
    pub result: Option<ModelStepResult>,
}
