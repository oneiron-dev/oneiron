//! Moved from `crates/oneiron/src/llm/step/public.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::model_step_submission::ModelStepRetryPolicy;
pub use crate::store::model_step_submission::ModelStepSubmit;
use oneiron_store::model_step_record::DREAMER_STEP_RETRY_BACKOFF_MS;
pub(crate) use oneiron_store::model_step_record::MODEL_STEP_ATTEMPT_KIND;
pub use oneiron_store::model_step_record::ModelStepCheckpoint;
pub use oneiron_store::model_step_record::SettledStepRequest;
pub use oneiron_store::model_step_record::SettledStepView;
pub use oneiron_store::model_step_submission::ModelStepFailure;
pub use oneiron_store::model_step_submission::ModelStepFailureClass;
pub use oneiron_store::model_step_submission::ModelStepResult;
pub use oneiron_store::model_step_submission::StepBudgetRefusal;

impl Default for ModelStepRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: (DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1) as u8,
        }
    }
}
