//! Moved from `crates/oneiron/src/llm/step/public.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::model_step_submission::ModelStepRetryPolicy;
pub use crate::store::model_step_submission::ModelStepSubmit;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_model::llm::BudgetGuard;
use oneiron_model::llm::ContentPart;
use oneiron_model::llm::FallbackRegistry;
use oneiron_model::llm::LlmBackend;
use oneiron_model::llm::LlmError;
use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::LlmResponse;
use oneiron_model::llm::ResponseFormat;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_inputs::ClaimAttempt;
use oneiron_store::attempt_inputs::CompleteAttempt;
use oneiron_store::attempt_inputs::EnqueueAttempt;
use oneiron_store::attempt_inputs::FailAttempt;
use oneiron_store::dispatch_attempt_kind::AGENT_DISPATCH_ATTEMPT_TYPE;
use oneiron_store::dreamer_attempt_payload::DreamerAttemptPayload;
use oneiron_store::dreamer_attempt_payload::decode_dreamer_attempt_payload;
use oneiron_store::dreamer_attempt_payload::encode_dreamer_attempt_payload;
use oneiron_store::model_step_record::DREAMER_STEP_RETRY_BACKOFF_MS;
use oneiron_store::model_step_record::DreamerTrapState;
pub(crate) use oneiron_store::model_step_record::MODEL_STEP_ATTEMPT_KIND;
pub use oneiron_store::model_step_record::ModelStepCheckpoint;
pub use oneiron_store::model_step_record::SettledStepRequest;
pub use oneiron_store::model_step_record::SettledStepView;
use oneiron_store::model_step_record::StepProgression;
pub use oneiron_store::model_step_submission::ModelStepFailure;
pub use oneiron_store::model_step_submission::ModelStepFailureClass;
pub use oneiron_store::model_step_submission::ModelStepResult;
pub use oneiron_store::model_step_submission::StepBudgetRefusal;
use oneiron_store::verb_invocation::InvocationId;
use oneiron_store::write_envelope::WriteActor;
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
