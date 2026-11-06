//! A public model-step submission row (`MODEL_STEP_SUBMISSION`, FIX 9929)
//! and the public step types it keeps: the owner's request with its retry
//! policy, and the step's result or failure. The public step door
//! (`llm::step::public`) and its body custody (`llm::step::submission_custody`)
//! write, read and erase the row; the row's side-table declaration names its
//! lift acceptance.
use oneiron_model::llm::{FatalLlmError, LlmError, LlmRequest, LlmResponse, LlmUsage};
use serde::{Deserialize, Serialize};

use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelStepFailureClass {
    Retryable,
    Fatal,
    BudgetDenied,
    SchemaValidation,
    Fallback,
    FinalizeRefused,
    DeadlineHardCut,
    Engine,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepFailure {
    pub class: ModelStepFailureClass,
    pub message: String,
    pub llm: Option<LlmError>,
    pub validation_attempts: Option<u8>,
    pub validation_errors: Vec<String>,
    pub spent_usage: Option<LlmUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ModelStepResult {
    Finished {
        response: LlmResponse,
        /// Present only for ResponseFormat::Json, parsed after the engine's validation.
        json: Option<serde_json::Value>,
        memoized: bool,
        fallback_source: Option<FatalLlmError>,
        claim_ref: String,
    },
    Failed {
        failure: ModelStepFailure,
    },
    /// The existing step executor parked this attempt on its budget trap.
    BudgetDenied {
        trap_ref: String,
    },
    /// An owner's erase took this step's request and result (FIX 9929). The
    /// receipt keeps its metadata; the step is over and is never asked again.
    Erased,
}
