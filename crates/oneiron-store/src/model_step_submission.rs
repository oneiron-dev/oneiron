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
    /// A spend scope refused the step's reservation and no write frees it:
    /// the failure's `budget_refusal` says which scope and why.
    BudgetRefused,
}

/// Why a step's spent budget refused it with no park
/// (BUDGET-TRAP-UNTYPED-NO-SENDER): no write the step could wait for gives
/// its budget room again, so the step fails at once, typed, and nothing parks.
/// `scope` is the refusing spend scope's id, `available_units` its room for
/// the reservation, `asked_units` what the reservation asked of it.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, thiserror::Error,
)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StepBudgetRefusal {
    /// A closed boundary on the way to the open scope that books the step has
    /// less room than asked. Nothing reopens a closed scope.
    #[error(
        "spend scope {scope} is closed with {available_units} of the {asked_units} units the step asks"
    )]
    BoundaryClosed {
        scope: String,
        available_units: u64,
        asked_units: u64,
    },
    /// A scope's ceiling, set at its launch, has less room than asked. A
    /// top-up of its cap does not raise it.
    #[error(
        "spend scope {scope} is at its ceiling with {available_units} of the {asked_units} units the step asks"
    )]
    CeilingReached {
        scope: String,
        available_units: u64,
        asked_units: u64,
    },
    /// The step's guard is spent and the step is bound to no wake pass and no
    /// spend scope, so no write it could wait for refills that guard.
    /// `asked_units` is the reservation the guard refused, when the refusal
    /// named one.
    #[error("the step's budget is spent and no wake pass or spend scope refills it")]
    Unbound { asked_units: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepFailure {
    pub class: ModelStepFailureClass,
    pub message: String,
    pub llm: Option<LlmError>,
    pub validation_attempts: Option<u8>,
    pub validation_errors: Vec<String>,
    pub spent_usage: Option<LlmUsage>,
    /// The typed refusal of a `BudgetRefused` failure; `None` for every
    /// other class, and on a row written before the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_refusal: Option<StepBudgetRefusal>,
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
