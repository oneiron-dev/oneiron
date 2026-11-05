//! Core half of `store::model_step_submission`: its store-layer items live in `oneiron_store::model_step_submission` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::model_step_submission::*;

use crate::entity_id::EntityId;
use crate::side_table::Named;
use oneiron_model::llm::{FatalLlmError, LlmError, LlmRequest, LlmResponse, LlmUsage};
use serde::{Deserialize, Serialize};

/// Transport attempts per model request, including the first send. Retries
/// past the engine schedule wait its last interval (FIX 9930); the default is
/// the schedule's own four. Schema corrections remain the existing
/// one/native or three/shim paid calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepRetryPolicy {
    pub max_attempts: u8,
}

/// A caller-owned stable key freezes one exact request and its retry policy.
/// The envelope's CallClass declares the deterministic fallback, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepSubmit {
    pub step_key: String,
    pub request: LlmRequest,
    #[serde(default)]
    pub retry: ModelStepRetryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Submission {
    pub(crate) actor: EntityId,
    pub(crate) input: ModelStepSubmit,
    pub(crate) step_hash: [u8; 32],
    pub(crate) result: Option<ModelStepResult>,
}

/// Whether a masked copy of a `MODEL_STEP_SUBMISSION` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn model_step_submission_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<Submission, Named>(bytes)
}
