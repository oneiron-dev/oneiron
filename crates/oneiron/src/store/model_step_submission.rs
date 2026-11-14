//! Core half of `store::model_step_submission`: its store-layer items live in `oneiron_store::model_step_submission` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::model_step_submission::*;

use crate::entity_id::EntityId;
use crate::side_table::Named;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::store::model_step_submission::{ModelStepRetryPolicy, ModelStepSubmit};

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
