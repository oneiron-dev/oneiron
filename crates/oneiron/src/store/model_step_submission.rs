//! Core half of `store::model_step_submission`: its store-layer items live in `oneiron_store::model_step_submission` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::model_step_submission::*;

use crate::entity_id::EntityId;
use crate::llm::{LlmMessage, LlmUsage};
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
    /// The sends the step made in its passes before this one (FIX 11226): a
    /// pass that parks or traps keeps them, and the next pass spends only the
    /// rest of the declared attempts. Kept apart from `result`, which a
    /// resume clears, so a pass stopped before it parks again loses none.
    #[serde(default)]
    pub(crate) sends: u8,
    /// Where the step's schema correction stands while it runs
    /// (STEP-CORRECTION-HEALTH-PARK): a pass that parks on its offer's
    /// health keeps it, and the next pass continues that correction, so no
    /// paid call is asked twice. Cleared when the step settles. A row kept
    /// before it reads as none.
    #[serde(default)]
    pub(crate) correction: Option<CorrectionPoint>,
}

/// A schema correction's place in its step: which call it is, the wire after
/// the step's request, what the calls before it spent, and its own sends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CorrectionPoint {
    /// The step's call it is, from 2: the first call is 1.
    pub(crate) attempt: u8,
    /// The messages after the step's request: each refused answer and the
    /// schema message that corrects it.
    pub(crate) tail: Vec<LlmMessage>,
    /// What the calls before it spent, each already settled.
    pub(crate) usage: LlmUsage,
    /// Its own sends, each counted before it goes.
    pub(crate) sends: u8,
}

/// Whether a masked copy of a `MODEL_STEP_SUBMISSION` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn model_step_submission_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<Submission, Named>(bytes)
}
