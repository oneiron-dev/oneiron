//! Moved from `crates/oneiron/src/llm/routing/readings.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::ModelId;
use oneiron_model::llm::ReasoningEffort;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One candidate's grade: the model, the effort it was graded at, and its
/// complete typed decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionGrading {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub decision: TypedDecision,
}

impl DescriptionGrading {
    /// Its `[0, 1]` fitness, read from its own decision: an abstained or
    /// unscored grade leaves the candidate unfit.
    #[must_use]
    pub fn fitness(&self) -> Option<f64> {
        match self.decision.answer {
            DecisionAnswer::Score(fitness) => Some(fitness),
            _ => None,
        }
    }
}
