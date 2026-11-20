//! Moved from `crates/oneiron/src/skill/graph.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_store::model_decision::questions::GraphQuestionInput;
use oneiron_store::model_decision::questions::GraphQuestionRef;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillStage {
    pub question: GraphQuestionRef,
    pub inputs: Vec<GraphSkillInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillInput {
    pub context: GraphQuestionInput,
    /// Answers from earlier stages become ordinary, scoped evidence. A missing
    /// answer holds this input back; an abstention never becomes a negative.
    pub answers: Vec<GraphSkillAnswerRef>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillAnswerRef {
    pub stage: usize,
    /// None selects all inputs in the stage (for a campaign rollup).
    pub input: Option<usize>,
}

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}
