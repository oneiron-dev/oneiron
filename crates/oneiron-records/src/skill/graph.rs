//! Moved from `crates/oneiron/src/skill/graph.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::model_decision::questions::GraphQuestionInput;
use oneiron_store::model_decision::questions::GraphQuestionRef;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// Policy is authored in a skill file, not shipped as an engine question set.
/// Stages can ask per-unit questions, roll up their answers, then propose a pick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillProgram {
    pub stages: Vec<GraphSkillStage>,
}

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

impl GraphSkillProgram {
    /// Structure only: every stage, input and reference is admitted however
    /// many there are, and each input runs as its own question (FIX 10152).
    fn validate(&self) -> Result<()> {
        if self.stages.is_empty() {
            return Err(invalid("graph workflow requires at least one stage"));
        }
        for (stage, step) in self.stages.iter().enumerate() {
            if step.inputs.is_empty() || step.question.version == 0 {
                return Err(invalid("invalid graph workflow stage"));
            }
            for input in &step.inputs {
                for source in &input.answers {
                    if source.stage >= stage
                        || source
                            .input
                            .is_some_and(|index| index >= self.stages[source.stage].inputs.len())
                    {
                        return Err(invalid("graph workflow must reference an earlier input"));
                    }
                }
            }
        }
        Ok(())
    }
}
