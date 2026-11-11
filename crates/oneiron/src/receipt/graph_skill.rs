//! The attached run's saved graph-workflow call and its staged answers.

use crate::EntityId;
use crate::llm::decision::questions::{AnswerRecord, QuestionCriteria};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_decision::DecisionRung;
use crate::skill::{GraphSkillFailure, GraphSkillResult};
use serde::{Deserialize, Serialize};

/// `self.skills.graph`: run a resident-owned workflow from its admitted
/// skill source tree. The host supplies the attached lease and executor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillRunRequest {
    /// The resident-owned workflow skill's entity id, in hex.
    pub skill: String,
    /// The exact workflow JSON path in the admitted skill source tree.
    /// This names no host file and has no default.
    pub reference: String,
    /// An optional caller ceiling over each saved question's authored dial.
    #[serde(default)]
    pub ceiling: Option<DecisionRung>,
    /// An explicit per-input clock; otherwise the saved question's own deadline.
    #[serde(default)]
    pub unit_deadline_ms: Option<u64>,
    /// Additional narrowing; never loosens the saved or vault posture.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub posture: Option<crate::config::HostingPrivacyPosture>,
    /// Explicit caller criteria; otherwise the saved version's criteria.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub criteria: Option<QuestionCriteria<String>>,
}

impl GraphSkillRunRequest {
    /// Check the caller's identifiers and existing per-question bounds.
    /// The workflow runner resolves `reference` only in admitted source.
    pub fn validate(&self) -> MemoryResult<()> {
        EntityId::from_hex(&self.skill)?;
        crate::request_limits::check_deadline_ms(self.unit_deadline_ms)?;
        if self
            .criteria
            .as_ref()
            .is_some_and(|criteria| criteria.validate().is_err())
        {
            return Err(MemoryError::bad_request("the criteria are not valid"));
        }
        Ok(())
    }
}

/// The stages retain their input positions. `None` is an unanswered or
/// held input, never a negative. Answers before a failure remain committed;
/// the last stage is proposed work, not permission to keep or send it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GraphSkillRunOutcome {
    Done {
        stages: Vec<Vec<Option<AnswerRecord>>>,
    },
    Failed {
        failed_stage: Option<usize>,
        failed_input: Option<usize>,
        code: String,
        message: String,
        stages: Vec<Vec<Option<AnswerRecord>>>,
    },
}

impl From<GraphSkillResult> for GraphSkillRunOutcome {
    fn from(result: GraphSkillResult) -> Self {
        Self::Done {
            stages: result.stages,
        }
    }
}

impl GraphSkillRunOutcome {
    /// As for a one-off graph ask, preparation errors are plain errors;
    /// failures after execution starts retain their completed positions.
    pub fn from_failure(failure: GraphSkillFailure) -> MemoryResult<Self> {
        let error = MemoryError::from(*failure.error);
        if failure.completed.stages.is_empty() {
            return Err(error);
        }
        Ok(Self::Failed {
            failed_stage: failure.stage,
            failed_input: failure.input,
            code: error.code,
            message: error.message,
            stages: failure.completed.stages,
        })
    }

    /// The same staged answers on success and on partial failure.
    pub fn stages(&self) -> &[Vec<Option<AnswerRecord>>] {
        match self {
            Self::Done { stages } | Self::Failed { stages, .. } => stages,
        }
    }
}
