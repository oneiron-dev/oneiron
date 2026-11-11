//! Explicit standing-question preparation before provider work and its admission.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::decision::questions::GraphQuestionInput;
use crate::llm::decision::{DecisionDial, DecisionQuestion, TypedDecision};

/// `vault.questions.prepare`: read this version's explicit unit and sources
/// under the actual caller, the saved question principal and the writing holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionPrepareRequest {
    pub id: EntityId,
    pub expected_version: u32,
    pub input: GraphQuestionInput,
}

/// One authorized logical source body, at the version returned before inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionPreparedSource {
    pub id: EntityId,
    pub entity_type: u8,
    pub body: Vec<u8>,
    pub hash: [u8; 32],
}

/// `vault.questions.prepare`'s result. The unit is the first source, followed
/// by `input.evidence` in order. Only these selected sources are returned,
/// not the question's other units or its saved read lane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionPrepared {
    pub question: DecisionQuestion,
    pub dial: DecisionDial,
    /// The authenticated asker, to be named on the provider's decision receipt.
    pub principal: EntityId,
    pub unit: EntityId,
    pub sources: Vec<QuestionPreparedSource>,
    /// A source pin, not a credential or a grant.
    pub source_frontier: [u8; 32],
}

/// `vault.questions.admit`: a provider's measurement over a prior preparation.
/// `input` and `source_frontier` are those measured, never a newer preparation
/// fetched after inference. `decision.evidence` equals `input.evidence` (the
/// standing unit is separate); `receipt.evidence_versions` names every returned
/// source, unit first, at its exact body hash. The full typed receipt is kept.
/// A repeated frontier returns the existing answer, as native backfill does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionAdmitRequest {
    pub id: EntityId,
    pub expected_version: u32,
    pub input: GraphQuestionInput,
    pub source_frontier: [u8; 32],
    pub decision: TypedDecision,
}
