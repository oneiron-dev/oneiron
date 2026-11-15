//! Moved from `crates/oneiron/src/llm/decision/questions/records.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::model_decision::questions::CalibrationPair;
pub use oneiron_store::model_decision::questions::DecisionRoute;
pub use oneiron_store::model_decision::questions::OmittedNeighbor;
pub use oneiron_store::model_decision::questions::OutcomeBinding;
pub use oneiron_store::model_decision::questions::OutcomeLabel;
pub use oneiron_store::model_decision::questions::OutcomeSource;
pub use oneiron_store::model_decision::questions::OutcomeWindowClose;
pub use oneiron_store::model_decision::questions::QuestionActivation;
pub use oneiron_store::model_decision::questions::QuestionAudience;
pub use oneiron_store::model_decision::questions::QuestionMedia;
pub use oneiron_store::model_decision::questions::QuestionScheduleHead;
pub use oneiron_store::model_decision::questions::RefreshPolicy;
pub use oneiron_store::model_decision::questions::RoutingPolicy;
pub use oneiron_store::model_decision::questions::SourceConflict;
pub use oneiron_store::model_decision::questions::WindowOutcome;
pub use oneiron_verb_wire::llm::decision::questions::criteria::MAX_CRITERION_BYTES;
pub use oneiron_verb_wire::llm::decision::questions::records::ARTIFACT_ADAPTER;
pub use oneiron_verb_wire::llm::decision::questions::records::QUESTION_CALL_BUDGET_MS;
use serde::Deserialize;
use serde::Serialize;

/// One artifact a standing artifact question asks: the artifact its answers land in, and
/// which of its units are asked, as a `vault.artifacts.ask` names them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUnits {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    pub artifact: EntityId,
    pub selection: oneiron_verb_wire::blob_artifact::verbs::ArtifactAskUnits,
}

/// A standing question's scheduled backfill: from `due_at`, the question
/// pump answers each covered unit with no answer at `version`, once. With
/// `joins`, it answers each join whose unit has no answer at `version`,
/// shown the join's own evidence instead of the unit's neighbours (FIX 2383).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledBackfill {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    pub question: EntityId,
    pub version: u32,
    pub due_at: u64,
    /// The explicit recipe: each unit and the exact sources its answer is
    /// shown. Empty: the default neighbourhood recipe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins: Vec<oneiron_store::model_decision::questions::GraphQuestionInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionHead {
    pub version: u32,
    pub paused: bool,
    pub last_refresh: Option<u64>,
    /// A failed refresh holds the question's work until then.
    pub retry_at: Option<u64>,
}
