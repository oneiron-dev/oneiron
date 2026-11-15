//! Moved from `crates/oneiron/src/skill_hub/shared_gate.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::claim_refinement_control::SharedSkillDelta;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_wake_contract::llm::decision::types::TypedDecision;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSkillMergeReceipt {
    pub receipt_id: String,
    pub delta: SharedSkillDelta,
    pub consent_digest: String,
    pub binding: String,
    pub useful_upstream: bool,
    pub resident: String,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    pub before: Option<f32>,
    pub after: Option<f32>,
    pub held_out_digest: String,
    pub accepted: bool,
    pub judge_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displaced_by_revision: Option<String>,
    pub at: u64,
}
