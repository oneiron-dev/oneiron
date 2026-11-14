//! Moved from `crates/oneiron/src/verbs/skill_execution.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackReceiptRequest {
    pub attempt_receipt: String,
}

/// An owner's external verdict. Neither the executor nor the judge, actor,
/// loaded versions or contribution checks can be supplied by this request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackOutcomeRequest {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub succeeded: bool,
    pub axis: String,
    pub at: u64,
    #[serde(default)]
    pub goal_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackCreditRequest {
    pub receipt_id: String,
}
