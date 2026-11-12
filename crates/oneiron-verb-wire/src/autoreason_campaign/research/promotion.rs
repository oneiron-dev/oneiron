//! Moved from `crates/oneiron/src/autoreason_campaign/research/promotion.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::general::DecideRules;
use crate::autoreason_campaign::general::Measurement;
use crate::autoreason_campaign::general::MetricRole;
use crate::autoreason_campaign::general::Verdict;
use crate::autoreason_campaign::research::CandidateRef;
use crate::autoreason_campaign::research::ResearchGoalPin;
use crate::autoreason_campaign::research::ResearchTarget;
use crate::autoreason_campaign::research::budget::ResearchBudgetRead;
use crate::autoreason_campaign::research::invalid;
use crate::skill_optimize::eval_set::cohort::EvalExposureKind;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// The held-out decision, as decided by the campaign's dominance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeldOutCall {
    Promote,
    Reject,
    EscalateTradeoff,
}

/// The one sealed confirmation of a candidate. `exposure` is empty when the
/// shot was consumed but the release never completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationReceipt {
    pub cohort: EntityId,
    pub consumed_at: u64,
    pub exposure: Option<EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDisposition {
    /// The candidate is the campaign's new incumbent.
    Promoted,
    /// The sealed referee did not see a strict win.
    LostSealed,
    /// The sufficiency card did not read not-worse.
    HeldInsufficient,
    /// The skill gate's own verdict did not accept the revision.
    HeldGate,
}
