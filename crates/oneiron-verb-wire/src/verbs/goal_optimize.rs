//! Moved from `crates/oneiron/src/verbs/goal_optimize.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize as optimize;
use crate::skill_optimize::goal_axes::GoalAxisReport;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeProposeRequest {
    pub skill: EntityId,
    pub expected_version: String,
    /// A real skill_optimize queue attempt; never a caller-chosen cycle label.
    pub attempt_ref: EntityId,
    pub desc: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeProposalReceipt {
    pub skill: EntityId,
    pub proposal: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeProposalRequest {
    pub proposal: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeMeasureRequest {
    pub proposal: EntityId,
    #[serde(default)]
    pub pulls_per_axis: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeMeasurement {
    pub preflight: optimize::SkillEditPreflight,
    /// Absent on a failed floor: no online pull is spent.
    pub report: Option<GoalAxisReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeGoalRequest {
    pub skill: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeGoalView {
    pub goal_id: EntityId,
    pub goal_revision: String,
    pub axes: Vec<optimize::GoalAxisSpec>,
    pub project: Option<EntityId>,
    pub goal_claim: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeGoalBindRequest {
    pub skill: EntityId,
    /// None unbinds; it never edits the project's goal record.
    pub project: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeGoalRevision {
    pub goal_revision: String,
    /// The tradeoff capacity crossings the goal's rules stand over now, if
    /// any; set only by the preference write, never by the goal bind.
    pub tradeoff_capacity_advisory: Option<Vec<TradeoffCapacityAdvisory>>,
}

/// One policy limit a goal's tradeoff rules have crossed (FIX 9123): the
/// capacity advisory the gate logs, carried on the preference write
/// response and the ask view. Advisory only: nothing was refused, and
/// every pending decision keeps its durable ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffCapacityAdvisory {
    /// More authored rules than `max_authored_rules`.
    AuthoredRules { held: u64, limit: u64 },
    /// More learned picks than a finite `max_learned_rules`.
    LearnedRules { held: u64, limit: u64 },
}

impl TradeoffCapacityAdvisory {
    /// The reason code the gate logs for this crossing.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::AuthoredRules { .. } => "gate.tradeoff_authored_rules_over_policy",
            Self::LearnedRules { .. } => "gate.tradeoff_learned_rules_over_policy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizePreferencesSetRequest {
    pub skill: EntityId,
    pub rules: Vec<optimize::TradeoffRule>,
    pub jev_band: Option<oneiron_store::model_decision::DecisionBand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeTradeoffPickRequest {
    pub proposal: EntityId,
    pub question_digest: String,
    /// Both approve and reject learn the responsible person's preference.
    pub choice: optimize::TradeoffChoice,
}

/// The owner's decision on one exact pending tradeoff (FIX 9125): the
/// proposal, the pending verdict the ask names, the bounded decision
/// evidence reference, and approve or reject.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeTradeoffResolveRequest {
    pub proposal: EntityId,
    pub pending: EntityId,
    pub evidence: String,
    pub choice: optimize::TradeoffChoice,
}
