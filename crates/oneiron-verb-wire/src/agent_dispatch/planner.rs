//! Moved from `crates/oneiron/src/agent_dispatch/planner.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::DecisionRung;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// One rung of the planner ladder. Cheap rungs handle the easy cases; the
/// strong rung is reserved for xhigh/max care or big plans.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PlannerRung {
    /// A cheap classifier: the deterministic floor plus, at most, a local
    /// model sorting the need.
    CheapClassifier,
    /// A small thinking model weighs the top shapes.
    SmallThinking,
    /// A strong model plans (xhigh/max care, or a big plan).
    Strong,
}

impl PlannerRung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheapClassifier => "cheap_classifier",
            Self::SmallThinking => "small_thinking",
            Self::Strong => "strong",
        }
    }

    /// The decision-ladder rung this planner rung rides.
    #[must_use]
    pub const fn decision_rung(self) -> DecisionRung {
        match self {
            Self::CheapClassifier => DecisionRung::Local,
            Self::SmallThinking => DecisionRung::Escalation,
            Self::Strong => DecisionRung::Big,
        }
    }
}

/// One skill revision a plan read or ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRevisionRef {
    pub skill: EntityId,
    pub version: String,
}
