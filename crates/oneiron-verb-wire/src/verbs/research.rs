//! Moved from `crates/oneiron/src/verbs/research.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::config::CampaignDatasetRef;
use crate::autoreason_campaign::general::Measurement;
use crate::autoreason_campaign::research::SearchEvidence;
use crate::autoreason_campaign::research::budget::ResearchReservationLine;
use crate::research_budget::RsiOverdraftReceipt;
use crate::research_budget::RsiSettlement;
use crate::research_budget::RsiSpendPurpose;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.research.measure_search`: a node's search-split evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSearchWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub evidence: SearchEvidence,
}

/// `vault.research.measure_held_out`: a node's held-out evidence, once.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchHeldOutWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub measurement: Measurement,
    pub receipt_refs: Vec<String>,
}

/// `vault.research.mark_invalid`: a buggy node, kept as evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchInvalidWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

/// Why a branch stops. A stop names the caller, never a field.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResearchPruneCause {
    Dominated { by: EntityId },
    FloorRegression { axis: String },
    GainBelowFloor,
    Stopped,
}

/// `vault.research.prune`: stop exploring a branch for a stated cause.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPruneWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub cause: ResearchPruneCause,
    pub evidence_refs: Vec<String>,
}

/// `vault.research.select`: one selection round.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSelectWire {
    pub root: EntityId,
    /// The external oracle's word that the goal is met. Only the owner
    /// gives it; a model's own success is not an oracle.
    #[serde(default)]
    pub goal_met: bool,
}

/// `vault.research.reserve_confirmation`: a candidate's one sealed shot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchCandidateWire {
    pub root: EntityId,
    pub candidate: EntityId,
}

/// The sealed referee's scores of candidate and incumbent on the released
/// cohort, in `[0, 1]`, under its content pin. The engine derives the win.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRefereeScores {
    pub candidate: f64,
    pub incumbent: f64,
    pub referee_pin: String,
}

/// `vault.research.promote`: settle a candidate on its sealed confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPromoteWire {
    pub root: EntityId,
    pub candidate: EntityId,
    pub referee: ResearchRefereeScores,
    pub sufficiency: SufficiencyInput,
    /// A skill campaign's staged revision proposal; a config campaign none.
    pub skill_proposal: Option<EntityId>,
}

/// `vault.research.reserve_work`: token work on the campaign's RSI share.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkWire {
    pub root: EntityId,
    pub purpose: RsiSpendPurpose,
    pub units: u64,
    /// The node the work is for, if one.
    pub attempt: Option<EntityId>,
}

/// `vault.research.reserve_exploration`: exposure on its own line; it
/// cannot debit token work, and token work cannot debit it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchExplorationWire {
    pub root: EntityId,
    pub units: u64,
    /// The node the exploration is for, if one.
    pub attempt: Option<EntityId>,
}

/// One campaign reservation on the RSI line, with the overdraft receipt a
/// soft share stamped at reservation time, when it took one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchReservationWire {
    pub id: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub line: ResearchReservationLine,
    pub units: u64,
    pub attempt: Option<EntityId>,
    #[schemars(with = "serde_json::Value")]
    pub settlement: Option<RsiSettlement>,
    pub overdraft: Option<RsiOverdraftReceipt>,
    pub reserved_at: u64,
}

/// `vault.research.settle_work`: a reservation's actual spend.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSettleWire {
    pub root: EntityId,
    pub reservation: EntityId,
    pub actual: u64,
}

/// `vault.research.refund_work`: an unspent reservation, returned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRefundWire {
    pub root: EntityId,
    pub reservation: EntityId,
}

/// `vault.research.record_benchmark`: an estimator version's held-out
/// selection benchmark against the DGM formula, once per version.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBenchmarkWire {
    pub estimator_version: String,
    pub benchmark: CampaignDatasetRef,
    pub cases: u64,
    pub dgm_score: f64,
    pub estimator_score: f64,
    pub receipt_refs: Vec<String>,
}

/// Enqueue real child work; record its candidate afterward with `fork` or
/// `weave`. The host binds the campaign's run and ordinary parent attenuation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchChildWire {
    pub root: EntityId,
    pub parent: EntityId,
    pub agent: EntityId,
    pub intent_key: String,
    pub briefing: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchChildReceipt {
    pub root: EntityId,
    pub parent: EntityId,
    pub child: EntityId,
}

/// The complete retained campaign record, not just its active search frontier.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchArchiveWire {
    pub root: EntityId,
}
