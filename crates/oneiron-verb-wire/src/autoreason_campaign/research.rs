//! Moved from `crates/oneiron/src/autoreason_campaign/research.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::config::CampaignDatasetRef;
use crate::autoreason_campaign::general::Measurement;
use crate::autoreason_campaign::general::MetricRole;
pub use crate::autoreason_campaign::research::budget::ResearchBudgetRead;
pub use crate::autoreason_campaign::research::budget::ResearchReservationLine;
pub use crate::autoreason_campaign::research::estimator::BranchBelief;
pub use crate::autoreason_campaign::research::estimator::PriorRung;
pub use crate::autoreason_campaign::research::estimator::PriorSeed;
pub use crate::autoreason_campaign::research::estimator::SelectionRanking;
pub use crate::autoreason_campaign::research::promotion::ConfirmationReceipt;
pub use crate::autoreason_campaign::research::promotion::HeldOutCall;
pub use crate::autoreason_campaign::research::promotion::PromotionDisposition;
use crate::skill_optimize::gate::goal_axis::GoalAxisKind;
use crate::skill_optimize::gate::goal_axis::GoalAxisSpec;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::limit_ask::EngineLimit;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub const MAX_REF_BYTES: usize = 256;

/// What a campaign improves, and so which ruler it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTarget {
    /// A governed skill. Its authenticated goal is the ruler, and a promotion
    /// stands only on the skill gate's own accepted verdict.
    Skill { skill: EntityId },
    /// A workflow configuration (an authoring strategy, a prompt, a knob
    /// set). The campaign's pinned metric set is the ruler.
    Config { subject: String },
}

/// The goal record a skill campaign was bound under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchGoalPin {
    pub goal_id: EntityId,
    pub revision: String,
    /// The joined project and its goal claim, when the goal has one.
    pub project: Option<(EntityId, EntityId)>,
}

/// A candidate configuration the sandbox wrote: a content reference and the
/// digest of its bytes. The loop never reads or runs the config itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub config_ref: String,
    pub config_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentKind {
    /// The incumbent the campaign starts from.
    Root,
    /// A child variation of one measured parent.
    Variation,
    /// A repair child of a buggy (invalid) parent.
    Debug,
    /// A crossover of several parents with a common ancestor.
    Weave,
}

/// Search-split evidence for one node: the selection signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchEvidence {
    /// Scores on the campaign's search split under its pinned metric set.
    pub measurement: Measurement,
    pub confirmed_hits: f64,
    /// The attribution check's score in `[0, 1]`; zero earns no reward.
    pub attribution: f64,
    pub hop_cost: f64,
    /// The estimator's predicted gain from trying this branch next.
    pub expected_gain: f64,
    /// The versioned estimator (DGM floor, Beta belief or information gain)
    /// that produced `expected_gain`.
    pub estimator_version: String,
    /// The reliability, in `[0, 1]`, of the knobs this node's change touched:
    /// its belief's prior mean is pulled halfway toward it.
    pub knob_reliability: Option<f64>,
    pub receipt_refs: Vec<String>,
}

impl SearchEvidence {
    /// Confirmed fact hits times the attribution score, less hop cost.
    #[must_use]
    pub fn reward(&self) -> f64 {
        self.confirmed_hits * self.attribution - self.hop_cost
    }
}

/// Held-out evidence for one node, recorded once and read only by promotion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeldOutEvidence {
    pub measurement: Measurement,
    pub receipt_refs: Vec<String>,
    pub recorded_at: u64,
}

/// A buggy node: kept as evidence, eligible for debug children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvalidReceipt {
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// Why a branch stopped being explored. There is deliberately no surprise
/// variant: surprise only picks the next experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PruneReason {
    /// Another measured branch beats it on search reward.
    Dominated { by: AttemptId },
    /// A floor axis regressed on its search measurement.
    FloorRegression { axis: String },
    /// Its expected gain stayed below the policy floor.
    GainBelowFloor,
    /// The owner or the responsible role stopped it.
    Stopped { by: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PruneReceipt {
    pub reason: PruneReason,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// The lineage receipt of a weave: its parents are on the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveReceipt {
    pub common_ancestor: AttemptId,
    pub validation_overlap: f64,
    /// The claim the weave landed as, through the gate.
    pub claim: EntityId,
    /// The claim's approval when the weave was recorded: proposed, unless an
    /// owner grant let the gate approve it.
    pub claim_approval: ClaimApprovalStatus,
    /// The gate's recorded decision on the claim's landing, by hex id: the
    /// claim door's record of its writer's write.
    pub gate_decision: String,
    pub at: u64,
}

/// One experiment: an existing attempt annotated with its campaign record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperimentNode {
    pub attempt: AttemptId,
    pub kind: ExperimentKind,
    /// One parent, every parent of a weave, none for the root.
    pub parents: Vec<AttemptId>,
    pub candidate: CandidateRef,
    pub search: Option<SearchEvidence>,
    pub held_out: Option<HeldOutEvidence>,
    pub invalid: Option<InvalidReceipt>,
    pub weave: Option<WeaveReceipt>,
    pub pruned: Option<PruneReceipt>,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForkKind {
    Variation,
    Debug,
}

/// What one selection round chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchStep {
    Fork { parent: AttemptId, stagnation: bool },
    PausedBudget,
    StoppedPlateau,
    EscalatePlateau,
    StoppedOracle,
}

/// The evidence one branch contributed to a round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BranchSnapshot {
    pub attempt: AttemptId,
    pub reward: f64,
    pub expected_gain: f64,
    pub estimator_version: String,
    /// The engine estimator's belief, once the incumbent is measured.
    pub belief: Option<BranchBelief>,
}

/// The durable receipt of one selection round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionReceipt {
    pub root: AttemptId,
    pub round: u64,
    /// The incumbent whose search reward the round's beliefs beat against.
    pub incumbent: AttemptId,
    pub step: ResearchStep,
    pub branches: Vec<BranchSnapshot>,
    pub best_quality: f64,
    pub best_gain: f64,
    pub ranking: SelectionRanking,
    pub policy_digest: String,
    pub budget_available: bool,
    pub oracle_goal_met: bool,
    pub at: u64,
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

pub fn bounded(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_REF_BYTES {
        return Err(invalid(what));
    }
    Ok(())
}

impl CandidateRef {
    fn validate(&self) -> Result<()> {
        bounded(&self.config_ref, "a candidate names a bounded config ref")?;
        if self.config_sha256.len() != 64
            || !self
                .config_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("a candidate config is pinned by its sha256"));
        }
        Ok(())
    }
}
pub mod budget;
pub mod estimator;
pub mod promotion;
