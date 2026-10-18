use serde::{Deserialize, Serialize};
use crate::EntityId;
use crate::critic::{CritiqueSeverity, CritiqueVerdict};
use crate::learning::LearningCell;
use crate::repo_mutation::proposal::RepoProposalStatus;
use crate::repo_mutation::proposal::settlement::{RepoProposalDecision, RepoProposalSettlement};
use super::CodeProposalSubmitRequest;

/// The engine stages both stored proposals at their shared retained base
/// and computes the overlap. No commit, conflict path or verdict is supplied.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeConflictRecordRequest {
    pub repo: EntityId,
    pub branch_subject: EntityId,
    pub branch: String,
    pub left_proposal: EntityId,
    pub right_proposal: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeConflictViewRequest {
    pub branch_subject: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeConflictView {
    pub open: bool,
    pub conflict: EntityId,
    pub branch_subject: EntityId,
    pub repo_ref: String,
    pub branch: String,
    pub base_tree: String,
    pub left_tree: String,
    pub right_tree: String,
    pub paths: Vec<String>,
    /// Original proposal refs, in left/right order. Empty for an admin conflict.
    pub proposals: Vec<EntityId>,
    pub task: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeConflictResolutionView {
    pub resolution: EntityId,
    pub conflict: EntityId,
    pub task: EntityId,
    pub resolved_tree: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeConflictHistory {
    pub conflicts: Vec<CodeConflictView>,
    pub resolved: Vec<CodeConflictResolutionView>,
}

/// A resolution is another Proposed file change, never a live edit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalResolveRequest {
    pub change: CodeProposalSubmitRequest,
    pub branch_subject: EntityId,
    pub conflict: EntityId,
    pub branch: String,
}

/// An owner's own immutable opinion for a lens, not a contract-check receipt.
/// The door binds candidate, critic identity, class and timestamp itself.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalReviewRequest {
    pub proposal: EntityId,
    pub artifact_id: String,
    pub run_id: String,
    pub attempt: EntityId,
    pub lens_id: String,
    pub domain: String,
    pub model_id: String,
    pub model_revision: Option<String>,
    pub calibration: LearningCell,
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    pub hard_check_passed: Option<bool>,
    pub evidence: Vec<EntityId>,
    pub suggested_edit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalSettleRequest {
    pub proposal: EntityId,
    pub decision: RepoProposalDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalSettlementRequest {
    pub proposal: EntityId,
}

/// A review decision and its durable execution lineage. Approved does not mean
/// applied: only the tested merge queue advances the repository's head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeProposalSettlementView {
    pub proposal: EntityId,
    pub status: RepoProposalStatus,
    pub reviews: usize,
    pub settlement: Option<RepoProposalSettlement>,
    pub conflict: Option<EntityId>,
    pub task: Option<EntityId>,
    pub parents: Vec<EntityId>,
    pub mutation_seq: Option<u64>,
    pub resolution: Option<EntityId>,
}
