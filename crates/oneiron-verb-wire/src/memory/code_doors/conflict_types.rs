//! Moved from `crates/oneiron/src/memory/code_doors/conflict_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::code_doors::types::CodeProposalSubmitRequest;
use crate::repo_mutation::proposal::settlement::RepoProposalDecision;
use crate::repo_mutation::proposal::settlement::RepoProposalSettlement;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::repo_proposal_record::RepoProposalStatus;
use serde::Deserialize;
use serde::Serialize;

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
    /// The reconciliation TASK; `None` while the conflict is held.
    pub task: Option<EntityId>,
    /// Why the open conflict's reconciliation waits, when no TASK was
    /// minted: its creator's ceiling is below Auto (FIX 8830).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
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

/// A fresh review of an approved conflict resolution, under the current
/// owner's proof and the ordinary resolution's current conflict checks.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalResolveRereviewRequest {
    pub original: EntityId,
    pub change: CodeProposalResolveRequest,
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
    /// Its `repo.proposal_admission` receipt (FIX 4338); absent for a
    /// proposal stored before submission receipts were kept.
    pub admission_receipt: Option<EntityId>,
    /// The `repo.proposal_attempt_completion` receipt of each execution
    /// attempt, in mutation seq order: applied or failed for that attempt
    /// alone, never queue green.
    pub attempt_receipts: Vec<EntityId>,
    /// The failed proposal this one replaces and its link (FIX 4364).
    pub repair_of: Option<CodeProposalReplacementView>,
    /// The replacement submitted for this proposal, once it failed, and
    /// its link. Read the replacement's own status and receipts apart: the
    /// link never says this proposal was repaired or green.
    pub replaced_by: Option<CodeProposalReplacementView>,
}

/// One stored repair link (FIX 4364): a failed proposal and the fresh
/// proposal submitted to replace it, on its own retained base.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeProposalReplacementView {
    /// The `repo.proposal_replacement` CLAIM.
    pub receipt: EntityId,
    /// The failed proposal.
    pub source: EntityId,
    /// The replacement proposal.
    pub replacement: EntityId,
    /// The replacement's retained pre-action fork hash: 64 lower-hex
    /// BLAKE3, not a git commit.
    pub replacement_base: String,
}
