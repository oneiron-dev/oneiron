//! Typed clustering diagnostics and the merge/split judgments they may inform.
//! Cohorts are advisory. Only the existing identity-topology doors change truth.

use serde::{Deserialize, Serialize};

/// A stored claim and the embedding the caller wants compared. The partition
/// descriptors are read from the claim, never accepted from the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterClaimInput {
    pub claim_ref: String,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterRequest {
    pub claims: Vec<ClusterClaimInput>,
    /// None uses the engine's pinned complete-link cohesion threshold.
    #[serde(default)]
    pub cohesion_threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterPartition {
    /// Entity ref, or edge:<source-ref>:<kind-byte>:<target-ref>; each ref is
    /// the short ref the vault keeps for it, else its full hex.
    pub subject_ref: String,
    pub predicate_root: String,
    pub world_ref: Option<String>,
    pub facet_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterCohort {
    pub cohort_id: [u8; 32],
    pub partition: ClusterPartition,
    pub member_refs: Vec<String>,
    pub cohesion: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterProposal {
    pub cohorts: Vec<ClusterCohort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterEvidence {
    /// Entity refs backing the judgment, including any cohort members: full
    /// 32-hex ids or short refs in, short refs (else hex) out.
    pub refs: Vec<String>,
    /// Records the agent's judgment, including an override of cosine grouping.
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterSurvivorship {
    #[default]
    ReadThrough,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterMerge {
    /// Full 32-hex ids or short refs in, short refs (else hex) out. Claim
    /// subjects are never rewritten.
    pub sources: Vec<String>,
    pub survivor: String,
    pub evidence: ClusterEvidence,
    #[serde(default)]
    pub survivorship_plan: ClusterSurvivorship,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClusterReassignmentTarget {
    Head { entity_ref: String },
    Residue,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterReassignment {
    /// Claim ref, or edge:<source-ref>:<kind-byte>:<target-ref>; a ref is a
    /// full 32-hex id or a short ref.
    pub item: String,
    pub target: ClusterReassignmentTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterSplit {
    pub entity: String,
    /// Empty is the canon's retire-without-successor split.
    pub heads: Vec<String>,
    pub reassignment_map: Vec<ClusterReassignment>,
    pub evidence: ClusterEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterOperation {
    Merge(ClusterMerge),
    Split(ClusterSplit),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterProposeRequest {
    pub operation: ClusterOperation,
    /// An agent's own live Grant naming topology_seal; owners omit it.
    #[serde(default)]
    pub grant_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterMergeRequest {
    pub merge: ClusterMerge,
    #[serde(default)]
    pub grant_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterSplitRequest {
    pub split: ClusterSplit,
    #[serde(default)]
    pub grant_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClusterRuling {
    Approve,
    AmendThenApprove { operation: ClusterOperation },
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterResolveRequest {
    pub proposal_ref: String,
    /// Revision returned by proposal inspection. Compared in the write txn.
    pub seen: [u8; 32],
    pub ruling: ClusterRuling,
    #[serde(default)]
    pub grant_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterProposalRequest {
    pub proposal_ref: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterTopologyOutcome {
    Applied,
    Proposed,
    ApprovedUntouched,
    ApprovedAmended,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterTopologyReceipt {
    /// Durable topology event; a resolution is itself its receipt handle.
    pub receipt_ref: String,
    pub proposal_ref: Option<String>,
    pub outcome: ClusterTopologyOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterProposalView {
    pub proposal_ref: String,
    pub operation: ClusterOperation,
    pub seen: [u8; 32],
    pub resolution: Option<ClusterTopologyOutcome>,
    pub moot: bool,
}

mod doors;
mod operation;
