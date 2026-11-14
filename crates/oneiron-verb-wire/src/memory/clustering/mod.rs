//! Moved from `crates/oneiron/src/memory/clustering/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterSurvivorship {
    #[default]
    ReadThrough,
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
