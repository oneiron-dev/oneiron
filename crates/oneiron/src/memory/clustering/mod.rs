//! Typed clustering diagnostics and the merge/split judgments they may inform.
//! Cohorts are advisory. Only the existing identity-topology doors change truth.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::clustering::{
    ClusterClaimInput, ClusterCohort, ClusterPartition, ClusterProposal, ClusterProposalRequest,
    ClusterReassignment, ClusterReassignmentTarget, ClusterRequest, ClusterSurvivorship,
    ClusterTopologyOutcome, ClusterTopologyReceipt,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterEvidence {
    /// Entity refs backing the judgment, including any cohort members: full
    /// 32-hex ids or short refs in, short refs (else hex) out.
    pub refs: Vec<String>,
    /// Records the agent's judgment, including an override of cosine grouping.
    pub rationale: String,
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
pub struct ClusterProposalView {
    pub proposal_ref: String,
    pub operation: ClusterOperation,
    pub seen: [u8; 32],
    pub resolution: Option<ClusterTopologyOutcome>,
    pub moot: bool,
}

mod doors;
mod operation;
