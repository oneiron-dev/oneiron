//! Moved from `crates/oneiron/src/verbs/identity_topology.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvidence {
    pub refs: Vec<EntityId>,
    pub rationale: String,
}

/// Read-through is the only ratified survivorship plan: subjects never move.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySurvivorshipPlan {
    ReadThrough,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityReassignmentItem {
    Claim {
        claim: EntityId,
    },
    /// Recorded in the ledger; the engine currently applies claim assignments only.
    Edge {
        source: EntityId,
        edge_kind: String,
        target: EntityId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityReassignmentTarget {
    Head { head: EntityId },
    Facet { index: u32 },
    Residue,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityFacetSpec {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssertDistinctRequest {
    pub a: EntityId,
    pub b: EntityId,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityEntityRequest {
    pub entity: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityEventRequest {
    pub event: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityUndoRequest {
    pub event: EntityId,
    #[serde(with = "crate::task_verb::hex32")]
    #[schemars(with = "String")]
    pub seen: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityLifecycle {
    Active,
    Merged,
    Split,
}

impl From<topology::EntityLifecycleState> for IdentityLifecycle {
    fn from(value: topology::EntityLifecycleState) -> Self {
        match value {
            topology::EntityLifecycleState::Active => Self::Active,
            topology::EntityLifecycleState::Merged => Self::Merged,
            topology::EntityLifecycleState::Split => Self::Split,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityTransition {
    pub entity: EntityId,
    pub state: IdentityLifecycle,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProposalOutcome {
    ApprovedUntouched,
    ApprovedAmended,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityResolution {
    pub entity: EntityId,
    pub state: IdentityLifecycle,
    pub heads: Vec<EntityId>,
    pub merged_into: Vec<EntityId>,
    pub split_into: Vec<EntityId>,
    pub facets: Vec<EntityId>,
    pub assigned_claims: Vec<EntityId>,
    pub ambiguous_residue: Vec<EntityId>,
    pub remaining_claims: Vec<EntityId>,
}

impl IdentityResolution {
    pub fn rows(&self) -> Vec<EntityId> {
        std::iter::once(self.entity)
            .chain(self.heads.iter().copied())
            .chain(self.merged_into.iter().copied())
            .chain(self.split_into.iter().copied())
            .chain(self.facets.iter().copied())
            .chain(self.assigned_claims.iter().copied())
            .chain(self.ambiguous_residue.iter().copied())
            .chain(self.remaining_claims.iter().copied())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityPairRequest {
    pub a: EntityId,
    pub b: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityPairProposals {
    pub a: EntityId,
    pub b: EntityId,
    pub proposals: Vec<EntityId>,
    pub distinct_claims: Vec<EntityId>,
}

impl IdentityPairProposals {
    pub fn rows(&self) -> Vec<EntityId> {
        [self.a, self.b]
            .into_iter()
            .chain(self.proposals.iter().copied())
            .chain(self.distinct_claims.iter().copied())
            .collect()
    }
}
