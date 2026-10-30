//! Typed identity-topology calls over the engine's append-only op family.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeKind;
use crate::identity_topology as topology;
use crate::memory::{MemoryError, MemoryResult};

mod ops;
pub use ops::*;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvidence {
    pub refs: Vec<EntityId>,
    pub rationale: String,
}

impl From<IdentityEvidence> for topology::IdentityOpEvidence {
    fn from(value: IdentityEvidence) -> Self {
        Self {
            refs: value.refs,
            rationale: value.rationale,
        }
    }
}

impl From<topology::IdentityOpEvidence> for IdentityEvidence {
    fn from(value: topology::IdentityOpEvidence) -> Self {
        Self {
            refs: value.refs,
            rationale: value.rationale,
        }
    }
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
pub struct IdentityReassignment {
    pub item: IdentityReassignmentItem,
    pub target: IdentityReassignmentTarget,
}

impl IdentityReassignment {
    fn into_engine(self) -> MemoryResult<topology::ReassignmentEntry> {
        let item = match self.item {
            IdentityReassignmentItem::Claim { claim } => ClaimSubject::Entity(claim),
            IdentityReassignmentItem::Edge {
                source,
                edge_kind,
                target,
            } => ClaimSubject::Edge {
                source,
                kind: EdgeKind::from_name(&edge_kind)
                    .ok_or_else(|| MemoryError::bad_request("unknown reassignment edge_kind"))?,
                target,
            },
        };
        let target = match self.target {
            IdentityReassignmentTarget::Head { head } => topology::ReassignmentTarget::Head(head),
            IdentityReassignmentTarget::Facet { index } => {
                topology::ReassignmentTarget::Facet { index }
            }
            IdentityReassignmentTarget::Residue => topology::ReassignmentTarget::Residue,
        };
        Ok(topology::ReassignmentEntry { item, target })
    }
}

impl From<topology::ReassignmentEntry> for IdentityReassignment {
    fn from(value: topology::ReassignmentEntry) -> Self {
        let item = match value.item {
            ClaimSubject::Entity(claim) => IdentityReassignmentItem::Claim { claim },
            ClaimSubject::Edge {
                source,
                kind,
                target,
            } => IdentityReassignmentItem::Edge {
                source,
                edge_kind: kind.name().to_owned(),
                target,
            },
        };
        let target = match value.target {
            topology::ReassignmentTarget::Head(head) => IdentityReassignmentTarget::Head { head },
            topology::ReassignmentTarget::Facet { index } => {
                IdentityReassignmentTarget::Facet { index }
            }
            topology::ReassignmentTarget::Residue => IdentityReassignmentTarget::Residue,
        };
        Self { item, target }
    }
}

fn map_into_engine(entries: Vec<IdentityReassignment>) -> MemoryResult<topology::ReassignmentMap> {
    Ok(topology::ReassignmentMap {
        entries: entries
            .into_iter()
            .map(IdentityReassignment::into_engine)
            .collect::<MemoryResult<_>>()?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityMergeRequest {
    pub sources: Vec<EntityId>,
    pub survivor: EntityId,
    pub evidence: IdentityEvidence,
    pub survivorship_plan: IdentitySurvivorshipPlan,
}

impl IdentityMergeRequest {
    fn into_engine(self) -> topology::MergeOp {
        let IdentitySurvivorshipPlan::ReadThrough = self.survivorship_plan;
        topology::MergeOp {
            sources: self.sources,
            survivor: self.survivor,
            evidence: self.evidence.into(),
            survivorship_plan: topology::SurvivorshipPlan::ReadThrough,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentitySplitRequest {
    pub entity: EntityId,
    /// Empty deliberately retires the entity without a successor.
    pub heads: Vec<EntityId>,
    pub reassignment_map: Vec<IdentityReassignment>,
    pub evidence: IdentityEvidence,
}

impl IdentitySplitRequest {
    fn into_engine(self) -> MemoryResult<topology::SplitOp> {
        Ok(topology::SplitOp {
            entity: self.entity,
            heads: self.heads,
            reassignment: map_into_engine(self.reassignment_map)?,
            evidence: self.evidence.into(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityFacetSpec {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityFacetRequest {
    pub entity: EntityId,
    pub facets: Vec<IdentityFacetSpec>,
    pub reassignment_map: Vec<IdentityReassignment>,
    pub evidence: IdentityEvidence,
}

impl IdentityFacetRequest {
    fn into_engine(self) -> MemoryResult<topology::FacetOp> {
        Ok(topology::FacetOp {
            entity: self.entity,
            facets: self
                .facets
                .into_iter()
                .map(|spec| topology::FacetSpec { label: spec.label })
                .collect(),
            reassignment: map_into_engine(self.reassignment_map)?,
            evidence: self.evidence.into(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssertDistinctRequest {
    pub a: EntityId,
    pub b: EntityId,
    pub reason: String,
}

/// Only merge and split have resolvable parked events in the engine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "op",
    content = "spec",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum IdentityProposedOp {
    Merge(IdentityMergeRequest),
    Split(IdentitySplitRequest),
}

impl IdentityProposedOp {
    fn into_engine(self) -> MemoryResult<topology::IdentityTopologyOp> {
        Ok(match self {
            Self::Merge(input) => topology::IdentityTopologyOp::Merge(input.into_engine()),
            Self::Split(input) => topology::IdentityTopologyOp::Split(input.into_engine()?),
        })
    }
}

/// Park an explicitly nominated candidate; this does not run a matcher.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityProposeRequest {
    pub operation: IdentityProposedOp,
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

/// An amendment narrows the reviewed topology. Its evidence remains the proposal's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityAmendment {
    Merge {
        sources: Vec<EntityId>,
        survivor: EntityId,
        survivorship_plan: IdentitySurvivorshipPlan,
    },
    Split {
        entity: EntityId,
        heads: Vec<EntityId>,
        reassignment_map: Vec<IdentityReassignment>,
    },
}

impl IdentityAmendment {
    fn into_engine(self) -> MemoryResult<topology::IdentityTopologyOp> {
        let evidence = topology::IdentityOpEvidence::default();
        Ok(match self {
            Self::Merge {
                sources,
                survivor,
                survivorship_plan,
            } => {
                let IdentitySurvivorshipPlan::ReadThrough = survivorship_plan;
                topology::IdentityTopologyOp::Merge(topology::MergeOp {
                    sources,
                    survivor,
                    evidence,
                    survivorship_plan: topology::SurvivorshipPlan::ReadThrough,
                })
            }
            Self::Split {
                entity,
                heads,
                reassignment_map,
            } => topology::IdentityTopologyOp::Split(topology::SplitOp {
                entity,
                heads,
                evidence,
                reassignment: map_into_engine(reassignment_map)?,
            }),
        })
    }
}

/// All three canon rulings are carried by one typed resolution door.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "ruling", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityProposalRuling {
    Approve,
    AmendThenApprove { operation: IdentityAmendment },
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityProposalResolveRequest {
    pub proposal: EntityId,
    #[serde(with = "crate::task_verb::hex32")]
    #[schemars(with = "String")]
    pub seen: [u8; 32],
    pub decision: IdentityProposalRuling,
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

impl From<topology::ProposalOutcome> for IdentityProposalOutcome {
    fn from(value: topology::ProposalOutcome) -> Self {
        match value {
            topology::ProposalOutcome::ApprovedUntouched => Self::ApprovedUntouched,
            topology::ProposalOutcome::ApprovedAmended => Self::ApprovedAmended,
            topology::ProposalOutcome::Rejected => Self::Rejected,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IdentityEventAction {
    Merge {
        sources: Vec<EntityId>,
        survivor: EntityId,
    },
    Split {
        entity: EntityId,
        heads: Vec<EntityId>,
        reassignment_map: Vec<IdentityReassignment>,
        applied_assigned: u64,
        applied_residue: u64,
    },
    Facet {
        entity: EntityId,
        facets: Vec<EntityId>,
        reassignment_map: Vec<IdentityReassignment>,
        applied_assigned: u64,
        applied_residue: u64,
        forked: Vec<EntityId>,
    },
    AssertDistinct {
        a: EntityId,
        b: EntityId,
        claim: EntityId,
    },
    Undo {
        target: EntityId,
    },
    ProposalResolution {
        proposal: EntityId,
        outcome: IdentityProposalOutcome,
        op_kind: String,
        target_class: String,
        proposer: String,
        amendment: Option<IdentityAmendment>,
    },
    ProposalCancellation {
        proposal: EntityId,
        participant: EntityId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityTopologyReceipt {
    pub event: EntityId,
    pub seq: u64,
    pub at: u64,
    pub actor: Option<EntityId>,
    pub source: ClaimSource,
    pub approval: ClaimApprovalStatus,
    pub confidence: f32,
    pub evidence: Option<IdentityEvidence>,
    pub action: IdentityEventAction,
    #[serde(with = "crate::task_verb::hex32")]
    #[schemars(with = "String")]
    pub seen: [u8; 32],
}

impl IdentityTopologyReceipt {
    pub fn rows(&self) -> Vec<EntityId> {
        let mut rows = vec![self.event];
        rows.extend(self.actor);
        if let Some(evidence) = &self.evidence {
            rows.extend(&evidence.refs);
        }
        match &self.action {
            IdentityEventAction::Merge { sources, survivor } => {
                rows.extend(sources);
                rows.push(*survivor);
            }
            IdentityEventAction::Split {
                entity,
                heads,
                reassignment_map,
                ..
            } => {
                rows.push(*entity);
                rows.extend(heads);
                map_rows(reassignment_map, &mut rows);
            }
            IdentityEventAction::Facet {
                entity,
                facets,
                reassignment_map,
                forked,
                ..
            } => {
                rows.push(*entity);
                rows.extend(facets);
                rows.extend(forked);
                map_rows(reassignment_map, &mut rows);
            }
            IdentityEventAction::AssertDistinct { a, b, claim } => rows.extend([*a, *b, *claim]),
            IdentityEventAction::Undo { target } => rows.push(*target),
            IdentityEventAction::ProposalResolution { proposal, .. } => rows.push(*proposal),
            IdentityEventAction::ProposalCancellation {
                proposal,
                participant,
            } => rows.extend([*proposal, *participant]),
        }
        rows
    }
}

fn map_rows(entries: &[IdentityReassignment], rows: &mut Vec<EntityId>) {
    for entry in entries {
        match &entry.item {
            IdentityReassignmentItem::Claim { claim } => rows.push(*claim),
            IdentityReassignmentItem::Edge { source, target, .. } => {
                rows.extend([*source, *target])
            }
        }
        if let IdentityReassignmentTarget::Head { head } = &entry.target {
            rows.push(*head);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum IdentityTopologyResult {
    Applied {
        receipt: IdentityTopologyReceipt,
        transitions: Vec<IdentityTransition>,
    },
    Parked {
        receipt: IdentityTopologyReceipt,
    },
    Noop,
}

impl IdentityTopologyResult {
    pub fn rows(&self) -> Vec<EntityId> {
        match self {
            Self::Applied { receipt, .. } | Self::Parked { receipt } => receipt.rows(),
            Self::Noop => Vec::new(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityProposalResolutionResult {
    pub receipt: IdentityTopologyReceipt,
    /// The approved op's own event, including its undo revision; absent on reject.
    pub applied: Option<IdentityTopologyReceipt>,
}

impl IdentityProposalResolutionResult {
    pub fn rows(&self) -> Vec<EntityId> {
        let mut rows = self.receipt.rows();
        if let Some(applied) = &self.applied {
            rows.extend(applied.rows());
        }
        rows
    }
}
