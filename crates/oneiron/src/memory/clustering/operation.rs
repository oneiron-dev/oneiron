//! Wire projection only. Topology validation and effects stay in identity_topology.

use super::*;
use crate::EntityId;
use crate::claim::ClaimSubject;
use crate::edge::EdgeKind;
use crate::identity_topology::{
    IdentityOpEvidence, IdentityTopologyOp, MergeOp, ReassignmentEntry, ReassignmentMap,
    ReassignmentTarget, SplitOp, SurvivorshipPlan,
};
use crate::memory::{MemoryError, MemoryResult};

pub(super) fn id(text: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(text)
        .map_err(|_| MemoryError::bad_request("topology refs are full 32-hex entity ids"))
}

pub(super) fn subject(text: &str) -> MemoryResult<ClaimSubject> {
    let Some(edge) = text.strip_prefix("edge:") else {
        return Ok(ClaimSubject::Entity(id(text)?));
    };
    let fields: Vec<_> = edge.split(':').collect();
    if let [source, kind, target] = fields.as_slice() {
        let kind = kind
            .parse::<u8>()
            .ok()
            .and_then(EdgeKind::try_from_u8)
            .ok_or_else(|| MemoryError::bad_request("edge item needs a known edge-kind byte"))?;
        return Ok(ClaimSubject::Edge {
            source: id(source)?,
            kind,
            target: id(target)?,
        });
    }
    Err(MemoryError::bad_request(
        "edge item is edge:<source-hex>:<kind-byte>:<target-hex>",
    ))
}

impl ClusterEvidence {
    fn into_engine(&self) -> MemoryResult<IdentityOpEvidence> {
        Ok(IdentityOpEvidence {
            refs: self
                .refs
                .iter()
                .map(|reference| id(reference))
                .collect::<MemoryResult<_>>()?,
            rationale: self.rationale.clone(),
        })
    }

    fn from_engine(evidence: &IdentityOpEvidence) -> Self {
        Self {
            refs: evidence.refs.iter().map(EntityId::to_hex).collect(),
            rationale: evidence.rationale.clone(),
        }
    }
}

impl ClusterOperation {
    pub(super) fn into_engine(&self) -> MemoryResult<IdentityTopologyOp> {
        match self {
            Self::Merge(merge) => Ok(IdentityTopologyOp::Merge(MergeOp {
                sources: merge
                    .sources
                    .iter()
                    .map(|reference| id(reference))
                    .collect::<MemoryResult<_>>()?,
                survivor: id(&merge.survivor)?,
                evidence: merge.evidence.into_engine()?,
                survivorship_plan: match merge.survivorship_plan {
                    ClusterSurvivorship::ReadThrough => SurvivorshipPlan::ReadThrough,
                },
            })),
            Self::Split(split) => Ok(IdentityTopologyOp::Split(SplitOp {
                entity: id(&split.entity)?,
                heads: split
                    .heads
                    .iter()
                    .map(|reference| id(reference))
                    .collect::<MemoryResult<_>>()?,
                reassignment: ReassignmentMap {
                    entries: split
                        .reassignment_map
                        .iter()
                        .map(|entry| {
                            Ok(ReassignmentEntry {
                                item: subject(&entry.item)?,
                                target: match &entry.target {
                                    ClusterReassignmentTarget::Head { entity_ref } => {
                                        ReassignmentTarget::Head(id(entity_ref)?)
                                    }
                                    ClusterReassignmentTarget::Residue => {
                                        ReassignmentTarget::Residue
                                    }
                                },
                            })
                        })
                        .collect::<MemoryResult<_>>()?,
                },
                evidence: split.evidence.into_engine()?,
            })),
        }
    }

    pub(super) fn from_engine(op: &IdentityTopologyOp) -> MemoryResult<Self> {
        match op {
            IdentityTopologyOp::Merge(merge) => Ok(Self::Merge(ClusterMerge {
                sources: merge.sources.iter().map(EntityId::to_hex).collect(),
                survivor: merge.survivor.to_hex(),
                evidence: ClusterEvidence::from_engine(&merge.evidence),
                survivorship_plan: ClusterSurvivorship::ReadThrough,
            })),
            IdentityTopologyOp::Split(split) => Ok(Self::Split(ClusterSplit {
                entity: split.entity.to_hex(),
                heads: split.heads.iter().map(EntityId::to_hex).collect(),
                reassignment_map: split
                    .reassignment
                    .entries
                    .iter()
                    .map(|entry| {
                        Ok(ClusterReassignment {
                            item: crate::memory::support::subject_ref_string(&entry.item),
                            target: match entry.target {
                                ReassignmentTarget::Head(head) => ClusterReassignmentTarget::Head {
                                    entity_ref: head.to_hex(),
                                },
                                ReassignmentTarget::Residue => ClusterReassignmentTarget::Residue,
                                ReassignmentTarget::Facet { .. } => {
                                    return Err(MemoryError::bad_request(
                                        "split cannot assign a facet",
                                    ));
                                }
                            },
                        })
                    })
                    .collect::<MemoryResult<_>>()?,
                evidence: ClusterEvidence::from_engine(&split.evidence),
            })),
            _ => Err(MemoryError::bad_request(
                "clustering judgments are merge or split operations",
            )),
        }
    }
}

pub(super) fn references(op: &IdentityTopologyOp) -> (Vec<EntityId>, Vec<ClaimSubject>) {
    let mut refs = op.participants();
    let mut edges = Vec::new();
    match op {
        IdentityTopologyOp::Merge(merge) => refs.extend(&merge.evidence.refs),
        IdentityTopologyOp::Split(split) => {
            refs.extend(&split.evidence.refs);
            for entry in &split.reassignment.entries {
                match entry.item {
                    ClaimSubject::Entity(item) => refs.push(item),
                    ClaimSubject::Edge { source, target, .. } => {
                        refs.extend([source, target]);
                        edges.push(entry.item);
                    }
                }
                if let ReassignmentTarget::Head(head) = entry.target {
                    refs.push(head);
                }
            }
        }
        _ => {}
    }
    (refs, edges)
}
