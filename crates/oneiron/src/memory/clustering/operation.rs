//! Wire projection only. Topology validation and effects stay in identity_topology.
//! A ref comes in as a full 32-hex id or a short ref, resolved on the caller's
//! read lane, and goes out as the short ref the vault keeps for it, else its
//! hex, in the snapshot the reply reads (FIX 9937).

use super::*;
use crate::EntityId;
use crate::claim::ClaimSubject;
use crate::edge::EdgeKind;
use crate::identity_topology::{
    IdentityOpEvidence, IdentityTopologyOp, MergeOp, ReassignmentEntry, ReassignmentMap,
    ReassignmentTarget, SplitOp, SurvivorshipPlan,
};
use crate::memory::{MemoryError, MemoryResult};

/// Resolves one inbound ref, a full 32-hex id or a short ref, on the
/// caller's read lane.
pub(super) type Resolve<'a> = &'a dyn Fn(&str) -> MemoryResult<EntityId>;

/// One outbound id as the short ref the vault keeps for it, else its hex, in
/// the snapshot the reply reads.
pub(super) type Project<'a> = &'a dyn Fn(&EntityId) -> String;

/// Whether `field` is a whole full 32-hex id, one colon field; a short ref
/// (`<presentation-id>:<hash>`) is two.
fn is_full_hex(field: &str) -> bool {
    field.len() == 32 && field.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn subject(text: &str, resolve: Resolve<'_>) -> MemoryResult<ClaimSubject> {
    let Some(edge) = text.strip_prefix("edge:") else {
        return Ok(ClaimSubject::Entity(resolve(text)?));
    };
    let fields: Vec<_> = edge.split(':').collect();
    // Each endpoint is one field as a full id, two as a short ref.
    let source_width = match fields.first() {
        Some(field) if !is_full_hex(field) => 2,
        _ => 1,
    };
    let target = fields
        .get(source_width + 1..)
        .filter(|target| matches!(target.len(), 1 | 2));
    let (Some(source), Some(kind), Some(target)) =
        (fields.get(..source_width), fields.get(source_width), target)
    else {
        return Err(MemoryError::bad_request(
            "edge item is edge:<source-ref>:<kind-byte>:<target-ref>",
        ));
    };
    let kind = kind
        .parse::<u8>()
        .ok()
        .and_then(EdgeKind::try_from_u8)
        .ok_or_else(|| MemoryError::bad_request("edge item needs a known edge-kind byte"))?;
    Ok(ClaimSubject::Edge {
        source: resolve(source.join(":").as_str())?,
        kind,
        target: resolve(target.join(":").as_str())?,
    })
}

/// `subject` as its outbound ref: its entity's, or
/// `edge:<source-ref>:<kind-byte>:<target-ref>`.
pub(super) fn subject_ref(subject: &ClaimSubject, project: Project<'_>) -> String {
    match subject {
        ClaimSubject::Entity(id) => project(id),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => format!(
            "edge:{}:{}:{}",
            project(source),
            *kind as u8,
            project(target)
        ),
    }
}

fn refs(ids: &[EntityId], project: Project<'_>) -> Vec<String> {
    ids.iter().map(|id| project(id)).collect()
}

fn resolved(refs: &[String], resolve: Resolve<'_>) -> MemoryResult<Vec<EntityId>> {
    refs.iter()
        .map(|reference| resolve(reference.as_str()))
        .collect()
}

impl ClusterEvidence {
    fn into_engine(&self, resolve: Resolve<'_>) -> MemoryResult<IdentityOpEvidence> {
        Ok(IdentityOpEvidence {
            refs: resolved(&self.refs, resolve)?,
            rationale: self.rationale.clone(),
        })
    }

    fn from_engine(evidence: &IdentityOpEvidence, project: Project<'_>) -> Self {
        Self {
            refs: refs(&evidence.refs, project),
            rationale: evidence.rationale.clone(),
        }
    }
}

impl ClusterOperation {
    pub(super) fn into_engine(&self, resolve: Resolve<'_>) -> MemoryResult<IdentityTopologyOp> {
        match self {
            Self::Merge(merge) => Ok(IdentityTopologyOp::Merge(MergeOp {
                sources: resolved(&merge.sources, resolve)?,
                survivor: resolve(merge.survivor.as_str())?,
                evidence: merge.evidence.into_engine(resolve)?,
                survivorship_plan: match merge.survivorship_plan {
                    ClusterSurvivorship::ReadThrough => SurvivorshipPlan::ReadThrough,
                },
            })),
            Self::Split(split) => Ok(IdentityTopologyOp::Split(SplitOp {
                entity: resolve(split.entity.as_str())?,
                heads: resolved(&split.heads, resolve)?,
                reassignment: ReassignmentMap {
                    entries: split
                        .reassignment_map
                        .iter()
                        .map(|entry| {
                            Ok(ReassignmentEntry {
                                item: subject(entry.item.as_str(), resolve)?,
                                target: match &entry.target {
                                    ClusterReassignmentTarget::Head { entity_ref } => {
                                        ReassignmentTarget::Head(resolve(entity_ref.as_str())?)
                                    }
                                    ClusterReassignmentTarget::Residue => {
                                        ReassignmentTarget::Residue
                                    }
                                },
                            })
                        })
                        .collect::<MemoryResult<_>>()?,
                },
                evidence: split.evidence.into_engine(resolve)?,
            })),
        }
    }

    pub(super) fn from_engine(op: &IdentityTopologyOp, project: Project<'_>) -> MemoryResult<Self> {
        match op {
            IdentityTopologyOp::Merge(merge) => Ok(Self::Merge(ClusterMerge {
                sources: refs(&merge.sources, project),
                survivor: project(&merge.survivor),
                evidence: ClusterEvidence::from_engine(&merge.evidence, project),
                survivorship_plan: ClusterSurvivorship::ReadThrough,
            })),
            IdentityTopologyOp::Split(split) => Ok(Self::Split(ClusterSplit {
                entity: project(&split.entity),
                heads: refs(&split.heads, project),
                reassignment_map: split
                    .reassignment
                    .entries
                    .iter()
                    .map(|entry| {
                        Ok(ClusterReassignment {
                            item: subject_ref(&entry.item, project),
                            target: match entry.target {
                                ReassignmentTarget::Head(head) => ClusterReassignmentTarget::Head {
                                    entity_ref: project(&head),
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
                evidence: ClusterEvidence::from_engine(&split.evidence, project),
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
