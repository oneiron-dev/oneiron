//! Capability candidates have a separate turn budget, never the memory budget.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_board::CapabilityHit;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL};
use crate::store::Store;
use heed::RoTxn;

use super::types::ScoredEntity;

pub(super) const PER_KIND_CAPABILITY_LIMIT: usize = 5;

pub(super) fn is_capability(kind: u8) -> bool {
    matches!(kind, ENTITY_TYPE_SKILL | ENTITY_TYPE_AGENT_DEF)
}

pub(crate) fn capability_hit(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<CapabilityHit>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let label = match header.entity_type {
        ENTITY_TYPE_SKILL => {
            let Ok(skill) = crate::skill::decode_skill_record(body) else {
                return Ok(None);
            };
            if !matches!(
                skill.approval_status,
                crate::claim::ClaimApprovalStatus::Auto
                    | crate::claim::ClaimApprovalStatus::Approved
            ) || skill.lifecycle_status != crate::skill::SkillLifecycle::Active
            {
                return Ok(None);
            }
            skill.skill_id
        }
        ENTITY_TYPE_AGENT_DEF => {
            let Ok(agent) = crate::agent_def::decode_agent_definition(body) else {
                return Ok(None);
            };
            agent.agent_id
        }
        _ => return Ok(None),
    };
    Ok(Some(CapabilityHit {
        id,
        entity_type: header.entity_type,
        label,
    }))
}

pub(super) fn partition_capabilities(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<Vec<ScoredEntity>> {
    let mut memory = Vec::with_capacity(scores.len());
    let mut capabilities = Vec::new();
    let mut skills = 0;
    let mut agents = 0;
    for scored in std::mem::take(scores) {
        let Some(raw) = store.entities.get(txn, scored.id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if !is_capability(header.entity_type) {
            memory.push(scored);
            continue;
        }
        if let Some(hit) = capability_hit(store, txn, scored.id)? {
            let count = if hit.entity_type == ENTITY_TYPE_SKILL {
                &mut skills
            } else {
                &mut agents
            };
            if *count < PER_KIND_CAPABILITY_LIMIT {
                *count += 1;
                capabilities.push(scored);
            }
        }
    }
    *scores = memory;
    Ok(capabilities)
}

pub(super) fn memory_candidate_count(
    store: &Store,
    txn: &RoTxn<'_>,
    scores: &[ScoredEntity],
) -> Result<usize> {
    let mut count = 0;
    for scored in scores {
        if let Some(raw) = store.entities.get(txn, scored.id.as_bytes())?
            && let Some(header) = EntityMetadataHeader::parse(&raw)
            && !is_capability(header.entity_type)
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Internal kind-category collection, below the one public context-pack query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CapabilityLane {
    Memory,
    Skill,
    Agent,
}

impl CapabilityLane {
    pub(super) fn admits(self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(false);
        };
        match self {
            Self::Memory => Ok(!is_capability(header.entity_type)),
            Self::Skill | Self::Agent => {
                let expected = if self == Self::Skill {
                    ENTITY_TYPE_SKILL
                } else {
                    ENTITY_TYPE_AGENT_DEF
                };
                Ok(header.entity_type == expected && capability_hit(store, txn, *id)?.is_some())
            }
        }
    }
}
