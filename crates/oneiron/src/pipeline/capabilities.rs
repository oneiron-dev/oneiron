//! Capability candidates have a separate turn budget, never the memory budget.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_board::CapabilityHit;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_SKILL};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, Store};
use heed::RoTxn;
use std::collections::{HashMap, HashSet};

use super::types::ScoredEntity;

pub(super) const PER_KIND_CAPABILITY_LIMIT: usize = 5;
/// Bounded semantic shortlist for the skill bandit, not a limit on Active skills.
/// The turn's five discoveries are selected only AFTER this pool is scored.
pub(super) const SKILL_RANK_CANDIDATE_LIMIT: usize = 256;

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
    vault: &Vault,
    txn: &RoTxn<'_>,
    signal_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
) -> Result<Vec<ScoredEntity>> {
    let store = &vault.store;
    let mut memory = Vec::with_capacity(scores.len());
    let mut eligible = Vec::new();
    let mut skill_ids = HashSet::new();
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
            if hit.entity_type == ENTITY_TYPE_SKILL {
                skill_ids.insert(scored.id);
            }
            eligible.push(scored);
        }
    }
    *scores = memory;

    // Sum pulls over every eligible skill BEFORE the turn's top-k. Ranking only
    // the old semantic top-k would keep under-tried skills permanently hidden.
    let mut total_pulls = 0_u32;
    let mut posteriors = HashMap::with_capacity(skill_ids.len());
    for id in &skill_ids {
        let posterior = crate::skill_reliability::selection_posterior_in_txn(vault, txn, id)?;
        // Observations are positive integer-valued Beta weights. Saturation
        // keeps an extremely large candidate set from wrapping the horizon.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "positive posterior observation counts saturate at the u32 UCB horizon"
        )]
        let pulls = posterior.observations() as u32;
        total_pulls = total_pulls.saturating_add(pulls);
        posteriors.insert(*id, posterior);
    }
    // The four-signal blend is neutral for default skill queries: it does not
    // preserve BM25/cosine scores. Read the already-admitted channel scores,
    // normalizing per channel so BM25 and cosine can both contribute without
    // either unit dominating. A non-semantic-only query keeps its old factor.
    let semantic = skill_semantic_relevance(&skill_ids, signal_components);
    for scored in &mut eligible {
        if let Some(posterior) = posteriors.get(&scored.id) {
            let relevance = semantic.as_ref().map_or(1.0, |factors| {
                factors.get(&scored.id).copied().unwrap_or(0.0)
            });
            scored.score *= relevance
                * crate::skill_reliability::skill_selection_score_from_posterior(
                    *posterior,
                    total_pulls,
                );
        }
    }
    crate::fusion::sort_scored_entities_desc(&mut eligible);
    let mut capabilities = Vec::new();
    let mut skills = 0;
    let mut agents = 0;
    for scored in eligible {
        let count = if skill_ids.contains(&scored.id) {
            &mut skills
        } else {
            &mut agents
        };
        if *count < PER_KIND_CAPABILITY_LIMIT {
            *count += 1;
            capabilities.push(scored);
        }
    }
    Ok(capabilities)
}

/// Per-skill semantic factor from the admitted text/vector channels. Only
/// candidates that survived scope/authority filtering participate in the
/// denominator. Multiple hits take their strongest normalized channel match;
/// no semantic signal at all leaves temporal/phonetic-only discovery neutral.
fn skill_semantic_relevance(
    skill_ids: &HashSet<EntityId>,
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
) -> Option<HashMap<EntityId, f32>> {
    let mut maxima = HashMap::<RetrievalSignal, f32>::new();
    for id in skill_ids {
        if let Some(rows) = components.get(id) {
            for row in rows {
                if semantic_signal(row.signal) && row.score.is_finite() && row.score > 0.0 {
                    maxima
                        .entry(row.signal)
                        .and_modify(|max| *max = max.max(row.score))
                        .or_insert(row.score);
                }
            }
        }
    }
    if maxima.is_empty() {
        return None;
    }
    let mut relevance = HashMap::<EntityId, f32>::new();
    for id in skill_ids {
        if let Some(rows) = components.get(id) {
            for row in rows {
                if row.score.is_finite()
                    && let Some(max) = maxima.get(&row.signal)
                {
                    let normalized = (row.score.max(0.0) / max).min(1.0);
                    relevance
                        .entry(*id)
                        .and_modify(|held| *held = held.max(normalized))
                        .or_insert(normalized);
                }
            }
        }
    }
    Some(relevance)
}

fn semantic_signal(signal: RetrievalSignal) -> bool {
    matches!(
        signal,
        RetrievalSignal::Text
            | RetrievalSignal::Vector
            | RetrievalSignal::Hyde
            | RetrievalSignal::HydeRetry
    )
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

/// Removes capabilities before a memory channel spends its top-k or seeds PPR.
/// Claim lifecycle and user filters retain their normal post-fusion stages.
pub(super) fn retain_memory_candidates(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<()> {
    let mut memory = Vec::with_capacity(scores.len());
    for score in std::mem::take(scores) {
        if CapabilityLane::Memory.admits(store, txn, &score.id)? {
            memory.push(score);
        }
    }
    *scores = memory;
    Ok(())
}
