use std::collections::HashMap;

use heed::RoTxn;

use crate::context_pack::ContextPackRetrievalBudget;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, Store};

use super::types::{
    CONTEXT_PACK_ANOMALOUS_REPEAT_RUN, CONTEXT_PACK_MEDIOCRE_VECTOR_SIMILARITY,
    CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO, CONTEXT_PACK_MIN_VECTOR_SIMILARITY,
    CONTEXT_PACK_SCORE_GAP_EPSILON, EntityMetadataCache, ScoredEntity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextPackBudgetKind {
    Claim,
    Turn,
    Summary,
    Facet,
    Other,
}

impl ContextPackBudgetKind {
    fn from_entity_type(entity_type: u8) -> Self {
        match entity_type {
            ENTITY_TYPE_CLAIM => Self::Claim,
            ENTITY_TYPE_TURN => Self::Turn,
            ENTITY_TYPE_SUMMARY => Self::Summary,
            ENTITY_TYPE_FACET => Self::Facet,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ContextPackBudgetCounts {
    claims: usize,
    turns: usize,
    summaries: usize,
    facets: usize,
    other: usize,
}

impl ContextPackBudgetCounts {
    fn from_budget(budget: ContextPackRetrievalBudget) -> Self {
        Self {
            claims: budget.claims,
            turns: budget.turns,
            summaries: budget.summaries,
            facets: budget.facets,
            other: budget.other,
        }
    }

    fn get(self, kind: ContextPackBudgetKind) -> usize {
        match kind {
            ContextPackBudgetKind::Claim => self.claims,
            ContextPackBudgetKind::Turn => self.turns,
            ContextPackBudgetKind::Summary => self.summaries,
            ContextPackBudgetKind::Facet => self.facets,
            ContextPackBudgetKind::Other => self.other,
        }
    }

    fn add(&mut self, kind: ContextPackBudgetKind, amount: usize) {
        let slot = match kind {
            ContextPackBudgetKind::Claim => &mut self.claims,
            ContextPackBudgetKind::Turn => &mut self.turns,
            ContextPackBudgetKind::Summary => &mut self.summaries,
            ContextPackBudgetKind::Facet => &mut self.facets,
            ContextPackBudgetKind::Other => &mut self.other,
        };
        *slot = slot.saturating_add(amount);
    }

    fn increment(&mut self, kind: ContextPackBudgetKind) {
        self.add(kind, 1);
    }
}

pub(super) fn apply_context_pack_retrieval_budget(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    budget: ContextPackRetrievalBudget,
) -> Result<()> {
    if scores.is_empty() {
        return Ok(());
    }

    let mut candidates = Vec::with_capacity(scores.len());
    let mut available = ContextPackBudgetCounts::default();
    for scored in scores.iter().copied() {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };
        let kind = ContextPackBudgetKind::from_entity_type(meta.entity_type);
        available.increment(kind);
        candidates.push((scored, kind));
    }

    let caps =
        redistribute_context_pack_budget(ContextPackBudgetCounts::from_budget(budget), available);
    let mut used = ContextPackBudgetCounts::default();
    let mut kept = Vec::with_capacity(candidates.len().min(scores.len()));
    for (scored, kind) in candidates {
        if used.get(kind) >= caps.get(kind) {
            continue;
        }
        used.increment(kind);
        kept.push(scored);
    }

    *scores = kept;
    Ok(())
}

fn redistribute_context_pack_budget(
    mut caps: ContextPackBudgetCounts,
    available: ContextPackBudgetCounts,
) -> ContextPackBudgetCounts {
    let kinds = [
        ContextPackBudgetKind::Claim,
        ContextPackBudgetKind::Turn,
        ContextPackBudgetKind::Summary,
        ContextPackBudgetKind::Facet,
        ContextPackBudgetKind::Other,
    ];

    let mut surplus = 0_usize;
    let mut hungry = Vec::new();
    for kind in kinds {
        let cap = caps.get(kind);
        let count = available.get(kind);
        if count <= cap {
            surplus = surplus.saturating_add(cap.saturating_sub(count));
        } else if cap > 0 {
            hungry.push((kind, count - cap));
        }
    }

    if surplus == 0 || hungry.is_empty() {
        return caps;
    }

    hungry.sort_unstable_by_key(|(kind, _)| match kind {
        ContextPackBudgetKind::Claim => 0,
        ContextPackBudgetKind::Turn => 1,
        ContextPackBudgetKind::Summary => 2,
        ContextPackBudgetKind::Facet => 3,
        ContextPackBudgetKind::Other => 4,
    });

    while surplus > 0 && !hungry.is_empty() {
        let mut still_hungry = Vec::with_capacity(hungry.len());
        for (kind, need) in hungry {
            if surplus == 0 {
                still_hungry.push((kind, need));
                continue;
            }
            caps.increment(kind);
            surplus -= 1;
            if need > 1 {
                still_hungry.push((kind, need - 1));
            }
        }
        hungry = still_hungry;
    }

    caps
}

/// Returns whether a context pack must withhold every candidate before
/// hydration. The predicate intentionally reads raw per-channel evidence,
/// rather than the blended score: blend dimensions can be incomparable or
/// flat, while cosine scores have a stable similarity meaning.
pub(super) fn context_pack_evidence_abstains(
    scores: &[ScoredEntity],
    signal_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    text_query: Option<&str>,
    has_vector_query: bool,
) -> bool {
    if text_query.is_some_and(context_pack_text_is_anomalous) {
        return true;
    }
    if scores.is_empty() {
        return false;
    }

    let mut has_keyword_hit = false;
    let mut vector_scores = Vec::new();
    for scored in scores {
        let Some(components) = signal_components.get(&scored.id) else {
            continue;
        };
        for component in components {
            match component.signal {
                RetrievalSignal::Text => has_keyword_hit = true,
                RetrievalSignal::Vector | RetrievalSignal::Hyde => {
                    vector_scores.push(component.score);
                }
                _ => {}
            }
        }
    }

    // A semantic-only result is not rejected merely for being below the
    // floor: this branch requires both caller-supplied channels and no
    // surviving keyword evidence, matching the RET-01 dual-signal rule.
    let absent_keyword_and_low_vector = text_query.is_some()
        && has_vector_query
        && !has_keyword_hit
        && !vector_scores.is_empty()
        && vector_scores
            .iter()
            .all(|score| !score.is_finite() || *score < CONTEXT_PACK_MIN_VECTOR_SIMILARITY);

    absent_keyword_and_low_vector || context_pack_vector_score_gap_is_poor(&mut vector_scores)
}

/// RET-01 pack hygiene for malformed or degenerate text input. Newlines and
/// tabs remain legitimate natural-language formatting; other controls and a
/// long non-whitespace character run are treated as anomalous evidence.
fn context_pack_text_is_anomalous(text: &str) -> bool {
    let mut previous = None;
    let mut repeated = 0_usize;

    for character in text.chars() {
        if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
            return true;
        }
        if character.is_whitespace() {
            previous = None;
            repeated = 0;
            continue;
        }
        if previous == Some(character) {
            repeated += 1;
            if repeated >= CONTEXT_PACK_ANOMALOUS_REPEAT_RUN {
                return true;
            }
        } else {
            previous = Some(character);
            repeated = 1;
        }
    }

    false
}

/// Score-gap evidence is meaningful only within the same raw vector channel.
/// The ratio follows `(top1 - top2) / max(top1, epsilon)`; it suppresses
/// uniformly mediocre results, not a close cluster of strong matches.
fn context_pack_vector_score_gap_is_poor(vector_scores: &mut [f32]) -> bool {
    if vector_scores.len() < 2 {
        return false;
    }

    vector_scores.sort_unstable_by(|left, right| right.total_cmp(left));
    let top = vector_scores[0];
    let next = vector_scores[1];
    if !top.is_finite() || !next.is_finite() || top <= 0.0 {
        return true;
    }
    if top >= CONTEXT_PACK_MEDIOCRE_VECTOR_SIMILARITY {
        return false;
    }

    let gap_ratio = (top - next) / top.max(CONTEXT_PACK_SCORE_GAP_EPSILON);
    gap_ratio < CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO
}
