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
    CONTEXT_PACK_ANOMALOUS_REPEAT_RUN, CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO,
    CONTEXT_PACK_SCORE_GAP_EPSILON, EntityMetadataCache, ScoredEntity,
};
use crate::vault::NoMatchFloors;

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

/// One raw vector score a pack holds: the embedding space it was scored in
/// and the kind of item, which pick the floors it is judged by.
#[derive(Debug, Clone, Copy)]
pub(super) struct VectorEvidence<'a> {
    pub(super) space: &'a str,
    /// The item's entity type, looked up only when `space` keys its floors
    /// by kind.
    pub(super) kind: Option<u8>,
    pub(super) score: f32,
}

/// Returns whether a context pack must withhold every candidate before
/// hydration. The predicate intentionally reads raw per-channel evidence,
/// rather than the blended score: blend dimensions can be incomparable or
/// flat, while cosine scores have a stable similarity meaning in their own
/// space. Every vector score here was scored in `space` (a vault has one);
/// `kind_of` reads an item's entity type when that space keys its floors by
/// kind. A folded MESSAGE's evidence is its TURN's.
pub(super) fn context_pack_evidence_abstains(
    scores: &[ScoredEntity],
    signal_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    text_query: Option<&str>,
    has_vector_query: bool,
    space: &str,
    floors: &NoMatchFloors,
    mut kind_of: impl FnMut(&EntityId) -> Result<Option<u8>>,
) -> Result<bool> {
    if text_query.is_some_and(context_pack_text_is_anomalous) {
        return Ok(true);
    }
    if scores.is_empty() {
        return Ok(false);
    }

    let keyed = floors.keys_space(space);
    let mut has_keyword_hit = false;
    let mut evidence = Vec::new();
    for scored in scores {
        let Some(components) = signal_components.get(&scored.id) else {
            continue;
        };
        let mut kind = None;
        for component in components {
            match component.signal {
                RetrievalSignal::Text => has_keyword_hit = true,
                RetrievalSignal::Vector | RetrievalSignal::Hyde => {
                    if keyed && kind.is_none() {
                        kind = Some(kind_of(&scored.id)?);
                    }
                    evidence.push(VectorEvidence {
                        space,
                        kind: kind.flatten(),
                        score: component.score,
                    });
                }
                _ => {}
            }
        }
    }

    Ok(vector_evidence_abstains(
        text_query.is_some(),
        has_vector_query,
        has_keyword_hit,
        &mut evidence,
        floors,
    ))
}

/// RET-01's two vector tests. No match: with both a text and a vector query
/// and no surviving keyword hit, every score sits under its own space and
/// kind's floor. Poor gap: a space's list is uniformly mediocre.
pub(super) fn vector_evidence_abstains(
    has_text_query: bool,
    has_vector_query: bool,
    has_keyword_hit: bool,
    evidence: &mut [VectorEvidence<'_>],
    floors: &NoMatchFloors,
) -> bool {
    // A semantic-only result is not rejected merely for being below the
    // floor: this branch requires both caller-supplied channels and no
    // surviving keyword evidence, matching the RET-01 dual-signal rule.
    let absent_keyword_and_low_vector = has_text_query
        && has_vector_query
        && !has_keyword_hit
        && !evidence.is_empty()
        && evidence.iter().all(|scored| {
            !scored.score.is_finite()
                || scored.score < floors.resolve(scored.space, scored.kind).floor
        });

    absent_keyword_and_low_vector || vector_score_gaps_are_poor(evidence, floors)
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

/// Score-gap evidence is meaningful only within one space's raw list, whose
/// kinds compete in it together (and HyDE's vectors are in the same space as
/// the query's). The ratio follows `(top1 - top2) / max(top1, epsilon)`; it
/// suppresses uniformly mediocre results, not a close cluster of strong
/// matches. A top at or above its own space and kind's strong score passes
/// its space. The pack abstains when some space is poor and none passes; a
/// space with one score is neither, unless that score is strong.
fn vector_score_gaps_are_poor(evidence: &mut [VectorEvidence<'_>], floors: &NoMatchFloors) -> bool {
    evidence.sort_unstable_by(|left, right| {
        left.space
            .cmp(right.space)
            .then_with(|| right.score.total_cmp(&left.score))
    });
    let mut poor = false;
    for list in evidence.chunk_by(|left, right| left.space == right.space) {
        match vector_score_gap_is_poor(list, floors) {
            Some(true) => poor = true,
            Some(false) => return false,
            None => {}
        }
    }
    poor
}

/// One space's verdict over its scores, best first: `Some(true)` poor,
/// `Some(false)` passes, `None` too few scores to say.
fn vector_score_gap_is_poor(list: &[VectorEvidence<'_>], floors: &NoMatchFloors) -> Option<bool> {
    let top = list.first()?;
    let strong = floors.resolve(top.space, top.kind).strong;
    let Some(next) = list.get(1) else {
        return (top.score.is_finite() && top.score >= strong).then_some(false);
    };
    let (top, next) = (top.score, next.score);
    if !top.is_finite() || !next.is_finite() || top <= 0.0 {
        return Some(true);
    }
    if top >= strong {
        return Some(false);
    }

    let gap_ratio = (top - next) / top.max(CONTEXT_PACK_SCORE_GAP_EPSILON);
    Some(gap_ratio < CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO)
}
