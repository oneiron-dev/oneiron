use std::collections::{HashMap, HashSet, VecDeque};

use heed::RoTxn;

use crate::config::VectorEvidenceFloors;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::embed::EmbeddingSpace;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, StoreRead};

use super::types::{
    CONTEXT_PACK_ANOMALOUS_REPEAT_RUN, CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO,
    CONTEXT_PACK_SCORE_GAP_EPSILON, ClaimStatusGateCache, EntityMetadataCache, ScoredEntity,
};
use crate::disclosure::DisclosureContext;
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

/// Whether `non_base` non-base CLAIMs may stand beside `base` base CLAIMs in
/// an `All`-world pack: non-base worlds take at most
/// `floor(fraction × emitted claims)` (ARCH-0004). None always may.
fn non_base_claims_fit(base: usize, non_base: usize, fraction: f32) -> bool {
    non_base == 0 || non_base as f32 <= (base.saturating_add(non_base) as f32 * fraction).floor()
}

/// The most of `non_base` non-base CLAIMs that may stand beside `base` base
/// CLAIMs ([`non_base_claims_fit`]).
pub(crate) fn non_base_claim_cap(base: usize, non_base: usize, fraction: f32) -> usize {
    (0..=non_base)
        .rev()
        .find(|&count| non_base_claims_fit(base, count, fraction))
        .unwrap_or(0)
}

/// An `All`-world pack's world share while its rows are selected: the
/// non-base claim fraction, and the run's claim decisions, which name each
/// claim's world.
#[derive(Clone, Copy)]
pub(super) struct WorldShare<'g> {
    pub(super) fraction: f32,
    pub(super) claim_gate: &'g ClaimStatusGateCache,
}

/// A scored row's part in a pack's world share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShareRole {
    /// Not a claim; it takes no share.
    Free,
    BaseClaim,
    NonBaseClaim,
}

impl WorldShare<'_> {
    /// A claim's world is the one its gate-decoded body names. A claim with
    /// no decoded body counts as non-base, so it never takes a base claim's
    /// room.
    fn role(self, kind: ContextPackBudgetKind, id: &EntityId) -> ShareRole {
        if kind != ContextPackBudgetKind::Claim {
            return ShareRole::Free;
        }
        match self.claim_gate.decisions.get(id) {
            Some(Some(body)) if body.world.is_none() => ShareRole::BaseClaim,
            _ => ShareRole::NonBaseClaim,
        }
    }
}

/// Picks `rows` in score order under per-kind `caps` and a `limit`. A
/// non-base claim enters only while the world share holds; one held back
/// enters as soon as later base claims make room, so the page goes short,
/// never over the share, when base claims are scarce. Picked rows keep
/// their score order. Also returns whether the share kept a claim out.
fn select_rows(
    rows: &[(ScoredEntity, ContextPackBudgetKind, ShareRole)],
    caps: Option<ContextPackBudgetCounts>,
    limit: usize,
    fraction: f32,
) -> (Vec<ScoredEntity>, bool) {
    let fits = |used: &ContextPackBudgetCounts, kind: ContextPackBudgetKind| {
        caps.is_none_or(|caps| used.get(kind) < caps.get(kind))
    };
    let mut picked = vec![false; rows.len()];
    let mut used = ContextPackBudgetCounts::default();
    let (mut total, mut base, mut non_base) = (0_usize, 0_usize, 0_usize);
    let mut held = VecDeque::new();
    for (index, &(_, kind, role)) in rows.iter().enumerate() {
        if total >= limit {
            break;
        }
        if !fits(&used, kind) {
            continue;
        }
        if role == ShareRole::NonBaseClaim && !non_base_claims_fit(base, non_base + 1, fraction) {
            held.push_back(index);
            continue;
        }
        picked[index] = true;
        used.increment(kind);
        total += 1;
        match role {
            ShareRole::Free => {}
            ShareRole::NonBaseClaim => non_base += 1,
            ShareRole::BaseClaim => {
                base += 1;
                while total < limit
                    && fits(&used, kind)
                    && non_base_claims_fit(base, non_base + 1, fraction)
                {
                    let Some(next) = held.pop_front() else {
                        break;
                    };
                    picked[next] = true;
                    used.increment(kind);
                    total += 1;
                    non_base += 1;
                }
            }
        }
    }
    let rows = rows
        .iter()
        .zip(picked)
        .filter_map(|(&(scored, ..), picked)| picked.then_some(scored))
        .collect();
    (rows, !held.is_empty())
}

/// Returns whether the world share kept a claim out; a kind's zero cap
/// is not the share's.
pub(super) fn apply_context_pack_retrieval_budget(
    scores: &mut Vec<ScoredEntity>,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    budget: ContextPackRetrievalBudget,
    world_share: Option<WorldShare<'_>>,
) -> Result<bool> {
    if scores.is_empty() {
        return Ok(false);
    }

    let mut candidates = Vec::with_capacity(scores.len());
    let mut available = ContextPackBudgetCounts::default();
    let (mut base_claims, mut non_base_claims) = (0_usize, 0_usize);
    for scored in scores.iter().copied() {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };
        let kind = ContextPackBudgetKind::from_entity_type(meta.entity_type);
        let role = world_share.map_or(ShareRole::Free, |share| share.role(kind, &scored.id));
        match role {
            ShareRole::Free => available.increment(kind),
            ShareRole::BaseClaim => base_claims += 1,
            ShareRole::NonBaseClaim => non_base_claims += 1,
        }
        candidates.push((scored, kind, role));
    }
    // Claims the world share can never emit leave their room to other kinds.
    let fraction = world_share.map_or(1.0, |share| share.fraction);
    available.add(
        ContextPackBudgetKind::Claim,
        base_claims + non_base_claim_cap(base_claims, non_base_claims, fraction),
    );

    let caps =
        redistribute_context_pack_budget(ContextPackBudgetCounts::from_budget(budget), available);
    let (rows, share_held_back) = select_rows(&candidates, Some(caps), usize::MAX, fraction);
    *scores = rows;
    Ok(share_held_back)
}

/// Cuts an `All`-world pack's scored rows to `limit` under its world share
/// ([`select_rows`]), after any reorder that followed the budget.
pub(super) fn truncate_under_world_share(
    scores: &mut Vec<ScoredEntity>,
    limit: usize,
    share: WorldShare<'_>,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let mut rows = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        let kind = match metadata_cache.get(store, rtxn, &scored.id)? {
            Some(meta) => ContextPackBudgetKind::from_entity_type(meta.entity_type),
            None => ContextPackBudgetKind::Other,
        };
        rows.push((scored, kind, share.role(kind, &scored.id)));
    }
    *scores = select_rows(&rows, None, limit, share.fraction).0;
    Ok(())
}

/// Drops the scored rows a pack's disclosure clamp withholds before any
/// selection, so a withheld row takes no slot (OF-365); the assembly's own
/// sweep still checks every survivor. Returns the ids it dropped.
pub(super) fn withhold_undisclosed(
    scores: &mut Vec<ScoredEntity>,
    clamp: &DisclosureContext,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &ClaimStatusGateCache,
) -> Result<Vec<EntityId>> {
    let mut withheld = Vec::new();
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.drain(..) {
        let admitted = match metadata_cache.get(store, rtxn, &scored.id)? {
            Some(meta) => crate::context_pack::retained_copies::clamp_admits(
                clamp,
                store.base(),
                rtxn,
                &scored.id,
                meta.entity_type,
                claim_gate
                    .decisions
                    .get(&scored.id)
                    .and_then(Option::as_ref),
            )?,
            None => false,
        };
        if admitted {
            kept.push(scored);
        } else {
            withheld.push(scored.id);
        }
    }
    *scores = kept;
    Ok(withheld)
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
    /// Floors already resolved for the score: a declared space's
    /// ([`media_space_floors`]).
    pub(super) floors: Option<VectorEvidenceFloors>,
}

impl VectorEvidence<'_> {
    fn floors(&self, floors: &NoMatchFloors) -> VectorEvidenceFloors {
        self.floors
            .unwrap_or_else(|| floors.resolve(self.space, self.kind))
    }
}

/// RET-01's read of the declared spaces' hits (OF-370).
#[derive(Debug, Clone, Default)]
pub(super) struct MediaEvidence {
    /// Hits at or above their space's floor: each one keeps the pack.
    pub(super) kept: HashSet<EntityId>,
    /// Hits under it, judged in their own space's list by its floors.
    pub(super) weak: Vec<WeakMediaHit>,
}

/// One declared space's hit under that space's floor.
#[derive(Debug, Clone)]
pub(super) struct WeakMediaHit {
    pub(super) id: EntityId,
    pub(super) space: String,
    pub(super) floors: VectorEvidenceFloors,
    pub(super) score: f32,
}

/// The floors a raw cosine in declared space `space` is judged by (OF-370):
/// the pair a host set for that kind there, then the space's own declared
/// floors, then the vault's, the same pair the text index's scores fall back
/// to.
pub(super) fn media_space_floors(
    floors: &NoMatchFloors,
    space: &EmbeddingSpace,
    kind: Option<u8>,
) -> VectorEvidenceFloors {
    kind.and_then(|kind| floors.keyed.get(&space.id)?.get(&kind))
        .copied()
        .or(space.evidence)
        .unwrap_or(floors.pair)
}

/// Returns whether a context pack must withhold every candidate before
/// hydration. The predicate intentionally reads raw per-channel evidence,
/// rather than the blended score: blend dimensions can be incomparable or
/// flat, while cosine scores have a stable similarity meaning in their own
/// space. Every vector score here was scored in `space`, the vault's own
/// index; `kind_of` reads an item's entity type when that space keys its
/// floors by kind. A folded MESSAGE's evidence is its TURN's.
///
/// A declared space's hits are judged in their own space when the run reads
/// them ([`media_space_floors`]): a candidate among `media_evidence`'s kept
/// hits is evidence that keeps the pack, whatever the text and vault-index
/// lists hold (OF-370). A candidate's weak hits join the vector tests as
/// their own space's list, by that space's floors, and a media query that
/// answered counts as a vector query.
#[expect(
    clippy::too_many_arguments,
    reason = "RET-01 reads each channel's raw evidence beside the run's query shape and floors"
)]
pub(super) fn context_pack_evidence_abstains(
    scores: &[ScoredEntity],
    signal_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    media_evidence: &MediaEvidence,
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
    if scores
        .iter()
        .any(|scored| media_evidence.kept.contains(&scored.id))
    {
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
                        floors: None,
                    });
                }
                _ => {}
            }
        }
    }
    let candidates: HashSet<&EntityId> = scores.iter().map(|scored| &scored.id).collect();
    evidence.extend(
        media_evidence
            .weak
            .iter()
            .filter(|weak| candidates.contains(&weak.id))
            .map(|weak| VectorEvidence {
                space: &weak.space,
                kind: None,
                score: weak.score,
                floors: Some(weak.floors),
            }),
    );

    Ok(vector_evidence_abstains(
        text_query.is_some(),
        has_vector_query || !media_evidence.weak.is_empty(),
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
        && evidence
            .iter()
            .all(|scored| !scored.score.is_finite() || scored.score < scored.floors(floors).floor);

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
/// matches. Any finite score at or above its own space and kind's strong
/// score passes its space. The pack abstains when some space is poor and none passes; a
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
/// `Some(false)` passes, `None` too few scores to say. A score at or above
/// its own kind's strong score passes the space, so one kind's calibration
/// never discards another's strong match.
fn vector_score_gap_is_poor(list: &[VectorEvidence<'_>], floors: &NoMatchFloors) -> Option<bool> {
    let strong = |scored: &VectorEvidence<'_>| {
        scored.score.is_finite() && scored.score >= scored.floors(floors).strong
    };
    let top = list.first()?;
    let Some(next) = list.get(1) else {
        return strong(top).then_some(false);
    };
    let (top, next) = (top.score, next.score);
    if !top.is_finite() || !next.is_finite() || top <= 0.0 {
        return Some(true);
    }
    if list.iter().any(strong) {
        return Some(false);
    }

    let gap_ratio = (top - next) / top.max(CONTEXT_PACK_SCORE_GAP_EPSILON);
    Some(gap_ratio < CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO)
}
