//! Score fusion: the linear-log blend of channel relevance with the recency, salience,
//! confidence and gravity signals, the per-signal score components the trace records, and
//! the deterministic score order every ranked list uses.
//!
//! Pure functions over values. The items are `pub` so `oneiron`'s retrieval pipeline, its
//! trace fork hash and its index ports can call them across the crate line; they hold no
//! state and guard nothing.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

use rmpv::Value;

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::retrieval_telemetry::{
    RetrievalBlendWeights, RetrievalScoreComponent, RetrievalSignal,
};

use crate::pipeline::ScoredEntity;

/// Sorts scores descending, ties broken by ascending id bytes: the one score order every
/// ranked list in the engine uses.
pub fn sort_scored_entities_desc(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

/// Highest score the blend hands downstream. A pool of thousands with one
/// extreme outlier (a PPR seed over its whole neighbourhood) z-normalizes
/// near `sqrt(n)`, and its `exp()` would pass `f32::MAX`. The cap keeps every
/// score finite with headroom for the post-blend multipliers (facet boosts,
/// contiguity, the community prior); `narrow_scores_desc` keeps strict order
/// above it. Hashed into the trace fork hash.
pub const BLEND_SCORE_CEILING: f32 = 1.0e18;

/// How many of a ranked channel's best scores set its z-scale (EMBED-PACK):
/// each list is scored against its own top `FUSION_LIST_LENGTH`, whatever the
/// pack's limit, so a list's best z does not grow with how many rows a caller
/// asked for. Rows past it stay candidates, scored on the same scale; the
/// pipeline fetches at least this many from every ranked channel. Hashed
/// into the trace fork hash and recorded in the trace.
pub const FUSION_LIST_LENGTH: usize = 80;

/// One candidate's blend inputs. The pipeline fills the signals after
/// [`retrieval_candidates_from_ranked_lists`] builds the candidate set.
#[derive(Debug, Clone, Copy)]
pub struct RetrievalBlendInput {
    /// The candidate.
    pub id: EntityId,
    /// Channel relevance: the sum, over every channel's ranked list, of the
    /// candidate's z-normalized score in that list (the list's lowest z when
    /// the channel did not return it). Scale-free across BM25F, cosine, PPR,
    /// temporal and phonetic scores.
    relevance: f64,
    /// f64, like the whole blend; `narrow_scores_desc` says why.
    pub recency: f64,
    pub salience: f32,
    pub confidence: f32,
    pub gravity: f32,
    /// Read-side multiplier in `[0, 1]`. Non-claims are 1.0.
    pub access_factor: f32,
}

/// The union of every channel's candidates, by id, with each one's channel relevance and
/// neutral signals.
///
/// A ranked list is z-scored against its own best [`FUSION_LIST_LENGTH`]
/// scores. The lists at `sparse` count matches (phonetic codes) and return
/// only their hits: each is z-scored as a list of that length whose other
/// places are non-hits scoring 0, and a candidate it did not return scores
/// 0, so one matched code lifts a hit above a candidate with none, by as
/// much whatever the other lists returned or the vault holds.
pub fn retrieval_candidates_from_ranked_lists(
    ranked_lists: &[Vec<ScoredEntity>],
    sparse: &[usize],
) -> Vec<RetrievalBlendInput> {
    let mut candidates = HashSet::<EntityId>::new();
    for ranked in ranked_lists {
        for scored in ranked {
            candidates.insert(scored.id);
        }
    }

    let mut candidates: Vec<EntityId> = candidates.into_iter().collect();
    candidates.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    // Each channel's own scores, z-normalized within its list, so channels
    // on different scales add up. A candidate a channel did not return takes
    // that list's lowest z (the owner's rule, EMBED-PACK): it ties the
    // weakest row the channel returned and never ranks above one.
    let channels: Vec<(HashMap<EntityId, f64>, f64)> = ranked_lists
        .iter()
        .enumerate()
        .filter(|(_, ranked)| !ranked.is_empty())
        .map(|(index, ranked)| {
            let mut by_id = HashMap::<EntityId, f64>::new();
            for scored in ranked {
                let score = f64::from(scored.score);
                let slot = by_id.entry(scored.id).or_insert(score);
                *slot = slot.max(score);
            }
            if sparse.contains(&index) {
                // RESEARCH-1216 measured z over all 80 clips, a hit among
                // non-hits (DESIGN §1.5 item 5); the fusion length stands in
                // for that pool, as for every other list: the best hits,
                // then non-hits at 0, to exactly that length. A pool of
                // equal hits alone keeps them at z 0 and a non-hit below, on
                // the spread one more place, a non-hit, would give it.
                let mut pool: Vec<f64> = by_id.values().copied().collect();
                pool.sort_unstable_by(|left, right| right.total_cmp(left));
                pool.resize(FUSION_LIST_LENGTH, 0.0);
                let scale = spread(&pool).or_else(|| {
                    let top = *pool.first().filter(|top| **top > 0.0)?;
                    pool.push(0.0);
                    Some((top, spread(&pool)?.1))
                });
                let z = |score: f64| scale.map_or(0.0, |(mean, stddev)| (score - mean) / stddev);
                for value in by_id.values_mut() {
                    *value = z(*value);
                }
                return (by_id, z(0.0));
            }
            let mut scores: Vec<f64> = ranked
                .iter()
                .map(|scored| f64::from(scored.score))
                .collect();
            scores.sort_unstable_by(|left, right| right.total_cmp(left));
            let window = &scores[..scores.len().min(FUSION_LIST_LENGTH)];
            // A window whose scores are all equal carries no scale. Its rows
            // stay at z 0, as with nothing past them, and weaker rows past it
            // fall below on the whole list's spread. A list flat throughout
            // stays neutral.
            let scale = spread(window).or_else(|| Some((*window.first()?, spread(&scores)?.1)));
            let z = |score: f64| match scale {
                Some((mean, stddev)) => (score - mean) / stddev,
                None => 0.0,
            };
            let floor = ranked
                .iter()
                .map(|scored| z(f64::from(scored.score)))
                .fold(f64::INFINITY, f64::min);
            for value in by_id.values_mut() {
                *value = z(*value);
            }
            (by_id, floor)
        })
        .collect();

    candidates
        .into_iter()
        .map(|id| RetrievalBlendInput {
            id,
            relevance: channels
                .iter()
                .map(|(by_id, floor)| by_id.get(&id).copied().unwrap_or(*floor))
                .sum(),
            recency: 0.0,
            salience: 0.0,
            confidence: 0.0,
            gravity: 0.0,
            // Neutral until read-side decay populates it: a candidate the
            // decay stage never classifies (every non-claim) surfaces
            // exactly as it did before the factor existed.
            access_factor: 1.0,
        })
        .collect()
}

/// Each candidate's channel relevance alone, as its score: the per-list
/// z-score sum [`retrieval_candidates_from_ranked_lists`] forms, with no
/// sparse list and no blend signals. A list flat throughout stays neutral,
/// and a candidate a list did not return takes that list's lowest z. Ids in
/// ascending byte order; the caller orders them.
pub fn fuse_ranked_lists(ranked_lists: &[Vec<ScoredEntity>]) -> Vec<ScoredEntity> {
    fuse_ranked_lists_with_sparse(ranked_lists, &[])
}

/// The same relevance sum, with the caller's sparse list indices.
pub fn fuse_ranked_lists_with_sparse(
    ranked_lists: &[Vec<ScoredEntity>],
    sparse_indexes: &[usize],
) -> Vec<ScoredEntity> {
    retrieval_candidates_from_ranked_lists(ranked_lists, sparse_indexes)
        .into_iter()
        .map(|input| ScoredEntity {
            id: input.id,
            score: input.relevance as f32,
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn linear_log_blend(inputs: &[RetrievalBlendInput]) -> Vec<ScoredEntity> {
    linear_log_blend_with_weights(inputs, RetrievalBlendWeights::bootstrap())
}

/// Both faces of one linear-log blend.
pub struct LinearLogBlendScores {
    /// The run's fused scores: `exp(log_blend)` times each candidate's
    /// read-side access factor, sorted descending.
    pub scores: Vec<ScoredEntity>,
    /// The same fused scores BEFORE the access multiplier, sorted
    /// descending. A stage that reassigns scores BETWEEN entities — the
    /// RET-010 rerank score ladder — reads this face, so it can never hand
    /// one entity another entity's decay, and never squares a factor the
    /// receiving entity already carries.
    pub base_scores: Vec<ScoredEntity>,
}

/// Blends `inputs` under `weights`; returns the applied and the pre-access-factor faces.
pub fn linear_log_blend_scores_with_weights(
    inputs: &[RetrievalBlendInput],
    weights: RetrievalBlendWeights,
) -> LinearLogBlendScores {
    let inputs = canonical_blend_inputs(inputs);
    let columns = normalized_blend_columns(&inputs);

    let mut scores = Vec::with_capacity(inputs.len());
    let mut base_scores = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let log_score = f64::from(weights.relevance) * columns.relevance[index]
            + f64::from(weights.recency) * columns.recency[index]
            + f64::from(weights.salience) * columns.salience[index]
            + f64::from(weights.confidence) * columns.confidence[index]
            + f64::from(weights.gravity) * columns.gravity[index];
        let base = log_score.exp();
        base_scores.push((input.id, base));
        // Read-side memory decay is a surfacing multiplier, not a fifth
        // blend signal: it lands ONCE here, on the exp() of the
        // z-normalized log blend, so it never enters
        // `normalized_blend_columns` and never becomes a `RetrievalSignal`.
        scores.push((input.id, base * f64::from(input.access_factor)));
    }
    LinearLogBlendScores {
        scores: narrow_scores_desc(scores),
        base_scores: narrow_scores_desc(base_scores),
    }
}

/// Sorts f64 blend scores descending, ties by id, and narrows them to the
/// pipeline's f32 score, at most [`BLEND_SCORE_CEILING`], without losing that
/// order.
///
/// Records written seconds apart, or of types whose recency half-lives
/// differ by days, differ in blend score by far less than one f32 step. A
/// plain cast would tie two of them in one clock second and part them in
/// the next, and every later sort would hand the tie to the id key, so two
/// recalls a few milliseconds apart could rank them differently. A strictly
/// lower f64 score therefore stays strictly below its predecessor, and an
/// exact f64 tie stays an exact tie for the id key to order.
fn narrow_scores_desc(mut scores: Vec<(EntityId, f64)>) -> Vec<ScoredEntity> {
    scores.sort_unstable_by(|(left_id, left), (right_id, right)| {
        right
            .total_cmp(left)
            .then_with(|| left_id.as_bytes().cmp(right_id.as_bytes()))
    });
    let mut narrowed = Vec::with_capacity(scores.len());
    let mut previous: Option<(f64, f32)> = None;
    for (id, wide) in scores {
        let capped = (wide as f32).min(BLEND_SCORE_CEILING);
        let score = match previous {
            Some((previous_wide, previous_score)) if wide == previous_wide => previous_score,
            Some((_, previous_score)) => capped.min(previous_score.next_down()),
            None => capped,
        };
        previous = Some((wide, score));
        narrowed.push(ScoredEntity { id, score });
    }
    narrowed
}

/// The applied face alone, for callers that want only `scores`. Every
/// production caller reads both faces through
/// [`linear_log_blend_scores_with_weights`], so this wrapper is reached
/// from tests only.
#[cfg(test)]
pub(crate) fn linear_log_blend_with_weights(
    inputs: &[RetrievalBlendInput],
    weights: RetrievalBlendWeights,
) -> Vec<ScoredEntity> {
    linear_log_blend_scores_with_weights(inputs, weights).scores
}

/// Per-candidate rank and z-score of each blend signal that varies across `inputs`, for the
/// retrieval trace.
pub fn retrieval_blend_score_components(
    inputs: &[RetrievalBlendInput],
) -> HashMap<EntityId, Vec<RetrievalScoreComponent>> {
    let inputs = canonical_blend_inputs(inputs);
    let columns = normalized_blend_columns(&inputs);
    let signals = [
        (RetrievalSignal::Recency, columns.recency),
        (RetrievalSignal::Salience, columns.salience),
        (RetrievalSignal::Confidence, columns.confidence),
        (RetrievalSignal::Gravity, columns.gravity),
        (RetrievalSignal::Relevance, columns.relevance),
    ];
    let mut components = HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
    for (signal, values) in signals {
        if values.iter().all(|value| value.to_bits() == 0) {
            continue;
        }
        let ranks = component_ranks(&inputs, &values);
        for (index, input) in inputs.iter().enumerate() {
            components
                .entry(input.id)
                .or_default()
                .push(RetrievalScoreComponent {
                    signal,
                    rank: ranks[index],
                    score: values[index] as f32,
                });
        }
    }
    components
}

struct NormalizedBlendColumns {
    relevance: Vec<f64>,
    recency: Vec<f64>,
    salience: Vec<f64>,
    confidence: Vec<f64>,
    gravity: Vec<f64>,
}

fn normalized_blend_columns(inputs: &[RetrievalBlendInput]) -> NormalizedBlendColumns {
    NormalizedBlendColumns {
        relevance: inputs.iter().map(|input| input.relevance).collect(),
        recency: z_normalized(inputs.iter().map(|input| input.recency.ln_1p()).collect()),
        salience: z_normalized(
            inputs
                .iter()
                .map(|input| f64::from(input.salience).ln_1p())
                .collect(),
        ),
        confidence: z_normalized(
            inputs
                .iter()
                .map(|input| f64::from(input.confidence).ln_1p())
                .collect(),
        ),
        gravity: z_normalized(
            inputs
                .iter()
                .map(|input| f64::from(input.gravity).ln_1p())
                .collect(),
        ),
    }
}

fn component_ranks(inputs: &[RetrievalBlendInput], values: &[f64]) -> Vec<u32> {
    let mut order: Vec<usize> = (0..inputs.len()).collect();
    order.sort_unstable_by(|left, right| {
        values[*right].total_cmp(&values[*left]).then_with(|| {
            inputs[*left]
                .id
                .as_bytes()
                .cmp(inputs[*right].id.as_bytes())
        })
    });
    let mut ranks = vec![0_u32; inputs.len()];
    for (rank, index) in order.into_iter().enumerate() {
        ranks[index] = (rank + 1).min(u32::MAX as usize) as u32;
    }
    ranks
}

fn canonical_blend_inputs(inputs: &[RetrievalBlendInput]) -> Cow<'_, [RetrievalBlendInput]> {
    if inputs
        .windows(2)
        .all(|pair| compare_blend_inputs(&pair[0], &pair[1]) != Ordering::Greater)
    {
        return Cow::Borrowed(inputs);
    }

    let mut ordered = inputs.to_vec();
    ordered.sort_unstable_by(compare_blend_inputs);
    Cow::Owned(ordered)
}

fn compare_blend_inputs(a: &RetrievalBlendInput, b: &RetrievalBlendInput) -> Ordering {
    a.id.as_bytes()
        .cmp(b.id.as_bytes())
        .then_with(|| a.relevance.total_cmp(&b.relevance))
        .then_with(|| a.recency.total_cmp(&b.recency))
        .then_with(|| a.salience.total_cmp(&b.salience))
        .then_with(|| a.confidence.total_cmp(&b.confidence))
        .then_with(|| a.gravity.total_cmp(&b.gravity))
}

fn z_normalized(values: Vec<f64>) -> Vec<f64> {
    match spread(&values) {
        Some((mean, stddev)) => values.iter().map(|value| (value - mean) / stddev).collect(),
        None => vec![0.0; values.len()],
    }
}

/// The mean and standard deviation of `values`; `None` when they do not
/// spread (one value, or all equal), where every z is 0.
fn spread(values: &[f64]) -> Option<(f64, f64)> {
    if values.len() <= 1 {
        return None;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    let stddev = variance.sqrt();
    (stddev > f64::EPSILON).then_some((mean, stddev))
}

/// Reads numeric map field `field` from an entity row's msgpack body (after the metadata
/// header), clamped to `[0, 1]`; `None` when absent, non-numeric or not finite.
pub fn decode_msgpack_float(raw: &[u8], field: &str) -> Option<f32> {
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return None;
    }

    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let Value::Map(entries) = value else {
        return None;
    };

    for (key, value) in entries {
        if key.as_str()? != field {
            continue;
        }

        return decode_numeric_value(value);
    }

    None
}

fn decode_numeric_value(value: Value) -> Option<f32> {
    let parsed = match value {
        Value::F32(v) => v,
        Value::F64(v) => v as f32,
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                i as f32
            } else if let Some(u) = v.as_u64() {
                u as f32
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if !parsed.is_finite() {
        return None;
    }
    Some(parsed.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests;
