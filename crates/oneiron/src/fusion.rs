use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::pipeline::ScoredEntity;
use crate::store::{RetrievalBlendWeights, RetrievalScoreComponent, RetrievalSignal};

pub(crate) fn sort_scored_entities_desc(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetrievalBlendInput {
    pub(crate) id: EntityId,
    /// f64, like the whole blend; `narrow_scores_desc` says why.
    pub(crate) recency: f64,
    pub(crate) salience: f32,
    pub(crate) confidence: f32,
    pub(crate) gravity: f32,
    /// Read-side multiplier in [0,1]. Non-claims are 1.0.
    pub(crate) access_factor: f32,
}

pub(crate) fn retrieval_candidates_from_ranked_lists(
    ranked_lists: &[Vec<ScoredEntity>],
) -> Vec<RetrievalBlendInput> {
    let mut candidates = HashSet::<EntityId>::new();
    for ranked in ranked_lists {
        for scored in ranked {
            candidates.insert(scored.id);
        }
    }

    let mut candidates: Vec<EntityId> = candidates.into_iter().collect();
    candidates.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    candidates
        .into_iter()
        .map(|id| RetrievalBlendInput {
            id,
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

#[cfg(test)]
pub(crate) fn linear_log_blend(inputs: &[RetrievalBlendInput]) -> Vec<ScoredEntity> {
    linear_log_blend_with_weights(inputs, RetrievalBlendWeights::bootstrap())
}

/// Both faces of one linear-log blend.
pub(crate) struct LinearLogBlendScores {
    /// The run's fused scores: `exp(log_blend)` times each candidate's
    /// read-side access factor, sorted descending.
    pub(crate) scores: Vec<ScoredEntity>,
    /// The same fused scores BEFORE the access multiplier, sorted
    /// descending. A stage that reassigns scores BETWEEN entities — the
    /// RET-010 rerank score ladder — reads this face, so it can never hand
    /// one entity another entity's decay, and never squares a factor the
    /// receiving entity already carries.
    pub(crate) base_scores: Vec<ScoredEntity>,
}

pub(crate) fn linear_log_blend_scores_with_weights(
    inputs: &[RetrievalBlendInput],
    weights: RetrievalBlendWeights,
) -> LinearLogBlendScores {
    let inputs = canonical_blend_inputs(inputs);
    let columns = normalized_blend_columns(&inputs);

    let mut scores = Vec::with_capacity(inputs.len());
    let mut base_scores = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let log_score = f64::from(weights.recency) * columns.recency[index]
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
/// pipeline's f32 score without losing that order.
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
        let score = match previous {
            Some((previous_wide, previous_score)) if wide == previous_wide => previous_score,
            Some((_, previous_score)) => (wide as f32).min(previous_score.next_down()),
            None => wide as f32,
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

pub(crate) fn retrieval_blend_score_components(
    inputs: &[RetrievalBlendInput],
) -> HashMap<EntityId, Vec<RetrievalScoreComponent>> {
    let inputs = canonical_blend_inputs(inputs);
    let columns = normalized_blend_columns(&inputs);
    let signals = [
        (RetrievalSignal::Recency, columns.recency),
        (RetrievalSignal::Salience, columns.salience),
        (RetrievalSignal::Confidence, columns.confidence),
        (RetrievalSignal::Gravity, columns.gravity),
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
    recency: Vec<f64>,
    salience: Vec<f64>,
    confidence: Vec<f64>,
    gravity: Vec<f64>,
}

fn normalized_blend_columns(inputs: &[RetrievalBlendInput]) -> NormalizedBlendColumns {
    NormalizedBlendColumns {
        recency: z_normalized(inputs.iter().map(|input| input.recency).collect()),
        salience: z_normalized(inputs.iter().map(|input| input.salience.into()).collect()),
        confidence: z_normalized(inputs.iter().map(|input| input.confidence.into()).collect()),
        gravity: z_normalized(inputs.iter().map(|input| input.gravity.into()).collect()),
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
        .then_with(|| a.recency.total_cmp(&b.recency))
        .then_with(|| a.salience.total_cmp(&b.salience))
        .then_with(|| a.confidence.total_cmp(&b.confidence))
        .then_with(|| a.gravity.total_cmp(&b.gravity))
}

fn z_normalized(values: Vec<f64>) -> Vec<f64> {
    if values.len() <= 1 {
        return vec![0.0; values.len()];
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
    if stddev <= f64::EPSILON {
        return vec![0.0; values.len()];
    }

    values.iter().map(|value| (value - mean) / stddev).collect()
}

pub(crate) fn decode_msgpack_float(raw: &[u8], field: &str) -> Option<f32> {
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
