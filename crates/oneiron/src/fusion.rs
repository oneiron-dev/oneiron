use std::collections::HashSet;
use std::io::Cursor;

use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::types::{EntityId, ScoredEntity};

pub(crate) fn sort_scored_entities_desc(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetrievalBlendSignal {
    Recency,
    Salience,
    Confidence,
    Gravity,
}

/// RET-010b retrieval-blend weights. This is a contract-pinned table in
/// the same discipline as `ppr::lambda_for_kind`: keep the rows explicit and
/// do not derive them from defaults or old multiplicative factors.
pub(crate) const RETRIEVAL_BLEND_WEIGHT_TABLE: &[(RetrievalBlendSignal, f32)] = &[
    (RetrievalBlendSignal::Recency, 0.35),
    (RetrievalBlendSignal::Salience, 0.30),
    (RetrievalBlendSignal::Confidence, 0.20),
    (RetrievalBlendSignal::Gravity, 0.15),
];

pub(crate) fn retrieval_blend_weight(signal: RetrievalBlendSignal) -> f32 {
    RETRIEVAL_BLEND_WEIGHT_TABLE
        .iter()
        .find_map(|(candidate, weight)| (*candidate == signal).then_some(*weight))
        .expect("every retrieval blend signal has a pinned weight row")
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetrievalBlendInput {
    pub(crate) id: EntityId,
    pub(crate) recency: f32,
    pub(crate) salience: f32,
    pub(crate) confidence: f32,
    pub(crate) gravity: f32,
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

    let mut inputs: Vec<RetrievalBlendInput> = candidates
        .into_iter()
        .map(|id| RetrievalBlendInput {
            id,
            recency: 0.0,
            salience: 0.0,
            confidence: 0.0,
            gravity: 0.0,
        })
        .collect();
    inputs.sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    inputs
}

pub(crate) fn linear_log_blend(inputs: &[RetrievalBlendInput]) -> Vec<ScoredEntity> {
    let mut recency: Vec<f32> = inputs.iter().map(|input| input.recency).collect();
    let mut salience: Vec<f32> = inputs.iter().map(|input| input.salience).collect();
    let mut confidence: Vec<f32> = inputs.iter().map(|input| input.confidence).collect();
    let mut gravity: Vec<f32> = inputs.iter().map(|input| input.gravity).collect();

    z_normalize(&mut recency);
    z_normalize(&mut salience);
    z_normalize(&mut confidence);
    z_normalize(&mut gravity);

    let mut scores: Vec<ScoredEntity> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let log_score = retrieval_blend_weight(RetrievalBlendSignal::Recency) * recency[index]
                + retrieval_blend_weight(RetrievalBlendSignal::Salience) * salience[index]
                + retrieval_blend_weight(RetrievalBlendSignal::Confidence) * confidence[index]
                + retrieval_blend_weight(RetrievalBlendSignal::Gravity) * gravity[index];
            ScoredEntity {
                id: input.id,
                score: log_score.exp(),
            }
        })
        .collect();
    sort_scored_entities_desc(&mut scores);
    scores
}

fn z_normalize(values: &mut [f32]) {
    if values.len() <= 1 {
        values.fill(0.0);
        return;
    }

    let mean = values.iter().map(|value| f64::from(*value)).sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let delta = f64::from(*value) - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    let stddev = variance.sqrt();
    if stddev <= f64::EPSILON {
        values.fill(0.0);
        return;
    }

    for value in values {
        *value = ((f64::from(*value) - mean) / stddev) as f32;
    }
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
mod tests {
    use super::*;

    fn scored(id: [u8; 16], score: f32) -> ScoredEntity {
        ScoredEntity {
            id: EntityId::from_bytes_unchecked(id),
            score,
        }
    }

    #[test]
    fn blend_weight_table_is_contract_pinned() {
        assert_eq!(
            RETRIEVAL_BLEND_WEIGHT_TABLE,
            &[
                (RetrievalBlendSignal::Recency, 0.35),
                (RetrievalBlendSignal::Salience, 0.30),
                (RetrievalBlendSignal::Confidence, 0.20),
                (RetrievalBlendSignal::Gravity, 0.15),
            ]
        );
        for (signal, weight) in RETRIEVAL_BLEND_WEIGHT_TABLE {
            assert_eq!(
                retrieval_blend_weight(*signal),
                *weight,
                "retrieval blend weight mismatch for {signal:?}"
            );
        }
    }

    #[test]
    fn linear_log_blend_is_deterministic_for_fixed_inputs() {
        let inputs = vec![
            RetrievalBlendInput {
                id: EntityId::from_bytes_unchecked([1; 16]),
                recency: 0.2,
                salience: 0.9,
                confidence: 0.8,
                gravity: 1.0,
            },
            RetrievalBlendInput {
                id: EntityId::from_bytes_unchecked([2; 16]),
                recency: 0.8,
                salience: 0.1,
                confidence: 0.6,
                gravity: 0.0,
            },
        ];

        let first = linear_log_blend(&inputs);
        let second = linear_log_blend(&inputs);

        assert_eq!(first, second);
    }

    #[test]
    fn recency_and_salience_co_reside_in_one_log_term() {
        let id_a = EntityId::from_bytes_unchecked([1; 16]);
        let id_b = EntityId::from_bytes_unchecked([2; 16]);
        let base = vec![
            RetrievalBlendInput {
                id: id_a,
                recency: 1.0,
                salience: 0.0,
                confidence: 0.0,
                gravity: 1.0,
            },
            RetrievalBlendInput {
                id: id_b,
                recency: 0.0,
                salience: 1.0,
                confidence: 0.0,
                gravity: 1.0,
            },
        ];
        let swapped = vec![
            RetrievalBlendInput {
                id: id_b,
                recency: 0.0,
                salience: 1.0,
                confidence: 0.0,
                gravity: 1.0,
            },
            RetrievalBlendInput {
                id: id_a,
                recency: 1.0,
                salience: 0.0,
                confidence: 0.0,
                gravity: 1.0,
            },
        ];

        let base_scores = linear_log_blend(&base);
        let swapped_scores = linear_log_blend(&swapped);

        assert_eq!(base_scores, swapped_scores);
    }

    #[test]
    fn ranked_lists_form_candidates_without_rank_score() {
        let list = vec![scored([1; 16], 10.0), scored([2; 16], 9.0)];
        let inputs = retrieval_candidates_from_ranked_lists(&[list]);
        let fused = linear_log_blend(&inputs);

        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].id, EntityId::from_bytes_unchecked([1; 16]));
        assert_eq!(fused[1].id, EntityId::from_bytes_unchecked([2; 16]));
    }

    #[test]
    fn ranked_list_candidates_merge_overlaps_without_k() {
        let a = vec![scored([1; 16], 1.0), scored([2; 16], 1.0)];
        let b = vec![scored([2; 16], 1.0), scored([1; 16], 1.0)];

        let inputs = retrieval_candidates_from_ranked_lists(&[a, b]);
        let fused = linear_log_blend(&inputs);
        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].score, fused[1].score);
        assert_eq!(fused[0].id, EntityId::from_bytes_unchecked([1; 16]));
        assert_eq!(fused[1].id, EntityId::from_bytes_unchecked([2; 16]));
    }

    #[test]
    fn ranked_list_candidates_empty_lists() {
        let inputs = retrieval_candidates_from_ranked_lists(&[Vec::new(), Vec::new()]);
        let fused = linear_log_blend(&inputs);
        assert!(fused.is_empty());
    }

    #[test]
    fn ranked_list_candidates_missing_entities_tie_by_id() {
        let a = vec![scored([1; 16], 1.0)];
        let b = vec![scored([2; 16], 1.0)];

        let inputs = retrieval_candidates_from_ranked_lists(&[a, b]);
        let fused = linear_log_blend(&inputs);
        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].score, fused[1].score);
        assert_eq!(fused[0].id, EntityId::from_bytes_unchecked([1; 16]));
        assert_eq!(fused[1].id, EntityId::from_bytes_unchecked([2; 16]));
    }
}
