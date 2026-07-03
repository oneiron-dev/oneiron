use std::borrow::Cow;
use std::cmp::Ordering;
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
        })
        .collect()
}

pub(crate) fn linear_log_blend(inputs: &[RetrievalBlendInput]) -> Vec<ScoredEntity> {
    let inputs = canonical_blend_inputs(inputs);
    let mut recency: Vec<f32> = inputs.iter().map(|input| input.recency).collect();
    let mut salience: Vec<f32> = inputs.iter().map(|input| input.salience).collect();
    let mut confidence: Vec<f32> = inputs.iter().map(|input| input.confidence).collect();
    let mut gravity: Vec<f32> = inputs.iter().map(|input| input.gravity).collect();

    z_normalize(&mut recency);
    z_normalize(&mut salience);
    z_normalize(&mut confidence);
    z_normalize(&mut gravity);

    let recency_weight = retrieval_blend_weight(RetrievalBlendSignal::Recency);
    let salience_weight = retrieval_blend_weight(RetrievalBlendSignal::Salience);
    let confidence_weight = retrieval_blend_weight(RetrievalBlendSignal::Confidence);
    let gravity_weight = retrieval_blend_weight(RetrievalBlendSignal::Gravity);

    let mut scores: Vec<ScoredEntity> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let log_score = recency_weight * recency[index]
                + salience_weight * salience[index]
                + confidence_weight * confidence[index]
                + gravity_weight * gravity[index];
            ScoredEntity {
                id: input.id,
                score: log_score.exp(),
            }
        })
        .collect();
    sort_scored_entities_desc(&mut scores);
    scores
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

    fn blend_input(
        id: [u8; 16],
        recency: f32,
        salience: f32,
        confidence: f32,
        gravity: f32,
    ) -> RetrievalBlendInput {
        RetrievalBlendInput {
            id: EntityId::from_bytes_unchecked(id),
            recency,
            salience,
            confidence,
            gravity,
        }
    }

    fn score_fingerprint(scores: &[ScoredEntity]) -> Vec<([u8; 16], u32)> {
        scores
            .iter()
            .map(|scored| (*scored.id.as_bytes(), scored.score.to_bits()))
            .collect()
    }

    fn determinism_harness_fingerprint(ranked_lists: &[Vec<ScoredEntity>]) -> Vec<([u8; 16], u32)> {
        let mut inputs = retrieval_candidates_from_ranked_lists(ranked_lists);
        for input in &mut inputs {
            match input.id.as_bytes()[0] {
                1 => {
                    input.recency = 0.03;
                    input.salience = 0.91;
                    input.confidence = 0.27;
                    input.gravity = 1.0;
                }
                2 => {
                    input.recency = 0.89;
                    input.salience = 0.07;
                    input.confidence = 0.63;
                    input.gravity = 0.0;
                }
                3 => {
                    input.recency = 0.41;
                    input.salience = 0.55;
                    input.confidence = 0.13;
                    input.gravity = 1.0;
                }
                4 => {
                    input.recency = 0.67;
                    input.salience = 0.33;
                    input.confidence = 0.97;
                    input.gravity = 0.0;
                }
                5 => {
                    input.recency = 0.21;
                    input.salience = 0.75;
                    input.confidence = 0.49;
                    input.gravity = 1.0;
                }
                _ => unreachable!("determinism harness only uses ids 1..=5"),
            }
        }
        score_fingerprint(&linear_log_blend(&inputs))
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
    fn linear_log_blend_canonicalizes_unordered_inputs_before_reductions() {
        let ordered = vec![
            blend_input([1; 16], 0.03, 0.91, 0.27, 1.0),
            blend_input([2; 16], 0.89, 0.07, 0.63, 0.0),
            blend_input([3; 16], 0.41, 0.55, 0.13, 1.0),
            blend_input([4; 16], 0.67, 0.33, 0.97, 0.0),
            blend_input([5; 16], 0.21, 0.75, 0.49, 1.0),
        ];
        let interleaved = vec![ordered[3], ordered[0], ordered[4], ordered[1], ordered[2]];

        assert_eq!(
            score_fingerprint(&linear_log_blend(&ordered)),
            score_fingerprint(&linear_log_blend(&interleaved))
        );
    }

    #[test]
    fn blend_fusion_bit_fingerprint_is_repeatable_across_threaded_runs() {
        let ranked_lists = vec![
            vec![
                scored([3; 16], 0.73),
                scored([1; 16], 0.73),
                scored([5; 16], 0.11),
            ],
            vec![
                scored([2; 16], 0.50),
                scored([4; 16], 0.50),
                scored([1; 16], 0.49),
            ],
            vec![scored([5; 16], 0.25), scored([3; 16], 0.25)],
        ];
        let reordered_ranked_lists = vec![
            vec![scored([3; 16], 0.25), scored([5; 16], 0.25)],
            vec![
                scored([1; 16], 0.49),
                scored([4; 16], 0.50),
                scored([2; 16], 0.50),
            ],
            vec![
                scored([5; 16], 0.11),
                scored([1; 16], 0.73),
                scored([3; 16], 0.73),
            ],
        ];
        let expected = determinism_harness_fingerprint(&ranked_lists);

        let worker_count = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .min(8);
        let handles: Vec<_> = (0..worker_count)
            .map(|worker| {
                let expected = expected.clone();
                let ranked_lists = if worker % 2 == 0 {
                    ranked_lists.clone()
                } else {
                    reordered_ranked_lists.clone()
                };
                std::thread::spawn(move || {
                    for _ in 0..64 {
                        assert_eq!(determinism_harness_fingerprint(&ranked_lists), expected);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("determinism worker panicked");
        }
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
