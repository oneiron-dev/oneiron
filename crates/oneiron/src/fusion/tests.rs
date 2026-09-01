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
        access_factor: 1.0,
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
fn bootstrap_blend_weights_are_explicit() {
    let weights = RetrievalBlendWeights::bootstrap();
    assert_eq!(weights.recency, 0.35);
    assert_eq!(weights.salience, 0.30);
    assert_eq!(weights.confidence, 0.20);
    assert_eq!(weights.gravity, 0.15);
    for signal in [
        RetrievalBlendSignal::Recency,
        RetrievalBlendSignal::Salience,
        RetrievalBlendSignal::Confidence,
        RetrievalBlendSignal::Gravity,
    ] {
        assert_eq!(retrieval_blend_weight(signal), weights.weight(signal));
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
            access_factor: 1.0,
        },
        RetrievalBlendInput {
            id: EntityId::from_bytes_unchecked([2; 16]),
            recency: 0.8,
            salience: 0.1,
            confidence: 0.6,
            gravity: 0.0,
            access_factor: 1.0,
        },
    ];

    let first = linear_log_blend(&inputs);
    let second = linear_log_blend(&inputs);

    assert_eq!(first, second);
}

#[test]
fn linear_log_blend_with_fixed_snapshot_is_bit_exact() {
    let inputs = vec![
        blend_input([1; 16], 0.03, 0.91, 0.27, 1.0),
        blend_input([2; 16], 0.89, 0.07, 0.63, 0.0),
        blend_input([3; 16], 0.41, 0.55, 0.13, 1.0),
        blend_input([4; 16], 0.67, 0.33, 0.97, 0.0),
    ];
    let weights = RetrievalBlendWeights::new(0.05, 0.70, 0.20, 0.05);
    let first = score_fingerprint(&linear_log_blend_with_weights(&inputs, weights));
    let second = score_fingerprint(&linear_log_blend_with_weights(&inputs, weights));

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
        .map_or(1, std::num::NonZero::get)
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
            access_factor: 1.0,
        },
        RetrievalBlendInput {
            id: id_b,
            recency: 0.0,
            salience: 1.0,
            confidence: 0.0,
            gravity: 1.0,
            access_factor: 1.0,
        },
    ];
    let swapped = vec![
        RetrievalBlendInput {
            id: id_b,
            recency: 0.0,
            salience: 1.0,
            confidence: 0.0,
            gravity: 1.0,
            access_factor: 1.0,
        },
        RetrievalBlendInput {
            id: id_a,
            recency: 1.0,
            salience: 0.0,
            confidence: 0.0,
            gravity: 1.0,
            access_factor: 1.0,
        },
    ];

    let base_scores = linear_log_blend(&base);
    let swapped_scores = linear_log_blend(&swapped);

    assert_eq!(base_scores, swapped_scores);
}

/// Read-side decay is a post-fusion multiplier, not a fifth blend
/// signal: changing one candidate's `access_factor` scales exactly that
/// candidate's fused score and leaves every other score bit-for-bit
/// identical. One more z-normalized column would move all of them,
/// because the mean and stddev of that column are shared.
#[test]
fn access_factor_multiplies_the_fused_score_after_the_log_blend() {
    let mut inputs = vec![
        blend_input([1; 16], 0.03, 0.91, 0.27, 1.0),
        blend_input([2; 16], 0.89, 0.07, 0.63, 0.0),
        blend_input([3; 16], 0.41, 0.55, 0.13, 1.0),
        blend_input([4; 16], 0.67, 0.33, 0.97, 0.0),
    ];
    let undecayed: HashMap<[u8; 16], f32> = linear_log_blend(&inputs)
        .iter()
        .map(|scored| (*scored.id.as_bytes(), scored.score))
        .collect();

    inputs[1].access_factor = 0.25;
    inputs[3].access_factor = 0.0;
    let decayed = linear_log_blend(&inputs);

    assert_eq!(decayed.len(), undecayed.len());
    for scored in &decayed {
        let blended = undecayed[scored.id.as_bytes()];
        let expected = match scored.id.as_bytes()[0] {
            2 => blended * 0.25,
            4 => blended * 0.0,
            _ => blended,
        };
        assert_eq!(
            scored.score.to_bits(),
            expected.to_bits(),
            "candidate {} must carry exactly one post-blend multiply",
            scored.id.as_bytes()[0]
        );
    }
    assert_eq!(
        decayed
            .last()
            .expect("four scored candidates")
            .id
            .as_bytes()[0],
        4,
        "a zero factor sinks a candidate to the bottom of the ranking"
    );
}

/// The factor stays out of the canonical tiebreak chain and out of the
/// signal columns: inputs that differ ONLY in `access_factor` keep the
/// same z-normalized blend, so the ratio of their scores is exactly the
/// ratio of their factors.
#[test]
fn access_factor_leaves_the_normalized_blend_columns_untouched() {
    let mut inputs = vec![
        blend_input([1; 16], 0.5, 0.5, 0.5, 1.0),
        blend_input([2; 16], 0.5, 0.5, 0.5, 1.0),
    ];
    inputs[0].access_factor = 0.5;

    let scores = linear_log_blend(&inputs);
    let decayed = scores
        .iter()
        .find(|scored| scored.id.as_bytes()[0] == 1)
        .expect("decayed candidate");
    let neutral = scores
        .iter()
        .find(|scored| scored.id.as_bytes()[0] == 2)
        .expect("neutral candidate");

    assert_eq!(decayed.score.to_bits(), (neutral.score * 0.5).to_bits());
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
