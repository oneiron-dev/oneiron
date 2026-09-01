use super::{PreparedCosine, cosine_distance, cosine_similarity};

fn approx_eq(a: f32, b: f32, eps: f32) {
    assert!((a - b).abs() <= eps, "left={a}, right={b}, eps={eps}");
}

fn manual_cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
    let mut norm_b = 0.0_f32;

    for (&ai, &bi) in a.iter().zip(b.iter()) {
        dot += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
    }

    if !dot.is_finite()
        || !norm_a.is_finite()
        || !norm_b.is_finite()
        || norm_a <= 0.0
        || norm_b <= 0.0
    {
        return 0.0;
    }

    (dot / (norm_a.sqrt() * norm_b.sqrt())).clamp(-1.0, 1.0)
}

/// Table of `(a, b, expected_similarity, expected_distance)` pairs
/// covering the public `cosine_similarity` / `cosine_distance` contract
/// across the originally-separate fixture tests.
///
/// Variants:
/// - `identical_vectors`: sim==1, dist==0.
/// - `orthogonal_vectors`: sim==0, dist==1.
/// - `zero_norm_zero_vs_non_zero`: degenerate one-zero pair returns dist==1.
/// - `zero_norm_zero_vs_zero`: degenerate both-zero pair returns dist==1.
/// - `mismatched_lengths`: short-circuit returns 0/1.
/// - `non_finite_inputs_nan`: NaN inputs short-circuit to 0/1.
/// - `non_finite_inputs_inf`: ±Inf inputs short-circuit to 0/1.
#[test]
#[allow(clippy::type_complexity)]
fn cosine_distance_cases() {
    let identical: Vec<f32> = vec![0.1, -0.2, 0.3, 0.4, -0.5];
    let zero7: Vec<f32> = vec![0.0; 7];
    let non_zero7: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
    let nan: Vec<f32> = vec![f32::NAN, 1.0, 2.0, 3.0];
    let inf: Vec<f32> = vec![f32::INFINITY, 1.0, 2.0, 3.0];
    let finite4: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];

    let cases: Vec<(&str, Vec<f32>, Vec<f32>, f32, f32)> = vec![
        ("identical_vectors", identical.clone(), identical, 1.0, 0.0),
        (
            "orthogonal_vectors",
            vec![1.0, 0.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0, 0.0],
            0.0,
            1.0,
        ),
        (
            "zero_norm_zero_vs_non_zero",
            zero7.clone(),
            non_zero7,
            0.0,
            1.0,
        ),
        ("zero_norm_zero_vs_zero", zero7.clone(), zero7, 0.0, 1.0),
        (
            "mismatched_lengths",
            vec![1.0, 2.0, 3.0],
            vec![1.0, 2.0],
            0.0,
            1.0,
        ),
        ("non_finite_inputs_nan", nan, finite4.clone(), 0.0, 1.0),
        ("non_finite_inputs_inf", inf, finite4, 0.0, 1.0),
    ];

    for (case_name, a, b, expected_sim, expected_dist) in cases {
        let sim = cosine_similarity(&a, &b);
        let dist = cosine_distance(&a, &b);
        assert!(
            (sim - expected_sim).abs() <= 1e-6,
            "case {case_name}: similarity left={sim}, right={expected_sim}"
        );
        assert!(
            (dist - expected_dist).abs() <= 1e-6,
            "case {case_name}: distance left={dist}, right={expected_dist}"
        );
    }
}

#[test]
fn cosine_handles_simd_remainder() {
    let a = vec![0.25_f32; 17];
    let b = vec![0.5_f32; 17];

    approx_eq(cosine_similarity(&a, &b), 1.0, 1e-6);
    approx_eq(cosine_distance(&a, &b), 0.0, 1e-6);
}

// mismatched_lengths and non_finite_inputs are folded into
// `cosine_distance_cases` above.

#[cfg(target_arch = "x86_64")]
#[test]
fn cosine_avx2_matches_scalar_across_lengths() {
    // Runtime detection so the test actually runs on default CI builds
    // (which don't include +avx2/+fma in their target_features), not only
    // under `-C target-cpu=native`.
    if !std::arch::is_x86_feature_detected!("avx2") || !std::arch::is_x86_feature_detected!("fma") {
        // Skip on CPUs without AVX2 + FMA; dispatcher coverage still exercises
        // the scalar fallback via `cosine_similarity`.
        return;
    }

    // Exercise the AVX2 path directly against the scalar reference across
    // lengths that stress the 8-lane main loop + scalar tail.
    for len in [1, 4, 7, 8, 15, 16, 17, 31, 32, 33, 64, 129] {
        let a: Vec<f32> = (0..len).map(|i| (i as f32) * 0.125 - 0.375).collect();
        let b: Vec<f32> = (0..len).map(|i| ((i as f32) * 0.0625).sin()).collect();

        let scalar = super::cosine_similarity_scalar(&a, &b);
        // SAFETY: AVX2 + FMA were runtime-detected above; calling the
        // AVX2 variant is sound. Slice lengths match (constructed equal).
        let avx = unsafe { super::cosine_similarity_avx2(&a, &b) };
        approx_eq(avx, scalar, 1e-5);
    }
}

#[test]
fn cosine_matches_manual_formula_across_unroll_boundaries() {
    let a = [
        0.5_f32, -0.75, 1.25, 0.125, -1.0, 0.625, 0.875, -0.5, 1.5, -1.25, 0.25, 0.75, -0.375,
    ];
    let b = [
        -0.25_f32, 0.5, 0.75, -1.0, 0.125, 1.25, -0.625, 0.375, -1.5, 0.875, 0.5, -0.25, 1.125,
    ];

    let expected = manual_cosine_similarity(&a, &b);
    approx_eq(super::cosine_similarity_scalar(&a, &b), expected, 1e-6);
    approx_eq(
        1.0 - super::cosine_similarity_scalar(&a, &b),
        1.0 - expected,
        1e-6,
    );

    // Keep the public dispatcher covered as well.
    approx_eq(cosine_similarity(&a, &b), expected, 1e-6);
    approx_eq(cosine_distance(&a, &b), 1.0 - expected, 1e-6);
}

// ===== ONE-1137: prepared (loop-invariant query norm) cosine =====

/// SplitMix64 — deterministic test PRNG, no external dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn pseudo_vector(state: &mut u64, len: usize) -> Vec<f32> {
    (0..len)
        .map(|_| ((splitmix64(state) >> 40) as f32 / (1 << 24) as f32) * 2.0 - 1.0)
        .collect()
}

/// Bit-for-bit, not approximate: the prepared path is a loop-invariant
/// hoist of the query norm, so ANY difference in the low bit is a
/// reassociation bug that could reorder a beam's tie-broken results.
fn assert_same_bits(prepared: f32, legacy: f32, case: &str) {
    assert_eq!(
        prepared.to_bits(),
        legacy.to_bits(),
        "case {case}: prepared={prepared} legacy={legacy}"
    );
}

/// Lengths straddle every block/tail boundary of all three kernels: below
/// the aarch64 4-lane cutoff (1, 3), exactly one 4-block (4), a 4-block
/// plus scalar tail (7), exactly one 8-block (8), 8-blocks plus a mixed
/// tail (31), and the production-scale 1024.
#[test]
fn prepared_cosine_matches_legacy_bit_for_bit_across_lengths() {
    for len in [1_usize, 3, 4, 7, 8, 31, 1024] {
        let mut state = 0x0011_3700 ^ (len as u64);
        let query = pseudo_vector(&mut state, len);
        // One prepared query, many candidates — the reuse the insert
        // path actually performs.
        let prepared = PreparedCosine::new(&query);

        for round in 0..8 {
            let candidate = pseudo_vector(&mut state, len);
            let case = format!("len={len} round={round}");
            assert_same_bits(
                prepared.similarity(&candidate),
                cosine_similarity(&query, &candidate),
                &case,
            );
            assert_same_bits(
                prepared.distance(&candidate),
                cosine_distance(&query, &candidate),
                &case,
            );
        }

        // Self-comparison exercises the clamp: the ratio can round just
        // above 1.0 and must be pinned to it on both paths.
        let self_similarity = prepared.similarity(&query);
        assert_same_bits(
            self_similarity,
            cosine_similarity(&query, &query),
            &format!("len={len} self"),
        );
        assert!(
            self_similarity <= 1.0,
            "len={len}: clamp must hold, got {self_similarity}"
        );

        // Negated candidate exercises the lower clamp bound.
        let negated: Vec<f32> = query.iter().map(|value| -value).collect();
        assert_same_bits(
            prepared.similarity(&negated),
            cosine_similarity(&query, &negated),
            &format!("len={len} negated"),
        );
        assert!(
            prepared.similarity(&negated) >= -1.0,
            "len={len}: lower clamp must hold"
        );
    }
}

/// The degenerate contract is part of the graph's semantics (a zero or
/// unusable norm scores as maximally distant, never as a near neighbor),
/// so the prepared path must reproduce it exactly rather than merely
/// avoid NaN.
#[test]
fn prepared_cosine_preserves_degenerate_contract() {
    let zero7 = vec![0.0_f32; 7];
    let non_zero7: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
    let nan4 = vec![f32::NAN, 1.0, 2.0, 3.0];
    let inf4 = vec![f32::INFINITY, 1.0, 2.0, 3.0];
    let neg_inf4 = vec![f32::NEG_INFINITY, 1.0, 2.0, 3.0];
    let finite4 = vec![1.0_f32, 2.0, 3.0, 4.0];

    // Every pair below is degenerate on one side or the other, so the
    // contract pins similarity 0.0 / distance 1.0.
    let cases: Vec<(&str, &[f32], &[f32])> = vec![
        ("zero_query", &zero7, &non_zero7),
        ("zero_candidate", &non_zero7, &zero7),
        ("both_zero", &zero7, &zero7),
        ("nan_query", &nan4, &finite4),
        ("nan_candidate", &finite4, &nan4),
        ("inf_query", &inf4, &finite4),
        ("inf_candidate", &finite4, &inf4),
        ("neg_inf_query", &neg_inf4, &finite4),
        // Mismatched lengths short-circuit before any accumulation.
        ("shorter_candidate", &non_zero7, &finite4),
        ("longer_candidate", &finite4, &non_zero7),
        ("empty_query", &[], &finite4),
        ("empty_both", &[], &[]),
    ];

    for (case, query, candidate) in cases {
        let prepared = PreparedCosine::new(query);
        assert_same_bits(
            prepared.similarity(candidate),
            cosine_similarity(query, candidate),
            case,
        );
        assert_same_bits(
            prepared.distance(candidate),
            cosine_distance(query, candidate),
            case,
        );
        assert_eq!(
            prepared.similarity(candidate),
            0.0,
            "case {case}: degenerate similarity must be 0.0"
        );
        assert_eq!(
            prepared.distance(candidate),
            1.0,
            "case {case}: degenerate distance must be 1.0"
        );
    }
}

/// A prepared query is stateless across candidates: scoring a degenerate
/// or mismatched candidate must not disturb the norm cached for the
/// healthy ones that follow.
#[test]
fn prepared_cosine_reuse_is_order_independent() {
    let mut state = 0x1137_0042;
    let query = pseudo_vector(&mut state, 33);
    let candidates: Vec<Vec<f32>> = vec![
        pseudo_vector(&mut state, 33),
        vec![0.0; 33],
        vec![1.0, 2.0],
        vec![f32::NAN; 33],
        pseudo_vector(&mut state, 33),
    ];

    let prepared = PreparedCosine::new(&query);
    for pass in 0..3 {
        for (index, candidate) in candidates.iter().enumerate() {
            assert_same_bits(
                prepared.distance(candidate),
                cosine_distance(&query, candidate),
                &format!("pass={pass} candidate={index}"),
            );
        }
    }
}
