//! Regressions for the ONE-1579 precision axis.
//!
//! Split out of `precision.rs` so the axis module itself stays well under the
//! repository's giant-file bar; nothing here is reachable outside `cfg(test)`.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;

fn corpus(rng: &mut StdRng, count: usize, dimensions: usize) -> Vec<Vec<f32>> {
    (0..count)
        .map(|_| {
            (0..dimensions)
                .map(|_| rng.gen_range(-1.0_f32..1.0))
                .collect()
        })
        .collect()
}

/// Every candidate must land four independent numbers on its row: recall
/// against the exact float32 ranking, the delta against that same row,
/// resident memory, and measured scan latency. None is allowed to stand in
/// for the others, and the binary candidate must record the breadth it
/// actually used.
#[test]
fn precision_candidates_report_recall_memory_and_scan_latency() {
    let mut rng = StdRng::seed_from_u64(1579);
    let vectors = corpus(&mut rng, 96, 64);
    let queries = corpus(&mut rng, 12, 64);
    let k = 10;
    let breadth = default_binary_prefix_breadth(k);
    assert_eq!(breadth, 40, "the contract default breadth is 4*k = 40");

    let axis = evaluate(
        &vectors,
        &queries,
        k,
        breadth,
        EvidenceKind::MeasuredWallClock,
    );

    assert_eq!(axis.rows.len(), 4, "all four candidates must be reported");
    let reported: Vec<PrecisionCandidate> = axis.rows.iter().map(|row| row.candidate).collect();
    assert_eq!(reported.as_slice(), PrecisionCandidate::ALL.as_slice());
    assert_eq!(axis.binary_prefix_breadth, 40);
    assert!(axis.bench_representations_only);
    assert_eq!(axis.engine_persist_representation, "f16");
    assert_eq!(axis.requested_k, k);
    assert!(!axis.k_reduced_to_corpus);

    for row in &axis.rows {
        let label = row.candidate.as_str();
        assert!(
            row.bytes_per_vector > 0,
            "{label} must report resident bytes per vector"
        );
        assert_eq!(
            row.total_vector_bytes,
            (row.bytes_per_vector as u64) * 96,
            "{label} total bytes must follow from the per-vector figure"
        );
        assert!(
            row.mean_recall_at_k.is_measured(),
            "{label} must report recall"
        );
        let recall = row.mean_recall_at_k.value().copied().unwrap_or(-1.0);
        assert!(
            (0.0..=1.0).contains(&recall),
            "{label} recall must be a fraction, got {recall}"
        );
        assert!(
            row.scan_latency_ms.is_measured(),
            "{label} must report measured scan latency"
        );
        let latency = row.scan_latency_ms.value().expect("scan latency measured");
        assert_eq!(latency.count, queries.len(), "{label} sample count");
        assert!(latency.p50 >= 0.0 && latency.p95 >= latency.p50, "{label}");
        assert!(
            row.recall_at_k.is_measured(),
            "{label} must report a recall distribution, not only a mean"
        );
    }

    let f32_row = &axis.rows[0];
    let f16_row = &axis.rows[1];
    let int8_row = &axis.rows[2];
    let binary_row = &axis.rows[3];

    assert!(
        (f32_row.mean_recall_at_k.value().copied().unwrap_or(0.0) - 1.0).abs() < 1e-9,
        "the float32 candidate is the ground truth and must score 1.0"
    );
    assert!(f32_row.scan_speedup_over_f32.is_none(), "no self-speedup");
    assert_eq!(f32_row.bytes_per_vector, 64 * 4);
    assert_eq!(f16_row.bytes_per_vector, 64 * 2);
    assert_eq!(int8_row.bytes_per_vector, 64 + 4);
    assert!(
        f16_row.bytes_per_vector < f32_row.bytes_per_vector
            && int8_row.bytes_per_vector < f16_row.bytes_per_vector,
        "memory must shrink from f32 to f16 to int8"
    );
    assert_eq!(
        binary_row.prefix_breadth,
        Some(40),
        "the binary candidate must record the breadth it used"
    );
    assert!(
        f16_row.mean_recall_at_k.value().copied().unwrap_or(0.0) > 0.9,
        "f16 must stay close to the exact ranking"
    );
}

/// Absolute recall alone does not answer "what did this representation
/// cost against exact float32". Every row must carry the delta, computed
/// against the float32 row measured in the SAME run.
#[test]
fn every_precision_row_carries_its_recall_delta_against_f32() {
    let mut rng = StdRng::seed_from_u64(1579);
    let vectors = corpus(&mut rng, 96, 64);
    let queries = corpus(&mut rng, 12, 64);
    let axis = evaluate(&vectors, &queries, 10, 40, EvidenceKind::MeasuredWallClock);

    let baseline = axis
        .f32_baseline_mean_recall_at_k
        .measured_f64()
        .expect("the float32 baseline is measured");
    assert!((baseline - 1.0).abs() < 1e-9);

    let f32_delta = axis.rows[0]
        .mean_recall_delta_vs_f32
        .measured_f64()
        .expect("the baseline row carries an exact zero delta");
    assert!(
        f32_delta.abs() < f64::EPSILON,
        "the float32 row is its own baseline, so its delta is exactly 0.0, got {f32_delta}"
    );

    for row in &axis.rows[1..] {
        let label = row.candidate.as_str();
        let recall = row
            .mean_recall_at_k
            .measured_f64()
            .unwrap_or_else(|| panic!("{label} recall measured"));
        let delta = row
            .mean_recall_delta_vs_f32
            .measured_f64()
            .unwrap_or_else(|| panic!("{label} must carry a recall delta"));
        assert!(
            (delta - (recall - baseline)).abs() < 1e-12,
            "{label} delta must be its own recall minus the float32 baseline"
        );
        assert!(
            delta <= 1e-12,
            "{label} cannot beat the exact float32 ranking it is scored against, got {delta}"
        );
    }
}

/// The parked Moorcheh binary benchmark must be identified and tied to the
/// local binary-prefix row, without any Moorcheh figure being invented.
#[test]
fn the_parked_moorcheh_benchmark_is_identified_not_imitated() {
    let mut rng = StdRng::seed_from_u64(23);
    let vectors = corpus(&mut rng, 64, 32);
    let queries = corpus(&mut rng, 8, 32);
    let axis = evaluate(&vectors, &queries, 8, 32, EvidenceKind::MeasuredWallClock);
    let evidence = &axis.moorcheh_binary_benchmark;

    assert!(
        !evidence.run_by_this_harness,
        "the harness must not claim to have run the parked benchmark"
    );
    assert_eq!(evidence.parked_by_ticket, "ONE-1579");
    assert_eq!(evidence.parked_by_ticket_url, MOORCHEH_PARKED_TICKET_URL);
    assert_eq!(
        evidence.external_evidence_status,
        "parked_external_not_run_by_this_harness"
    );
    assert_eq!(evidence.local_counterpart_row, "binary_prefix_rescore");
    let binary = &axis.rows[3];
    assert_eq!(
        evidence.local_counterpart_recall_at_k.measured_f64(),
        binary.mean_recall_at_k.measured_f64(),
        "the evidence block must quote the row it points at, not a separate number"
    );
    assert_eq!(
        evidence
            .local_counterpart_recall_delta_vs_f32
            .measured_f64(),
        binary.mean_recall_delta_vs_f32.measured_f64()
    );
    assert_eq!(
        evidence.local_counterpart_bytes_per_vector.value().copied(),
        Some(binary.bytes_per_vector)
    );
    assert_eq!(evidence.artifact_reference_source, MOORCHEH_REFERENCE_ENV);

    let rendered = serde_json::to_string(evidence).expect("evidence renders");
    match declared_moorcheh_reference() {
        None => {
            assert!(
                !evidence.artifact_reference.is_measured(),
                "with no declared reference the artifact cell stays not_ready"
            );
            assert!(rendered.contains(MOORCHEH_REFERENCE_ENV), "{rendered}");
            assert!(rendered.contains(MOORCHEH_PARKED_TICKET_URL), "{rendered}");
        }
        Some(reference) => assert_eq!(
            evidence.artifact_reference.value().map(String::as_str),
            Some(reference.as_str())
        ),
    }
}

/// `evaluate` is reachable from tests with a k larger than the corpus.
/// Plan admission refuses that shape, and when it is reached anyway the
/// reduction is REPORTED rather than silently applied.
#[test]
fn a_k_larger_than_the_corpus_is_reported_as_reduced() {
    let mut rng = StdRng::seed_from_u64(5);
    let vectors = corpus(&mut rng, 6, 8);
    let queries = corpus(&mut rng, 2, 8);
    let axis = evaluate(&vectors, &queries, 50, 50, EvidenceKind::MeasuredWallClock);
    assert_eq!(axis.requested_k, 50);
    assert_eq!(axis.k, 6, "k cannot exceed the vectors that exist");
    assert!(
        axis.k_reduced_to_corpus,
        "a reduced k must be visible in the axis, never silent"
    );
}

/// The binary candidate's memory must be the storage the encoder really
/// allocates: `ceil(dimensions/64)` `u64` WORDS, plus the exact float32
/// payload its rescore stage still reads. A bit-count rounded to bytes —
/// or any other representation's buffer size — under-reports every
/// dimension that is not a multiple of 64.
#[test]
fn binary_memory_is_counted_from_the_allocated_u64_words() {
    for dimensions in [1_usize, 32, 63, 64, 65, 100, 128, 384] {
        let words = encode_binary(&vec![0.0_f32; dimensions]).len();
        assert_eq!(words, dimensions.div_ceil(64), "{dimensions} words");
        let code_bytes = binary_code_bytes_per_vector(dimensions);
        assert_eq!(
            code_bytes,
            words * 8,
            "{dimensions}: the code costs whole allocated u64 words"
        );
        assert_eq!(
            PrecisionCandidate::BinaryPrefixRescore.bytes_per_vector(dimensions),
            code_bytes + dimensions * 4,
            "{dimensions}: word storage plus the float32 rescore payload"
        );
        // The buffer sizes that must NOT be the answer.
        assert!(
            code_bytes >= dimensions.div_ceil(8),
            "{dimensions}: allocated words are never fewer bytes than a bit-packed count"
        );
        assert_ne!(
            PrecisionCandidate::BinaryPrefixRescore.bytes_per_vector(dimensions),
            PrecisionCandidate::F16.bytes_per_vector(dimensions),
            "{dimensions}: binary memory must not be an F16 buffer size"
        );
    }
    // The regression case: 32 dimensions allocate one whole 8-byte word,
    // not the four bytes a bit-packed count would report.
    assert_eq!(binary_code_bytes_per_vector(32), 8);

    let mut rng = StdRng::seed_from_u64(1579);
    let vectors = corpus(&mut rng, 12, 100);
    let queries = corpus(&mut rng, 3, 100);
    let axis = evaluate(&vectors, &queries, 4, 8, EvidenceKind::MeasuredWallClock);
    assert_eq!(axis.rows[3].bytes_per_vector, 16 + 400);
    assert_eq!(axis.rows[3].total_vector_bytes, (16 + 400) * 12);
    assert!(axis.binary_memory_rule.contains("u64 WORDS"));
}

/// Plan admission refuses an out-of-range breadth outright. When
/// `evaluate` is reached directly anyway, the requested breadth and the
/// reshape are both REPORTED, so a plan hash naming breadth 1 can never
/// front a run that actually scanned 10.
#[test]
fn a_reshaped_binary_prefix_breadth_is_reported_beside_the_requested_one() {
    let mut rng = StdRng::seed_from_u64(31);
    let vectors = corpus(&mut rng, 16, 8);
    let queries = corpus(&mut rng, 2, 8);

    let narrow = evaluate(&vectors, &queries, 10, 1, EvidenceKind::MeasuredWallClock);
    assert_eq!(narrow.requested_binary_prefix_breadth, 1);
    assert_eq!(narrow.binary_prefix_breadth, 10, "reshaped up to k");
    assert!(
        narrow.binary_prefix_breadth_reshaped,
        "a reshaped breadth must be visible in the axis, never silent"
    );
    assert_eq!(narrow.rows[3].prefix_breadth, Some(10));

    let wide = evaluate(
        &vectors,
        &queries,
        4,
        9_000,
        EvidenceKind::MeasuredWallClock,
    );
    assert_eq!(wide.requested_binary_prefix_breadth, 9_000);
    assert_eq!(
        wide.binary_prefix_breadth, 16,
        "reshaped down to the corpus"
    );
    assert!(wide.binary_prefix_breadth_reshaped);

    let honest = evaluate(&vectors, &queries, 4, 12, EvidenceKind::MeasuredWallClock);
    assert_eq!(honest.requested_binary_prefix_breadth, 12);
    assert_eq!(honest.binary_prefix_breadth, 12);
    assert!(
        !honest.binary_prefix_breadth_reshaped,
        "an in-range breadth is measured exactly as requested"
    );
}

#[test]
fn the_binary_prefix_rescore_reads_exactly_its_breadth() {
    let mut rng = StdRng::seed_from_u64(11);
    let vectors = corpus(&mut rng, 40, 32);
    let queries = corpus(&mut rng, 4, 32);
    // Breadth == the whole corpus makes stage 2 exact, so the candidate
    // must reproduce the float32 ranking.
    let axis = evaluate(&vectors, &queries, 5, 40, EvidenceKind::MeasuredWallClock);
    let binary = &axis.rows[3];
    assert_eq!(binary.prefix_breadth, Some(40));
    assert!(
        (binary.mean_recall_at_k.value().copied().unwrap_or(0.0) - 1.0).abs() < 1e-9,
        "a full-corpus breadth rescore is exact"
    );
    assert!(
        binary
            .mean_recall_delta_vs_f32
            .measured_f64()
            .unwrap_or(-1.0)
            .abs()
            < 1e-9,
        "an exact rescore loses nothing against the float32 baseline"
    );
}
