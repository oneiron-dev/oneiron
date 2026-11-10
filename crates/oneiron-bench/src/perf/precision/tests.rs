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
            "{dimensions}: the code costs whole allocated u64 words",
        );
        assert_eq!(
            PrecisionCandidate::BinaryPrefixRescore.bytes_per_vector(dimensions),
            code_bytes + dimensions * 4,
            "{dimensions}: word storage plus the float32 rescore payload",
        );
        // The buffer sizes that must NOT be the answer.
        assert!(
            code_bytes >= dimensions.div_ceil(8),
            "{dimensions}: allocated words are never fewer bytes than a bit-packed count",
        );
        assert_ne!(
            PrecisionCandidate::BinaryPrefixRescore.bytes_per_vector(dimensions),
            PrecisionCandidate::F16.bytes_per_vector(dimensions),
            "{dimensions}: binary memory must not be an F16 buffer size",
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
}
