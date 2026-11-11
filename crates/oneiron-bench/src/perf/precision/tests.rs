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
