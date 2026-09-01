//! ONE-1579 precision axis: F32 / F16 / Int8Sq / `BinaryPrefixRescore` rows.
//!
//! **Storage boundary.** Everything here is a BENCH REPRESENTATION. The
//! candidates are built, scanned and scored inside this module over the
//! bench's own copy of the corpus vectors; no engine type, no engine config
//! and no on-disk layout is touched. Nothing in this file changes what the
//! engine persists, and nothing here proposes a below-f16 engine default —
//! the engine persist path stays f16 and the report says so on every row.
//!
//! Each row reports three things side by side and never fuses them: recall@k
//! against an exact float32 cosine ranking, resident bytes per vector, and
//! measured scan latency. The `BinaryPrefixRescore` row additionally records
//! its prefix breadth, which defaults to `4 * k` (40 at the contract k=10).

use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::report::{Cell, EvidenceKind, Percentiles, Ratio, measured_speedup};

/// Binary-prefix breadth default multiplier: breadth = `4 * k` (40 at k=10).
pub(crate) const BINARY_PREFIX_BREADTH_MULTIPLIER: usize = 4;

/// The engine's persisted vector representation. Pinned into every report so
/// a precision ROW can never be misread as an engine storage change.
const ENGINE_PERSIST_REPRESENTATION: &str = "f16";
const ENGINE_STORAGE_NOTE: &str = "bench representations only: these rows are built and scanned \
     inside the bench over its own copy of the corpus vectors; the engine's storage layout is \
     unchanged, the engine persist path stays f16, and no below-f16 engine default is proposed \
     or implied by any row here";
const GROUND_TRUTH_NOTE: &str = "exact float32 cosine brute force over the bench's own vectors, \
     computed independently of every candidate representation";
const BREADTH_RULE: &str = "binary prefix breadth defaults to 4*k (40 at the contract k=10) and \
     is always recorded, never left implicit";

/// One candidate vector representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrecisionCandidate {
    F32,
    F16,
    Int8Sq,
    BinaryPrefixRescore,
}

impl PrecisionCandidate {
    /// The four rows every full and smoke report must carry, in report order.
    pub(crate) const ALL: [Self; 4] = [
        Self::F32,
        Self::F16,
        Self::Int8Sq,
        Self::BinaryPrefixRescore,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F16 => "f16",
            Self::Int8Sq => "int8_sq",
            Self::BinaryPrefixRescore => "binary_prefix_rescore",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::F32 => {
                "exact float32 payload; also the ground-truth ranking and the latency baseline"
            }
            Self::F16 => "IEEE-754 binary16 payload, dequantised during the scan",
            Self::Int8Sq => "per-vector symmetric int8 scalar quantisation plus one float32 scale",
            Self::BinaryPrefixRescore => {
                "sign-bit binary codes ranked by Hamming distance, then an exact float32 rescore \
                 of the prefix"
            }
        }
    }

    /// Resident bytes for one vector under this representation. The rescore
    /// candidate honestly counts the full-precision payload its second stage
    /// still needs, rather than reporting only the binary code.
    fn bytes_per_vector(self, dimensions: usize) -> usize {
        match self {
            Self::F32 => dimensions * 4,
            Self::F16 => dimensions * 2,
            Self::Int8Sq => dimensions + 4,
            Self::BinaryPrefixRescore => dimensions.div_ceil(8) + dimensions * 4,
        }
    }
}

/// One reported precision row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PrecisionRow {
    pub(crate) candidate: PrecisionCandidate,
    pub(crate) representation: &'static str,
    pub(crate) bytes_per_vector: usize,
    pub(crate) total_vector_bytes: u64,
    pub(crate) memory_ratio_vs_f32: f64,
    pub(crate) mean_recall_at_k: Cell<f64>,
    pub(crate) recall_at_k: Cell<Percentiles>,
    pub(crate) scan_latency_ms: Cell<Percentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prefix_breadth: Option<usize>,
    /// Present only when both this row and the float32 row produced measured
    /// wall-clock scan latencies in this same run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scan_speedup_over_f32: Option<Ratio>,
}

/// Axis 6: the four precision rows plus the storage boundary they sit behind.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PrecisionAxis {
    pub(crate) k: usize,
    pub(crate) dimensions: usize,
    pub(crate) vectors: usize,
    pub(crate) queries: usize,
    pub(crate) binary_prefix_breadth: usize,
    pub(crate) binary_prefix_breadth_rule: &'static str,
    pub(crate) ground_truth: &'static str,
    pub(crate) rows: Vec<PrecisionRow>,
    pub(crate) bench_representations_only: bool,
    pub(crate) engine_persist_representation: &'static str,
    pub(crate) engine_storage_note: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
}

/// The default prefix breadth for a given `k`.
pub(crate) const fn default_binary_prefix_breadth(k: usize) -> usize {
    BINARY_PREFIX_BREADTH_MULTIPLIER * k
}

/// Raw per-candidate measurement before it is turned into a report row.
struct CandidateMeasure {
    recall: Vec<f64>,
    latency_ms: Vec<f64>,
}

/// Runs every candidate representation over `vectors` for every query and
/// returns the four-row axis. `vectors` and `queries` are the bench's own
/// copies; nothing is read from or written to a vault.
pub(crate) fn evaluate(
    vectors: &[Vec<f32>],
    queries: &[Vec<f32>],
    k: usize,
    breadth: usize,
    evidence_kind: EvidenceKind,
) -> PrecisionAxis {
    let dimensions = vectors.first().map_or(0, Vec::len);
    let k = k.clamp(1, vectors.len().max(1));
    let breadth = breadth.clamp(k, vectors.len().max(k));
    let truth: Vec<Vec<usize>> = queries
        .iter()
        .map(|query| scan_f32(vectors, query, k))
        .collect();

    let f16_codes: Vec<Vec<u16>> = vectors.iter().map(Vec::as_slice).map(encode_f16).collect();
    let int8_codes: Vec<Int8Vector> = vectors.iter().map(Vec::as_slice).map(encode_int8).collect();
    let binary_codes: Vec<Vec<u64>> = vectors
        .iter()
        .map(Vec::as_slice)
        .map(encode_binary)
        .collect();

    let measures = [
        measure(queries, &truth, k, |query: &[f32], limit: usize| {
            scan_f32(vectors, query, limit)
        }),
        measure(queries, &truth, k, |query: &[f32], limit: usize| {
            scan_f16(&f16_codes, query, limit)
        }),
        measure(queries, &truth, k, |query: &[f32], limit: usize| {
            scan_int8(&int8_codes, query, limit)
        }),
        measure(queries, &truth, k, |query: &[f32], limit: usize| {
            scan_binary_prefix(&binary_codes, vectors, query, limit, breadth)
        }),
    ];

    let baseline_p50 = Percentiles::from_samples(&measures[0].latency_ms).map(|p| p.p50);
    let shape = RowShape {
        dimensions,
        vectors: vectors.len(),
        f32_bytes: PrecisionCandidate::F32.bytes_per_vector(dimensions),
        breadth,
        baseline_p50,
    };
    let rows = PrecisionCandidate::ALL
        .iter()
        .zip(&measures)
        .map(|(candidate, measure)| row(*candidate, measure, &shape))
        .collect();

    PrecisionAxis {
        k,
        dimensions,
        vectors: vectors.len(),
        queries: queries.len(),
        binary_prefix_breadth: breadth,
        binary_prefix_breadth_rule: BREADTH_RULE,
        ground_truth: GROUND_TRUTH_NOTE,
        rows,
        bench_representations_only: true,
        engine_persist_representation: ENGINE_PERSIST_REPRESENTATION,
        engine_storage_note: ENGINE_STORAGE_NOTE,
        evidence_kind,
    }
}

/// Shared per-run shape every row is built against.
struct RowShape {
    dimensions: usize,
    vectors: usize,
    f32_bytes: usize,
    breadth: usize,
    baseline_p50: Option<f64>,
}

fn row(
    candidate: PrecisionCandidate,
    measure: &CandidateMeasure,
    shape: &RowShape,
) -> PrecisionRow {
    let bytes_per_vector = candidate.bytes_per_vector(shape.dimensions);
    let scan_latency_ms = Cell::from_option(
        Percentiles::from_samples(&measure.latency_ms),
        format!("no {} scan samples were collected", candidate.as_str()),
    );
    let mean_recall = if measure.recall.is_empty() {
        None
    } else {
        Some(measure.recall.iter().sum::<f64>() / measure.recall.len() as f64)
    };
    let scan_speedup_over_f32 = if candidate == PrecisionCandidate::F32 {
        None
    } else {
        measured_speedup(
            "float32 scan p50",
            shape.baseline_p50,
            &format!("{} scan p50", candidate.as_str()),
            scan_latency_ms.value().map(|percentiles| percentiles.p50),
        )
    };
    PrecisionRow {
        candidate,
        representation: candidate.description(),
        bytes_per_vector,
        total_vector_bytes: (bytes_per_vector as u64) * (shape.vectors as u64),
        memory_ratio_vs_f32: if shape.f32_bytes == 0 {
            1.0
        } else {
            bytes_per_vector as f64 / shape.f32_bytes as f64
        },
        mean_recall_at_k: Cell::from_option(
            mean_recall,
            format!("no {} recall samples were collected", candidate.as_str()),
        ),
        recall_at_k: Cell::from_option(
            Percentiles::from_samples(&measure.recall),
            format!("no {} recall samples were collected", candidate.as_str()),
        ),
        scan_latency_ms,
        prefix_breadth: match candidate {
            PrecisionCandidate::BinaryPrefixRescore => Some(shape.breadth),
            _ => None,
        },
        scan_speedup_over_f32,
    }
}

/// Times one scan per query and scores it against the exact float32 ranking.
fn measure<F>(queries: &[Vec<f32>], truth: &[Vec<usize>], k: usize, mut scan: F) -> CandidateMeasure
where
    F: FnMut(&[f32], usize) -> Vec<usize>,
{
    let mut recall = Vec::with_capacity(queries.len());
    let mut latency_ms = Vec::with_capacity(queries.len());
    for (query, expected) in queries.iter().zip(truth) {
        let started = Instant::now();
        let hits = scan(query.as_slice(), k);
        latency_ms.push(started.elapsed().as_secs_f64() * 1e3);
        let overlap = expected
            .iter()
            .filter(|index| hits.contains(*index))
            .count();
        recall.push(if expected.is_empty() {
            0.0
        } else {
            overlap as f64 / expected.len() as f64
        });
    }
    CandidateMeasure { recall, latency_ms }
}

// ─── representations ─────────────────────────────────────────────────────

/// Per-vector symmetric int8 scalar quantisation.
struct Int8Vector {
    codes: Vec<i8>,
    scale: f32,
}

fn encode_f16(vector: &[f32]) -> Vec<u16> {
    vector.iter().map(|value| f32_to_f16_bits(*value)).collect()
}

fn encode_int8(vector: &[f32]) -> Int8Vector {
    let peak = vector
        .iter()
        .fold(0.0_f32, |acc, value| acc.max(value.abs()));
    let scale = if peak > 0.0 { peak / 127.0 } else { 1.0 };
    let codes = vector
        .iter()
        .map(|value| (value / scale).round().clamp(-127.0, 127.0) as i8)
        .collect();
    Int8Vector { codes, scale }
}

/// Sign-bit binary code, packed 64 components per word.
fn encode_binary(vector: &[f32]) -> Vec<u64> {
    let mut words = vec![0_u64; vector.len().div_ceil(64)];
    for (index, value) in vector.iter().enumerate() {
        if *value >= 0.0 {
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    words
}

fn scan_f32(vectors: &[Vec<f32>], query: &[f32], k: usize) -> Vec<usize> {
    let scored = vectors
        .iter()
        .enumerate()
        .map(|(index, vector)| (index, cosine_distance(query, vector.iter().copied())))
        .collect();
    top_k(scored, k)
}

fn scan_f16(codes: &[Vec<u16>], query: &[f32], k: usize) -> Vec<usize> {
    let scored = codes
        .iter()
        .enumerate()
        .map(|(index, code)| {
            (
                index,
                cosine_distance(query, code.iter().map(|bits| f16_bits_to_f32(*bits))),
            )
        })
        .collect();
    top_k(scored, k)
}

fn scan_int8(codes: &[Int8Vector], query: &[f32], k: usize) -> Vec<usize> {
    let scored = codes
        .iter()
        .enumerate()
        .map(|(index, code)| {
            let scale = code.scale;
            (
                index,
                cosine_distance(query, code.codes.iter().map(|raw| f32::from(*raw) * scale)),
            )
        })
        .collect();
    top_k(scored, k)
}

/// Stage 1 ranks every vector by Hamming distance between sign-bit codes and
/// keeps the `breadth`-long prefix; stage 2 rescores exactly that prefix in
/// float32 and returns the top `k`.
fn scan_binary_prefix(
    codes: &[Vec<u64>],
    vectors: &[Vec<f32>],
    query: &[f32],
    k: usize,
    breadth: usize,
) -> Vec<usize> {
    let query_code = encode_binary(query);
    let hamming: Vec<(usize, f32)> = codes
        .iter()
        .enumerate()
        .map(|(index, code)| (index, hamming_distance(code, &query_code)))
        .collect();
    let prefix = top_k(hamming, breadth.max(k));
    let rescored = prefix
        .into_iter()
        .map(|index| {
            (
                index,
                cosine_distance(query, vectors[index].iter().copied()),
            )
        })
        .collect();
    top_k(rescored, k)
}

fn hamming_distance(left: &[u64], right: &[u64]) -> f32 {
    let mut distance = 0_u32;
    for (a, b) in left.iter().zip(right) {
        distance += (a ^ b).count_ones();
    }
    distance as f32
}

/// `1 - cos(a, b)` in sequential float32 over a lazily dequantised candidate.
fn cosine_distance<I>(query: &[f32], candidate: I) -> f32
where
    I: Iterator<Item = f32>,
{
    let mut dot = 0.0_f32;
    let mut query_norm = 0.0_f32;
    let mut candidate_norm = 0.0_f32;
    for (left, right) in query.iter().zip(candidate) {
        dot += left * right;
        query_norm += left * left;
        candidate_norm += right * right;
    }
    let denominator = query_norm.sqrt() * candidate_norm.sqrt();
    if denominator == 0.0 {
        return 1.0;
    }
    1.0 - dot / denominator
}

/// Ascending by distance, ties broken by index so every candidate sees the
/// same deterministic ordering.
fn top_k(mut scored: Vec<(usize, f32)>, k: usize) -> Vec<usize> {
    scored.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.truncate(k);
    scored.into_iter().map(|(index, _)| index).collect()
}

// ─── IEEE-754 binary16 ───────────────────────────────────────────────────

/// float32 -> binary16 bits, round-to-nearest with the usual tie handling.
fn f32_to_f16_bits(value: f32) -> u16 {
    let raw = value.to_bits();
    let sign = raw & 0x8000_0000_u32;
    let exponent = raw & 0x7F80_0000_u32;
    let mantissa = raw & 0x007F_FFFF_u32;

    if exponent == 0x7F80_0000_u32 {
        let nan_bit = if mantissa == 0 { 0 } else { 0x0200_u32 };
        return ((sign >> 16) | 0x7C00_u32 | nan_bit | (mantissa >> 13)) as u16;
    }

    let half_sign = sign >> 16;
    let half_exponent = ((exponent >> 23) as i32) - 127 + 15;
    if half_exponent >= 0x1F {
        return (half_sign | 0x7C00_u32) as u16;
    }
    if half_exponent <= 0 {
        if 14 - half_exponent > 24 {
            return half_sign as u16;
        }
        let mantissa = mantissa | 0x0080_0000_u32;
        let mut half_mantissa = mantissa >> (14 - half_exponent);
        let round_bit = 1_u32 << (13 - half_exponent);
        if (mantissa & round_bit) != 0 && (mantissa & (3 * round_bit - 1)) != 0 {
            half_mantissa += 1;
        }
        return (half_sign | half_mantissa) as u16;
    }

    let half_exponent = (half_exponent as u32) << 10;
    let half_mantissa = mantissa >> 13;
    let round_bit = 0x0000_1000_u32;
    if (mantissa & round_bit) != 0 && (mantissa & (3 * round_bit - 1)) != 0 {
        ((half_sign | half_exponent | half_mantissa) + 1) as u16
    } else {
        (half_sign | half_exponent | half_mantissa) as u16
    }
}

/// binary16 bits -> float32, exact (every binary16 value is representable).
fn f16_bits_to_f32(bits: u16) -> f32 {
    if (bits & 0x7FFF) == 0 {
        return f32::from_bits(u32::from(bits) << 16);
    }
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from(bits & 0x7C00);
    let mantissa = u32::from(bits & 0x03FF);

    if exponent == 0x7C00 {
        if mantissa == 0 {
            return f32::from_bits(sign | 0x7F80_0000_u32);
        }
        return f32::from_bits(sign | 0x7FC0_0000_u32 | (mantissa << 13));
    }
    if exponent == 0 {
        // Subnormal: normalise by shifting the leading mantissa bit up.
        let shift = (mantissa as u16).leading_zeros() - 6;
        let normalised_exponent = (127 - 15 - shift) << 23;
        let normalised_mantissa = (mantissa << (14 + shift)) & 0x007F_FFFF_u32;
        return f32::from_bits(sign | normalised_exponent | normalised_mantissa);
    }
    let unbiased = ((exponent >> 10) as i32) - 15;
    let rebiased = ((unbiased + 127) as u32) << 23;
    f32::from_bits(sign | rebiased | (mantissa << 13))
}

#[cfg(test)]
mod tests {
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

    /// Every candidate must land three independent numbers on its row: recall
    /// against the exact float32 ranking, resident memory, and measured scan
    /// latency. None of the three is allowed to stand in for the others, and
    /// the binary candidate must record the breadth it actually used.
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

    #[test]
    fn binary16_round_trip_is_close_and_exact_on_representable_values() {
        for value in [0.0_f32, 1.0, -1.0, 0.5, -0.25, 65504.0, 6.1035156e-5] {
            let round_tripped = f16_bits_to_f32(f32_to_f16_bits(value));
            assert!(
                (round_tripped - value).abs() <= value.abs() * 1e-3,
                "{value} round-tripped to {round_tripped}"
            );
        }
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..512 {
            let value: f32 = rng.gen_range(-4.0_f32..4.0);
            let round_tripped = f16_bits_to_f32(f32_to_f16_bits(value));
            assert!(
                (round_tripped - value).abs() <= 0.01,
                "{value} round-tripped to {round_tripped}"
            );
        }
        assert!(f16_bits_to_f32(f32_to_f16_bits(f32::INFINITY)).is_infinite());
        assert!(f16_bits_to_f32(f32_to_f16_bits(f32::NAN)).is_nan());
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
    }
}
