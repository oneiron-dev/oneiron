//! ONE-1579 precision axis: F32 / F16 / Int8Sq / `BinaryPrefixRescore` rows.
//!
//! **Storage boundary.** Everything here is a BENCH REPRESENTATION. The
//! candidates are built, scanned and scored inside this module over the
//! bench's own copy of the corpus vectors; no engine type, no engine config
//! and no on-disk layout is touched. Nothing in this file changes what the
//! engine persists, and nothing here proposes a below-f16 engine default —
//! the engine persist path stays f16 and the report says so on every row.
//!
//! Each row reports four things side by side and never fuses them: recall@k
//! against an exact float32 cosine ranking, the recall DELTA against that same
//! float32 row, resident bytes per vector, and measured scan latency. The
//! `BinaryPrefixRescore` row additionally records its prefix breadth, which
//! defaults to `4 * k` (40 at the contract k=10).
//!
//! The parked Moorcheh binary benchmark is IDENTIFIED rather than imitated:
//! [`MoorchehEvidence`] names it, points at the binary-prefix row that is its
//! in-harness counterpart, and carries an artifact reference only when one was
//! declared for the run. No Moorcheh number this harness did not run is ever
//! restated.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::cells::{Cell, EvidenceKind, Percentiles, Ratio, measured_speedup};
use super::representations::{
    Int8Vector, encode_binary, encode_f16, encode_int8, scan_binary_prefix, scan_f16, scan_f32,
    scan_int8,
};

/// Binary-prefix breadth default multiplier: breadth = `4 * k` (40 at k=10).
pub(crate) const BINARY_PREFIX_BREADTH_MULTIPLIER: usize = 4;
/// Environment variable declaring a traceable artifact reference for the
/// parked Moorcheh binary benchmark (a run id, artifact path or ticket ref).
pub(crate) const MOORCHEH_REFERENCE_ENV: &str = "ONEIRON_BENCH_MOORCHEH_REF";
/// ONE-1579 is the traceable source that parks and folds the external Moorcheh
/// binary-vector benchmark into this precision axis.
pub(crate) const MOORCHEH_PARKED_TICKET: &str = "ONE-1579";
pub(crate) const MOORCHEH_PARKED_TICKET_URL: &str =
    "https://linear.app/oneiron/issue/ONE-1579/perf-1-engine-performance-bench-beam-sibling";

/// The engine's persisted vector representation. Pinned into every report so
/// a precision ROW can never be misread as an engine storage change.
const ENGINE_PERSIST_REPRESENTATION: &str = "f16";
const ENGINE_STORAGE_NOTE: &str = "bench representations only: these rows are built and scanned \
     inside the bench over its own copy of the corpus vectors; the engine's storage layout is \
     unchanged, the engine persist path stays f16, and no below-f16 engine default is proposed \
     or implied by any row here";
const GROUND_TRUTH_NOTE: &str = "exact float32 cosine brute force over the bench's own vectors, \
     computed independently of every candidate representation";
const BREADTH_RULE: &str = "binary prefix breadth defaults to 4*k (40 at the contract k=10), is always recorded, and plan admission rejects any resolved breadth outside [k, indexed_docs] rather than silently clamping the experiment";
const DELTA_RULE: &str = "every row carries recall@k MINUS the float32 row's recall@k from this \
     same run; the float32 row is the baseline and carries an exact 0.0 by construction, and a \
     row whose recall was not measured has a not_ready delta rather than a zero";
const MOORCHEH_BENCHMARK: &str = "Moorcheh binary vector benchmark (external, parked): the \
     binary-code-plus-rescore trade-off study this axis' BinaryPrefixRescore row is the \
     in-harness counterpart of";
const MOORCHEH_NOTE: &str = "this harness does not run the Moorcheh benchmark and never restates \
     a Moorcheh figure it did not produce; it identifies the parked benchmark, points at the \
     local binary-prefix row that answers the same question over this run's own corpus, and \
     carries a traceable artifact reference only when one was declared for the run";

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
    /// This row's recall@k minus the float32 row's recall@k in the SAME run.
    /// Negative means the representation lost ranking quality against exact
    /// float32; the float32 row itself carries an exact 0.0.
    pub(crate) mean_recall_delta_vs_f32: Cell<f64>,
    pub(crate) recall_at_k: Cell<Percentiles>,
    pub(crate) scan_latency_ms: Cell<Percentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prefix_breadth: Option<usize>,
    /// Present only when both this row and the float32 row produced measured
    /// wall-clock scan latencies in this same run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scan_speedup_over_f32: Option<Ratio>,
}

/// The parked external binary benchmark this axis is traceable to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MoorchehEvidence {
    pub(crate) benchmark: &'static str,
    pub(crate) parked_by_ticket: &'static str,
    pub(crate) parked_by_ticket_url: &'static str,
    pub(crate) external_evidence_status: &'static str,
    pub(crate) run_by_this_harness: bool,
    pub(crate) local_counterpart_row: &'static str,
    pub(crate) local_counterpart_recall_at_k: Cell<f64>,
    pub(crate) local_counterpart_recall_delta_vs_f32: Cell<f64>,
    pub(crate) local_counterpart_bytes_per_vector: Cell<usize>,
    pub(crate) artifact_reference_source: &'static str,
    pub(crate) artifact_reference: Cell<String>,
    pub(crate) note: &'static str,
}

/// Axis 6: the four precision rows plus the storage boundary they sit behind.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PrecisionAxis {
    /// What the plan asked for. Plan admission refuses `k > indexed_docs`, so
    /// for an admitted plan this equals `k`.
    pub(crate) requested_k: usize,
    pub(crate) k: usize,
    /// True only if `requested_k` had to be reduced to the corpus size. An
    /// admitted plan can never set this, and it is emitted so a caller that
    /// reached `evaluate` directly cannot hide the reduction.
    pub(crate) k_reduced_to_corpus: bool,
    pub(crate) dimensions: usize,
    pub(crate) vectors: usize,
    pub(crate) queries: usize,
    pub(crate) binary_prefix_breadth: usize,
    pub(crate) binary_prefix_breadth_rule: &'static str,
    pub(crate) ground_truth: &'static str,
    pub(crate) recall_delta_rule: &'static str,
    pub(crate) f32_baseline_mean_recall_at_k: Cell<f64>,
    pub(crate) rows: Vec<PrecisionRow>,
    pub(crate) moorcheh_binary_benchmark: MoorchehEvidence,
    pub(crate) bench_representations_only: bool,
    pub(crate) engine_persist_representation: &'static str,
    pub(crate) engine_storage_note: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
}

/// The default prefix breadth for a given `k`.
pub(crate) const fn default_binary_prefix_breadth(k: usize) -> usize {
    BINARY_PREFIX_BREADTH_MULTIPLIER.saturating_mul(k)
}

/// Raw per-candidate measurement before it is turned into a report row.
struct CandidateMeasure {
    recall: Vec<f64>,
    latency_ms: Vec<f64>,
}

impl CandidateMeasure {
    fn mean_recall(&self) -> Option<f64> {
        if self.recall.is_empty() {
            return None;
        }
        Some(self.recall.iter().sum::<f64>() / self.recall.len() as f64)
    }
}

/// Runs every candidate representation over `vectors` for every query and
/// returns the four-row axis. `vectors` and `queries` are the bench's own
/// copies; nothing is read from or written to a vault.
pub(crate) fn evaluate(
    vectors: &[Vec<f32>],
    queries: &[Vec<f32>],
    requested_k: usize,
    breadth: usize,
    evidence_kind: EvidenceKind,
) -> PrecisionAxis {
    let dimensions = vectors.first().map_or(0, Vec::len);
    let k = requested_k.clamp(1, vectors.len().max(1));
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
    let baseline_recall = measures[0].mean_recall();
    let shape = RowShape {
        dimensions,
        vectors: vectors.len(),
        f32_bytes: PrecisionCandidate::F32.bytes_per_vector(dimensions),
        breadth,
        baseline_p50,
        baseline_recall,
    };
    let rows: Vec<PrecisionRow> = PrecisionCandidate::ALL
        .iter()
        .zip(&measures)
        .map(|(candidate, measure)| row(*candidate, measure, &shape))
        .collect();

    let moorcheh = moorcheh_evidence(rows.last());
    PrecisionAxis {
        requested_k,
        k,
        k_reduced_to_corpus: k != requested_k,
        dimensions,
        vectors: vectors.len(),
        queries: queries.len(),
        binary_prefix_breadth: breadth,
        binary_prefix_breadth_rule: BREADTH_RULE,
        ground_truth: GROUND_TRUTH_NOTE,
        recall_delta_rule: DELTA_RULE,
        f32_baseline_mean_recall_at_k: Cell::from_option(
            baseline_recall,
            "no float32 recall samples were collected, so there is no baseline to delta against",
        ),
        rows,
        moorcheh_binary_benchmark: moorcheh,
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
    baseline_recall: Option<f64>,
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
    let mean_recall = measure.mean_recall();
    let delta = if candidate == PrecisionCandidate::F32 {
        // The float32 row IS the baseline; its delta against itself is an
        // exact zero rather than a derived subtraction.
        mean_recall.map(|_| 0.0)
    } else {
        mean_recall
            .zip(shape.baseline_recall)
            .map(|(row, base)| row - base)
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
        mean_recall_delta_vs_f32: Cell::from_option(
            delta,
            format!(
                "a recall delta needs BOTH this {} row and the float32 baseline row measured in \
                 this run; at least one was not",
                candidate.as_str()
            ),
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

/// Identifies the parked Moorcheh binary benchmark and ties it to the local
/// binary-prefix row without inventing a Moorcheh number.
fn moorcheh_evidence(binary_row: Option<&PrecisionRow>) -> MoorchehEvidence {
    let missing = "the binary-prefix rescore row was not measured in this run";
    MoorchehEvidence {
        benchmark: MOORCHEH_BENCHMARK,
        parked_by_ticket: MOORCHEH_PARKED_TICKET,
        parked_by_ticket_url: MOORCHEH_PARKED_TICKET_URL,
        external_evidence_status: "parked_external_not_run_by_this_harness",
        run_by_this_harness: false,
        local_counterpart_row: PrecisionCandidate::BinaryPrefixRescore.as_str(),
        local_counterpart_recall_at_k: Cell::from_option(
            binary_row.and_then(|row| row.mean_recall_at_k.measured_f64()),
            missing,
        ),
        local_counterpart_recall_delta_vs_f32: Cell::from_option(
            binary_row.and_then(|row| row.mean_recall_delta_vs_f32.measured_f64()),
            missing,
        ),
        local_counterpart_bytes_per_vector: Cell::from_option(
            binary_row.map(|row| row.bytes_per_vector),
            missing,
        ),
        artifact_reference_source: MOORCHEH_REFERENCE_ENV,
        artifact_reference: Cell::from_option(
            declared_moorcheh_reference(),
            format!(
                "the Moorcheh binary benchmark is parked and was not run here; no traceable \
                 artifact reference was declared via {MOORCHEH_REFERENCE_ENV}, so no external \
                 comparison figure is emitted"
            ),
        ),
        note: MOORCHEH_NOTE,
    }
}

fn declared_moorcheh_reference() -> Option<String> {
    let raw = std::env::var(MOORCHEH_REFERENCE_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
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
}
