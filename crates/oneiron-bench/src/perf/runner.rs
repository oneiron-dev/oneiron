//! ONE-1579 run orchestration: measure every axis, then assemble the report.
//!
//! Ordering matters in exactly one place and it is deliberate: the COLD sample
//! set is taken first, on a vault handle that has just been reopened and has
//! served nothing. Everything else follows on the same handle.
//!
//! Assembly is where the fail-closed rules land. An under-floor full run has
//! its latency cells rewritten to not-applicable, the publication predicate is
//! evaluated over the measured axes rather than over the plan's intentions,
//! and provenance records what actually happened — including how many NVMe
//! operations completed and the content hash of the cache stream that produced
//! the reported hit rates.

use std::collections::BTreeMap;
use std::path::Path;

use oneiron::Vault;

use super::acceptance::{AcceptanceEvidence, AcceptanceInputs};
use super::axes::{
    GatedWriteAxis, REQUIRED_FULL_SESSION_CURVE, RecallLatencyAxis, ResidentMemoryAxis,
    SESSION_SYNCHRONIZATION_RULE, SessionsAxis, WakeAxis,
};
use super::cache_events::CacheAxis;
use super::cells::RunMode;
use super::corpus::{Corpus, generate_corpus, index_corpus, perf_vault_config};
use super::nvme::{NvmeFsyncAxis, describe_nvme_fsync};
use super::plan::PerfPlan;
use super::precision::{self, PrecisionAxis, PrecisionCandidate};
use super::provenance::{NodeIdentity, Provenance, ProvenanceInputs};
use super::publication::{self, PublicationInputs};
use super::report::{BEAM_RELATIONSHIP, PERF_REPORT_SCHEMA, PerfReport, SCORING_POLICY};
use super::{gated_writes, resident_memory, retrieval, sessions, wake};

const SESSIONS_NOTE: &str = "all sessions run concurrently against ONE open vault; each query is \
     `Vault::search_text_with_telemetry`, so the measured cost includes the engine's own \
     best-effort retrieval-telemetry persistence exactly as a real caller pays it";

/// Everything one run needs, already read off disk (or out of the fixtures).
pub(crate) struct RunInputs {
    pub(crate) plan: PerfPlan,
    pub(crate) plan_bytes: Vec<u8>,
    pub(crate) plan_source: String,
    pub(crate) cache_events: String,
    pub(crate) cache_source: String,
}

/// The measured axes, before they are wrapped in provenance and emitted.
struct MeasuredAxes {
    recall_latency: RecallLatencyAxis,
    wake: WakeAxis,
    sessions: SessionsAxis,
    resident_memory: ResidentMemoryAxis,
    gated_writes: GatedWriteAxis,
    precision: PrecisionAxis,
    cache: CacheAxis,
    nvme_fsync: NvmeFsyncAxis,
}

pub(crate) fn execute(inputs: &RunInputs) -> Result<PerfReport, String> {
    inputs.plan.validate().map_err(|error| error.to_string())?;
    let plan = &inputs.plan;
    let evidence = plan.mode.evidence_kind();
    let corpus = generate_corpus(
        plan.seed,
        plan.corpus.indexed_docs,
        plan.corpus.queries,
        plan.corpus.dimensions,
    )?;

    let root = tempfile::tempdir().map_err(|error| format!("perf tempdir failed: {error}"))?;
    let vault_dir = root.path().join("vault");
    std::fs::create_dir_all(&vault_dir)
        .map_err(|error| format!("perf vault dir failed: {error}"))?;
    let config = perf_vault_config(plan.corpus.indexed_docs, plan.sessions.max_sessions());
    {
        let builder = Vault::open(&vault_dir, config.clone())
            .map_err(|error| format!("perf vault open failed: {error}"))?;
        index_corpus(&builder, &corpus)?;
    }

    // COLD first, on a handle that has served nothing: no pre-seed, no warm,
    // no replay before the measurement window.
    let vault = Vault::open(&vault_dir, config)
        .map_err(|error| format!("perf vault reopen failed: {error}"))?;
    let cold = retrieval::measure_cold(&vault, &corpus, plan.corpus.k);
    let warm = retrieval::measure_warm(&vault, &corpus, plan.corpus.k, plan.corpus.warm_passes);
    let recall_latency = RecallLatencyAxis::new(
        plan.corpus.k,
        plan.corpus.indexed_docs,
        plan.corpus.queries,
        cold,
        warm,
        evidence,
    );
    let axes = measure_remaining_axes(inputs, &corpus, &vault, root.path(), recall_latency)?;
    Ok(finish(inputs, axes, &corpus.hash, &vault_dir))
}

/// Everything except the warm/cold sets, which the caller measures first so
/// the cold window is genuinely the first thing the vault handle serves.
fn measure_remaining_axes(
    inputs: &RunInputs,
    corpus: &Corpus,
    vault: &Vault,
    root: &Path,
    recall_latency: RecallLatencyAxis,
) -> Result<MeasuredAxes, String> {
    let plan = &inputs.plan;
    let mode = plan.mode.run_mode();
    let evidence = plan.mode.evidence_kind();
    let child_settings = plan.child_settings();
    let curve = sessions::measure_session_curve(
        vault,
        corpus,
        plan.corpus.k,
        &plan.sessions.curve,
        plan.sessions.queries_per_session,
    );
    let wake = wake::measure_wake(&root.join("wake"), &child_settings, evidence);
    let resident_memory = resident_memory::measure_resident_memory(
        &root.join("ready"),
        &child_settings,
        plan.resident_memory.ready_children,
        evidence,
    );
    let gated = gated_writes::measure_gated_writes(
        vault,
        plan.gated_writes.warmup,
        plan.gated_writes.measured,
        evidence,
    )?;
    let breadth = plan.precision.breadth(plan.corpus.k);
    let precision = precision::evaluate(
        &corpus.vectors,
        &corpus.query_vectors,
        plan.corpus.k,
        breadth,
        evidence,
    );
    let cache = CacheAxis::ingest(mode, &plan.cache.rungs, &inputs.cache_events)
        .map_err(|error| error.to_string())?;
    Ok(MeasuredAxes {
        recall_latency,
        wake,
        sessions: SessionsAxis {
            vaults: 1,
            required_full_curve: REQUIRED_FULL_SESSION_CURVE,
            requested_curve: plan.sessions.curve.clone(),
            exact_full_curve: plan.sessions.curve.as_slice()
                == REQUIRED_FULL_SESSION_CURVE.as_slice(),
            curve,
            evidence_kind: evidence,
            synchronization: SESSION_SYNCHRONIZATION_RULE,
            note: SESSIONS_NOTE,
        },
        resident_memory,
        gated_writes: gated,
        precision,
        cache,
        // The descriptive fsync probe writes its own scratch file at the run
        // root rather than inside the live vault directory; same mount, same
        // device, no interference with the open LMDB environment.
        nvme_fsync: describe_nvme_fsync(root, plan.nvme.probe(plan.seed)),
    })
}

/// Assembles the emitted report and applies the full-run floor rewrite.
fn finish(
    inputs: &RunInputs,
    mut axes: MeasuredAxes,
    corpus_hash: &str,
    vault_dir: &Path,
) -> PerfReport {
    let mode = inputs.plan.mode.run_mode();
    if mode.is_full() {
        axes.recall_latency.enforce_full_run_floor();
    }
    let node = NodeIdentity::collect();
    let decision = publication::decide(&publication_inputs(mode, &inputs.plan, &axes, &node));
    let acceptance = AcceptanceEvidence::collect(&AcceptanceInputs {
        recall_latency: &axes.recall_latency,
        wake: &axes.wake,
        sessions: &axes.sessions,
        resident_memory: &axes.resident_memory,
    });
    let provenance = Provenance::collect(ProvenanceInputs {
        plan_hash: blake3::hash(&inputs.plan_bytes).to_hex().to_string(),
        corpus_hash: corpus_hash.to_owned(),
        cache_events: inputs.cache_events.clone(),
        seed: inputs.plan.seed,
        sample_counts: sample_counts(&axes),
        evidence_kind: inputs.plan.mode.evidence_kind(),
        plan_source: inputs.plan_source.clone(),
        cache_source: inputs.cache_source.clone(),
        measured_path: vault_dir.to_path_buf(),
        node,
    });
    PerfReport {
        schema: PERF_REPORT_SCHEMA,
        mode,
        publishable: decision.publishable,
        non_publishable_reason: decision.non_publishable_reason.clone(),
        publication: decision,
        scoring_policy: SCORING_POLICY,
        beam_relationship: BEAM_RELATIONSHIP,
        plan_label: inputs.plan.label.clone(),
        provenance,
        acceptance,
        recall_latency: axes.recall_latency,
        wake: axes.wake,
        sessions: axes.sessions,
        resident_memory: axes.resident_memory,
        gated_writes: axes.gated_writes,
        precision: axes.precision,
        cache: axes.cache,
        nvme_fsync: axes.nvme_fsync,
    }
}

/// Flattens the measured axes into the publication predicate's inputs. Every
/// value here comes from what was MEASURED, never from what the plan asked
/// for.
fn publication_inputs(
    mode: RunMode,
    plan: &PerfPlan,
    axes: &MeasuredAxes,
    node: &NodeIdentity,
) -> PublicationInputs {
    let (retrieval_measurements_valid, retrieval_detail) =
        retrieval_publication_state(plan, &axes.recall_latency);
    let (wake_axis_valid, wake_detail) = wake_publication_state(plan, &axes.wake);
    let (session_curve_valid, session_detail) = sessions_publication_state(plan, &axes.sessions);
    let (resident_memory_valid, resident_memory_detail) =
        resident_memory_publication_state(&axes.resident_memory);
    let (precision_axis_valid, precision_detail) =
        precision_publication_state(plan, &axes.precision);
    let (cache_axis_valid, cache_detail) = cache_publication_state(plan, &axes.cache);
    PublicationInputs {
        mode,
        meets_plan_floor: axes.recall_latency.meets_plan_floor,
        meets_completed_sample_floor: axes.recall_latency.meets_completed_sample_floor,
        cold_completed: axes.recall_latency.cold.samples,
        warm_completed: axes.recall_latency.warm.samples,
        completed_sample_floor: axes.recall_latency.cold.completed_sample_floor,
        retrieval_measurements_valid,
        retrieval_detail,
        wake_axis_valid,
        wake_detail,
        session_curve_valid,
        session_detail,
        resident_memory_valid,
        resident_memory_detail,
        gated_write_meets_floor: axes.gated_writes.meets_full_run_floor,
        warmup_attempts: axes.gated_writes.warmup_attempts,
        warmup_commits: axes.gated_writes.warmup_commits,
        warmup_commit_errors: axes.gated_writes.warmup_commit_errors,
        measured_commits: axes.gated_writes.measured_commits,
        commits_ok: axes.gated_writes.commits_ok,
        commit_errors: axes.gated_writes.commit_errors,
        gate_decisions_recorded: axes.gated_writes.gate_decisions_recorded,
        one_decision_per_commit: axes.gated_writes.one_decision_per_commit,
        precision_axis_valid,
        precision_detail,
        cache_axis_valid,
        cache_detail,
        node_is_designated_first_tokyo: node.is_designated_first_tokyo_node,
        node_detail: node.publication_detail(),
        nvme_sanity_ok: axes.nvme_fsync.sanity_ok(),
        nvme_detail: axes.nvme_fsync.publication_detail(),
    }
}

fn retrieval_publication_state(plan: &PerfPlan, axis: &RecallLatencyAxis) -> (bool, String) {
    let set_valid = |set: &super::axes::SampleSet| {
        set.samples == plan.corpus.queries
            && set.errors == 0
            && set
                .latency_ms
                .value()
                .is_some_and(|percentiles| percentiles.count == set.samples)
            && set
                .recall_at_k
                .value()
                .is_some_and(|percentiles| percentiles.count == set.samples)
    };
    let valid = axis.meets_full_run_floor
        && set_valid(&axis.cold)
        && set_valid(&axis.warm)
        && axis.k == plan.corpus.k
        && axis.indexed_docs == plan.corpus.indexed_docs
        && axis.queries == plan.corpus.queries;
    (
        valid,
        format!(
            "cold completed {} of {} planned calls with {} errors; warm completed {} of {} with \
             {} errors; both latency and recall distributions must contain every planned call",
            axis.cold.samples,
            plan.corpus.queries,
            axis.cold.errors,
            axis.warm.samples,
            plan.corpus.queries,
            axis.warm.errors
        ),
    )
}

fn wake_publication_state(plan: &PerfPlan, axis: &WakeAxis) -> (bool, String) {
    let percentile_samples = axis
        .spawn_to_ready_ms
        .value()
        .map_or(0, |percentiles| percentiles.count);
    let shutdowns: usize = axis.shutdown_outcomes.values().sum();
    let valid = axis.samples == plan.wake.samples
        && percentile_samples == axis.samples
        && axis.child.is_measured()
        && axis.errors.is_empty()
        && shutdowns == axis.samples;
    (
        valid,
        format!(
            "{} of {} requested children reached completed TCP accept; percentile count {}; {} \
             probe error(s); {} bounded shutdown outcome(s)",
            axis.samples,
            plan.wake.samples,
            percentile_samples,
            axis.errors.len(),
            shutdowns
        ),
    )
}

fn sessions_publication_state(plan: &PerfPlan, axis: &SessionsAxis) -> (bool, String) {
    let points_valid =
        axis.curve
            .iter()
            .zip(REQUIRED_FULL_SESSION_CURVE)
            .all(|(point, expected_sessions)| {
                let Some(expected_queries) =
                    expected_sessions.checked_mul(plan.sessions.queries_per_session)
                else {
                    return false;
                };
                point.sessions == expected_sessions
                    && point.workers_released == expected_sessions
                    && point.synchronized
                    && point.queries == expected_queries
                    && point.errors == 0
                    && point
                        .latency_ms
                        .value()
                        .is_some_and(|percentiles| percentiles.count == expected_queries)
                    && point.throughput_qps.is_measured()
            });
    let valid = axis.vaults == 1
        && axis.exact_full_curve
        && axis.requested_curve.as_slice() == REQUIRED_FULL_SESSION_CURVE.as_slice()
        && axis.curve.len() == REQUIRED_FULL_SESSION_CURVE.len()
        && points_valid;
    let point_states: Vec<String> = axis
        .curve
        .iter()
        .map(|point| {
            format!(
                "{} sessions: released {}, synchronized={}, completed {}, errors={}, latency={}, throughput={}",
                point.sessions,
                point.workers_released,
                point.synchronized,
                point.queries,
                point.errors,
                point.latency_ms.is_measured(),
                point.throughput_qps.is_measured()
            )
        })
        .collect();
    (
        valid,
        format!(
            "requested {:?}, {} queries/session; emitted {} point(s) against {} vault(s): {:?}",
            axis.requested_curve,
            plan.sessions.queries_per_session,
            axis.curve.len(),
            axis.vaults,
            point_states
        ),
    )
}

fn resident_memory_publication_state(axis: &ResidentMemoryAxis) -> (bool, String) {
    let rss_values = axis.per_child_rss_bytes.value();
    let rss_samples = rss_values.map_or(0, Vec::len);
    let rss_total = rss_values.and_then(|samples| {
        samples
            .iter()
            .try_fold(0_u64, |total, sample| total.checked_add(*sample))
    });
    let rss_mean = rss_total
        .zip((rss_samples > 0).then_some(rss_samples as u64))
        .map(|(total, count)| total / count);
    let valid = axis.required_ready_children == super::axes::REQUIRED_READY_CHILDREN
        && axis.ready_children_observed == axis.required_ready_children
        && axis.sampled_while_all_children_ready
        && axis.child_holds_open_vault
        && rss_samples == axis.required_ready_children
        && axis.total_child_rss_bytes.value().copied() == rss_total
        && axis.mean_child_rss_bytes.value().copied() == rss_mean
        && axis.errors.is_empty();
    (
        valid,
        format!(
            "observed {} of {} ready children with {} RSS samples; sampled together={}; open-vault \
             residency proven={}; errors={}; provenance: {}",
            axis.ready_children_observed,
            axis.required_ready_children,
            rss_samples,
            axis.sampled_while_all_children_ready,
            axis.child_holds_open_vault,
            axis.errors.len(),
            axis.vault_residency_evidence
        ),
    )
}

fn precision_publication_state(plan: &PerfPlan, axis: &PrecisionAxis) -> (bool, String) {
    let candidates: Vec<PrecisionCandidate> = axis.rows.iter().map(|row| row.candidate).collect();
    let expected_breadth = plan.precision.breadth(plan.corpus.k);
    let row_valid = |row: &super::precision::PrecisionRow| {
        row.mean_recall_at_k.is_measured()
            && row.mean_recall_delta_vs_f32.is_measured()
            && row
                .recall_at_k
                .value()
                .is_some_and(|percentiles| percentiles.count == plan.corpus.queries)
            && row
                .scan_latency_ms
                .value()
                .is_some_and(|percentiles| percentiles.count == plan.corpus.queries)
            && match row.candidate {
                PrecisionCandidate::BinaryPrefixRescore => {
                    row.prefix_breadth == Some(expected_breadth)
                }
                _ => row.prefix_breadth.is_none(),
            }
    };
    let complete_rows = axis.rows.iter().filter(|row| row_valid(row)).count();
    let rows_valid = complete_rows == axis.rows.len();
    let valid = axis.requested_k == plan.corpus.k
        && axis.k == plan.corpus.k
        && !axis.k_reduced_to_corpus
        && axis.dimensions == plan.corpus.dimensions
        && axis.vectors == plan.corpus.indexed_docs
        && axis.queries == plan.corpus.queries
        && axis.binary_prefix_breadth == expected_breadth
        && candidates.as_slice() == PrecisionCandidate::ALL.as_slice()
        && axis.f32_baseline_mean_recall_at_k.is_measured()
        && rows_valid;
    (
        valid,
        format!(
            "precision emitted candidates {:?}, {}/{} complete row(s), k {} (requested {}), \
             breadth {} (planned {})",
            candidates,
            complete_rows,
            PrecisionCandidate::ALL.len(),
            axis.k,
            axis.requested_k,
            axis.binary_prefix_breadth,
            expected_breadth
        ),
    )
}

fn cache_publication_state(plan: &PerfPlan, axis: &CacheAxis) -> (bool, String) {
    let rows_valid = axis.rows.len() == plan.cache.rungs.len()
        && axis
            .rows
            .iter()
            .zip(&plan.cache.rungs)
            .all(|(row, expected)| {
                row.rung == *expected
                    && row.events > 0
                    && row.hits + row.misses == row.events
                    && row.hit_rate.is_measured()
            });
    let events_reported: usize = axis.rows.iter().map(|row| row.events).sum();
    let silent: Vec<&str> = axis
        .rows
        .iter()
        .filter(|row| row.events == 0 || !row.hit_rate.is_measured())
        .map(|row| row.rung.as_str())
        .collect();
    let valid = axis.source_kind == "real_traffic_only"
        && axis.rungs_listed == plan.cache.rungs
        && rows_valid
        && events_reported == axis.events_admitted;
    (
        valid,
        format!(
            "listed {:?}, emitted {} row(s), admitted {} real-traffic event(s), silent or invalid \
             rung(s): {:?}",
            axis.rungs_listed,
            axis.rows.len(),
            axis.events_admitted,
            silent
        ),
    )
}

fn sample_counts(axes: &MeasuredAxes) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    counts.insert("cold_queries".to_owned(), axes.recall_latency.cold.samples);
    counts.insert("warm_queries".to_owned(), axes.recall_latency.warm.samples);
    counts.insert("wake_probes".to_owned(), axes.wake.samples);
    counts.insert("session_curve_points".to_owned(), axes.sessions.curve.len());
    counts.insert(
        "ready_children".to_owned(),
        axes.resident_memory.ready_children_observed,
    );
    counts.insert(
        "gated_write_warmup_attempts".to_owned(),
        axes.gated_writes.warmup_attempts,
    );
    counts.insert(
        "gated_write_warmup_commits_ok".to_owned(),
        axes.gated_writes.warmup_commits,
    );
    counts.insert(
        "gated_write_commits_ok".to_owned(),
        axes.gated_writes.commits_ok,
    );
    counts.insert(
        "gated_write_commits_attempted".to_owned(),
        axes.gated_writes.measured_commits,
    );
    counts.insert("precision_rows".to_owned(), axes.precision.rows.len());
    counts.insert("cache_events".to_owned(), axes.cache.events_admitted);
    // COMPLETED operations, not the requested count: a probe that was skipped
    // on a non-NVMe mount must not claim the operations it never ran.
    counts.insert(
        "nvme_fsync_ops_completed".to_owned(),
        axes.nvme_fsync.completed_ops(),
    );
    counts
}

#[cfg(test)]
mod tests {
    use super::super::cells::{Cell, EvidenceKind};
    use super::super::child_process::{ChildSettings, minimum_child_hold_ms};
    use super::super::nvme::NvmeProbe;
    use super::*;

    /// Provenance must count NVMe operations that ACTUALLY RAN. A smoke on an
    /// overlay or tmpfs mount skips the fsync loops entirely, and reporting
    /// the requested count there would claim work that never happened.
    #[test]
    fn provenance_counts_completed_nvme_operations_not_requested_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = NvmeProbe {
            sequential_ops: 16,
            random_ops: 16,
            block_bytes: 4096,
            seed: 1579,
        };
        let axis = describe_nvme_fsync(dir.path(), probe);
        let requested = axis.sequential_ops + axis.random_ops;
        assert_eq!(requested, 32, "the plan asked for 32 operations");

        if axis.status == "not_ready" {
            assert_eq!(
                axis.completed_ops(),
                0,
                "a skipped probe completed nothing, so provenance must not report 32"
            );
        } else {
            assert_eq!(
                axis.completed_ops(),
                requested,
                "a probe that ran completed everything it timed"
            );
        }
        assert!(axis.completed_ops() <= requested);
    }

    fn idle_child_settings() -> ChildSettings {
        ChildSettings {
            samples: 0,
            timeout_ms: 100,
            hold_ms: minimum_child_hold_ms(100),
            child: None,
        }
    }

    /// A deliberately under-floor set of measured axes, built the same way a
    /// real run builds them so the predicate reads genuine measurements.
    fn under_floor_axes(dir: &Path, vault: &Vault) -> MeasuredAxes {
        let gated = gated_writes::measure_gated_writes(vault, 1, 3, EvidenceKind::SyntheticSmoke)
            .expect("gated-write axis measures");
        let corpus = generate_corpus(1, 4, 2, 4).expect("corpus");
        MeasuredAxes {
            recall_latency: RecallLatencyAxis::new(
                2,
                4,
                2,
                retrieval::measure_cold(vault, &corpus, 2),
                retrieval::measure_warm(vault, &corpus, 2, 0),
                EvidenceKind::SyntheticSmoke,
            ),
            wake: wake::measure_wake(
                &dir.join("wake"),
                &idle_child_settings(),
                EvidenceKind::SyntheticSmoke,
            ),
            sessions: SessionsAxis {
                vaults: 1,
                required_full_curve: REQUIRED_FULL_SESSION_CURVE,
                requested_curve: vec![1],
                exact_full_curve: false,
                curve: Vec::new(),
                evidence_kind: EvidenceKind::SyntheticSmoke,
                synchronization: SESSION_SYNCHRONIZATION_RULE,
                note: SESSIONS_NOTE,
            },
            resident_memory: resident_memory::measure_resident_memory(
                &dir.join("ready"),
                &idle_child_settings(),
                10,
                EvidenceKind::SyntheticSmoke,
            ),
            gated_writes: gated,
            precision: precision::evaluate(
                &corpus.vectors,
                &corpus.query_vectors,
                2,
                4,
                EvidenceKind::SyntheticSmoke,
            ),
            cache: CacheAxis::ingest(
                RunMode::SyntheticSmoke,
                &["embedding".to_owned()],
                r#"{"rung":"embedding","outcome":"hit","source":"synthetic_smoke"}"#,
            )
            .expect("cache ingests"),
            nvme_fsync: describe_nvme_fsync(
                dir,
                NvmeProbe {
                    sequential_ops: 0,
                    random_ops: 0,
                    block_bytes: 4096,
                    seed: 1,
                },
            ),
        }
    }

    /// The publication inputs are built from MEASURED axis state. A gated-write
    /// axis whose commits failed must reach the predicate as a failure rather
    /// than as the plan's intention.
    #[test]
    fn publication_inputs_carry_measured_state_not_planned_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault =
            Vault::open(dir.path(), perf_vault_config(16, 2)).expect("vault opens for the axis");
        let axes = under_floor_axes(dir.path(), &vault);

        let node = NodeIdentity::collect();
        let plan = super::super::plan::full_plan_fixture();
        let inputs = publication_inputs(RunMode::Full, &plan, &axes, &node);
        assert_eq!(inputs.measured_commits, 3);
        assert_eq!(
            inputs.commits_ok + inputs.commit_errors,
            3,
            "every attempted commit reaches the predicate"
        );
        assert_eq!(inputs.cold_completed, axes.recall_latency.cold.samples);
        assert!(
            !inputs.meets_plan_floor,
            "a four-doc fixture is under floor"
        );
        assert!(
            !inputs.wake_axis_valid,
            "an unavailable wake probe must reach publication as invalid"
        );
        assert!(
            !inputs.session_curve_valid,
            "an empty session curve must reach publication as invalid"
        );
        assert!(
            !inputs.resident_memory_valid,
            "not-ready ten-child RSS must reach publication as invalid"
        );

        let decision = publication::decide(&inputs);
        assert!(
            !decision.publishable,
            "an under-floor fixture on an undeclared node is never publishable"
        );
        assert!(
            decision
                .blocking_checks
                .contains(&"recall_latency_plan_floor")
        );

        let counts = sample_counts(&axes);
        assert_eq!(
            counts.get("nvme_fsync_ops_completed").copied(),
            Some(axes.nvme_fsync.completed_ops())
        );
        assert_eq!(
            counts.get("gated_write_commits_ok").copied(),
            Some(axes.gated_writes.commits_ok)
        );
        assert!(
            axes.resident_memory.child_hold_ms >= axes.resident_memory.minimum_child_hold_ms,
            "the axis reports the hold floor the plan was held to"
        );
        assert!(
            !matches!(
                axes.resident_memory.per_child_rss_bytes,
                Cell::NotApplicable { .. }
            ),
            "a ready-children sample set is measured or not_ready, never not_applicable"
        );
    }
}
