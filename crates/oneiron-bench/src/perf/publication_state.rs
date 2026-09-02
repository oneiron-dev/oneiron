//! Fail-closed projection from measured ONE-1579 axes into publication checks.
//!
//! This module never runs a workload. It verifies that every report cell is
//! arithmetically and structurally consistent with the admitted plan, then
//! flattens those facts for `publication::decide`.

use super::acceptance::AcceptanceEvidence;
use super::axes::{
    GatedWriteAxis, REQUIRED_FULL_SESSION_CURVE, RecallLatencyAxis, ResidentMemoryAxis,
    SessionsAxis, WakeAxis,
};
use super::cache_events::CacheAxis;
use super::cells::{Cell, RunMode};
use super::child_process::ResolvedChildProgram;
use super::nvme::NvmeFsyncAxis;
use super::plan::PerfPlan;
use super::precision::{PRECISION_WARMUP_PASSES, PrecisionAxis, PrecisionCandidate};
use super::provenance::{NodeIdentity, Provenance};
use super::publication::PublicationInputs;

/// Private bundle of measured axes for [`inputs`]. Keeps the projection at one
/// argument so clippy's argument-count lint does not fire on this mapper.
pub(crate) struct Inputs<'a> {
    pub(crate) mode: RunMode,
    pub(crate) plan: &'a PerfPlan,
    pub(crate) recall_latency: &'a RecallLatencyAxis,
    pub(crate) wake: &'a WakeAxis,
    pub(crate) sessions: &'a SessionsAxis,
    pub(crate) resident_memory: &'a ResidentMemoryAxis,
    pub(crate) gated_writes: &'a GatedWriteAxis,
    pub(crate) precision: &'a PrecisionAxis,
    pub(crate) cache: &'a CacheAxis,
    pub(crate) nvme_fsync: &'a NvmeFsyncAxis,
    pub(crate) node: &'a NodeIdentity,
    pub(crate) provenance: &'a Provenance,
    pub(crate) acceptance: &'a AcceptanceEvidence,
    /// The ready-child program this run resolved and hashed BEFORE spawning
    /// anything (ONE-1963).
    pub(crate) child_program: &'a ResolvedChildProgram,
}

pub(crate) fn inputs(source: Inputs<'_>) -> PublicationInputs {
    let Inputs {
        mode,
        plan,
        recall_latency,
        wake,
        sessions,
        resident_memory,
        gated_writes,
        precision,
        cache,
        nvme_fsync,
        node,
        provenance,
        acceptance,
        child_program,
    } = source;
    let (retrieval_measurements_valid, retrieval_detail) =
        retrieval_publication_state(plan, recall_latency);
    let (wake_axis_valid, wake_detail) = wake_publication_state(plan, wake);
    let (session_curve_valid, session_detail) = sessions_publication_state(plan, sessions);
    let (resident_memory_valid, resident_memory_detail) =
        resident_memory_publication_state(resident_memory);
    let (gated_write_measurements_valid, gated_write_detail) =
        gated_write_publication_state(plan, gated_writes);
    let (precision_axis_valid, precision_detail) = precision_publication_state(plan, precision);
    let (cache_axis_valid, cache_detail) = cache_publication_state(plan, cache);
    let (child_program_matches_build_revision, child_program_detail) =
        child_program_publication_state(child_program, &provenance.build_revision_blake3);
    let anchors = &provenance.corpus_query_evidence;
    PublicationInputs {
        mode,
        meets_plan_floor: recall_latency.meets_plan_floor,
        meets_completed_sample_floor: recall_latency.meets_completed_sample_floor,
        cold_completed: recall_latency.cold.samples,
        warm_completed: recall_latency.warm.samples,
        completed_sample_floor: recall_latency.cold.completed_sample_floor,
        retrieval_measurements_valid,
        retrieval_detail,
        wake_axis_valid,
        wake_detail,
        session_curve_valid,
        session_detail,
        resident_memory_valid,
        resident_memory_detail,
        gated_write_measurements_valid,
        gated_write_detail,
        gated_write_meets_floor: gated_writes.meets_full_run_floor,
        warmup_attempts: gated_writes.warmup_attempts,
        warmup_commits: gated_writes.warmup_commits,
        warmup_commit_errors: gated_writes.warmup_commit_errors,
        measured_commits: gated_writes.measured_commits,
        commits_ok: gated_writes.commits_ok,
        commit_errors: gated_writes.commit_errors,
        gate_decisions_recorded: gated_writes.gate_decisions_recorded,
        one_decision_per_commit: gated_writes.one_decision_per_commit,
        precision_axis_valid,
        precision_detail,
        cache_axis_valid,
        cache_detail,
        corpus_marker_evidence_valid: provenance.corpus_marker_evidence.collision_free
            && provenance.corpus_marker_evidence.documents == plan.corpus.indexed_docs
            && provenance.corpus_marker_evidence.unique_markers == plan.corpus.indexed_docs
            && provenance
                .corpus_marker_evidence
                .capacity_covers_full_usize_domain,
        corpus_marker_detail: format!(
            "{} indexed documents, {} unique planted markers; full-usize capacity={}",
            provenance.corpus_marker_evidence.documents,
            provenance.corpus_marker_evidence.unique_markers,
            provenance
                .corpus_marker_evidence
                .capacity_covers_full_usize_domain
        ),
        // Fail-closed: the queries a run reports must have probed as many
        // DISTINCT documents as the plan asked for queries. A wrapped anchor
        // would re-score a document another query already retrieved and
        // present it as an independent sample.
        corpus_query_anchors_distinct: anchors.anchors_distinct
            && anchors.indexed_docs == plan.corpus.indexed_docs
            && anchors.requested_queries == plan.corpus.queries
            && anchors.emitted_queries == plan.corpus.queries
            && anchors.distinct_anchors == plan.corpus.queries
            && anchors.distinct_expected_documents == plan.corpus.queries,
        corpus_query_anchor_detail: format!(
            "{} planned queries over {} indexed documents emitted {} queries on {} distinct \
             anchors and {} distinct expected documents",
            plan.corpus.queries,
            anchors.indexed_docs,
            anchors.emitted_queries,
            anchors.distinct_anchors,
            anchors.distinct_expected_documents,
        ),
        measured_qps_acceptance_valid: acceptance.measured_qps.valid_for_lifecycle_support
            && !acceptance.measured_qps.valid_for_one_1537_embed_gate,
        measured_qps_acceptance_detail: format!(
            "ONE-1578 support at {} sessions from `{}`; measured={}, and explicitly not ONE-1537 embed-gate evidence",
            acceptance.measured_qps.sessions,
            acceptance.measured_qps.source_report_cell,
            acceptance.measured_qps.measured_qps.is_measured(),
        ),
        build_revision_valid: provenance.build_revision_blake3.is_measured(),
        build_revision_detail: format!(
            "running artifact revision measured={}, source: {}",
            provenance.build_revision_blake3.is_measured(),
            provenance.build_revision_source
        ),
        // Fail-closed: only an embedded, explicit `clean` satisfies this. A
        // `not_ready` cell means the artifact carries no build-tree evidence
        // at all, which is exactly as unpublishable as a declared dirty tree.
        build_tree_clean: provenance.build_tree_dirty.value() == Some(&false),
        build_tree_detail: format!(
            "compile-time build-tree cleanliness: dirty={:?}, source: {}",
            provenance.build_tree_dirty.value(),
            provenance.build_tree_dirty_source
        ),
        // The MEASURED compiled settings, never the declared profile name.
        build_settings_optimized: provenance.build_profile.approved_for_publication,
        build_settings_detail: provenance.build_profile.publication_detail(),
        node_is_designated_first_tokyo: node.is_designated_first_tokyo_node,
        node_detail: node.publication_detail(),
        nvme_sanity_ok: nvme_fsync.sanity_ok(),
        nvme_detail: nvme_fsync.publication_detail(),
        child_program_matches_build_revision,
        child_program_detail,
        // ONE-1961 runtime trust: a child program the OPERATOR named is a
        // value they chose, whatever the static table says about digests being
        // measured. A full run never reaches this — the override is refused
        // before any axis runs — so this is the second net under a closed door.
        runtime_operator_declared_inputs: if child_program.overridden_by_environment {
            vec!["child_program_blake3"]
        } else {
            Vec::new()
        },
    }
}

/// ONE-1963: the artifact that measured the run must be the artifact that was
/// spawned as its ready child.
///
/// Fail-closed on either digest being unavailable: "we could not hash one of
/// them" is not evidence that they matched.
fn child_program_publication_state(
    child: &ResolvedChildProgram,
    build_revision: &Cell<String>,
) -> (bool, String) {
    let spawned = child.path.as_ref().map_or_else(
        || "<none>".to_owned(),
        |path| format!("`{}`", path.display()),
    );
    match (child.blake3.value(), build_revision.value()) {
        (Some(child_digest), Some(revision)) => (
            child_digest == revision,
            format!(
                "ready-child program {spawned} hashes to {child_digest}; the measuring artifact is \
                 {revision} (harness_owned={}, environment_override={})",
                child.harness_owned, child.overridden_by_environment
            ),
        ),
        (child_digest, revision) => (
            false,
            format!(
                "the ready-child program {spawned} and the measuring artifact cannot be compared: \
                 child digest measured={}, build revision measured={}; an unhashed pair is not a \
                 match",
                child_digest.is_some(),
                revision.is_some()
            ),
        ),
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
    let unreapable = axis
        .shutdown_outcomes
        .get("unreapable")
        .copied()
        .unwrap_or(0);
    let valid = axis.samples == plan.wake.samples
        && percentile_samples == axis.samples
        && axis.child.is_measured()
        && axis.errors.is_empty()
        && shutdowns == axis.samples
        && unreapable == 0;
    (
        valid,
        format!(
            "{} of {} requested children reached completed TCP accept; percentile count {}; {} \
             probe error(s); {} bounded shutdown outcome(s), {} unreapable",
            axis.samples,
            plan.wake.samples,
            percentile_samples,
            axis.errors.len(),
            shutdowns,
            unreapable
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

fn gated_write_publication_state(plan: &PerfPlan, axis: &GatedWriteAxis) -> (bool, String) {
    let successful_latency_count = axis
        .commit_latency_ms
        .value()
        .map_or(0, |percentiles| percentiles.count);
    let failed_latency_count = axis
        .failed_attempt_latency_ms
        .value()
        .map_or(0, |percentiles| percentiles.count);
    let warmup_errors_reported: usize = axis.warmup_error_kinds.values().sum();
    let measured_errors_reported: usize = axis.error_kinds.values().sum();
    let outcomes_reported: usize = axis.gate_outcomes.values().sum();
    let successful_rate = axis.commits_per_second.measured_f64();
    let attempted_rate = axis.attempted_commits_per_second.measured_f64();
    let derived_successful_rate =
        (axis.wall_clock_ms.is_finite() && axis.wall_clock_ms > 0.0 && axis.commits_ok > 0)
            .then(|| axis.commits_ok as f64 / (axis.wall_clock_ms / 1e3));
    let rate_agrees =
        successful_rate
            .zip(derived_successful_rate)
            .is_some_and(|(reported, derived)| {
                reported.is_finite()
                    && reported > 0.0
                    && (reported - derived).abs()
                        <= f64::EPSILON * reported.abs().max(derived.abs()) * 8.0
            });
    let valid = axis.warmup_attempts == plan.gated_writes.warmup
        && axis.warmup_commits + axis.warmup_commit_errors == axis.warmup_attempts
        && warmup_errors_reported == axis.warmup_commit_errors
        && axis.measured_commits == plan.gated_writes.measured
        && axis.commits_ok + axis.commit_errors == axis.measured_commits
        && measured_errors_reported == axis.commit_errors
        && successful_latency_count == axis.commits_ok
        && failed_latency_count == axis.commit_errors
        && rate_agrees
        && attempted_rate.is_some_and(|rate| rate.is_finite() && rate > 0.0)
        && outcomes_reported == axis.gate_decisions_recorded;
    (
        valid,
        format!(
            "warmup {} ok + {} failed of {}; measured {} ok + {} failed of {}; successful latency samples={}, failed latency samples={}, successful QPS traceable={}, gate outcomes={} of {} decisions",
            axis.warmup_commits,
            axis.warmup_commit_errors,
            axis.warmup_attempts,
            axis.commits_ok,
            axis.commit_errors,
            axis.measured_commits,
            successful_latency_count,
            failed_latency_count,
            rate_agrees,
            outcomes_reported,
            axis.gate_decisions_recorded,
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
            // Every row must have been warmed with the same treatment: a row
            // whose warm-up count is short was timed colder than its
            // neighbours, which makes the latency column incomparable.
            && row.warmup_scans == axis.warmup_scans_per_candidate
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
        && axis.requested_binary_prefix_breadth == expected_breadth
        && axis.binary_prefix_breadth == expected_breadth
        && !axis.binary_prefix_breadth_reshaped
        && candidates.as_slice() == PrecisionCandidate::ALL.as_slice()
        && axis.f32_baseline_mean_recall_at_k.is_measured()
        && axis.warmup_passes_per_candidate == PRECISION_WARMUP_PASSES
        && axis.warmup_scans_per_candidate == PRECISION_WARMUP_PASSES * plan.corpus.queries
        && rows_valid;
    (
        valid,
        format!(
            "precision emitted candidates {:?}, {}/{} complete row(s), k {} (requested {}), \
             breadth {} (planned {}), {} warm-up scan(s) per candidate before timing",
            candidates,
            complete_rows,
            PrecisionCandidate::ALL.len(),
            axis.k,
            axis.requested_k,
            axis.binary_prefix_breadth,
            expected_breadth,
            axis.warmup_scans_per_candidate,
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
    // Completeness is still checked exactly as strictly as before. What
    // changed in ONE-1961 is what a PASS is worth: the stream is
    // operator-declared, so this check is advisory and its result is a caveat
    // rather than a licence. Nothing here tries to make it stronger than that
    // — an assertion inside the stream about the stream cannot.
    let valid = axis.rungs_listed == plan.cache.rungs
        && rows_valid
        && events_reported == axis.events_admitted;
    (
        valid,
        format!(
            "listed {:?}, emitted {} row(s), admitted {} real-traffic event(s) from an \
             operator-declared stream (advisory evidence: the rows declare their own source), \
             silent or invalid rung(s): {:?}",
            axis.rungs_listed,
            axis.rows.len(),
            axis.events_admitted,
            silent
        ),
    )
}
