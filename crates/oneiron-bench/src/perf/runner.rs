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
use super::certificate::{self, PERF_CANDIDATE_CONTRACT_VERSION};
use super::child_process::{self, ResolvedChildProgram};
use super::corpus::{Corpus, generate_corpus, index_corpus, perf_vault_config};
use super::nvme::{NvmeFsyncAxis, describe_nvme_fsync};
use super::plan::PerfPlan;
use super::precision::{self, PrecisionAxis};
use super::provenance::{NodeIdentity, Provenance, ProvenanceInputs};
use super::publication;
use super::publication_state;
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

    // ONE-1963, BEFORE any axis. Two separate things happen here and the order
    // matters: a full run with an environment-pinned ready child is refused
    // outright rather than measured and downgraded, and whatever program WILL
    // be spawned is hashed while it is still the program that will be spawned.
    // Hashing after the run would hash whatever is on that path afterwards.
    let child_program = child_process::resolve_and_hash_child_program(
        plan.mode.run_mode(),
        plan.wake.child.as_ref(),
    )?;

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
    finish(inputs, axes, &corpus, &vault_dir, &child_program)
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
    corpus: &Corpus,
    vault_dir: &Path,
    child_program: &ResolvedChildProgram,
) -> Result<PerfReport, String> {
    let mode = inputs.plan.mode.run_mode();
    if mode.is_full() {
        axes.recall_latency.enforce_full_run_floor();
    }
    let node = NodeIdentity::collect();
    let provenance = Provenance::collect(ProvenanceInputs {
        plan_hash: blake3::hash(&inputs.plan_bytes).to_hex().to_string(),
        corpus_hash: corpus.hash.clone(),
        corpus_marker_evidence: corpus.marker_evidence.clone(),
        corpus_query_evidence: corpus.query_evidence.clone(),
        cache_events: inputs.cache_events.clone(),
        seed: inputs.plan.seed,
        sample_counts: sample_counts(&axes),
        evidence_kind: inputs.plan.mode.evidence_kind(),
        plan_source: inputs.plan_source.clone(),
        cache_source: inputs.cache_source.clone(),
        measured_path: vault_dir.to_path_buf(),
        node: node.clone(),
    });
    let acceptance = AcceptanceEvidence::collect(&AcceptanceInputs {
        recall_latency: &axes.recall_latency,
        wake: &axes.wake,
        sessions: &axes.sessions,
        resident_memory: &axes.resident_memory,
    });
    let decision = publication::decide(&publication_state::inputs(publication_state::Inputs {
        mode,
        plan: &inputs.plan,
        recall_latency: &axes.recall_latency,
        wake: &axes.wake,
        sessions: &axes.sessions,
        resident_memory: &axes.resident_memory,
        gated_writes: &axes.gated_writes,
        precision: &axes.precision,
        cache: &axes.cache,
        nvme_fsync: &axes.nvme_fsync,
        node: &node,
        provenance: &provenance,
        acceptance: &acceptance,
        child_program,
    }));
    // Sealed over the axes and provenance exactly as they will be emitted, and
    // fail-closed: a report whose hashes cannot be computed does not ship.
    let certificate = certificate::seal(certificate::CertificateInputs {
        axes: certificate::AxesView {
            recall_latency: &axes.recall_latency,
            wake: &axes.wake,
            sessions: &axes.sessions,
            resident_memory: &axes.resident_memory,
            gated_writes: &axes.gated_writes,
            precision: &axes.precision,
            cache: &axes.cache,
            nvme_fsync: &axes.nvme_fsync,
        },
        provenance: &provenance,
        child_program_blake3: child_program.blake3.clone(),
    })?;
    Ok(PerfReport {
        schema: PERF_REPORT_SCHEMA,
        contract_version: PERF_CANDIDATE_CONTRACT_VERSION,
        mode,
        publication_candidate: decision.candidate,
        non_candidate_reason: decision.non_candidate_reason.clone(),
        publication: decision,
        certificate,
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
    })
}

/// Flattens the measured axes into the publication predicate's inputs. Every
/// value here comes from what was MEASURED, never from what the plan asked
/// for.
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
    use super::super::cells::{Cell, EvidenceKind, RunMode};
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

    /// Every count the certificate's statistics block reads must be tallied by
    /// this runner. A missing one is a sealing failure, not a zero, so the two
    /// tables are asserted against each other rather than kept in step by hand.
    fn certificate_statistics_are_derivable(counts: &BTreeMap<String, usize>) {
        for (axis, key) in certificate::AXIS_SAMPLE_SOURCES {
            assert!(
                counts.contains_key(key),
                "the `{axis}` axis reports its sample size from `sample_counts.{key}`, which this \
                 runner did not tally"
            );
        }
    }

    /// One bench-owned smoke cache row, explicitly synthetic.
    const SMOKE_CACHE_EVENT: &str =
        r#"{"rung":"embedding","outcome":"hit","source":"synthetic_smoke"}"#;

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
                SMOKE_CACHE_EVENT,
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
        let corpus = generate_corpus(1, 4, 2, 4).expect("corpus");
        let provenance = Provenance::collect(ProvenanceInputs {
            plan_hash: "plan".to_owned(),
            corpus_hash: corpus.hash,
            corpus_marker_evidence: corpus.marker_evidence,
            corpus_query_evidence: corpus.query_evidence,
            cache_events: "event".to_owned(),
            seed: 1,
            sample_counts: sample_counts(&axes),
            evidence_kind: EvidenceKind::SyntheticSmoke,
            plan_source: "fixture".to_owned(),
            cache_source: "fixture".to_owned(),
            measured_path: dir.path().to_path_buf(),
            node: node.clone(),
        });
        let acceptance = AcceptanceEvidence::collect(&AcceptanceInputs {
            recall_latency: &axes.recall_latency,
            wake: &axes.wake,
            sessions: &axes.sessions,
            resident_memory: &axes.resident_memory,
        });
        let inputs = publication_state::inputs(publication_state::Inputs {
            mode: RunMode::Full,
            plan: &plan,
            recall_latency: &axes.recall_latency,
            wake: &axes.wake,
            sessions: &axes.sessions,
            resident_memory: &axes.resident_memory,
            gated_writes: &axes.gated_writes,
            precision: &axes.precision,
            cache: &axes.cache,
            nvme_fsync: &axes.nvme_fsync,
            node: &node,
            provenance: &provenance,
            acceptance: &acceptance,
            child_program: &child_process::resolve_and_hash_child_program(
                RunMode::SyntheticSmoke,
                None,
            )
            .expect("a smoke resolves its ready child"),
        });
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
            !decision.candidate,
            "an under-floor fixture on an undeclared node is never a publication candidate"
        );
        assert!(
            decision
                .blocking_checks
                .contains(&"recall_latency_plan_floor")
        );

        // Every count the certificate's statistics block reads is present, so
        // sealing a report over these axes cannot fail for a missing count.
        let counts = sample_counts(&axes);
        certificate_statistics_are_derivable(&counts);
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
