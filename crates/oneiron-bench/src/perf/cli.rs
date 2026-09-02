//! ONE-1579 `perf` command surface: argument parsing, the bundled smoke, and
//! the rendered report.
//!
//! Output goes through explicit `io::Write` handles rather than print macros.
//! A bench harness whose stdout is piped into `head` should not die of a
//! panicking print macro half way through a run, and routing every line
//! through one place keeps the command's output surface reviewable in a single
//! spot.
//!
//! The emit path refuses to write a report that dropped an axis, a section or
//! a provenance field, so a partial report fails the command instead of
//! shipping.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::child_process;
use super::plan::{PerfPlan, PlanMode};
use super::report::{self, PerfReport};
use super::runner::{self, RunInputs};

const SMOKE_PLAN_FIXTURE_NAME: &str = "perf_smoke.plan.json";
const SMOKE_CACHE_FIXTURE_NAME: &str = "perf_smoke.cache.jsonl";
const SMOKE_PLAN_FIXTURE: &str = include_str!("../../fixtures/perf_smoke.plan.json");
const SMOKE_CACHE_FIXTURE: &str = include_str!("../../fixtures/perf_smoke.cache.jsonl");
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");

/// Writes one line to stdout, tolerating a closed pipe.
fn write_out(text: &str) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(text.as_bytes());
    let _ = handle.write_all(b"\n");
    let _ = handle.flush();
}

/// Writes one line to stderr, tolerating a closed pipe.
fn write_err(text: &str) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(text.as_bytes());
    let _ = handle.write_all(b"\n");
    let _ = handle.flush();
}

/// `perf` dispatch.
pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            write_out(help_text());
            ExitCode::SUCCESS
        }
        [first, ..] if is_help(first) => {
            write_out(help_text());
            ExitCode::SUCCESS
        }
        [sub, rest @ ..] if sub == "run" => finish_command(run_plan(rest)),
        [sub, rest @ ..] if sub == "smoke" => {
            if rest.is_empty() {
                finish_command(run_smoke_command())
            } else {
                write_err(&format!("perf smoke takes no arguments, got: {rest:?}"));
                ExitCode::FAILURE
            }
        }
        [sub, rest @ ..] if sub == "wake-child" => {
            finish_command(child_process::run_wake_child(rest))
        }
        [sub, ..] => {
            write_err(&format!("unknown perf subcommand: {sub}"));
            write_out(help_text());
            ExitCode::FAILURE
        }
    }
}

fn is_help(argument: &str) -> bool {
    matches!(argument, "--help" | "-h" | "help")
}

fn finish_command(outcome: Result<(), String>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            write_err(&format!("perf: {reason}"));
            ExitCode::FAILURE
        }
    }
}

const fn help_text() -> &'static str {
    "usage: oneiron-bench perf <subcommand>\n\
     \n\
     subcommands:\n\
       run --plan <JSON> --out <JSON>   run a perf plan and write the report\n\
       smoke                            run the bundled synthetic smoke; the report is\n\
                                        always marked synthetic_smoke and is never a\n\
                                        publication candidate\n\
       wake-child --ready-addr <ADDR> [--vault <DIR>] [--hold-ms <N>]\n\
                                        harness-internal ready child, spawned by the wake\n\
                                        and ready-children probes; not a user command\n\
     \n\
     the report emits eight axes side by side and never collapses them into one\n\
     score: warm/cold recall as separate sample sets, TCP-accept wake latency,\n\
     the [1, 10, 100, 300] concurrent-session curve against one vault, RSS across\n\
     exactly ten ready children, gated-write commits/s with one gate decision per\n\
     commit, F32/F16/Int8Sq/BinaryPrefixRescore precision rows (bench\n\
     representations only; engine storage is unchanged and persist stays f16),\n\
     real-traffic cache hit rates per listed rung, and a descriptive NVMe fsync\n\
     row. Accuracy and cost stay BEAM-owned.\n\
     \n\
     this command NEVER publishes. The strongest verdict it emits is\n\
     `publication_candidate`: every BLOCKING check satisfied — the doc/query and\n\
     COMPLETED-sample floors, the gated-write floor with zero failed commits and\n\
     exactly one gate decision per commit, the designated first Tokyo node\n\
     identity, a ready child that hashes to this same artifact, and a successful\n\
     NVMe sanity result. The cache axis is advisory: its stream is\n\
     operator-declared, so it is reported but never withholds candidacy.\n\
     `oneiron-eval perf-verify` decides publishability from the candidate plus\n\
     an independent build record."
}

fn run_plan(args: &[String]) -> Result<(), String> {
    let (plan_path, out_path) = parse_run_args(args)?;
    let plan_bytes = std::fs::read(&plan_path)
        .map_err(|error| format!("could not read plan `{}`: {error}", plan_path.display()))?;
    let parsed: PerfPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| format!("plan `{}` is not valid: {error}", plan_path.display()))?;
    parsed.validate().map_err(|error| error.to_string())?;

    let (cache_events, cache_source) = read_cache_events(&parsed, &plan_path)?;
    let inputs = RunInputs {
        plan: parsed,
        plan_bytes,
        plan_source: plan_path.display().to_string(),
        cache_events,
        cache_source,
    };
    let report = runner::execute(&inputs)?;
    let rendered = emit(&report)?;
    std::fs::write(&out_path, rendered)
        .map_err(|error| format!("could not write `{}`: {error}", out_path.display()))?;
    write_out(&summary(&report));
    write_out(&format!("report written to {}", out_path.display()));
    Ok(())
}

fn parse_run_args(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let mut plan = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("`{flag}` needs a value"))?;
        match flag {
            "--plan" => plan = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("unknown `perf run` flag `{other}`")),
        }
        index += 2;
    }
    let plan = plan.ok_or_else(|| "`perf run` requires --plan <JSON>".to_owned())?;
    let out = out.ok_or_else(|| "`perf run` requires --out <JSON>".to_owned())?;
    Ok((plan, out))
}

fn read_cache_events(plan: &PerfPlan, plan_path: &Path) -> Result<(String, String), String> {
    let Some(relative) = &plan.cache.events_path else {
        return Ok((
            String::new(),
            "none (the plan named no cache-event stream)".to_owned(),
        ));
    };
    let base = plan_path.parent().unwrap_or_else(|| Path::new("."));
    let resolved = base.join(relative);
    let contents = std::fs::read_to_string(&resolved).map_err(|error| {
        format!(
            "could not read cache events `{}`: {error}",
            resolved.display()
        )
    })?;
    Ok((contents, resolved.display().to_string()))
}

fn run_smoke_command() -> Result<(), String> {
    let report = smoke_report()?;
    let rendered = emit(&report)?;
    write_out(&summary(&report));
    write_out(&rendered);
    Ok(())
}

/// Runs the bundled synthetic smoke and returns its report.
pub(crate) fn smoke_report() -> Result<PerfReport, String> {
    let (plan_text, plan_source) = load_fixture(SMOKE_PLAN_FIXTURE_NAME, SMOKE_PLAN_FIXTURE);
    let (cache_events, cache_source) = load_fixture(SMOKE_CACHE_FIXTURE_NAME, SMOKE_CACHE_FIXTURE);
    let parsed: PerfPlan = serde_json::from_str(&plan_text)
        .map_err(|error| format!("the bundled smoke plan is not valid: {error}"))?;
    if parsed.mode != PlanMode::SyntheticSmoke {
        return Err("the bundled smoke plan must declare mode `synthetic_smoke`".to_owned());
    }
    let inputs = RunInputs {
        plan: parsed,
        plan_bytes: plan_text.into_bytes(),
        plan_source,
        cache_events,
        cache_source,
    };
    runner::execute(&inputs)
}

fn load_fixture(name: &str, embedded: &'static str) -> (String, String) {
    let path = Path::new(FIXTURE_DIR).join(name);
    match std::fs::read_to_string(&path) {
        Ok(contents) => (contents, format!("filesystem:{}", path.display())),
        Err(_) => (embedded.to_owned(), format!("embedded:{name}")),
    }
}

/// Renders the report, refusing to emit one that dropped an axis, a section or
/// a provenance field.
fn emit(report: &PerfReport) -> Result<String, String> {
    let value = serde_json::to_value(report)
        .map_err(|error| format!("the perf report could not be rendered: {error}"))?;
    let missing_axes = report::missing_axes(&value);
    if !missing_axes.is_empty() {
        return Err(format!("the perf report is missing axes: {missing_axes:?}"));
    }
    let missing_sections = report::missing_sections(&value);
    if !missing_sections.is_empty() {
        return Err(format!(
            "the perf report is missing sections: {missing_sections:?}"
        ));
    }
    let missing_provenance = report::missing_provenance_fields(&value);
    if !missing_provenance.is_empty() {
        return Err(format!(
            "the perf report is missing provenance: {missing_provenance:?}"
        ));
    }
    serde_json::to_string_pretty(&value)
        .map_err(|error| format!("the perf report could not be serialized: {error}"))
}

/// The human-readable block printed beside the rendered JSON.
fn summary(report: &PerfReport) -> String {
    let mut lines = vec![
        "== oneiron perf bench (ONE-1579) ==".to_owned(),
        format!(
            "mode: {} | publication_candidate: {} | plan: {}",
            report.mode.as_str(),
            report.publication_candidate,
            report.plan_label
        ),
    ];
    if let Some(reason) = &report.non_candidate_reason {
        lines.push(format!("not a publication candidate: {reason}"));
    }
    if !report.publication.blocking_checks.is_empty() {
        lines.push(format!(
            "blocking publication checks: {:?}",
            report.publication.blocking_checks
        ));
    }
    if !report.publication.advisory_failures.is_empty() {
        lines.push(format!(
            "advisory failures (reported, never blocking): {:?}",
            report.publication.advisory_failures
        ));
    }
    lines.push(format!(
        "certificate: {} (axes {}, provenance {})",
        report.certificate.certificate_blake3,
        report.certificate.body.axes_blake3,
        report.certificate.body.provenance_blake3,
    ));
    lines.push(
        "this harness emits a CANDIDATE only; `oneiron-eval perf-verify` decides publishability"
            .to_owned(),
    );
    lines.push(report.scoring_policy.to_owned());
    for (axis, measured) in [
        (
            "cold recall/latency",
            report.recall_latency.cold.latency_ms.is_measured(),
        ),
        (
            "warm recall/latency",
            report.recall_latency.warm.latency_ms.is_measured(),
        ),
        (
            "wake (tcp accept)",
            report.wake.spawn_to_ready_ms.is_measured(),
        ),
        (
            "ten ready children rss",
            report.resident_memory.total_child_rss_bytes.is_measured(),
        ),
        (
            "gated writes (successful commits/s)",
            report.gated_writes.commits_per_second.is_measured(),
        ),
        (
            "nvme fsync (descriptive)",
            report.nvme_fsync.sequential_fsync_ms.is_measured(),
        ),
    ] {
        let state = if measured { "measured" } else { "not measured" };
        lines.push(format!("  {axis}: {state}"));
    }
    lines.push(format!(
        "  sessions: {:?} against {} vault(s)",
        report.sessions.requested_curve, report.sessions.vaults
    ));
    lines.push(format!(
        "  precision rows: {} (binary prefix breadth {})",
        report.precision.rows.len(),
        report.precision.binary_prefix_breadth
    ));
    lines.push(format!("  cache rungs: {:?}", report.cache.rungs_listed));
    lines.push(format!(
        "  nvme fsync ops completed: {} of {} requested",
        report.nvme_fsync.completed_ops(),
        report.nvme_fsync.sequential_ops + report.nvme_fsync.random_ops
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::super::axes::{
        FULL_RUN_MIN_COMPLETED_SAMPLES, REQUIRED_FULL_SESSION_CURVE, REQUIRED_READY_CHILDREN,
        ReadinessSignal,
    };
    use super::super::cells::{Cell, RunMode};
    use super::super::certificate::{self, PERF_CANDIDATE_CONTRACT_VERSION};
    use super::super::child_process::minimum_child_hold_ms;
    use super::super::precision::{PrecisionCandidate, default_binary_prefix_breadth};
    use super::super::publication::SMOKE_NON_CANDIDATE_REASON;
    use super::super::report::{AXES, PERF_REPORT_SCHEMA};
    use super::*;

    #[test]
    fn the_bundled_smoke_plan_parses_and_validates() {
        let (text, _) = load_fixture(SMOKE_PLAN_FIXTURE_NAME, SMOKE_PLAN_FIXTURE);
        let parsed: PerfPlan = serde_json::from_str(&text).expect("the smoke plan parses");
        assert_eq!(parsed.mode, PlanMode::SyntheticSmoke);
        assert_eq!(
            parsed.resident_memory.ready_children, REQUIRED_READY_CHILDREN,
            "the RSS axis is defined at exactly ten ready children even for a smoke"
        );
        assert_eq!(
            parsed.precision.candidates.as_slice(),
            PrecisionCandidate::ALL.as_slice()
        );
        assert!(
            parsed.corpus.k <= parsed.corpus.indexed_docs,
            "the bundled plan may not ask for a k larger than its corpus"
        );
        assert!(
            parsed.wake.hold_ms >= minimum_child_hold_ms(parsed.wake.timeout_ms),
            "the bundled plan's child hold must outlast its accept window plus the sampling margin"
        );
        parsed.validate().expect("the bundled smoke plan validates");
    }

    #[test]
    fn the_help_text_keeps_both_perf_forms() {
        let help = help_text();
        assert!(help.contains("run --plan <JSON> --out <JSON>"), "{help}");
        assert!(help.contains("smoke"), "{help}");
        assert!(help.contains("wake-child"), "{help}");
        assert!(help.contains("[1, 10, 100, 300]"), "{help}");
        assert!(help.contains("first Tokyo node"), "{help}");
        assert!(help.contains("publication_candidate"), "{help}");
        assert!(help.contains("NEVER publishes"), "{help}");
        assert!(help.contains("perf-verify"), "{help}");
    }

    /// The smoke must run end to end against its bundled fixtures and emit
    /// every axis, section and provenance field, marked synthetic and never a
    /// publication candidate.
    ///
    /// The per-axis assertions live in the helpers below so the smoke is run
    /// ONCE and each group of claims stays readable on its own.
    #[test]
    fn perf_smoke_emits_every_axis() {
        let report = smoke_report().expect("the bundled smoke runs");

        assert_eq!(report.mode, RunMode::SyntheticSmoke);
        assert!(
            !report.publication_candidate,
            "a smoke is never a publication candidate"
        );
        assert_eq!(
            report.non_candidate_reason.as_deref(),
            Some(SMOKE_NON_CANDIDATE_REASON)
        );
        assert_eq!(report.schema, PERF_REPORT_SCHEMA);
        assert_eq!(report.contract_version, PERF_CANDIDATE_CONTRACT_VERSION);
        assert!(
            report
                .publication
                .blocking_checks
                .contains(&"run_mode_is_full"),
            "the smoke's own mode is the first thing that blocks it"
        );

        let value = serde_json::to_value(&report).expect("the report renders");
        assert_nothing_was_dropped(&value);
        assert_engine_axes(&report);
        assert_precision_and_cache_axes(&report);
        assert_environment_and_acceptance(&report);
        assert_certificate(&report, &value);

        // No collapsed score anywhere.
        let object = value.as_object().expect("report object");
        for forbidden in ["score", "overall_score", "composite", "beam_score"] {
            assert!(
                !object.contains_key(forbidden),
                "{forbidden} must not exist"
            );
        }
        // The v2 vocabulary, at the top level of the emitted document.
        assert!(
            !object.contains_key("publishable"),
            "schema v2 renamed `publishable` to `publication_candidate`"
        );
        assert!(!object.contains_key("non_publishable_reason"));
        assert!(object.contains_key("publication_candidate"));
        assert!(object.contains_key("contract_version"));
        assert!(object.contains_key("certificate"));

        assert!(emit(&report).is_ok());
        assert!(summary(&report).contains("publication_candidate: false"));
        assert!(summary(&report).contains("perf-verify"));
    }

    /// ONE-1961: the certificate says what the verdict was allowed to rest on
    /// and pins the exact bytes it was computed over. The digests are
    /// recomputed here the way the external verifier will recompute them —
    /// from the EMITTED document, not from the in-memory structs.
    fn assert_certificate(report: &PerfReport, value: &serde_json::Value) {
        let certificate = &report.certificate;
        assert_eq!(
            certificate.body.contract_version,
            PERF_CANDIDATE_CONTRACT_VERSION
        );

        // The scope partition covers every emitted axis exactly once, and the
        // advisory half is the operator-declared cache axis.
        let scope = &certificate.body.publication_scope;
        assert_eq!(scope.advisory_axes, ["cache"]);
        for axis in AXES {
            assert!(
                scope.blocking_axes.contains(&axis) ^ scope.advisory_axes.contains(&axis),
                "`{axis}` must be in exactly one half of the publication scope"
            );
        }

        // Statistical exposure (§8): every axis carries its sample size, every
        // axis ran once, and the single-trial list is present rather than
        // implied. A verifier treats its absence as a contract violation.
        let statistics = &certificate.body.statistics;
        assert_eq!(statistics.repeats, 1);
        assert_eq!(statistics.per_axis.len(), AXES.len());
        for axis in AXES {
            let row = statistics
                .per_axis
                .get(axis)
                .unwrap_or_else(|| panic!("`{axis}` must carry statistics"));
            assert_eq!(row.repeats, 1);
        }
        assert_eq!(
            statistics.per_axis.get("wake").map(|row| row.samples),
            report.provenance.sample_counts.get("wake_probes").copied()
        );
        assert!(!statistics.single_trial_axes.is_empty());

        // `axes_blake3` really is the digest of the eight emitted axis objects,
        // read back out of the rendered report.
        let mut emitted_axes = serde_json::Map::new();
        for axis in AXES {
            emitted_axes.insert(
                (*axis).to_owned(),
                value.get(axis).expect("the axis is emitted").clone(),
            );
        }
        assert_eq!(
            certificate::canonical_blake3("axes", &serde_json::Value::Object(emitted_axes))
                .expect("the emitted axes canonicalize"),
            certificate.body.axes_blake3,
            "axes_blake3 must cover exactly the axes the report emits"
        );
        assert_eq!(
            certificate::canonical_blake3(
                "provenance",
                value.get("provenance").expect("provenance is emitted")
            )
            .expect("the emitted provenance canonicalizes"),
            certificate.body.provenance_blake3,
        );

        // And the certificate's own digest reproduces from the emitted
        // document with the self-referential field removed.
        let mut emitted = value
            .get("certificate")
            .expect("the certificate is emitted")
            .clone();
        let reported = emitted
            .as_object_mut()
            .expect("certificate object")
            .remove("certificate_blake3")
            .expect("the certificate reports its own digest");
        assert_eq!(
            reported.as_str(),
            Some(certificate.certificate_blake3.as_str())
        );
        assert_eq!(
            certificate::canonical_blake3("certificate", &emitted).expect("recomputes"),
            certificate.certificate_blake3,
        );

        // The trust manifest travels with the report, and the cache row in it
        // is the operator-declared one.
        let cache = certificate
            .body
            .trust_inputs
            .iter()
            .find(|row| row.name == "cache_events")
            .expect("the cache stream is a declared trust input");
        assert_eq!(cache.class.as_str(), "operator_declared");
        assert_eq!(cache.consumed_by, vec!["cache_rungs_complete"]);
    }

    /// Every axis, non-axis section and provenance field survived rendering.
    fn assert_nothing_was_dropped(value: &serde_json::Value) {
        for missing in [report::missing_axes(value), report::missing_sections(value)] {
            assert!(missing.is_empty(), "the smoke dropped: {missing:?}");
        }
        assert!(
            report::missing_provenance_fields(value).is_empty(),
            "the smoke dropped provenance: {:?}",
            report::missing_provenance_fields(value)
        );
    }

    /// Axes 1-5: recall/latency, wake, sessions, resident memory, gated writes.
    fn assert_engine_axes(report: &PerfReport) {
        // Axis 1: two separate populations, and the completed-sample floor is
        // counted on calls that came back.
        assert_eq!(report.recall_latency.cold.label, "cold");
        assert_eq!(report.recall_latency.warm.label, "warm");
        assert!(report.recall_latency.cold.latency_ms.is_measured());
        assert!(report.recall_latency.warm.latency_ms.is_measured());
        assert!(!report.recall_latency.meets_full_run_floor);
        assert_eq!(
            report.recall_latency.cold.completed_sample_floor,
            FULL_RUN_MIN_COMPLETED_SAMPLES
        );
        assert!(!report.recall_latency.meets_completed_sample_floor);

        // Axis 2: readiness is the TCP accept, whatever the outcome.
        assert_eq!(report.wake.readiness_signal, ReadinessSignal::TcpAccept);

        // Axis 3: the curve actually ran, and each point assembled its cohort.
        assert!(!report.sessions.curve.is_empty());
        assert_eq!(report.sessions.vaults, 1);
        assert_eq!(
            report.sessions.required_full_curve,
            REQUIRED_FULL_SESSION_CURVE
        );
        for point in &report.sessions.curve {
            assert_eq!(point.workers_released, point.sessions);
            assert!(point.synchronized, "{}-session point", point.sessions);
        }

        // Axis 4: the axis is defined at ten ready children, and the plan's
        // hold outlasts the accept-and-sample phase.
        assert_eq!(
            report.resident_memory.required_ready_children,
            REQUIRED_READY_CHILDREN
        );
        assert_eq!(report.resident_memory.arch_0023b_per_vault_budget_mb, 50);
        assert!(
            report.resident_memory.child_hold_ms >= report.resident_memory.minimum_child_hold_ms
        );

        // Axis 5: one gate decision per commit, and throughput from successes.
        assert!(report.gated_writes.measured_commits > 0);
        assert_eq!(
            report.gated_writes.gate_decisions_recorded, report.gated_writes.measured_commits,
            "one gate decision per commit"
        );
        assert_eq!(
            report.gated_writes.commits_ok + report.gated_writes.commit_errors,
            report.gated_writes.measured_commits
        );
        if report.gated_writes.commits_ok == 0 {
            assert!(!report.gated_writes.commits_per_second.is_measured());
        }
    }

    /// Axes 6-7: precision rows with their deltas, and the cache rungs.
    fn assert_precision_and_cache_axes(report: &PerfReport) {
        assert_eq!(report.precision.rows.len(), 4);
        assert!(report.precision.bench_representations_only);
        assert_eq!(report.precision.engine_persist_representation, "f16");
        assert_eq!(
            report.precision.binary_prefix_breadth,
            default_binary_prefix_breadth(report.precision.k)
        );
        assert!(!report.precision.k_reduced_to_corpus);
        assert!(report.precision.warmup_scans_per_candidate > 0);
        for row in &report.precision.rows {
            assert!(
                row.mean_recall_delta_vs_f32.is_measured(),
                "{} must carry its recall delta against f32",
                row.candidate.as_str()
            );
            assert_eq!(
                row.warmup_scans,
                report.precision.warmup_scans_per_candidate,
                "{} must be warmed exactly like every other row",
                row.candidate.as_str()
            );
        }
        assert!(
            !report
                .precision
                .moorcheh_binary_benchmark
                .run_by_this_harness
        );

        // The bundled smoke stream is a file the harness was pointed at, and
        // the axis says so: operator-declared evidence, advisory scope. Its
        // rows saying `synthetic_smoke` is a shape check on the rows, never
        // evidence of where they came from.
        assert_eq!(report.cache.source_kind, "synthetic_smoke_fixture");
        assert_eq!(report.cache.evidence_trust_class, "operator_declared");
        assert_eq!(report.cache.publication_scope, "advisory");
        assert!(
            !report
                .publication
                .blocking_checks
                .contains(&"cache_rungs_complete"),
            "an advisory check may never appear among the blocking ones"
        );

        // Rungs come from the plan; a silent rung is not_ready; and sessions
        // are counted distinctly.
        assert!(!report.cache.rows.is_empty());
        for row in &report.cache.rows {
            if row.events == 0 {
                assert!(
                    matches!(row.hit_rate, Cell::NotReady { .. }),
                    "silent rung `{}` must be not_ready, never 0",
                    row.rung
                );
            }
            assert!(
                row.sessions <= row.events_with_session,
                "rung `{}` cannot have more distinct sessions than session-carrying events",
                row.rung
            );
        }
        let embedding = &report.cache.rows[0];
        assert_eq!(embedding.sessions, 2, "smoke-a and smoke-b");
        assert_eq!(embedding.events_with_session, 4);
    }

    /// Axis 8 plus the provenance and acceptance sections.
    fn assert_environment_and_acceptance(report: &PerfReport) {
        assert!(report.nvme_fsync.descriptive_only);
        assert!(matches!(
            report.nvme_fsync.status,
            "measured" | "partial" | "not_ready"
        ));
        assert!(
            report.nvme_fsync.errors.is_empty() || report.nvme_fsync.status != "measured",
            "a pass that failed part way can never be reported as a complete measurement"
        );
        assert!(
            report.nvme_fsync.completed_ops()
                <= report.nvme_fsync.sequential_ops + report.nvme_fsync.random_ops
        );
        assert_eq!(
            report
                .provenance
                .sample_counts
                .get("nvme_fsync_ops_completed")
                .copied(),
            Some(report.nvme_fsync.completed_ops())
        );

        // Provenance identifies the running build, exact cache stream, planted
        // marker population, and node. The build digest is independent of cwd;
        // a build-time Git SHA is optional and stays distinct from source HEAD.
        assert!(report.provenance.build_revision_blake3.is_measured());
        assert!(report.provenance.build_revision_source.contains("BLAKE3"));
        assert!(report.provenance.cache_events_hash.is_measured());
        assert!(report.provenance.cache_events_bytes > 0);
        assert!(report.provenance.corpus_marker_evidence.collision_free);
        assert_eq!(
            report.provenance.corpus_marker_evidence.documents,
            report.provenance.corpus_marker_evidence.unique_markers
        );
        let queries = &report.provenance.corpus_query_evidence;
        assert!(queries.anchors_distinct, "{queries:?}");
        assert_eq!(queries.distinct_anchors, queries.emitted_queries);
        assert_eq!(queries.distinct_expected_documents, queries.emitted_queries);
        assert!(queries.emitted_queries <= queries.indexed_docs);
        assert_eq!(
            report.provenance.node.designated_first_tokyo_node,
            "tokyo-1"
        );

        // Acceptance names ONE-1578's actual lifecycle knobs, their canonical
        // link, and the separate ONE-1537 embed-p95 relationship. Neither
        // external ticket is turned into an invented measurement.
        assert_eq!(report.acceptance.knob_ticket, "ONE-1578");
        assert!(report.acceptance.knob_ticket_url.contains("/ONE-1578/"));
        assert_eq!(
            report
                .acceptance
                .knobs
                .iter()
                .map(|knob| knob.knob)
                .collect::<Vec<_>>(),
            vec![
                "idle_ttl",
                "hot_vault_extension",
                "reap_lookahead",
                "spawn_concurrency_cap",
                "sigkill_grace",
            ]
        );
        assert!(report.acceptance.knobs.iter().all(|knob| {
            !knob.directly_exercised_by_this_harness
                && !knob.direct_measurement.is_measured()
                && !knob.supporting_measurements.is_empty()
        }));
        assert_eq!(report.acceptance.measured_qps.lifecycle_ticket, "ONE-1578");
        assert_eq!(
            report.acceptance.measured_qps.related_embed_gate_ticket,
            "ONE-1537"
        );
        assert!(!report.acceptance.measured_qps.valid_for_one_1537_embed_gate);
        assert!(
            !report.acceptance.measured_qps.measured_qps.is_measured(),
            "synthetic smoke QPS is never promoted into measured acceptance evidence"
        );
        assert_eq!(report.acceptance.embed_latency_gate.gate_ticket, "ONE-1537");
        assert!(
            report
                .acceptance
                .embed_latency_gate
                .gate_ticket_url
                .contains("/ONE-1537/")
        );
        assert_eq!(
            report.acceptance.embed_latency_gate.required_metric,
            "oneironer_single_query_embed_p95_ms"
        );
        assert!(
            !report
                .acceptance
                .embed_latency_gate
                .measured_by_this_harness
        );
    }
}
