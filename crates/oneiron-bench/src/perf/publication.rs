//! ONE-1579 publication-CANDIDATE predicate.
//!
//! This harness measures. It never publishes. The strongest verdict it can
//! reach is `publication_candidate`: every BLOCKING check it can evaluate for
//! itself is satisfied, so an external verifier (`oneiron-eval perf-verify`)
//! may now go and decide whether the numbers are publishable. Nothing in this
//! process ever emits `publishable: true`, because a measuring process
//! certifying its own measurements is the failure this design exists to close.
//!
//! The predicate fails closed: a check the harness could not evaluate counts as
//! unsatisfied, and each failed check contributes its own named reason, so a
//! reader is never left to guess why a report was withheld.
//!
//! The checks exist because passing a numeric floor is not the same as having
//! valid evidence:
//!
//! * a gated-write axis whose commits FAILED, or whose gate ledger did not
//!   record exactly one decision per measured commit, is failed gate
//!   enforcement, not benchmark evidence;
//! * a latency axis whose retrieval calls mostly errored has percentiles over
//!   survivors rather than over the planned population;
//! * numeric floors alone say nothing about the other required axes. Wake must
//!   contain every requested TCP-ready sample, the full session curve must be
//!   synchronized and error-free, ten-child RSS must prove vault residency,
//!   every precision row must be measured, and the NVMe pass must be complete;
//! * numeric floors also say nothing about WHERE a run happened, so a full
//!   report has to prove it ran on the designated first Tokyo node;
//! * and they say nothing about WHICH ARTIFACT produced them. A binary built
//!   from uncommitted sources belongs to no commit, and a binary whose
//!   MEASURED compiled settings are unoptimised, debug-assertion-carrying or
//!   overflow-checked measures a differently shaped experiment rather than a
//!   slower one, so both are refused — and the profile NAME the build claimed
//!   is never what that verdict rests on. The artifact that was spawned as the
//!   ready child must be that same artifact, hash for hash.
//!
//! ONE-1961 adds the second axis of the verdict: not just whether a check
//! passed, but whether it was ENTITLED to. Every check carries its
//! [`CheckScope`] and the [`trust`] inputs it rests on, and a blocking check
//! that rests on operator-declared evidence is a contradiction the tables refuse
//! statically ([`trust::blocking_evidence_violations`]) and [`decide`] refuses
//! again at runtime for inputs whose class depends on how they resolved.

use serde::Serialize;

use super::cells::RunMode;
use super::trust::{self, CheckScope};

/// Reason stamped on every synthetic smoke report.
pub(crate) const SMOKE_NON_CANDIDATE_REASON: &str = "synthetic smoke over bundled under-floor fixtures: it proves the harness emits every axis, \
     and is never a publishable performance result";

const PUBLICATION_RULE: &str = "this harness emits CANDIDATES only and never publishes: a full report is a publication \
     candidate when every BLOCKING check is satisfied, and an external verifier decides \
     publishability from the candidate plus an independent build record. The predicate fails \
     closed, so an unevaluated blocking check withholds candidacy exactly as a failed one does. \
     Advisory checks are reported and carried forward but never withhold candidacy, because \
     their evidence is operator-declared";

/// One named condition on the way to candidacy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PublicationCheck {
    pub(crate) check: &'static str,
    /// Whether failing this check withholds candidacy or only annotates it.
    pub(crate) scope: CheckScope,
    pub(crate) satisfied: bool,
    pub(crate) detail: String,
    /// The named evidence this check rests on, resolved from the ONE-1961
    /// trust tables. A verifier compares these against its OWN table rather
    /// than trusting the labels travelling in the report.
    pub(crate) trust_inputs: &'static [&'static str],
}

/// The candidacy verdict plus every check that produced it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PublicationDecision {
    /// NEVER named `publishable`. This process cannot reach that verdict.
    pub(crate) candidate: bool,
    pub(crate) rule: &'static str,
    pub(crate) checks: Vec<PublicationCheck>,
    /// Failed BLOCKING checks. These are what withheld candidacy.
    pub(crate) blocking_checks: Vec<&'static str>,
    /// Failed ADVISORY checks. Reported and carried into the verdict as
    /// caveats; they never appear in `blocking_checks`.
    pub(crate) advisory_failures: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) non_candidate_reason: Option<String>,
}

/// Flattened axis facts the predicate reads. The runner fills this in from the
/// measured axes; nothing here re-runs a workload or promotes a plan request
/// into measured evidence.
#[derive(Debug, Clone)]
pub(crate) struct PublicationInputs {
    pub(crate) mode: RunMode,
    pub(crate) meets_plan_floor: bool,
    pub(crate) meets_completed_sample_floor: bool,
    pub(crate) cold_completed: usize,
    pub(crate) warm_completed: usize,
    pub(crate) completed_sample_floor: usize,
    pub(crate) retrieval_measurements_valid: bool,
    pub(crate) retrieval_detail: String,
    pub(crate) wake_axis_valid: bool,
    pub(crate) wake_detail: String,
    pub(crate) session_curve_valid: bool,
    pub(crate) session_detail: String,
    pub(crate) resident_memory_valid: bool,
    pub(crate) resident_memory_detail: String,
    pub(crate) gated_write_measurements_valid: bool,
    pub(crate) gated_write_detail: String,
    pub(crate) gated_write_meets_floor: bool,
    pub(crate) warmup_attempts: usize,
    pub(crate) warmup_commits: usize,
    pub(crate) warmup_commit_errors: usize,
    pub(crate) measured_commits: usize,
    pub(crate) commits_ok: usize,
    pub(crate) commit_errors: usize,
    pub(crate) gate_decisions_recorded: usize,
    pub(crate) one_decision_per_commit: bool,
    pub(crate) precision_axis_valid: bool,
    pub(crate) precision_detail: String,
    pub(crate) cache_axis_valid: bool,
    pub(crate) cache_detail: String,
    pub(crate) corpus_marker_evidence_valid: bool,
    pub(crate) corpus_marker_detail: String,
    /// Every reported query probed a DISTINCT indexed document.
    pub(crate) corpus_query_anchors_distinct: bool,
    pub(crate) corpus_query_anchor_detail: String,
    pub(crate) measured_qps_acceptance_valid: bool,
    pub(crate) measured_qps_acceptance_detail: String,
    pub(crate) build_revision_valid: bool,
    pub(crate) build_revision_detail: String,
    /// The artifact's compile-time declaration that its sources were committed.
    /// Fail-closed: an artifact that embedded nothing is not "clean".
    pub(crate) build_tree_clean: bool,
    pub(crate) build_tree_detail: String,
    /// The artifact's MEASURED compiled settings are publishable: an
    /// optimised level, no debug assertions, no overflow checks. The profile
    /// NAME it was built under is provenance and is deliberately not read.
    pub(crate) build_settings_optimized: bool,
    pub(crate) build_settings_detail: String,
    pub(crate) node_is_designated_first_tokyo: bool,
    pub(crate) node_detail: String,
    pub(crate) nvme_sanity_ok: bool,
    pub(crate) nvme_detail: String,
    /// ONE-1963: the ready child that was spawned hashes to the same artifact
    /// that measured the run.
    pub(crate) child_program_matches_build_revision: bool,
    pub(crate) child_program_detail: String,
    /// Inputs whose trust class resolved to `operator_declared` FOR THIS RUN,
    /// whatever the static table says. Any blocking check resting on one of
    /// them fails closed; see the [`trust`] module.
    pub(crate) runtime_operator_declared_inputs: Vec<&'static str>,
}

/// Evaluates every publication check and returns the candidacy verdict.
pub(crate) fn decide(inputs: &PublicationInputs) -> PublicationDecision {
    let mut checks = evaluate_checks(inputs);
    apply_runtime_trust(&mut checks, &inputs.runtime_operator_declared_inputs);

    let failed = |scope: CheckScope| -> Vec<&'static str> {
        checks
            .iter()
            .filter(|check| !check.satisfied && check.scope == scope)
            .map(|check| check.check)
            .collect()
    };
    let blocking_checks = failed(CheckScope::Blocking);
    let advisory_failures = failed(CheckScope::Advisory);
    let candidate = blocking_checks.is_empty();

    let non_candidate_reason = if candidate {
        None
    } else if inputs.mode.is_full() {
        Some(format!(
            "this full report is not a publication candidate; {} unsatisfied blocking check(s): {}",
            blocking_checks.len(),
            checks
                .iter()
                .filter(|check| !check.satisfied && check.scope.is_blocking())
                .map(|check| format!("{}: {}", check.check, check.detail))
                .collect::<Vec<_>>()
                .join(" | ")
        ))
    } else {
        Some(SMOKE_NON_CANDIDATE_REASON.to_owned())
    };

    PublicationDecision {
        candidate,
        rule: PUBLICATION_RULE,
        checks,
        blocking_checks,
        advisory_failures,
        non_candidate_reason,
    }
}

/// The runtime half of the ONE-1961 trust rule. An input that resolved to an
/// operator declaration for THIS run cannot support a blocking check, even
/// though the static table classifies it otherwise.
fn apply_runtime_trust(checks: &mut [PublicationCheck], operator_declared: &[&'static str]) {
    if operator_declared.is_empty() {
        return;
    }
    for check in &mut *checks {
        if !check.scope.is_blocking() {
            continue;
        }
        let tainted: Vec<&str> = check
            .trust_inputs
            .iter()
            .copied()
            .filter(|input| operator_declared.contains(input))
            .collect();
        if tainted.is_empty() {
            continue;
        }
        check.satisfied = false;
        check.detail = format!(
            "{} | input(s) {tainted:?} resolved to operator_declared at runtime, so this blocking \
             check may not rest on them",
            check.detail
        );
    }
}

/// Builds one check, attaching the scope and evidence the ONE-1961 tables
/// declare for it.
///
/// Fail-closed on an undeclared name: a check the trust tables do not know
/// about has no stated evidence, so it is treated as an unsatisfied blocking
/// check rather than silently trusted. A unit test makes that unreachable.
fn check(name: &'static str, satisfied: bool, detail: String) -> PublicationCheck {
    match trust::check_spec(name) {
        Some(spec) => PublicationCheck {
            check: spec.name,
            scope: spec.scope,
            satisfied,
            detail,
            trust_inputs: spec.inputs,
        },
        None => PublicationCheck {
            check: name,
            scope: CheckScope::Blocking,
            satisfied: false,
            detail: format!(
                "`{name}` is not declared in the ONE-1961 trust tables, so the evidence it rests \
                 on is unstated and it cannot support candidacy: {detail}"
            ),
            trust_inputs: &[],
        },
    }
}

/// Every named condition, in report order. Each one is evaluated from already
/// measured axis state; none of them re-runs or re-derives a measurement.
///
/// The names and their order must match `trust::CHECKS` exactly.
fn evaluate_checks(inputs: &PublicationInputs) -> Vec<PublicationCheck> {
    vec![
        check(
            "run_mode_is_full",
            inputs.mode.is_full(),
            format!(
                "run mode is `{}`; only a full run can ever become a publication candidate",
                inputs.mode.as_str()
            ),
        ),
        check(
            "recall_latency_plan_floor",
            inputs.meets_plan_floor,
            "the plan must ask for >=1000 indexed docs and >=100 queries".to_owned(),
        ),
        check(
            "recall_latency_completed_sample_floor",
            inputs.meets_completed_sample_floor,
            format!(
                "{} cold and {} warm retrieval calls COMPLETED; each set needs >={}, and a call \
                 that errored is not a sample",
                inputs.cold_completed, inputs.warm_completed, inputs.completed_sample_floor
            ),
        ),
        check(
            "recall_latency_measurements_complete",
            inputs.retrieval_measurements_valid,
            inputs.retrieval_detail.clone(),
        ),
        check(
            "wake_axis_complete",
            inputs.wake_axis_valid,
            inputs.wake_detail.clone(),
        ),
        check(
            "session_curve_complete",
            inputs.session_curve_valid,
            inputs.session_detail.clone(),
        ),
        check(
            "ten_child_rss_complete",
            inputs.resident_memory_valid,
            inputs.resident_memory_detail.clone(),
        ),
        check(
            "gated_write_measurements_complete",
            inputs.gated_write_measurements_valid,
            inputs.gated_write_detail.clone(),
        ),
        check(
            "gated_write_floor",
            inputs.gated_write_meets_floor,
            format!(
                concat!(
                    "{} of {} requested warmup ClaimCandidate commits succeeded ({} failed); ",
                    "a full run needs >=1000 successful warmups and >=10000 measured commits"
                ),
                inputs.warmup_commits, inputs.warmup_attempts, inputs.warmup_commit_errors
            ),
        ),
        check(
            "gated_write_commits_all_succeeded",
            inputs.commit_errors == 0
                && inputs.commits_ok == inputs.measured_commits
                && inputs.measured_commits > 0,
            format!(
                "{} of {} measured gated-write commits succeeded ({} failed); a failed commit is \
                 failed gate enforcement, not benchmark evidence",
                inputs.commits_ok, inputs.measured_commits, inputs.commit_errors
            ),
        ),
        check(
            "gate_ledger_one_decision_per_commit",
            inputs.one_decision_per_commit
                && inputs.gate_decisions_recorded == inputs.measured_commits,
            format!(
                "the gate ledger recorded {} decisions for {} measured commits; the axis is only \
                 valid at exactly one decision per commit",
                inputs.gate_decisions_recorded, inputs.measured_commits
            ),
        ),
        check(
            "precision_axis_complete",
            inputs.precision_axis_valid,
            inputs.precision_detail.clone(),
        ),
        // ADVISORY (ONE-1961): its only evidence is a stream the operator
        // pointed at. A silent rung is still reported, and still lands in
        // `advisory_failures`; it just cannot withhold candidacy.
        check(
            "cache_rungs_complete",
            inputs.cache_axis_valid,
            inputs.cache_detail.clone(),
        ),
        check(
            "corpus_markers_collision_free",
            inputs.corpus_marker_evidence_valid,
            inputs.corpus_marker_detail.clone(),
        ),
        check(
            "corpus_query_anchors_distinct",
            inputs.corpus_query_anchors_distinct,
            inputs.corpus_query_anchor_detail.clone(),
        ),
        check(
            "measured_qps_acceptance_traceable",
            inputs.measured_qps_acceptance_valid,
            inputs.measured_qps_acceptance_detail.clone(),
        ),
        check(
            "build_revision_identified",
            inputs.build_revision_valid,
            inputs.build_revision_detail.clone(),
        ),
        check(
            "build_tree_clean_at_compile_time",
            inputs.build_tree_clean,
            inputs.build_tree_detail.clone(),
        ),
        check(
            "measured_optimized_build_settings",
            inputs.build_settings_optimized,
            inputs.build_settings_detail.clone(),
        ),
        check(
            "designated_first_tokyo_node",
            inputs.node_is_designated_first_tokyo,
            inputs.node_detail.clone(),
        ),
        check(
            "nvme_sanity",
            inputs.nvme_sanity_ok,
            inputs.nvme_detail.clone(),
        ),
        check(
            "child_program_matches_build_revision",
            inputs.child_program_matches_build_revision,
            inputs.child_program_detail.clone(),
        ),
    ]
}

#[cfg(test)]
mod tests;
