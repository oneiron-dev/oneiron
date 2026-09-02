//! ONE-1579 / ONE-1961 / ONE-1963 regressions over the candidacy predicate.

use super::*;

/// A full run with every check satisfied.
fn candidate_inputs() -> PublicationInputs {
    PublicationInputs {
        mode: RunMode::Full,
        meets_plan_floor: true,
        meets_completed_sample_floor: true,
        cold_completed: 100,
        warm_completed: 100,
        completed_sample_floor: 100,
        retrieval_measurements_valid: true,
        retrieval_detail: "100 of 100 cold and warm calls completed without error".to_owned(),
        wake_axis_valid: true,
        wake_detail: "all requested TCP-ready samples completed".to_owned(),
        session_curve_valid: true,
        session_detail: "the exact curve completed without errors".to_owned(),
        resident_memory_valid: true,
        resident_memory_detail: "ten harness-owned vault children were sampled".to_owned(),
        gated_write_measurements_valid: true,
        gated_write_detail: "successful-commit throughput and latency were measured".to_owned(),
        gated_write_meets_floor: true,
        warmup_attempts: 1_000,
        warmup_commits: 1_000,
        warmup_commit_errors: 0,
        measured_commits: 10_000,
        commits_ok: 10_000,
        commit_errors: 0,
        gate_decisions_recorded: 10_000,
        one_decision_per_commit: true,
        precision_axis_valid: true,
        precision_detail: "all four precision rows were measured".to_owned(),
        cache_axis_valid: true,
        cache_detail: "every listed cache rung was measured".to_owned(),
        corpus_marker_evidence_valid: true,
        corpus_marker_detail: "1000 document markers, 1000 unique".to_owned(),
        corpus_query_anchors_distinct: true,
        corpus_query_anchor_detail: "100 queries on 100 distinct anchors".to_owned(),
        measured_qps_acceptance_valid: true,
        measured_qps_acceptance_detail: "300-session QPS copies an exact measured cell".to_owned(),
        build_revision_valid: true,
        build_revision_detail: "running executable BLAKE3 measured".to_owned(),
        build_tree_clean: true,
        build_tree_detail: "the build environment declared a committed tree".to_owned(),
        build_settings_optimized: true,
        build_settings_detail: "compiled opt_level 3, no debug assertions or overflow checks"
            .to_owned(),
        node_is_designated_first_tokyo: true,
        node_detail: "declared node `tokyo-1` in `tokyo`".to_owned(),
        nvme_sanity_ok: true,
        nvme_detail: "measured on /dev/nvme0n1".to_owned(),
        child_program_matches_build_revision: true,
        child_program_detail: "the ready child hashes to the measuring artifact".to_owned(),
        runtime_operator_declared_inputs: Vec::new(),
    }
}

#[test]
fn a_fully_satisfied_full_run_is_a_publication_candidate() {
    let decision = decide(&candidate_inputs());
    assert!(decision.candidate);
    assert!(decision.blocking_checks.is_empty());
    assert!(decision.advisory_failures.is_empty());
    assert!(decision.non_candidate_reason.is_none());
    assert!(decision.checks.iter().all(|check| check.satisfied));
}

/// The emitted checks and the ONE-1961 trust table are ONE table. If they can
/// drift, a check can be added with no stated evidence and the rule stops
/// meaning anything.
#[test]
fn every_emitted_check_matches_the_trust_table_exactly() {
    let decision = decide(&candidate_inputs());
    let emitted: Vec<&str> = decision.checks.iter().map(|check| check.check).collect();
    let declared: Vec<&str> = trust::CHECKS.iter().map(|spec| spec.name).collect();
    assert_eq!(
        emitted, declared,
        "emitted checks must match the trust table"
    );

    for check in &decision.checks {
        let spec = trust::check_spec(check.check).expect("every emitted check is declared");
        assert_eq!(check.scope, spec.scope);
        assert_eq!(check.trust_inputs, spec.inputs);
        assert!(
            !check.trust_inputs.is_empty(),
            "`{}` must state the evidence it rests on",
            check.check
        );
    }
}

/// Cache evidence is operator-declared, so its failure is ADVISORY: it is
/// reported, it is carried in `advisory_failures`, and it never appears in
/// `blocking_checks` or withholds candidacy.
#[test]
fn a_silent_cache_rung_is_advisory_and_never_blocks_candidacy() {
    let mut inputs = candidate_inputs();
    inputs.cache_axis_valid = false;
    inputs.cache_detail = "listed rung `embedding` had no event".to_owned();
    let decision = decide(&inputs);

    assert!(
        decision.candidate,
        "an operator-declared cache stream may not withhold candidacy"
    );
    assert!(decision.blocking_checks.is_empty());
    assert_eq!(decision.advisory_failures, vec!["cache_rungs_complete"]);
    assert!(decision.non_candidate_reason.is_none());

    let cache = decision
        .checks
        .iter()
        .find(|check| check.check == "cache_rungs_complete")
        .expect("the cache axis is still checked and still emitted");
    assert_eq!(cache.scope, CheckScope::Advisory);
    assert!(!cache.satisfied, "the failure is reported, not hidden");
    assert!(cache.detail.contains("embedding"));
    assert_eq!(cache.trust_inputs, &["cache_events"]);
}

/// Every mandatory measured axis is an independent BLOCKING check. A full run
/// with otherwise perfect floors cannot become a candidate with a missing wake
/// sample, a broken session point, opaque-child RSS or an incomplete precision
/// row.
#[test]
fn every_mandatory_axis_blocks_candidacy_when_unavailable() {
    for (expected_check, break_axis) in [
        ("recall_latency_measurements_complete", 0_u8),
        ("wake_axis_complete", 1),
        ("session_curve_complete", 2),
        ("ten_child_rss_complete", 3),
        ("gated_write_measurements_complete", 4),
        ("precision_axis_complete", 5),
        ("corpus_markers_collision_free", 6),
        ("measured_qps_acceptance_traceable", 7),
        ("build_revision_identified", 8),
        ("corpus_query_anchors_distinct", 9),
        ("child_program_matches_build_revision", 10),
    ] {
        let mut inputs = candidate_inputs();
        match break_axis {
            0 => {
                inputs.retrieval_measurements_valid = false;
                inputs.retrieval_detail = "one cold call failed".to_owned();
            }
            1 => {
                inputs.wake_axis_valid = false;
                inputs.wake_detail = "zero requested wake samples completed".to_owned();
            }
            2 => {
                inputs.session_curve_valid = false;
                inputs.session_detail = "the 300-session point had query errors".to_owned();
            }
            3 => {
                inputs.resident_memory_valid = false;
                inputs.resident_memory_detail =
                    "custom child TCP readiness did not prove vault residency".to_owned();
            }
            4 => {
                inputs.gated_write_measurements_valid = false;
                inputs.gated_write_detail =
                    "successful commit throughput was unavailable".to_owned();
            }
            5 => {
                inputs.precision_axis_valid = false;
                inputs.precision_detail = "the f16 recall delta is unavailable".to_owned();
            }
            6 => {
                inputs.corpus_marker_evidence_valid = false;
                inputs.corpus_marker_detail = "1000 documents but 999 unique markers".to_owned();
            }
            7 => {
                inputs.measured_qps_acceptance_valid = false;
                inputs.measured_qps_acceptance_detail =
                    "QPS did not trace to a synchronized point".to_owned();
            }
            8 => {
                inputs.build_revision_valid = false;
                inputs.build_revision_detail = "running executable could not be hashed".to_owned();
            }
            9 => {
                inputs.corpus_query_anchors_distinct = false;
                inputs.corpus_query_anchor_detail =
                    "100 queries wrapped onto 60 distinct documents".to_owned();
            }
            10 => {
                inputs.child_program_matches_build_revision = false;
                inputs.child_program_detail =
                    "the spawned ready child is a different binary".to_owned();
            }
            _ => unreachable!("fixed test cases"),
        }
        let decision = decide(&inputs);
        assert!(!decision.candidate, "{expected_check} must fail closed");
        assert_eq!(decision.blocking_checks, vec![expected_check]);
        assert!(decision.advisory_failures.is_empty());
        assert!(
            decision
                .non_candidate_reason
                .as_deref()
                .is_some_and(|reason| reason.contains(expected_check))
        );
    }
}

/// ONE-1963: the artifact that produced the numbers and the artifact that was
/// spawned as its ready child must be the same bytes. A different binary is
/// REJECTED — it is never pinned into the certificate as if it belonged there.
#[test]
fn a_child_program_that_is_not_the_measuring_artifact_blocks_candidacy() {
    let mut inputs = candidate_inputs();
    inputs.child_program_matches_build_revision = false;
    inputs.child_program_detail =
        "child program blake3 `aaaa` does not equal build revision `bbbb`".to_owned();
    let decision = decide(&inputs);

    assert!(!decision.candidate);
    assert_eq!(
        decision.blocking_checks,
        vec!["child_program_matches_build_revision"]
    );
    let check = decision
        .checks
        .last()
        .expect("the child-program check is emitted last");
    assert_eq!(check.check, "child_program_matches_build_revision");
    assert_eq!(check.scope, CheckScope::Blocking);
    assert_eq!(
        check.trust_inputs,
        &["child_program_blake3", "build_revision_blake3"]
    );
}

/// The RUNTIME half of the ONE-1961 rule. An input the static table calls
/// measured, but which this particular run resolved from an operator
/// declaration, cannot support a blocking check — so every dependent check
/// fails closed and says why.
#[test]
fn an_input_that_resolves_to_operator_declared_at_runtime_fails_its_blocking_checks() {
    let mut inputs = candidate_inputs();
    inputs.runtime_operator_declared_inputs = vec!["child_program_blake3"];
    let decision = decide(&inputs);

    assert!(
        !decision.candidate,
        "a blocking check resting on a runtime operator declaration is not evidence"
    );
    assert_eq!(
        decision.blocking_checks,
        vec!["child_program_matches_build_revision"]
    );
    let check = decision
        .checks
        .iter()
        .find(|check| check.check == "child_program_matches_build_revision")
        .expect("the check is emitted");
    assert!(!check.satisfied);
    assert!(
        check.detail.contains("operator_declared at runtime"),
        "{}",
        check.detail
    );
    assert!(
        check.detail.contains("child_program_blake3"),
        "{}",
        check.detail
    );

    // An advisory check is not rewritten by the runtime rule: it already
    // carries no candidacy weight, and blanking it would hide its result.
    let mut advisory = candidate_inputs();
    advisory.runtime_operator_declared_inputs = vec!["cache_events"];
    let decision = decide(&advisory);
    assert!(decision.candidate);
    assert!(decision.advisory_failures.is_empty());
}

/// A commit that FAILED, or a ledger that did not record exactly one decision
/// per measured commit, is failed gate enforcement. Neither may ride to
/// candidacy on satisfied sample floors.
#[test]
fn gated_write_failures_block_candidacy() {
    let mut failed_commit = candidate_inputs();
    failed_commit.commits_ok = 9_999;
    failed_commit.commit_errors = 1;
    let decision = decide(&failed_commit);
    assert!(
        !decision.candidate,
        "one failed commit must fail the report closed"
    );
    assert_eq!(
        decision.blocking_checks,
        vec!["gated_write_commits_all_succeeded"]
    );
    let reason = decision
        .non_candidate_reason
        .expect("a blocked full run states why");
    assert!(reason.contains("9999 of 10000"), "{reason}");

    for (recorded, one_per_commit) in [(9_999_usize, false), (10_001, false), (10_000, false)] {
        let mut ledger = candidate_inputs();
        ledger.gate_decisions_recorded = recorded;
        ledger.one_decision_per_commit = one_per_commit;
        let decision = decide(&ledger);
        assert!(
            !decision.candidate,
            "a ledger with {recorded} decisions and one_decision_per_commit={one_per_commit} is \
             invalid gate evidence"
        );
        assert!(
            decision
                .blocking_checks
                .contains(&"gate_ledger_one_decision_per_commit")
        );
    }

    // Zero measured commits is not a vacuous pass either.
    let mut empty = candidate_inputs();
    empty.measured_commits = 0;
    empty.commits_ok = 0;
    empty.gate_decisions_recorded = 0;
    assert!(!decide(&empty).candidate);
}

/// The warmup floor is runtime evidence. A plan asking for 1,000 attempts
/// cannot pass it when only 999 ClaimCandidate commits succeeded.
#[test]
fn failed_warmup_attempts_do_not_satisfy_the_candidacy_floor() {
    let mut inputs = candidate_inputs();
    inputs.gated_write_meets_floor = false;
    inputs.warmup_commits = 999;
    inputs.warmup_commit_errors = 1;
    let decision = decide(&inputs);
    assert_eq!(decision.blocking_checks, vec!["gated_write_floor"]);
    let reason = decision.non_candidate_reason.unwrap_or_default();
    assert!(reason.contains("999 of 1000"), "{reason}");
    assert!(reason.contains("1 failed"), "{reason}");
}

/// Numeric floors alone must not make an arbitrary host a candidate.
#[test]
fn a_non_tokyo_host_or_failed_nvme_sanity_blocks_candidacy() {
    let mut off_node = candidate_inputs();
    off_node.node_is_designated_first_tokyo = false;
    off_node.node_detail = "no node identity was declared for this run".to_owned();
    let decision = decide(&off_node);
    assert!(!decision.candidate);
    assert_eq!(
        decision.blocking_checks,
        vec!["designated_first_tokyo_node"]
    );

    let mut no_nvme = candidate_inputs();
    no_nvme.nvme_sanity_ok = false;
    no_nvme.nvme_detail = "the backing device is not NVMe".to_owned();
    let decision = decide(&no_nvme);
    assert!(!decision.candidate);
    assert_eq!(decision.blocking_checks, vec!["nvme_sanity"]);
}

/// Performance numbers are properties of an ARTIFACT. A binary compiled from
/// uncommitted sources belongs to no commit, and a debug or unoptimised binary
/// measures a differently shaped experiment rather than a slower one. Each is
/// its own named, independently blocking check, and both fail closed when the
/// artifact embedded nothing to prove otherwise.
#[test]
fn a_dirty_or_unapproved_build_artifact_blocks_candidacy() {
    let mut dirty = candidate_inputs();
    dirty.build_tree_clean = false;
    dirty.build_tree_detail = "the build environment declared uncommitted sources".to_owned();
    let decision = decide(&dirty);
    assert!(!decision.candidate);
    assert_eq!(
        decision.blocking_checks,
        vec!["build_tree_clean_at_compile_time"]
    );
    assert!(
        decision
            .non_candidate_reason
            .unwrap_or_default()
            .contains("uncommitted sources")
    );

    let mut unknown = candidate_inputs();
    unknown.build_tree_clean = false;
    unknown.build_tree_detail = "no cleanliness was embedded at compile time".to_owned();
    assert!(
        !decide(&unknown).candidate,
        "an artifact that embedded nothing must not be assumed clean"
    );

    let mut debug_build = candidate_inputs();
    debug_build.build_settings_optimized = false;
    debug_build.build_settings_detail =
        "compiled settings: opt_level=`0`; debug_assertions=true".to_owned();
    let decision = decide(&debug_build);
    assert!(!decision.candidate);
    assert_eq!(
        decision.blocking_checks,
        vec!["measured_optimized_build_settings"]
    );
    assert!(
        decision
            .non_candidate_reason
            .unwrap_or_default()
            .contains("debug_assertions=true")
    );

    // The two are independent: neither one masks the other.
    let mut both = candidate_inputs();
    both.build_tree_clean = false;
    both.build_settings_optimized = false;
    let decision = decide(&both);
    assert_eq!(
        decision.blocking_checks,
        vec![
            "build_tree_clean_at_compile_time",
            "measured_optimized_build_settings"
        ]
    );
}

/// A starved completed-sample floor blocks candidacy even when the plan asked
/// for the full query count.
#[test]
fn a_starved_completed_sample_floor_blocks_candidacy() {
    let mut starved = candidate_inputs();
    starved.meets_completed_sample_floor = false;
    starved.cold_completed = 3;
    let decision = decide(&starved);
    assert!(!decision.candidate);
    assert_eq!(
        decision.blocking_checks,
        vec!["recall_latency_completed_sample_floor"]
    );
    assert!(
        decision
            .non_candidate_reason
            .unwrap_or_default()
            .contains("3 cold")
    );
}

/// A smoke is never a candidate and keeps its own reason, however good its
/// other evidence looks.
#[test]
fn a_smoke_is_never_a_publication_candidate() {
    let mut smoke = candidate_inputs();
    smoke.mode = RunMode::SyntheticSmoke;
    let decision = decide(&smoke);
    assert!(!decision.candidate);
    assert_eq!(decision.blocking_checks, vec!["run_mode_is_full"]);
    assert_eq!(
        decision.non_candidate_reason.as_deref(),
        Some(SMOKE_NON_CANDIDATE_REASON)
    );
}

/// The decision renders the candidate vocabulary and nothing else. `publishable`
/// is a word only the external verifier may use.
#[test]
fn the_rendered_decision_never_says_publishable() {
    let decision = decide(&candidate_inputs());
    let rendered = serde_json::to_string(&decision).expect("the decision renders");
    assert!(rendered.contains("\"candidate\":true"), "{rendered}");
    assert!(rendered.contains("advisory_failures"), "{rendered}");
    assert!(rendered.contains("blocking_checks"), "{rendered}");
    assert!(
        !rendered.contains("publishable"),
        "the engine must never emit a publishable verdict: {rendered}"
    );
}
