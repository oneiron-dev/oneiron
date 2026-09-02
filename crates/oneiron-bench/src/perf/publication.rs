//! ONE-1579 publication predicate.
//!
//! A full report is publishable only when EVERY check below is satisfied. The
//! predicate fails closed: a check the harness could not evaluate counts as
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
//!   every precision row and listed cache rung must be measured, and the NVMe
//!   pass must be complete;
//! * numeric floors also say nothing about WHERE a run happened, so a full
//!   report has to prove it ran on the designated first Tokyo node;
//! * and they say nothing about WHICH ARTIFACT produced them. A binary built
//!   from uncommitted sources belongs to no commit, and an unoptimised or
//!   debug-assertion-carrying binary measures a differently shaped experiment
//!   rather than a slower one, so both are refused.

use serde::Serialize;

use super::cells::RunMode;

/// Reason stamped on every synthetic smoke report.
pub(crate) const SMOKE_NON_PUBLISHABLE_REASON: &str = "synthetic smoke over bundled under-floor fixtures: it proves the harness emits every axis, \
     and is never a publishable performance result";

const PUBLICATION_RULE: &str = "a full report is publishable only when every required check below is satisfied; the predicate \
     fails closed, so an unevaluated check blocks publication exactly as a failed one does";

/// One named condition on the way to publication.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PublicationCheck {
    pub(crate) check: &'static str,
    pub(crate) satisfied: bool,
    pub(crate) detail: String,
}

/// The publication verdict plus every check that produced it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PublicationDecision {
    pub(crate) publishable: bool,
    pub(crate) rule: &'static str,
    pub(crate) checks: Vec<PublicationCheck>,
    pub(crate) blocking_checks: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) non_publishable_reason: Option<String>,
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
    pub(crate) measured_qps_acceptance_valid: bool,
    pub(crate) measured_qps_acceptance_detail: String,
    pub(crate) build_revision_valid: bool,
    pub(crate) build_revision_detail: String,
    /// The artifact's compile-time declaration that its sources were committed.
    /// Fail-closed: an artifact that embedded nothing is not "clean".
    pub(crate) build_tree_clean: bool,
    pub(crate) build_tree_detail: String,
    /// The artifact was built with an approved OPTIMIZED profile.
    pub(crate) build_profile_approved: bool,
    pub(crate) build_profile_detail: String,
    pub(crate) node_is_designated_first_tokyo: bool,
    pub(crate) node_detail: String,
    pub(crate) nvme_sanity_ok: bool,
    pub(crate) nvme_detail: String,
}

/// Evaluates every publication check and returns the verdict.
pub(crate) fn decide(inputs: &PublicationInputs) -> PublicationDecision {
    let checks = evaluate_checks(inputs);
    let blocking: Vec<&'static str> = checks
        .iter()
        .filter(|check| !check.satisfied)
        .map(|check| check.check)
        .collect();
    let publishable = blocking.is_empty();
    let non_publishable_reason = if publishable {
        None
    } else if inputs.mode.is_full() {
        Some(format!(
            "this full report is not publishable; {} unsatisfied check(s): {}",
            blocking.len(),
            checks
                .iter()
                .filter(|check| !check.satisfied)
                .map(|check| format!("{}: {}", check.check, check.detail))
                .collect::<Vec<_>>()
                .join(" | ")
        ))
    } else {
        Some(SMOKE_NON_PUBLISHABLE_REASON.to_owned())
    };

    PublicationDecision {
        publishable,
        rule: PUBLICATION_RULE,
        checks,
        blocking_checks: blocking,
        non_publishable_reason,
    }
}

/// Every named condition, in report order. Each one is evaluated from already
/// measured axis state; none of them re-runs or re-derives a measurement.
fn evaluate_checks(inputs: &PublicationInputs) -> Vec<PublicationCheck> {
    vec![
        PublicationCheck {
            check: "run_mode_is_full",
            satisfied: inputs.mode.is_full(),
            detail: format!(
                "run mode is `{}`; only a full run can ever be published",
                inputs.mode.as_str()
            ),
        },
        PublicationCheck {
            check: "recall_latency_plan_floor",
            satisfied: inputs.meets_plan_floor,
            detail: "the plan must ask for >=1000 indexed docs and >=100 queries".to_owned(),
        },
        PublicationCheck {
            check: "recall_latency_completed_sample_floor",
            satisfied: inputs.meets_completed_sample_floor,
            detail: format!(
                "{} cold and {} warm retrieval calls COMPLETED; each set needs >={}, and a call \
                 that errored is not a sample",
                inputs.cold_completed, inputs.warm_completed, inputs.completed_sample_floor
            ),
        },
        PublicationCheck {
            check: "recall_latency_measurements_complete",
            satisfied: inputs.retrieval_measurements_valid,
            detail: inputs.retrieval_detail.clone(),
        },
        PublicationCheck {
            check: "wake_axis_complete",
            satisfied: inputs.wake_axis_valid,
            detail: inputs.wake_detail.clone(),
        },
        PublicationCheck {
            check: "session_curve_complete",
            satisfied: inputs.session_curve_valid,
            detail: inputs.session_detail.clone(),
        },
        PublicationCheck {
            check: "ten_child_rss_complete",
            satisfied: inputs.resident_memory_valid,
            detail: inputs.resident_memory_detail.clone(),
        },
        PublicationCheck {
            check: "gated_write_measurements_complete",
            satisfied: inputs.gated_write_measurements_valid,
            detail: inputs.gated_write_detail.clone(),
        },
        PublicationCheck {
            check: "gated_write_floor",
            satisfied: inputs.gated_write_meets_floor,
            detail: format!(
                concat!(
                    "{} of {} requested warmup ClaimCandidate commits succeeded ({} failed); ",
                    "a full run needs >=1000 successful warmups and >=10000 measured commits"
                ),
                inputs.warmup_commits, inputs.warmup_attempts, inputs.warmup_commit_errors
            ),
        },
        PublicationCheck {
            check: "gated_write_commits_all_succeeded",
            satisfied: inputs.commit_errors == 0
                && inputs.commits_ok == inputs.measured_commits
                && inputs.measured_commits > 0,
            detail: format!(
                "{} of {} measured gated-write commits succeeded ({} failed); a failed commit is \
                 failed gate enforcement, not benchmark evidence",
                inputs.commits_ok, inputs.measured_commits, inputs.commit_errors
            ),
        },
        PublicationCheck {
            check: "gate_ledger_one_decision_per_commit",
            satisfied: inputs.one_decision_per_commit
                && inputs.gate_decisions_recorded == inputs.measured_commits,
            detail: format!(
                "the gate ledger recorded {} decisions for {} measured commits; the axis is only \
                 valid at exactly one decision per commit",
                inputs.gate_decisions_recorded, inputs.measured_commits
            ),
        },
        PublicationCheck {
            check: "precision_axis_complete",
            satisfied: inputs.precision_axis_valid,
            detail: inputs.precision_detail.clone(),
        },
        PublicationCheck {
            check: "cache_rungs_complete",
            satisfied: inputs.cache_axis_valid,
            detail: inputs.cache_detail.clone(),
        },
        PublicationCheck {
            check: "corpus_markers_collision_free",
            satisfied: inputs.corpus_marker_evidence_valid,
            detail: inputs.corpus_marker_detail.clone(),
        },
        PublicationCheck {
            check: "measured_qps_acceptance_traceable",
            satisfied: inputs.measured_qps_acceptance_valid,
            detail: inputs.measured_qps_acceptance_detail.clone(),
        },
        PublicationCheck {
            check: "build_revision_identified",
            satisfied: inputs.build_revision_valid,
            detail: inputs.build_revision_detail.clone(),
        },
        PublicationCheck {
            check: "build_tree_clean_at_compile_time",
            satisfied: inputs.build_tree_clean,
            detail: inputs.build_tree_detail.clone(),
        },
        PublicationCheck {
            check: "approved_optimized_build_profile",
            satisfied: inputs.build_profile_approved,
            detail: inputs.build_profile_detail.clone(),
        },
        PublicationCheck {
            check: "designated_first_tokyo_node",
            satisfied: inputs.node_is_designated_first_tokyo,
            detail: inputs.node_detail.clone(),
        },
        PublicationCheck {
            check: "nvme_sanity",
            satisfied: inputs.nvme_sanity_ok,
            detail: inputs.nvme_detail.clone(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full run with every check satisfied.
    fn publishable_inputs() -> PublicationInputs {
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
            cache_detail: "every listed real-traffic cache rung was measured".to_owned(),
            corpus_marker_evidence_valid: true,
            corpus_marker_detail: "1000 document markers, 1000 unique".to_owned(),
            measured_qps_acceptance_valid: true,
            measured_qps_acceptance_detail: "300-session QPS copies an exact measured cell"
                .to_owned(),
            build_revision_valid: true,
            build_revision_detail: "running executable BLAKE3 measured".to_owned(),
            build_tree_clean: true,
            build_tree_detail: "the build environment declared a committed tree".to_owned(),
            build_profile_approved: true,
            build_profile_detail: "declared build profile `release`, optimized artifact".to_owned(),
            node_is_designated_first_tokyo: true,
            node_detail: "declared node `tokyo-1` in `tokyo`".to_owned(),
            nvme_sanity_ok: true,
            nvme_detail: "measured on /dev/nvme0n1".to_owned(),
        }
    }

    #[test]
    fn a_fully_satisfied_full_run_is_publishable() {
        let decision = decide(&publishable_inputs());
        assert!(decision.publishable);
        assert!(decision.blocking_checks.is_empty());
        assert!(decision.non_publishable_reason.is_none());
        assert!(decision.checks.iter().all(|check| check.satisfied));
    }

    /// A commit that FAILED, or a ledger that did not record exactly one
    /// decision per measured commit, is failed gate enforcement. Neither may
    /// ride to publication on satisfied sample floors.
    #[test]
    fn gated_write_failures_block_publication() {
        let mut failed_commit = publishable_inputs();
        failed_commit.commits_ok = 9_999;
        failed_commit.commit_errors = 1;
        let decision = decide(&failed_commit);
        assert!(
            !decision.publishable,
            "one failed commit must fail the report closed"
        );
        assert_eq!(
            decision.blocking_checks,
            vec!["gated_write_commits_all_succeeded"]
        );
        let reason = decision
            .non_publishable_reason
            .expect("a blocked full run states why");
        assert!(reason.contains("9999 of 10000"), "{reason}");

        for (recorded, one_per_commit) in [(9_999_usize, false), (10_001, false), (10_000, false)] {
            let mut ledger = publishable_inputs();
            ledger.gate_decisions_recorded = recorded;
            ledger.one_decision_per_commit = one_per_commit;
            let decision = decide(&ledger);
            assert!(
                !decision.publishable,
                "a ledger with {recorded} decisions and one_decision_per_commit={one_per_commit} \
                 is invalid gate evidence"
            );
            assert!(
                decision
                    .blocking_checks
                    .contains(&"gate_ledger_one_decision_per_commit")
            );
        }

        // Zero measured commits is not a vacuous pass either.
        let mut empty = publishable_inputs();
        empty.measured_commits = 0;
        empty.commits_ok = 0;
        empty.gate_decisions_recorded = 0;
        assert!(!decide(&empty).publishable);
    }

    /// Every mandatory measured axis is an independent publication check. A
    /// full run with otherwise perfect floors cannot publish a missing wake
    /// sample, a broken session point, opaque-child RSS, an incomplete
    /// precision row, or a silent listed cache rung.
    #[test]
    fn every_mandatory_axis_blocks_publication_when_unavailable() {
        for (expected_check, break_axis) in [
            ("recall_latency_measurements_complete", 0_u8),
            ("wake_axis_complete", 1),
            ("session_curve_complete", 2),
            ("ten_child_rss_complete", 3),
            ("gated_write_measurements_complete", 4),
            ("precision_axis_complete", 5),
            ("cache_rungs_complete", 6),
            ("corpus_markers_collision_free", 7),
            ("measured_qps_acceptance_traceable", 8),
            ("build_revision_identified", 9),
        ] {
            let mut inputs = publishable_inputs();
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
                    inputs.cache_axis_valid = false;
                    inputs.cache_detail = "listed rung `embedding` had no event".to_owned();
                }
                7 => {
                    inputs.corpus_marker_evidence_valid = false;
                    inputs.corpus_marker_detail =
                        "1000 documents but 999 unique markers".to_owned();
                }
                8 => {
                    inputs.measured_qps_acceptance_valid = false;
                    inputs.measured_qps_acceptance_detail =
                        "QPS did not trace to a synchronized point".to_owned();
                }
                9 => {
                    inputs.build_revision_valid = false;
                    inputs.build_revision_detail =
                        "running executable could not be hashed".to_owned();
                }
                _ => unreachable!("fixed test cases"),
            }
            let decision = decide(&inputs);
            assert!(!decision.publishable, "{expected_check} must fail closed");
            assert_eq!(decision.blocking_checks, vec![expected_check]);
            assert!(
                decision
                    .non_publishable_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(expected_check))
            );
        }
    }

    /// The warmup floor is runtime evidence. A plan asking for 1,000 attempts
    /// cannot pass it when only 999 ClaimCandidate commits succeeded.
    #[test]
    fn failed_warmup_attempts_do_not_satisfy_the_publication_floor() {
        let mut inputs = publishable_inputs();
        inputs.gated_write_meets_floor = false;
        inputs.warmup_commits = 999;
        inputs.warmup_commit_errors = 1;
        let decision = decide(&inputs);
        assert_eq!(decision.blocking_checks, vec!["gated_write_floor"]);
        let reason = decision.non_publishable_reason.unwrap_or_default();
        assert!(reason.contains("999 of 1000"), "{reason}");
        assert!(reason.contains("1 failed"), "{reason}");
    }

    /// Numeric floors alone must not make an arbitrary host publishable.
    #[test]
    fn a_non_tokyo_host_or_failed_nvme_sanity_blocks_publication() {
        let mut off_node = publishable_inputs();
        off_node.node_is_designated_first_tokyo = false;
        off_node.node_detail = "no node identity was declared for this run".to_owned();
        let decision = decide(&off_node);
        assert!(!decision.publishable);
        assert_eq!(
            decision.blocking_checks,
            vec!["designated_first_tokyo_node"]
        );

        let mut no_nvme = publishable_inputs();
        no_nvme.nvme_sanity_ok = false;
        no_nvme.nvme_detail = "the backing device is not NVMe".to_owned();
        let decision = decide(&no_nvme);
        assert!(!decision.publishable);
        assert_eq!(decision.blocking_checks, vec!["nvme_sanity"]);
    }

    /// Performance numbers are properties of an ARTIFACT. A binary compiled
    /// from uncommitted sources belongs to no commit, and a debug or
    /// unoptimised binary measures a differently shaped experiment rather than
    /// a slower one. Each is its own named, independently blocking check, and
    /// both fail closed when the artifact embedded nothing to prove otherwise.
    #[test]
    fn a_dirty_or_unapproved_build_artifact_blocks_publication() {
        let mut dirty = publishable_inputs();
        dirty.build_tree_clean = false;
        dirty.build_tree_detail = "the build environment declared uncommitted sources".to_owned();
        let decision = decide(&dirty);
        assert!(!decision.publishable);
        assert_eq!(
            decision.blocking_checks,
            vec!["build_tree_clean_at_compile_time"]
        );
        assert!(
            decision
                .non_publishable_reason
                .unwrap_or_default()
                .contains("uncommitted sources")
        );

        let mut unknown = publishable_inputs();
        unknown.build_tree_clean = false;
        unknown.build_tree_detail = "no cleanliness was embedded at compile time".to_owned();
        assert!(
            !decide(&unknown).publishable,
            "an artifact that embedded nothing must not be assumed clean"
        );

        let mut debug_build = publishable_inputs();
        debug_build.build_profile_approved = false;
        debug_build.build_profile_detail =
            "declared build profile `dev`; debug_assertions=true".to_owned();
        let decision = decide(&debug_build);
        assert!(!decision.publishable);
        assert_eq!(
            decision.blocking_checks,
            vec!["approved_optimized_build_profile"]
        );
        assert!(
            decision
                .non_publishable_reason
                .unwrap_or_default()
                .contains("debug_assertions=true")
        );

        // The two are independent: neither one masks the other.
        let mut both = publishable_inputs();
        both.build_tree_clean = false;
        both.build_profile_approved = false;
        let decision = decide(&both);
        assert_eq!(
            decision.blocking_checks,
            vec![
                "build_tree_clean_at_compile_time",
                "approved_optimized_build_profile"
            ]
        );
    }

    /// A starved completed-sample floor blocks publication even when the plan
    /// asked for the full query count.
    #[test]
    fn a_starved_completed_sample_floor_blocks_publication() {
        let mut starved = publishable_inputs();
        starved.meets_completed_sample_floor = false;
        starved.cold_completed = 3;
        let decision = decide(&starved);
        assert!(!decision.publishable);
        assert_eq!(
            decision.blocking_checks,
            vec!["recall_latency_completed_sample_floor"]
        );
        assert!(
            decision
                .non_publishable_reason
                .unwrap_or_default()
                .contains("3 cold")
        );
    }

    /// A smoke is never publishable and keeps its own reason, however good its
    /// other evidence looks.
    #[test]
    fn a_smoke_is_never_publishable() {
        let mut smoke = publishable_inputs();
        smoke.mode = RunMode::SyntheticSmoke;
        let decision = decide(&smoke);
        assert!(!decision.publishable);
        assert_eq!(decision.blocking_checks, vec!["run_mode_is_full"]);
        assert_eq!(
            decision.non_publishable_reason.as_deref(),
            Some(SMOKE_NON_PUBLISHABLE_REASON)
        );
    }
}
