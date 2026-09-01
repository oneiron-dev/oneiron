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
//! * numeric floors alone say nothing about WHERE a run happened, so a full
//!   report also has to prove it ran on the designated first Tokyo node with a
//!   successful NVMe sanity result.

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
/// measured axes; nothing here re-runs or re-derives a measurement.
pub(crate) struct PublicationInputs {
    pub(crate) mode: RunMode,
    pub(crate) meets_plan_floor: bool,
    pub(crate) meets_completed_sample_floor: bool,
    pub(crate) cold_completed: usize,
    pub(crate) warm_completed: usize,
    pub(crate) completed_sample_floor: usize,
    pub(crate) gated_write_meets_floor: bool,
    pub(crate) measured_commits: usize,
    pub(crate) commits_ok: usize,
    pub(crate) commit_errors: usize,
    pub(crate) gate_decisions_recorded: usize,
    pub(crate) one_decision_per_commit: bool,
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
            check: "gated_write_floor",
            satisfied: inputs.gated_write_meets_floor,
            detail: "the plan must ask for >=1000 warmup and >=10000 measured gated writes"
                .to_owned(),
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
            gated_write_meets_floor: true,
            measured_commits: 10_000,
            commits_ok: 10_000,
            commit_errors: 0,
            gate_decisions_recorded: 10_000,
            one_decision_per_commit: true,
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

    /// Numeric floors alone must not make an arbitrary host publishable.
    #[test]
    fn a_non_tokyo_host_or_failed_nvme_sanity_blocks_publication() {
        let mut off_node = publishable_inputs();
        off_node.node_is_designated_first_tokyo = false;
        off_node.node_detail = "no node identity was declared for this run".to_owned();
        let decision = decide(&off_node);
        assert!(!decision.publishable);
        assert_eq!(decision.blocking_checks, vec!["designated_first_tokyo_node"]);

        let mut no_nvme = publishable_inputs();
        no_nvme.nvme_sanity_ok = false;
        no_nvme.nvme_detail = "the backing device is not NVMe".to_owned();
        let decision = decide(&no_nvme);
        assert!(!decision.publishable);
        assert_eq!(decision.blocking_checks, vec!["nvme_sanity"]);
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
