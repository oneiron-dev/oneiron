use crate::run_tree::{RunTree, RunTreeNode, RunTreeRepair, RunTreeStatus, RunTreeTimestamps};

use super::{
    MeasuredBranch, OracleSignal, SelectionDecision, SelectionError, SelectionPolicy,
    decide_experiment,
};

fn node(id: &str, children: Vec<RunTreeNode>) -> RunTreeNode {
    RunTreeNode {
        attempt_id: id.to_owned(),
        run_id: Some("campaign-1".into()),
        parent_id: None,
        worker_kind: "experiment".into(),
        worker: None,
        agent_id: None,
        status: RunTreeStatus::Completed,
        result_ref: None,
        timestamps: RunTreeTimestamps {
            created_at: 0,
            updated_at: 0,
        },
        failure: None,
        events: Vec::new(),
        children,
    }
}

fn tree() -> RunTree {
    RunTree {
        roots: vec![
            node(
                "high",
                vec![node("child-1", vec![]), node("child-2", vec![])],
            ),
            node("fresh", vec![]),
        ],
        repairs: vec![],
    }
}

fn branch(id: &str, quality: f64, gain: f64) -> MeasuredBranch {
    MeasuredBranch {
        attempt_id: id.into(),
        quality,
        expected_gain: gain,
    }
}

fn policy() -> SelectionPolicy {
    SelectionPolicy {
        expected_gain_floor: 0.2,
        plateau_rounds: 2,
        stagnation_rounds: 2,
        escalate_plateau: false,
    }
}

fn decide(
    branches: &[MeasuredBranch],
    quality_history: &[f64],
    gain_history: &[f64],
    budget: bool,
    oracle: OracleSignal,
    policy: SelectionPolicy,
) -> Result<SelectionDecision, SelectionError> {
    decide_experiment(
        &tree(),
        branches,
        quality_history,
        gain_history,
        policy,
        budget,
        oracle,
    )
}

#[test]
fn dgm_weights_prefer_unexplored_branch_and_ties_are_stable() {
    let branches = [branch("high", 2.0, 0.5), branch("fresh", 0.0, 0.3)];
    assert_eq!(
        decide(&branches, &[], &[], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::Fork {
            parent_id: "fresh".into(),
            stagnation: false
        }
    );
    let reversed = [branches[1].clone(), branches[0].clone()];
    assert_eq!(
        decide(&reversed, &[], &[], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::Fork {
            parent_id: "fresh".into(),
            stagnation: false
        }
    );
    let equal = [branch("fresh", 0.0, 1.0), branch("child-1", 0.0, 1.0)];
    assert_eq!(
        decide(&equal, &[], &[], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::Fork {
            parent_id: "child-1".into(),
            stagnation: false
        }
    );
}

#[test]
fn top_one_stagnation_forks_from_an_alternate_parent() {
    let branches = [branch("high", 10.0, 0.6), branch("fresh", -10.0, 0.4)];
    assert_eq!(
        decide(
            &branches,
            &[10.0, 10.0],
            &[0.8],
            true,
            OracleSignal::NoSignal,
            policy()
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "fresh".into(),
            stagnation: true
        }
    );
    assert_eq!(
        decide(
            &branches,
            &[9.0, 9.0],
            &[],
            true,
            OracleSignal::NoSignal,
            policy()
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "high".into(),
            stagnation: false
        }
    );
    assert_eq!(
        decide(
            &branches[..1],
            &[10.0, 10.0],
            &[],
            true,
            OracleSignal::NoSignal,
            policy()
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "high".into(),
            stagnation: true
        }
    );
}

#[test]
fn plateau_stops_only_after_k_consecutive_low_gain_rounds() {
    let low = [branch("fresh", 0.0, 0.1)];
    let high = [branch("fresh", 0.0, 0.2)];
    assert!(matches!(
        decide(&low, &[], &[], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::Fork { .. }
    ));
    assert_eq!(
        decide(&low, &[], &[0.1], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::StoppedPlateau
    );
    assert!(matches!(
        decide(
            &low,
            &[],
            &[0.1, 0.2],
            true,
            OracleSignal::NoSignal,
            policy()
        )
        .unwrap(),
        SelectionDecision::Fork { .. }
    ));
    assert!(matches!(
        decide(&high, &[], &[0.1], true, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::Fork { .. }
    ));
    let mut escalate = policy();
    escalate.escalate_plateau = true;
    assert_eq!(
        decide(&low, &[], &[0.1], true, OracleSignal::NoSignal, escalate).unwrap(),
        SelectionDecision::EscalatePlateau
    );
}

#[test]
fn budget_is_pause_not_terminal_cause_and_oracle_is_external_cause() {
    let low = [branch("fresh", 0.0, 0.1)];
    assert_eq!(
        decide(&low, &[], &[0.1], false, OracleSignal::NoSignal, policy()).unwrap(),
        SelectionDecision::PausedBudget
    );
    assert_eq!(
        decide(&low, &[], &[0.1], false, OracleSignal::GoalMet, policy()).unwrap(),
        SelectionDecision::StoppedOracle
    );
}

#[test]
fn ungrounded_or_invalid_evidence_never_selects_a_parent() {
    let invalid = [branch("not-in-tree", 1.0, 0.5)];
    assert_eq!(
        decide(&invalid, &[], &[], true, OracleSignal::NoSignal, policy()),
        Err(SelectionError::Invalid(
            "measured branch absent from run tree"
        ))
    );
    let duplicate = [branch("fresh", 1.0, 0.5), branch("fresh", 2.0, 0.5)];
    assert_eq!(
        decide(&duplicate, &[], &[], true, OracleSignal::NoSignal, policy()),
        Err(SelectionError::Invalid("duplicate measured branch"))
    );
    for (quality, gain) in [(f64::NAN, 0.5), (1.0, f64::INFINITY), (1.0, -0.5)] {
        assert!(
            decide(
                &[branch("fresh", quality, gain)],
                &[],
                &[],
                true,
                OracleSignal::NoSignal,
                policy()
            )
            .is_err()
        );
    }
    assert!(
        decide(
            &[branch("fresh", 0.0, 0.5)],
            &[],
            &[f64::NAN],
            true,
            OracleSignal::NoSignal,
            policy()
        )
        .is_err()
    );
    assert!(decide(&[], &[], &[], false, OracleSignal::GoalMet, policy()).is_err());
}

#[test]
fn repaired_tree_cannot_choose_a_parent_using_rewritten_child_counts() {
    let mut repaired = tree();
    repaired.repairs.push(RunTreeRepair::MissingParent {
        attempt_id: "fresh".into(),
        missing_parent_id: "lost".into(),
    });
    assert_eq!(
        decide_experiment(
            &repaired,
            &[branch("fresh", 0.0, 0.5)],
            &[],
            &[],
            policy(),
            true,
            OracleSignal::NoSignal
        ),
        Err(SelectionError::Invalid("repaired run-tree ancestry"))
    );
}
