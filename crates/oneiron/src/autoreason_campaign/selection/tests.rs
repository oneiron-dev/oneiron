use crate::run_tree::{RunTree, RunTreeNode, RunTreeRepair, RunTreeStatus, RunTreeTimestamps};

use super::{
    MeasuredBranch, OracleSignal, SelectionDecision, SelectionError, SelectionPolicy,
    SelectionPolicyRow, SelectionPolicyScope, SelectionPrecedence, StagnationAction,
    decide_experiment, decide_experiment_for, selection_policy_for,
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
        stagnation_action: StagnationAction::Diversify,
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
fn finite_extreme_scores_keep_the_dgm_order_without_underflow() {
    let tree = RunTree {
        roots: vec![node("a", vec![]), node("b", vec![])],
        repairs: vec![],
    };
    let branches = [branch("a", -2000.0, 0.5), branch("b", -1000.0, 0.5)];
    assert_eq!(
        decide_experiment(
            &tree,
            &branches,
            &[],
            &[],
            policy(),
            true,
            OracleSignal::NoSignal
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "b".into(),
            stagnation: false
        }
    );
    let positive = [branch("a", 2000.0, 0.5), branch("b", 1000.0, 0.5)];
    assert_eq!(
        decide_experiment(
            &tree,
            &positive,
            &[],
            &[],
            policy(),
            true,
            OracleSignal::NoSignal
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "a".into(),
            stagnation: false
        }
    );
}

#[test]
fn saturated_negative_logits_still_count_children() {
    let tree = RunTree {
        roots: vec![node("a", vec![node("a-child", vec![])]), node("b", vec![])],
        repairs: vec![],
    };
    let branches = [branch("a", -1e308, 0.5), branch("b", -1e308, 0.5)];
    assert_eq!(
        decide_experiment(
            &tree,
            &branches,
            &[],
            &[],
            policy(),
            true,
            OracleSignal::NoSignal
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "b".into(),
            stagnation: false
        },
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
    assert!(matches!(
        decide(&invalid, &[], &[], true, OracleSignal::NoSignal, policy()),
        Err(SelectionError::Invalid(_))
    ));
    let duplicate = [branch("fresh", 1.0, 0.5), branch("fresh", 2.0, 0.5)];
    assert!(matches!(
        decide(&duplicate, &[], &[], true, OracleSignal::NoSignal, policy()),
        Err(SelectionError::Invalid(_))
    ));
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
    assert!(matches!(
        decide_experiment(
            &repaired,
            &[branch("fresh", 0.0, 0.5)],
            &[],
            &[],
            policy(),
            true,
            OracleSignal::NoSignal
        ),
        Err(SelectionError::Invalid(_))
    ));
}

/// Replace just the decision rows in the real seeded POLICY_MANIFEST, as a
/// locally trusted owner edit. The normal manifest fold must see the change.
fn write_policy_rows(vault: &crate::Vault, rows: &[SelectionPolicyRow]) {
    let raw = crate::gate::default_policy_manifest();
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut raw.as_slice()).unwrap()
    else {
        panic!("seed is a manifest map")
    };
    let bytes = rmp_serde::to_vec_named(rows).unwrap();
    let value = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap();
    *entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("experiment_selection"))
        .unwrap() = (rmpv::Value::from("experiment_selection"), value);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &rmpv::Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &data,
    )
    .unwrap();
}

#[test]
fn manifest_row_edit_changes_stagnation_action_without_code_change() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let measured = [branch("high", 10.0, 0.6), branch("fresh", -10.0, 0.4)];
    let decide_from_vault = || {
        decide_experiment_for(
            &vault,
            "campaign-1",
            None,
            &tree(),
            &measured,
            &[10.0, 10.0],
            &[],
            true,
            OracleSignal::NoSignal,
        )
        .unwrap()
    };
    assert_eq!(
        decide_from_vault(),
        SelectionDecision::Fork {
            parent_id: "fresh".into(),
            stagnation: true,
        }
    );
    let mut vault_policy = selection_policy_for(&vault, "campaign-1", None).unwrap();
    vault_policy.stagnation_action = StagnationAction::Dgm;
    write_policy_rows(
        &vault,
        &[SelectionPolicyRow {
            precedence: SelectionPrecedence::NestedNarrowing,
            scope: SelectionPolicyScope {
                campaign_id: None,
                holder_id: None,
            },
            policy: vault_policy,
        }],
    );
    assert_eq!(
        decide_from_vault(),
        SelectionDecision::Fork {
            parent_id: "high".into(),
            stagnation: true,
        }
    );
}

#[test]
fn nested_policy_narrows_and_holder_cannot_override_vault_cap() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let base = selection_policy_for(&vault, "campaign-1", None).unwrap();
    assert_eq!(base.stagnation_action, StagnationAction::Diversify);
    let rows = [
        SelectionPolicyRow {
            precedence: SelectionPrecedence::NestedNarrowing,
            scope: SelectionPolicyScope {
                campaign_id: None,
                holder_id: None,
            },
            policy: base,
        },
        SelectionPolicyRow {
            precedence: SelectionPrecedence::NestedNarrowing,
            scope: SelectionPolicyScope {
                campaign_id: Some("campaign-1".into()),
                holder_id: None,
            },
            policy: SelectionPolicy {
                stagnation_rounds: 1,
                expected_gain_floor: 0.25,
                ..base
            },
        },
        SelectionPolicyRow {
            precedence: SelectionPrecedence::NestedNarrowing,
            scope: SelectionPolicyScope {
                campaign_id: Some("campaign-1".into()),
                holder_id: Some("agent-a".into()),
            },
            policy: SelectionPolicy {
                stagnation_rounds: 99,
                expected_gain_floor: 0.0,
                stagnation_action: StagnationAction::Dgm,
                ..base
            },
        },
    ];
    write_policy_rows(&vault, &rows);
    let selected = selection_policy_for(&vault, "campaign-1", Some("agent-a")).unwrap();
    assert_eq!(selected.stagnation_rounds, 1);
    assert_eq!(selected.expected_gain_floor, 0.25);
    assert_eq!(selected.stagnation_action, StagnationAction::Diversify);
    assert_eq!(
        selection_policy_for(&vault, "campaign-1", Some("agent-b")).unwrap(),
        selected
    );
    assert_eq!(
        selection_policy_for(&vault, "other", Some("agent-a")).unwrap(),
        base
    );
    // The precedence row is itself data: owner switches to holder-over-campaign.
    let mut precedence_rows = rows.clone();
    precedence_rows[0].precedence = SelectionPrecedence::HolderUnderVault;
    write_policy_rows(&vault, &precedence_rows);
    let holder = selection_policy_for(&vault, "campaign-1", Some("agent-a")).unwrap();
    assert_eq!(holder.stagnation_rounds, base.stagnation_rounds);
    assert_eq!(holder.stagnation_action, StagnationAction::Diversify);
    assert_eq!(
        selection_policy_for(&vault, "campaign-1", Some("agent-b")).unwrap(),
        selected
    );
    // Restore the nested rule for the default decision assertion below.
    write_policy_rows(&vault, &rows);
    let measured = [branch("high", 10.0, 0.6), branch("fresh", -10.0, 0.4)];
    assert_eq!(
        decide_experiment(
            &tree(),
            &measured,
            &[10.0],
            &[],
            selected,
            true,
            OracleSignal::NoSignal
        )
        .unwrap(),
        SelectionDecision::Fork {
            parent_id: "fresh".into(),
            stagnation: true,
        }
    );
}

#[test]
fn malformed_or_missing_manifest_policy_never_grants_a_search_choice() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    write_policy_rows(&vault, &[]);
    assert!(selection_policy_for(&vault, "campaign-1", None).is_err());
    let id = crate::gate::default_policy_manifest_id().unwrap();
    crate::test_util::put_policy_manifest_bytes(&vault, id, b"bad manifest").unwrap();
    assert!(selection_policy_for(&vault, "campaign-1", None).is_err());
}
