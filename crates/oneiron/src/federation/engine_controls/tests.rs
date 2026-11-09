//! The Coach's default grant (untangle 6.6; S66-MAP ruled A): `read` and
//! `engine.controls`, held to the grant and its MACHINE binding. Through it
//! the Coach tunes the engine's knobs with a receipt naming it, and reads a
//! project goal through the gate (GOAL-PRIVACY). Narrowing it warns first.
//!
//! Written by reading: the oneiron lib test target does not compile on main
//! (26 Oct decree). The narrowing signs the owner's revoke and mint, so its
//! fixture must carry an owner act (an install machine profile), as 6.3c's.
use super::*;
use crate::federation::grant_scope::{ENGINE_CONTROLS_VERB, STEWARD_READ_VERB, STEWARD_VERBS};
use crate::federation::{SystemAgentGrantNarrowing, SystemFunction};
use crate::workspace_roster::{GoalAxis, GoalExplorationBudget, GoalPreference, GoalRecord};
use std::collections::BTreeSet;

fn axis(name: &str, measure: &str, bound: &str) -> GoalAxis {
    GoalAxis {
        name: name.into(),
        measure: measure.into(),
        bound: bound.into(),
    }
}

fn goal() -> GoalRecord {
    GoalRecord {
        goal: "Answer customer requests correctly".into(),
        why: "Reduce repeat support tickets".into(),
        primary_axes: vec![axis(
            "confirmed_answers",
            "resolved requests per week from receipts",
            ">= 90",
        )],
        floor_axes: vec![axis(
            "unsafe_answers",
            "held-out unsafe answer count",
            "= 0",
        )],
        cost_axes: vec![axis("tokens", "token spend per week", "<= 10000")],
        preferences: vec![GoalPreference {
            prefer: "lower cost".into(),
            over: "faster response".into(),
            reason: "The human chose cost on this tradeoff".into(),
        }],
        exploration_budget: GoalExplorationBudget {
            max_spend: 1000,
            exploration_slice: 100,
            unit: crate::run_budget::LeaseUnit::tokens(),
            human_minutes: 20,
        },
    }
}

const CLASSES: [EngineControlClass; 4] = [
    EngineControlClass::MaintenanceCadence,
    EngineControlClass::WorkBudget,
    EngineControlClass::WakeCadence,
    EngineControlClass::KnowledgeRecipe,
];

fn allowed(vault: &Vault, actor: EngineControlActor<'_>, class: EngineControlClass) -> bool {
    vault.engine_control_allowed(actor, class).expect("check")
}

#[test]
fn the_coach_tunes_the_engine_and_reads_through_its_default_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("vault");
    crate::test_util::provision_engine_machines(&vault);
    let owner_ref = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    let coach = vault.coach_authority().expect("coach").entity_ref();
    let project = vault.root_project().expect("root project");
    vault
        .write_project_goal_from_intake(&owner, project, &goal(), 2)
        .expect("goal");

    // Before any grant: the owner tunes, the Coach does not, and the
    // Coach's goal read is as before.
    for class in CLASSES {
        assert!(allowed(&vault, EngineControlActor::Owner(&owner), class));
        assert!(!allowed(&vault, EngineControlActor::Holder(coach), class));
    }
    assert_eq!(
        vault.project_intake_goal_for_coach(project).unwrap(),
        Some(goal())
    );
    assert!(vault.coach_offer_reach().unwrap());

    // With its default grant: every class, a receipt naming it, the goal
    // read through its own read row, and its offer row kept.
    vault
        .stand_steward_grant_for_test(coach, &[STEWARD_READ_VERB, ENGINE_CONTROLS_VERB])
        .expect("coach grant");
    for class in CLASSES {
        assert!(allowed(&vault, EngineControlActor::Holder(coach), class));
    }
    let mut wrote = false;
    let receipt = vault
        .apply_engine_control(
            EngineControlActor::Holder(coach),
            EngineControlClass::WakeCadence,
            "DREAMER_PROACTIVITY_CADENCE",
            "{\"period_secs\":43200}",
            |_| {
                wrote = true;
                Ok(())
            },
        )
        .expect("the Coach's change");
    assert!(wrote);
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(id, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(*id, receipt);
    assert_eq!(change.by, coach);
    assert!(!change.owner);
    assert_eq!(change.class, EngineControlClass::WakeCadence);
    assert_eq!(
        vault.project_intake_goal_for_coach(project).unwrap(),
        Some(goal())
    );
    assert!(vault.coach_offer_reach().unwrap());

    // Narrowed off engine.controls, after the warning: the Coach tunes
    // nothing and the door refuses it, while it still reads.
    let keep = BTreeSet::from([STEWARD_READ_VERB.to_owned()]);
    let SystemAgentGrantNarrowing::ConfirmRequired {
        breaks, confirm, ..
    } = vault
        .narrow_system_agent_grant(&owner, coach, &keep, None)
        .expect("narrowing")
    else {
        panic!("the Coach's grant is system-critical");
    };
    assert_eq!(breaks, vec![SystemFunction::EngineControlsJobs]);
    assert!(allowed(
        &vault,
        EngineControlActor::Holder(coach),
        EngineControlClass::WorkBudget
    ));
    vault
        .narrow_system_agent_grant(&owner, coach, &keep, Some(confirm))
        .expect("confirmed narrowing");
    assert!(!allowed(
        &vault,
        EngineControlActor::Holder(coach),
        EngineControlClass::WorkBudget
    ));
    assert!(
        vault
            .apply_engine_control(
                EngineControlActor::Holder(coach),
                EngineControlClass::WorkBudget,
                "DREAMER_CONSOLIDATION_SELECTION",
                "{}",
                |_| Ok(()),
            )
            .is_err()
    );
    assert_eq!(
        vault.project_intake_goal_for_coach(project).unwrap(),
        Some(goal())
    );

    // Without `read`, the Coach's goal read is absent, while the owner's
    // read of the same goal stands (GOAL-PRIVACY).
    vault
        .stand_steward_grant_for_test(coach, &[ENGINE_CONTROLS_VERB])
        .expect("controls only");
    assert_eq!(vault.project_intake_goal_for_coach(project).unwrap(), None);
    assert_eq!(vault.project_intake_goal(project).unwrap(), Some(goal()));
    assert!(vault.coach_offer_reach().unwrap());
}

#[test]
fn only_an_owners_grant_gives_engine_controls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).expect("vault");
    crate::test_util::provision_engine_machines(&vault);
    let agent = EntityId::now();

    // A Steward grant on the default four verbs holds no engine.controls.
    vault
        .stand_steward_grant_for_test(agent, &STEWARD_VERBS)
        .expect("default Steward grant");
    assert!(!allowed(
        &vault,
        EngineControlActor::Holder(agent),
        EngineControlClass::WorkBudget
    ));

    // One that names it does.
    vault
        .stand_steward_grant_for_test(agent, &[ENGINE_CONTROLS_VERB])
        .expect("engine.controls grant");
    assert!(allowed(
        &vault,
        EngineControlActor::Holder(agent),
        EngineControlClass::WorkBudget
    ));
}
