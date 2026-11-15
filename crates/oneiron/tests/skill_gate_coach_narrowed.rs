//! Owner skill-goal work does not borrow the Coach's read grant.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::federation::{SystemAgentGrantNarrowing, SystemFunction};
use oneiron::skill_optimize::{
    set_skill_goal_project, skill_edit_goal, skill_tradeoff_preferences,
};
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, coach, write_root_goal};
use oneiron::test_doors::skill_gate::write_skill;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{EdgeActorClass, WriteActor};
use std::collections::BTreeSet;

#[test]
fn owner_skill_goal_binding_does_not_require_coach_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    vault
        .provision_system_agent_grants()
        .expect("provision grants");
    let coach = coach(&vault).expect("Coach");
    let project = write_root_goal(&vault, &owner).expect("root goal");
    let skill = write_skill(&vault, "skill-gate.fixture").expect("active skill");
    set_skill_goal_project(&vault, &owner, &skill, Some(project)).expect("initial binding");
    let coach_reader = WriteActor::new(coach, EdgeActorClass::System);
    assert!(
        vault
            .project_intake_goal_as(coach_reader, project)
            .unwrap()
            .is_some()
    );

    let keep: BTreeSet<String> = ENGINE_CONTROLS_VERBS
        .into_iter()
        .map(str::to_owned)
        .collect();
    let confirm = match vault
        .narrow_system_agent_grant(&owner, coach, &keep, None)
        .unwrap()
    {
        SystemAgentGrantNarrowing::ConfirmRequired {
            breaks, confirm, ..
        } => {
            assert!(
                breaks.contains(&SystemFunction::CoachChecks),
                "narrowing to the controls verbs breaks the Coach's checks: {breaks:?}"
            );
            confirm
        }
        other => panic!("expected narrowing confirmation, got {other:?}"),
    };
    let narrowed = vault
        .narrow_system_agent_grant(&owner, coach, &keep, Some(confirm))
        .unwrap();
    assert!(matches!(
        narrowed,
        SystemAgentGrantNarrowing::Narrowed { .. }
    ));
    assert!(
        vault
            .project_intake_goal_as(coach_reader, project)
            .unwrap()
            .is_none()
    );
    assert!(
        skill_edit_goal(&vault, &skill).is_err(),
        "Coach goal wrapper stays narrowed"
    );

    assert!(
        set_skill_goal_project(&vault, &owner, &skill, Some(project)).is_ok(),
        "the owner's skill goal binding must not require the Coach's read grant"
    );
    assert!(skill_tradeoff_preferences(&vault, &skill).is_ok());
    assert!(
        vault
            .project_intake_goal_as(coach_reader, project)
            .unwrap()
            .is_none()
    );
    assert!(
        skill_edit_goal(&vault, &skill).is_err(),
        "owner act must not widen Coach"
    );
}
