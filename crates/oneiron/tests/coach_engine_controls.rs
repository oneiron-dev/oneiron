//! The Coach's default grant (untangle 6.6a; S66-MAP ruled A, A, A, A):
//! `read` and `engine.controls`. Through it the Coach tunes every class of
//! the engine's stored knobs, each change writing a receipt that names it,
//! and reads a project goal through its own read row (GOAL-PRIVACY). A
//! Steward grant on the default four verbs holds no `engine.controls`; a
//! Coach grant without `read` reads no goal, while the owner's read stands.
//! On the base there is no `engine.controls` check.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_engine_controls`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::{
    EngineControlActor, EngineControlClass, SystemAgentGrantNarrowing, SystemFunction,
};
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERB, coach, write_root_goal};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_READ_VERB, STEWARD_VERBS, grant_mark, open_owner_carrier_vault, owner,
    stand_steward_grant,
};
use oneiron::{EntityId, Vault};

const CLASSES: [EngineControlClass; 4] = [
    EngineControlClass::MaintenanceCadence,
    EngineControlClass::WorkBudget,
    EngineControlClass::WakeCadence,
    EngineControlClass::KnowledgeRecipe,
];

/// A device vault as the other Coach tests open it: an embedded owner, an
/// in-memory device keystore and this install's machine profile, so the
/// owner's goal write has a carrier.
fn open(dir: &tempfile::TempDir) -> Vault {
    open_owner_carrier_vault(dir.path()).expect("owner carrier vault")
}

fn allowed(vault: &Vault, actor: EngineControlActor<'_>, class: EngineControlClass) -> bool {
    vault.engine_control_allowed(actor, class).expect("check")
}

#[test]
fn the_coach_tunes_the_engine_and_reads_through_its_default_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    let project = write_root_goal(&vault, &owner).expect("goal");
    let goal = vault.project_intake_goal(project).expect("owner read");
    assert!(goal.is_some(), "the owner reads the goal");

    // Before any grant: the owner tunes, the Coach does not.
    for class in CLASSES {
        assert!(allowed(&vault, EngineControlActor::Owner(&owner), class));
        assert!(
            !allowed(&vault, EngineControlActor::Holder(coach), class),
            "{class:?}: no grant, no control"
        );
    }
    assert!(
        vault
            .apply_engine_control(
                EngineControlActor::Holder(coach),
                EngineControlClass::WakeCadence,
                "DREAMER_PROACTIVITY_CADENCE",
                "{\"period_secs\":43200}",
                |_| Ok(()),
            )
            .is_err(),
        "the door refuses a Coach without the grant"
    );

    // With its default grant: every class, a receipt naming it, the goal
    // read through its own read row, and its offer row kept.
    stand_steward_grant(&vault, coach, &[STEWARD_READ_VERB, ENGINE_CONTROLS_VERB])
        .expect("the Coach's default grant");
    for class in CLASSES {
        assert!(
            allowed(&vault, EngineControlActor::Holder(coach), class),
            "{class:?}: the grant gives control"
        );
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
    assert!(wrote, "the change was written");
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(id, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(*id, receipt);
    assert_eq!(change.by, coach, "the receipt names the Coach");
    assert!(!change.owner);
    assert_eq!(change.class, EngineControlClass::WakeCadence);
    assert_eq!(change.knob, "DREAMER_PROACTIVITY_CADENCE");
    assert_eq!(
        vault
            .project_intake_goal_for_coach(project)
            .expect("coach read"),
        goal,
        "the Coach reads the goal through its grant"
    );
    assert!(vault.coach_offer_reach().expect("offer reach"));

    // Without `read`, the Coach reads no goal, while the owner's read of the
    // same goal stands (GOAL-PRIVACY).
    stand_steward_grant(&vault, coach, &[ENGINE_CONTROLS_VERB]).expect("controls only");
    assert_eq!(
        vault
            .project_intake_goal_for_coach(project)
            .expect("coach read"),
        None,
        "a grant without read reads no goal"
    );
    assert_eq!(
        vault.project_intake_goal(project).expect("owner read"),
        goal
    );
    assert!(vault.coach_offer_reach().expect("offer reach"));
}

#[test]
fn only_a_grant_that_names_engine_controls_gives_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(&dir);
    let agent = EntityId::now();

    // A Steward grant on the default four verbs holds no engine.controls.
    stand_steward_grant(&vault, agent, &STEWARD_VERBS).expect("default Steward grant");
    assert!(!allowed(
        &vault,
        EngineControlActor::Holder(agent),
        EngineControlClass::WorkBudget
    ));

    // One that names it does.
    stand_steward_grant(&vault, agent, &[ENGINE_CONTROLS_VERB]).expect("engine.controls grant");
    assert!(allowed(
        &vault,
        EngineControlActor::Holder(agent),
        EngineControlClass::WorkBudget
    ));
}

/// The host's first mint gives the Coach its default grant, {read,
/// engine.controls}, as the owner's signed act and marked system-critical:
/// narrowing it off engine.controls warns first, and once confirmed the
/// Coach tunes nothing.
#[test]
fn the_coachs_first_mint_holds_engine_controls_and_narrowing_it_warns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    assert!(!allowed(
        &vault,
        EngineControlActor::Holder(coach),
        EngineControlClass::WorkBudget
    ));

    vault.provision_system_agent_grants().expect("first mint");
    let Some(GrantMark::Minted { verbs, .. }) = grant_mark(&vault, coach).expect("mark") else {
        panic!("the first mint gives the Coach its grant");
    };
    let read = BTreeSet::from([STEWARD_READ_VERB.to_owned()]);
    let mut default = read.clone();
    default.insert(ENGINE_CONTROLS_VERB.to_owned());
    assert_eq!(verbs, default, "the Coach's default grant");
    for class in CLASSES {
        assert!(
            allowed(&vault, EngineControlActor::Holder(coach), class),
            "{class:?}: the minted grant gives control"
        );
    }

    let SystemAgentGrantNarrowing::ConfirmRequired {
        breaks, confirm, ..
    } = vault
        .narrow_system_agent_grant(&owner, coach, &read, None)
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
        .narrow_system_agent_grant(&owner, coach, &read, Some(confirm))
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
            .is_err(),
        "the door refuses a narrowed Coach"
    );
}
