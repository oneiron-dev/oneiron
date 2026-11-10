//! A holder of `engine.controls.work_budget` only lowers the bounds on
//! snapshot handles (untangle 6.6f; Engine 9 Nov 19:48,
//! SNAPSHOT-SETTINGS-IN-6.6, in the shape of S66B-BUDGETS B1 = A). The row in
//! force is the owner's cap: the Coach lowers a bound and is refused a raise,
//! an agent without the work-budget class is refused, and the owner raises at
//! his own door, which writes no engine-control receipt. A holder of any
//! `engine.controls` class reads the bounds (Engine 10 Nov 14:36, S66F-READ =
//! C); an agent without one is refused. On the base there is no holder door,
//! and the read answers the owner alone.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_snapshot_read_bounds`.
#![cfg(oneiron_test_support)]

use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::settings::snapshot_read::{SNAPSHOT_READ_BOUNDS_KNOB, SnapshotReadSettings};
use oneiron::task_verb::sdk::{invoke, lower_snapshot_read_bounds_as};
use oneiron::test_doors::coach::{
    ENGINE_CONTROLS_VERBS, ENGINE_CONTROLS_WORK_BUDGET_VERB, coach, define_agent,
};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, owner, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

/// Bounds below the defaults in three places: half the rows per page, and
/// both lifetimes at five minutes.
fn lowered(held: SnapshotReadSettings) -> SnapshotReadSettings {
    SnapshotReadSettings {
        page_rows: held.page_rows / 2,
        default_lifetime_secs: 300,
        max_lifetime_secs: 300,
        ..held
    }
}

#[test]
fn the_coach_lowers_the_snapshot_bounds_and_never_raises_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let held = vault.snapshot_read_settings().expect("bounds");
    assert_eq!(held, SnapshotReadSettings::DEFAULT, "no row yet");

    let lower = lowered(held);
    vault
        .lower_snapshot_read_bounds_as_holder(coach, lower)
        .expect("lower bounds");
    assert_eq!(vault.snapshot_read_settings().expect("bounds"), lower);

    // A raise of one bound is refused, and the refusal names the bound.
    let raise = SnapshotReadSettings {
        page_rows: held.page_rows,
        ..lower
    };
    let refused = vault
        .lower_snapshot_read_bounds_as_holder(coach, raise)
        .expect_err("raising is the owner's act");
    assert!(format!("{refused:?}").contains("page_rows"), "{refused:?}");

    // The row's own rules stand: no zero bound, and the most lifetime never
    // falls below the default lifetime.
    let zero = SnapshotReadSettings {
        handle_rows: 0,
        ..lower
    };
    assert!(
        vault
            .lower_snapshot_read_bounds_as_holder(coach, zero)
            .is_err(),
        "a zero bound"
    );
    let most_below_default = SnapshotReadSettings {
        max_lifetime_secs: 100,
        ..lower
    };
    assert!(
        vault
            .lower_snapshot_read_bounds_as_holder(coach, most_below_default)
            .is_err(),
        "the most lifetime below the default lifetime"
    );
    assert_eq!(
        vault.snapshot_read_settings().expect("bounds"),
        lower,
        "a refused change leaves the row"
    );

    // One receipt, for the one change that landed.
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(_, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(change.knob, SNAPSHOT_READ_BOUNDS_KNOB);
    assert_eq!(change.class, EngineControlClass::WorkBudget);
    assert_eq!(change.by, coach);
    assert!(!change.owner);
    assert_eq!(
        change.value,
        serde_json::to_string(&lower).expect("rendered bounds")
    );
}

#[test]
fn only_the_work_budget_class_lowers_the_snapshot_bounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let agent = define_agent(&vault).expect("an agent");
    let held = vault.snapshot_read_settings().expect("bounds");
    let lower = lowered(held);

    // No grant: refused.
    assert!(
        lower_snapshot_read_bounds_as(&vault, EngineControlActor::Holder(agent), lower).is_err(),
        "an agent with no grant"
    );

    // The three other classes of engine.controls: still refused.
    let other_classes: Vec<&str> = ENGINE_CONTROLS_VERBS
        .iter()
        .copied()
        .filter(|verb| *verb != ENGINE_CONTROLS_WORK_BUDGET_VERB)
        .collect();
    assert_eq!(other_classes.len(), 3);
    stand_steward_grant(&vault, agent, &other_classes).expect("the other three classes");
    assert!(
        lower_snapshot_read_bounds_as(&vault, EngineControlActor::Holder(agent), lower).is_err(),
        "a grant that does not name the work-budget class"
    );
    assert_eq!(vault.snapshot_read_settings().expect("bounds"), held);
    assert!(
        vault
            .engine_control_changes(&owner)
            .expect("receipts")
            .is_empty(),
        "a refusal writes no receipt"
    );

    // The work-budget class alone: the verb lowers the bounds and answers
    // with the receipt.
    stand_steward_grant(&vault, agent, &[ENGINE_CONTROLS_WORK_BUDGET_VERB])
        .expect("the work-budget class");
    let answer = lower_snapshot_read_bounds_as(&vault, EngineControlActor::Holder(agent), lower)
        .expect("a work-budget holder lowers the bounds");
    assert_eq!(answer.change.class, EngineControlClass::WorkBudget);
    assert_eq!(answer.change.by, agent);
    assert!(!answer.change.owner);
    assert_eq!(vault.snapshot_read_settings().expect("bounds"), lower);
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].0, answer.id);
}

#[test]
fn the_owner_raises_at_his_own_door_and_the_coach_lowers_from_there() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let person = vault.ensure_embedded_owner_actor().expect("owner");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let held = vault.snapshot_read_settings().expect("bounds");
    let lower = lowered(held);

    // The owner may lower at this door too; it never raises for him either.
    let answer = lower_snapshot_read_bounds_as(&vault, EngineControlActor::Owner(&owner), lower)
        .expect("the owner lowers");
    assert!(answer.change.owner);
    assert_eq!(answer.change.by, person);
    assert!(
        lower_snapshot_read_bounds_as(&vault, EngineControlActor::Owner(&owner), held).is_err(),
        "this door raises for no one"
    );

    // The owner raises at his own door. That act is not an engine-control
    // change, so it writes no receipt of that kind.
    vault
        .replace_snapshot_read_settings_as_owner(&owner, held)
        .expect("the owner's replace");
    assert_eq!(vault.snapshot_read_settings().expect("bounds"), held);
    assert_eq!(
        vault
            .engine_control_changes(&owner)
            .expect("receipts")
            .len(),
        1
    );

    // The row in force is the cap again: the Coach lowers from it.
    vault
        .lower_snapshot_read_bounds_as_holder(coach, lower)
        .expect("the Coach lowers from the owner's new row");
    assert_eq!(vault.snapshot_read_settings().expect("bounds"), lower);
}

/// `vault.settings.snapshot_read` through the verb, on `actor`'s handle.
fn read_bounds(vault: &Vault, actor: EntityId, class: EdgeActorClass) -> MemoryResult<Value> {
    invoke(
        &vault.memory(actor, class),
        "vault.settings.snapshot_read",
        json!({}),
    )
}

#[test]
fn a_holder_of_any_engine_controls_class_reads_the_bounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let held = vault.snapshot_read_settings().expect("bounds");

    // No grant: refused.
    let refused = read_bounds(&vault, agent, EdgeActorClass::Agent).expect_err("no grant");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    // A Steward grant naming `read` alone names no engine.controls class:
    // still refused.
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let refused = read_bounds(&vault, agent, EdgeActorClass::Agent)
        .expect_err("`read` is not an engine.controls class");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    // One class other than the work budget reads the bounds, and still may
    // not lower them.
    let other_class = ENGINE_CONTROLS_VERBS
        .iter()
        .copied()
        .find(|verb| *verb != ENGINE_CONTROLS_WORK_BUDGET_VERB)
        .expect("another class");
    stand_steward_grant(&vault, agent, &[other_class]).expect("another class");
    let answer = read_bounds(&vault, agent, EdgeActorClass::Agent)
        .expect("a holder of an engine.controls class reads the bounds");
    let read: SnapshotReadSettings = serde_json::from_value(answer).expect("bounds");
    assert_eq!(read, held);
    assert!(
        lower_snapshot_read_bounds_as(&vault, EngineControlActor::Holder(agent), lowered(held))
            .is_err(),
        "reading the bounds is not lowering them"
    );

    // The Coach reads them through its default grant.
    let answer = read_bounds(&vault, coach, EdgeActorClass::System).expect("the Coach reads");
    let read: SnapshotReadSettings = serde_json::from_value(answer).expect("bounds");
    assert_eq!(read, held);
}
