//! A holder of any `engine.controls` class reads the bounds on snapshot
//! handles through `vault.settings.snapshot_read` (untangle 6.6f; Engine
//! 10 Nov 14:36, S66F-READ = C: every `engine.controls` read has the learning
//! dials' rule). An agent with no grant, or with a Steward grant that names
//! `read` alone, is refused. On the base the verb answers the owner alone.
//! Reading is not lowering: `coach_snapshot_read_bounds` holds that side.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test snapshot_bounds_read_through_grant`.
#![cfg(oneiron_test_support)]

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{
    ENGINE_CONTROLS_VERBS, ENGINE_CONTROLS_WORK_BUDGET_VERB, coach, define_agent,
};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

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

    // One class other than the work budget reads the bounds. On a base
    // where the read is the owner's alone, the test fails here.
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

    // The Coach reads them through its default grant.
    let answer = read_bounds(&vault, coach, EdgeActorClass::System).expect("the Coach reads");
    let read: SnapshotReadSettings = serde_json::from_value(answer).expect("bounds");
    assert_eq!(read, held);
}
