//! The Coach tunes the learning dials through `engine.controls` (untangle
//! 6.6b, the first family; S66-MAP = A). The host's first mint gives the
//! Coach its default grant; through it the Coach sets a dial it may tune,
//! the row records it as the setter, the value is in force, and a receipt
//! names it. A key outside the list stays the owner's. The owner's rows
//! stand: a pin the owner set is the owner's to change, and a work budget
//! stays within the owner's own row. An agent without the grant changes
//! nothing. On the base there is no holder door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_learning_dials`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::EngineControlClass;
use oneiron::learning_setting::{
    AUDIT_RATE, CREDIT_ENABLED, SettingMode, SettingRow, SettingScope, put_setting_row,
    setting_value,
};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::write_envelope::WriteActor;

const QUESTION_BUDGET: &str = "question_call_budget_ms";

fn row(key: &str, mode: SettingMode, value: f64) -> SettingRow {
    SettingRow {
        key: key.to_owned(),
        mode,
        value,
        weight_runs: (mode == SettingMode::Seed).then_some(4.0),
        at: 10,
        why: "tuning".to_owned(),
    }
}

#[test]
fn the_coach_tunes_a_learning_dial_and_the_owners_rows_stand() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let owner = WriteActor::new(
        vault.ensure_embedded_owner_actor().expect("owner"),
        EdgeActorClass::Human,
    );
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let vault_scope = SettingScope::Vault;

    // The Coach pins a dial it may tune: in force, its setter, a receipt.
    let receipt = vault
        .put_setting_row_as_holder(
            coach,
            &vault_scope,
            &row(AUDIT_RATE.key, SettingMode::Pin, 0.25),
        )
        .expect("the Coach's dial");
    assert_eq!(setting_value(&vault, &AUDIT_RATE).expect("value"), 0.25);
    let changes = vault
        .engine_control_changes(&owner_proof)
        .expect("receipts");
    let [(id, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(*id, receipt);
    assert_eq!(change.by, coach);
    assert!(!change.owner);
    assert_eq!(change.class, EngineControlClass::MaintenanceCadence);
    assert_eq!(change.knob, AUDIT_RATE.key);

    // A key outside the list stays the owner's.
    assert!(
        vault
            .put_setting_row_as_holder(
                coach,
                &vault_scope,
                &row(CREDIT_ENABLED.key, SettingMode::Pin, 0.0)
            )
            .is_err(),
        "credit_enabled is the owner's"
    );
    assert!(
        vault
            .put_setting_row_as_holder(
                coach,
                &vault_scope,
                &row("health.card.owner_copy", SettingMode::Pin, 0.0)
            )
            .is_err(),
        "the owner's copy of health cards is the owner's"
    );

    // A pin the owner set is the owner's to change.
    put_setting_row(&vault, &owner, &row(AUDIT_RATE.key, SettingMode::Pin, 0.5))
        .expect("the owner's pin");
    assert!(
        vault
            .put_setting_row_as_holder(
                coach,
                &vault_scope,
                &row(AUDIT_RATE.key, SettingMode::Pin, 0.1)
            )
            .is_err(),
        "the Coach does not replace the owner's pin"
    );
    assert!(
        vault
            .clear_setting_row_as_holder(coach, &vault_scope, AUDIT_RATE.key, SettingMode::Pin)
            .is_err(),
        "the Coach does not clear the owner's pin"
    );
    assert_eq!(setting_value(&vault, &AUDIT_RATE).expect("value"), 0.5);

    // A work budget stays within the owner's own row.
    put_setting_row(
        &vault,
        &owner,
        &row(QUESTION_BUDGET, SettingMode::Seed, 5_000.0),
    )
    .expect("the owner's budget");
    assert!(
        vault
            .put_setting_row_as_holder(
                coach,
                &vault_scope,
                &row(QUESTION_BUDGET, SettingMode::Pin, 6_000.0)
            )
            .is_err(),
        "above the owner's cap"
    );
    vault
        .put_setting_row_as_holder(
            coach,
            &vault_scope,
            &row(QUESTION_BUDGET, SettingMode::Pin, 4_000.0),
        )
        .expect("within the owner's cap");
    assert!(
        vault
            .clear_setting_row_as_holder(coach, &vault_scope, QUESTION_BUDGET, SettingMode::Seed)
            .is_err(),
        "the Coach does not clear the owner's budget row"
    );
    let budget = vault
        .engine_control_changes(&owner_proof)
        .expect("receipts")
        .into_iter()
        .filter(|(_, change)| change.knob == QUESTION_BUDGET)
        .map(|(_, change)| change.class)
        .collect::<Vec<_>>();
    assert_eq!(budget, vec![EngineControlClass::WorkBudget]);

    // An agent without the grant changes nothing.
    assert!(
        vault
            .put_setting_row_as_holder(
                EntityId::now(),
                &vault_scope,
                &row(AUDIT_RATE.key, SettingMode::Seed, 0.2)
            )
            .is_err(),
        "no grant, no change"
    );
}
