//! The Coach tunes the learning dials through `engine.controls` (untangle
//! 6.6b, the first family; S66-MAP = A). The host's first mint gives the
//! Coach its default grant; through it the Coach sets a dial it may tune,
//! the value is in force, and the change row names the Coach as its holder.
//! Since Setting stage 3 (PLAIN-4) each dial is a learned Setting key: the
//! Coach writes a value row, never a pin (DESIGN 1.2 step 4), and its change
//! is a setting change, not an engine-control receipt. A key outside the
//! list stays the owner's. The owner's rows stand: a pin the owner set is the
//! owner's to change, and a work budget stays within the owner's nearest
//! row. An agent without the grant changes nothing.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_learning_dials`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use oneiron::setting::{
    SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingMode, SettingScope,
};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::learning_setting_sourced::knob_value;
use oneiron::test_doors::setting::setting_change;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{EntityId, Vault};

const AUDIT_RATE: &str = "audit.rate";
const CREDIT_ENABLED: &str = "credit.enabled";
const OWNER_COPY: &str = "health.card.owner_copy";
const QUESTION_BUDGET: &str = "question.call_budget_ms";

/// One change of a learning dial: a seed (a value row with its weight in
/// runs), a pin, or a clear (`value` none).
fn row(key: &str, scope: SettingScope, mode: SettingMode, value: Option<f64>) -> SetSetting {
    let seed = mode == SettingMode::Value && value.is_some();
    SetSetting {
        key: key.to_owned(),
        item: None,
        scope,
        mode,
        value: value.map(|value| serde_json::json!(value)),
        expected_revision: None,
        why: Some("tuning".to_owned()),
        check_in_ref: None,
        weight_runs: seed.then_some(4.0),
    }
}

/// Whether a change applied. One that waits on a check-in, or a refusal,
/// changes nothing.
fn applied<E>(outcome: &Result<SetSettingOutcome, E>) -> bool {
    matches!(outcome, Ok(SetSettingOutcome::Applied { .. }))
}

/// The sequence an applied change recorded.
fn sequence_of(outcome: &oneiron::Result<SetSettingOutcome>) -> u64 {
    let Ok(SetSettingOutcome::Applied {
        sequence: Some(sequence),
        ..
    }) = outcome
    else {
        panic!("an applied change with its sequence: {outcome:?}");
    };
    *sequence
}

fn value(vault: &Vault, key: &str, project: Option<EntityId>) -> f64 {
    knob_value(vault, key, project).expect("the dial reads")
}

#[test]
fn the_coach_tunes_a_learning_dial_and_the_owners_rows_stand() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let as_coach = || SettingCaller::Agent(coach);
    let as_owner = || SettingCaller::Owner(&owner);
    let vault_scope = || SettingScope::Vault;

    // The Coach sets a dial it may tune: in force, the change names it as
    // the holder, and no engine-control receipt is written.
    let tuned = vault.set_setting(
        as_coach(),
        row(AUDIT_RATE, vault_scope(), SettingMode::Value, Some(0.25)),
    );
    let change = setting_change(&vault, sequence_of(&tuned))
        .expect("the change reads")
        .expect("the change is recorded");
    assert_eq!(value(&vault, AUDIT_RATE, None), 0.25);
    assert_eq!(change.key, AUDIT_RATE);
    assert_eq!(change.by, Some(coach));
    assert!(
        matches!(change.setter, Setter::Holder { .. }),
        "the Coach sets it as a holder of its class: {:?}",
        change.setter
    );
    assert!(
        vault
            .engine_control_changes(&owner)
            .expect("receipts")
            .is_empty(),
        "a dial change is a setting change, with no engine-control receipt"
    );

    // A holder never pins.
    let pin = vault.set_setting(
        as_coach(),
        row(AUDIT_RATE, vault_scope(), SettingMode::Pin, Some(0.1)),
    );
    assert!(!applied(&pin), "the Coach's pin: {pin:?}");
    assert_eq!(value(&vault, AUDIT_RATE, None), 0.25);

    // A key outside the list stays the owner's.
    let credit = vault.set_setting(
        as_coach(),
        row(CREDIT_ENABLED, vault_scope(), SettingMode::Value, Some(0.0)),
    );
    assert!(
        !applied(&credit),
        "credit.enabled is the owner's: {credit:?}"
    );
    assert_eq!(value(&vault, CREDIT_ENABLED, None), 1.0);
    let copy = vault.set_setting(
        as_coach(),
        row(OWNER_COPY, vault_scope(), SettingMode::Value, Some(1.0)),
    );
    assert!(
        !applied(&copy),
        "the owner's copy of health cards is the owner's: {copy:?}"
    );
    assert_eq!(value(&vault, OWNER_COPY, None), 0.0);

    // A pin the owner set is the owner's to change.
    let owners_pin = vault.set_setting(
        as_owner(),
        row(AUDIT_RATE, vault_scope(), SettingMode::Pin, Some(0.5)),
    );
    assert!(applied(&owners_pin), "the owner's pin: {owners_pin:?}");
    let under = vault.set_setting(
        as_coach(),
        row(AUDIT_RATE, vault_scope(), SettingMode::Value, Some(0.1)),
    );
    assert!(
        !applied(&under),
        "the Coach changes nothing under the owner's pin: {under:?}"
    );
    let unpin = vault.set_setting(
        as_coach(),
        row(AUDIT_RATE, vault_scope(), SettingMode::Pin, None),
    );
    assert!(
        !applied(&unpin),
        "the Coach does not clear the owner's pin: {unpin:?}"
    );
    assert_eq!(value(&vault, AUDIT_RATE, None), 0.5);

    // A work budget stays within the owner's nearest row.
    let project = EntityId::now();
    let budget = vault.set_setting(
        as_owner(),
        row(
            QUESTION_BUDGET,
            vault_scope(),
            SettingMode::Value,
            Some(5_000.0),
        ),
    );
    assert!(applied(&budget), "the owner's budget: {budget:?}");
    let above = vault.set_setting(
        as_coach(),
        row(
            QUESTION_BUDGET,
            SettingScope::Project(project),
            SettingMode::Value,
            Some(6_000.0),
        ),
    );
    assert!(!applied(&above), "above the owner's cap: {above:?}");
    let within = vault.set_setting(
        as_coach(),
        row(
            QUESTION_BUDGET,
            SettingScope::Project(project),
            SettingMode::Value,
            Some(4_000.0),
        ),
    );
    let within = setting_change(&vault, sequence_of(&within))
        .expect("the change reads")
        .expect("within the owner's cap");
    assert_eq!(within.by, Some(coach));
    assert_eq!(value(&vault, QUESTION_BUDGET, Some(project)), 4_000.0);
    let clear = vault.set_setting(
        as_coach(),
        row(QUESTION_BUDGET, vault_scope(), SettingMode::Value, None),
    );
    assert!(
        !applied(&clear),
        "the Coach does not clear the owner's budget row: {clear:?}"
    );
    assert_eq!(value(&vault, QUESTION_BUDGET, None), 5_000.0);

    // An agent without the grant changes nothing.
    let stranger = vault.set_setting(
        SettingCaller::Agent(EntityId::now()),
        row(AUDIT_RATE, vault_scope(), SettingMode::Value, Some(0.2)),
    );
    assert!(!applied(&stranger), "no grant, no change: {stranger:?}");
    assert_eq!(value(&vault, AUDIT_RATE, None), 0.5);
}
