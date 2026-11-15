//! A holder's work budget stays within the owner's cap at every read, not
//! only at the holder's door (HOLDER-WORK-BUDGET-CAP-ORDER; Engine RULING
//! ROW4-HOLDER-BUDGET-CAP = B, 13 Nov 21:09). Since Setting stage 3
//! (PLAIN-4) the knob `question.call_budget_ms` is a learned Setting key
//! whose tighter direction is lower, and a holder writes a value row, never a
//! pin (DESIGN 1.2 step 4). The door and the walk both hold a holder's row
//! inside the owner's nearest value row at its scope or a wider one, and
//! inside the catalogue default where the owner set none (primitive 0.3 item
//! 12): a cap the owner sets after the holder's row holds it at every read,
//! the read cites the owner's change when the cap decides, and the holder's
//! row stays stored, so raising the cap revives it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test holder_work_budget_cap_order`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::learning_setting_sourced::{knob_value, knob_value_sourced};
use oneiron::test_doors::setting::setting_change;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{EntityId, Vault};

const QUESTION_BUDGET: &str = "question.call_budget_ms";

/// One change of the question budget: a seed (a value row with its weight
/// in runs) or a pin.
fn budget(scope: SettingScope, mode: SettingMode, value: f64) -> SetSetting {
    SetSetting {
        key: QUESTION_BUDGET.to_owned(),
        item: None,
        scope,
        mode,
        value: Some(serde_json::json!(value)),
        expected_revision: None,
        why: Some("cap-order".to_owned()),
        check_in_ref: None,
        weight_runs: (mode == SettingMode::Value).then_some(4.0),
    }
}

/// Whether a change applied. One that waits on a check-in, or a refusal,
/// changes nothing.
fn applied<E>(outcome: &Result<SetSettingOutcome, E>) -> bool {
    matches!(outcome, Ok(SetSettingOutcome::Applied { .. }))
}

/// The id of the setting change an applied `outcome` recorded.
fn change_id(vault: &Vault, outcome: &oneiron::Result<SetSettingOutcome>) -> EntityId {
    let Ok(SetSettingOutcome::Applied {
        sequence: Some(sequence),
        ..
    }) = outcome
    else {
        panic!("an applied change with its sequence: {outcome:?}");
    };
    setting_change(vault, *sequence)
        .expect("the change reads")
        .expect("the change is recorded")
        .id
}

/// The vault, the owner's proof and the Coach holding its default grant.
fn owner_and_coach(
    dir: &std::path::Path,
) -> (Vault, oneiron::consent::AuthenticatedOwner, EntityId) {
    let vault = open_owner_carrier_vault(dir).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    (vault, owner, coach)
}

/// The value in force over `project` and the one change it cites.
fn cited(vault: &Vault, project: EntityId) -> (f64, EntityId) {
    let (value, rows) =
        knob_value_sourced(vault, QUESTION_BUDGET, Some(project)).expect("the sourced read");
    let rows = rows.expect("the deciding change is live");
    assert_eq!(rows.len(), 1, "a row-decided read cites one change");
    (value, rows[0])
}

#[test]
fn a_later_owner_cap_holds_a_holders_row_and_raising_it_revives_the_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let project = EntityId::now();

    let held = vault.set_setting(
        SettingCaller::Agent(coach),
        budget(SettingScope::Project(project), SettingMode::Value, 6000.0),
    );
    let holders = change_id(&vault, &held);
    assert_eq!(
        cited(&vault, project),
        (6000.0, holders),
        "the holder's row decides while the owner has set no cap",
    );

    let cap = vault.set_setting(
        SettingCaller::Owner(&owner),
        budget(SettingScope::Vault, SettingMode::Value, 5000.0),
    );
    let owners = change_id(&vault, &cap);
    assert_eq!(
        knob_value(&vault, QUESTION_BUDGET, Some(project)).expect("the value in force"),
        5000.0,
        "a holder's work budget reads no higher than the owner's later cap at a wider scope",
    );
    assert_eq!(
        cited(&vault, project),
        (5000.0, owners),
        "when the cap decides, the read cites the owner's change, not the holder's",
    );

    let raised = vault.set_setting(
        SettingCaller::Owner(&owner),
        budget(SettingScope::Vault, SettingMode::Value, 8000.0),
    );
    assert!(applied(&raised), "the owner raises the cap: {raised:?}");
    assert_eq!(
        cited(&vault, project),
        (6000.0, holders),
        "the holder's row was kept, so a cap raised above it revives it",
    );

    let pinned = vault.set_setting(
        SettingCaller::Owner(&owner),
        budget(SettingScope::Project(project), SettingMode::Pin, 7000.0),
    );
    assert!(applied(&pinned), "the owner's own pin: {pinned:?}");
    assert_eq!(
        knob_value(&vault, QUESTION_BUDGET, Some(project)).expect("the value in force"),
        7000.0,
        "the owner's pin decides over the holder's row at its scope",
    );
}

#[test]
fn the_holders_door_keeps_its_row_inside_the_owners_nearest_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let project = EntityId::now();

    // Where the owner set no row, the cap is the catalogue default.
    let past_default = vault.set_setting(
        SettingCaller::Agent(coach),
        budget(SettingScope::Project(project), SettingMode::Value, 20_000.0),
    );
    assert!(
        !applied(&past_default),
        "a holder never raises the budget past the catalogue default: {past_default:?}"
    );

    let cap = vault.set_setting(
        SettingCaller::Owner(&owner),
        budget(SettingScope::Vault, SettingMode::Value, 5000.0),
    );
    assert!(applied(&cap), "the owner's vault seed: {cap:?}");
    let above = vault.set_setting(
        SettingCaller::Agent(coach),
        budget(SettingScope::Project(project), SettingMode::Value, 6000.0),
    );
    assert!(
        !applied(&above),
        "the cap is the owner's nearest row at the holder's scope or a wider one: {above:?}"
    );
    let within = vault.set_setting(
        SettingCaller::Agent(coach),
        budget(SettingScope::Project(project), SettingMode::Value, 4000.0),
    );
    assert!(applied(&within), "within the owner's cap: {within:?}");
    assert_eq!(
        knob_value(&vault, QUESTION_BUDGET, Some(project)).expect("the project's value"),
        4000.0,
    );
    assert_eq!(
        knob_value(&vault, QUESTION_BUDGET, None).expect("the vault's value"),
        5000.0,
    );
}
