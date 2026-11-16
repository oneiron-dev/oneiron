//! An owner's pin stands over a holder's row at every scope a read walks
//! (untangle 6.6d, review round 1 of #6999). A holder of `engine.controls`
//! that tuned a dial over one project used to decide that project even where
//! the owner had pinned the dial for the whole vault. Since Setting stage 3
//! (PLAIN-4) the dial is a learned Setting key, and a holder writes a value
//! row, never a pin (DESIGN 1.2 step 4). The walk takes the owner's
//! narrowest pin first, whichever row was set first, and the holder's door
//! makes no change under the owner's pin. The owner's own narrower pin still
//! decides its scope, and a holder's row is in force again once the owner
//! withdraws the pin above it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_pin_over_holder_pin`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::Vault;
use oneiron::dreamer_runner::maintenance::agent_health::HEALTH_REVIEW;
use oneiron::learning_setting::setting_value_scoped;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};

/// The Coach's own review switch: 1 runs it, 0 does not.
const REVIEW: &str = "health.review";

/// One change of [`REVIEW`]: a seed (a value row with its weight in runs),
/// a pin, or a clear (`value` none).
fn review(scope: SettingScope, mode: SettingMode, value: Option<f64>) -> SetSetting {
    let seed = mode == SettingMode::Value && value.is_some();
    SetSetting {
        key: REVIEW.to_owned(),
        item: None,
        scope,
        mode,
        value: value.map(|value| serde_json::json!(value)),
        expected_revision: None,
        why: Some("review".to_owned()),
        check_in_ref: None,
        weight_runs: seed.then_some(1.0),
    }
}

/// Whether a change applied. One that waits on a check-in, or a refusal,
/// changes nothing.
fn applied<E>(outcome: &Result<SetSettingOutcome, E>) -> bool {
    matches!(outcome, Ok(SetSettingOutcome::Applied { .. }))
}

fn in_force(vault: &Vault, project: EntityId) -> f64 {
    setting_value_scoped(vault, &HEALTH_REVIEW, Some(project), None).expect("the value in force")
}

/// The vault and the Coach holding its default grant.
fn vault_and_coach(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = open_owner_carrier_vault(dir).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    (vault, coach)
}

#[test]
fn the_owners_later_vault_pin_stands_over_a_holders_project_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, coach) = vault_and_coach(dir.path());
    let owner = owner(&vault).expect("owner proof");
    let project = EntityId::now();

    // With no pin of the owner's, the Coach's row over one project decides
    // that project and no other.
    let held = vault.set_setting(
        SettingCaller::Agent(coach),
        review(
            SettingScope::Project(project),
            SettingMode::Value,
            Some(0.0),
        ),
    );
    assert!(applied(&held), "the Coach's project row: {held:?}");
    assert_eq!(in_force(&vault, project), 0.0);
    assert_eq!(in_force(&vault, EntityId::now()), 1.0);

    // The owner pins the review on for the whole vault.
    let pinned = vault.set_setting(
        SettingCaller::Owner(&owner),
        review(SettingScope::Vault, SettingMode::Pin, Some(1.0)),
    );
    assert!(applied(&pinned), "the owner's vault pin: {pinned:?}");
    assert_eq!(
        in_force(&vault, project),
        1.0,
        "the owner's vault pin stands over the holder's earlier project row"
    );

    // The owner withdraws the pin: the Coach's project row decides again.
    let withdrawn = vault.set_setting(
        SettingCaller::Owner(&owner),
        review(SettingScope::Vault, SettingMode::Pin, None),
    );
    assert!(
        applied(&withdrawn),
        "the owner withdraws the vault pin: {withdrawn:?}"
    );
    assert_eq!(in_force(&vault, project), 0.0);
}

#[test]
fn a_holder_changes_nothing_under_the_owners_vault_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, coach) = vault_and_coach(dir.path());
    let owner = owner(&vault).expect("owner proof");
    let project = EntityId::now();
    let pinned = vault.set_setting(
        SettingCaller::Owner(&owner),
        review(SettingScope::Vault, SettingMode::Pin, Some(1.0)),
    );
    assert!(applied(&pinned), "the owner's vault pin: {pinned:?}");

    let under = vault.set_setting(
        SettingCaller::Agent(coach),
        review(
            SettingScope::Project(project),
            SettingMode::Value,
            Some(0.0),
        ),
    );
    assert!(
        !applied(&under),
        "a holder's narrower row under the owner's vault pin waits on the owner or is refused: \
         {under:?}"
    );
    let holder_pin = vault.set_setting(
        SettingCaller::Agent(coach),
        review(SettingScope::Project(project), SettingMode::Pin, Some(0.0)),
    );
    assert!(!applied(&holder_pin), "a holder never pins: {holder_pin:?}");
    assert_eq!(in_force(&vault, project), 1.0);

    // The owner's own narrower pin still decides its project.
    let narrower = vault.set_setting(
        SettingCaller::Owner(&owner),
        review(SettingScope::Project(project), SettingMode::Pin, Some(0.0)),
    );
    assert!(applied(&narrower), "the owner's project pin: {narrower:?}");
    assert_eq!(in_force(&vault, project), 0.0);
}
