//! An owner's pin stands over a holder's pin at every scope a read walks
//! (untangle 6.6d, review round 1 of #6999). A read takes the narrowest
//! pin, so a holder of `engine.controls` that pinned a dial over one
//! project used to decide that project even where the owner had pinned the
//! dial for the whole vault. Now the read walks the owner's pins first,
//! whichever pin was set first, and the holder's door refuses a new pin
//! under the owner's vault pin. The owner's own narrower pin still decides
//! its scope, and a holder's pin is in force again once the owner withdraws
//! the pin above it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_pin_over_holder_pin`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::Vault;
use oneiron::edge::EdgeActorClass;
use oneiron::learning_setting::{
    SettingMode, SettingRow, SettingScope, SettingSpec, clear_setting_row, put_scoped_setting_row,
    put_setting_row, setting_spec, setting_value_scoped,
};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::open_owner_carrier_vault;
use oneiron::write_envelope::WriteActor;

/// The Coach's own review switch: 1 runs it, 0 does not.
const HEALTH_REVIEW: &str = "health.review";

fn pin(value: f64) -> SettingRow {
    SettingRow {
        key: HEALTH_REVIEW.to_owned(),
        mode: SettingMode::Pin,
        value,
        weight_runs: None,
        at: 10,
        why: "review".to_owned(),
    }
}

fn review() -> &'static SettingSpec {
    setting_spec(HEALTH_REVIEW).expect("the review dial")
}

fn in_force(vault: &Vault, project: EntityId) -> f64 {
    setting_value_scoped(vault, review(), Some(project), None).expect("the value in force")
}

/// The vault, its owner and the Coach holding its default grant.
fn owner_and_coach(dir: &std::path::Path) -> (Vault, WriteActor, EntityId) {
    let vault = open_owner_carrier_vault(dir).expect("owner carrier vault");
    let owner = WriteActor::new(
        vault.ensure_embedded_owner_actor().expect("owner"),
        EdgeActorClass::Human,
    );
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    (vault, owner, coach)
}

#[test]
fn the_owners_later_vault_pin_stands_over_a_holders_project_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let project = EntityId::now();

    // With no pin of the owner's, the Coach's pin over one project decides
    // that project and no other.
    vault
        .put_setting_row_as_holder(coach, &SettingScope::Project(project), &pin(0.0))
        .expect("the Coach's project pin");
    assert_eq!(in_force(&vault, project), 0.0);
    assert_eq!(in_force(&vault, EntityId::now()), 1.0);

    // The owner pins the review on for the whole vault.
    put_setting_row(&vault, &owner, &pin(1.0)).expect("the owner's vault pin");
    assert_eq!(
        in_force(&vault, project),
        1.0,
        "the owner's vault pin stands over the holder's earlier project pin"
    );

    // The owner withdraws the pin: the Coach's project pin decides again.
    clear_setting_row(&vault, &owner, HEALTH_REVIEW, SettingMode::Pin)
        .expect("the owner withdraws the vault pin");
    assert_eq!(in_force(&vault, project), 0.0);
}

#[test]
fn a_holder_pins_nothing_under_the_owners_vault_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let project = EntityId::now();
    put_setting_row(&vault, &owner, &pin(1.0)).expect("the owner's vault pin");

    assert!(
        vault
            .put_setting_row_as_holder(coach, &SettingScope::Project(project), &pin(0.0))
            .is_err(),
        "a holder's narrower pin under the owner's vault pin is refused"
    );
    assert_eq!(in_force(&vault, project), 1.0);

    // The owner's own narrower pin still decides its project.
    put_scoped_setting_row(&vault, &owner, &SettingScope::Project(project), &pin(0.0))
        .expect("the owner's project pin");
    assert_eq!(in_force(&vault, project), 0.0);
}
