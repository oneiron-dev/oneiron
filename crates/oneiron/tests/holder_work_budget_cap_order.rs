//! A holder's work budget stays within the owner's cap at every read, not
//! only at the holder's door (HOLDER-WORK-BUDGET-CAP-ORDER; Engine RULING
//! ROW4-HOLDER-BUDGET-CAP = B, 13 Nov 21:09). The door refuses a holder's
//! value above the owner's own seed or pin for that knob and scope, but a
//! cap the owner set after the holder's pin was never checked: the read
//! returned the holder's pin before the owner's seed. Now the read clamps a
//! holder-decided value to the owner's seed or pin at the same scope, the
//! scope the door checks, and cites the cap's own act when the cap decides.
//! The holder's row stays stored, so raising the cap revives it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test holder_work_budget_cap_order`.
#![cfg(oneiron_test_support)]

use oneiron::edge::EdgeActorClass;
use oneiron::learning_setting::{
    SettingMode, SettingRow, SettingScope, SettingSpec, put_scoped_setting_row, setting_spec,
    setting_value, setting_value_scoped,
};
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::learning_setting_sourced::setting_value_sourced;
use oneiron::test_doors::steward::open_owner_carrier_vault;
use oneiron::write_envelope::WriteActor;
use oneiron::{ClaimSource, EntityId, Vault};

const QUESTION_BUDGET: &str = "question_call_budget_ms";

fn row(mode: SettingMode, value: f64) -> SettingRow {
    SettingRow {
        key: QUESTION_BUDGET.to_owned(),
        mode,
        value,
        weight_runs: (mode == SettingMode::Seed).then_some(4.0),
        at: 10,
        why: "cap-order".to_owned(),
    }
}

fn budget() -> &'static SettingSpec {
    setting_spec(QUESTION_BUDGET).expect("the question budget")
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

/// The vault-wide read's value and the one act it cites: that act's mode
/// and source.
fn cited(vault: &Vault) -> (f64, String, Option<ClaimSource>) {
    let (value, rows) = setting_value_sourced(vault, budget()).expect("the sourced read");
    let rows = rows.expect("the deciding act is live");
    assert_eq!(rows.len(), 1, "a row-decided read cites one act");
    let act = vault
        .get_claim(&rows[0])
        .expect("read the act")
        .expect("the cited act");
    let mode = act
        .value
        .as_map()
        .and_then(|members| {
            members
                .iter()
                .find_map(|(name, member)| (name.as_str() == Some("mode")).then_some(member))
        })
        .and_then(|mode| mode.as_str())
        .expect("the act names its mode")
        .to_owned();
    (value, mode, act.source)
}

#[test]
fn a_later_owner_seed_caps_a_holders_pin_and_raising_it_revives_the_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let scope = SettingScope::Vault;

    vault
        .put_setting_row_as_holder(coach, &scope, &row(SettingMode::Pin, 6000.0))
        .expect("the Coach's pin, with no cap of the owner's yet");
    assert_eq!(
        cited(&vault),
        (6000.0, "pin".to_owned(), Some(ClaimSource::Observed)),
        "the holder's pin decides while the owner has set no cap",
    );

    put_scoped_setting_row(&vault, &owner, &scope, &row(SettingMode::Seed, 5000.0))
        .expect("the owner's later, lower seed");
    assert_eq!(
        setting_value(&vault, budget()).expect("the value in force"),
        5000.0,
        "a holder's work budget reads no higher than the owner's later cap at its scope",
    );
    assert_eq!(
        cited(&vault),
        (5000.0, "seed".to_owned(), Some(ClaimSource::UserStated)),
        "when the cap decides, the read cites the owner's act, not the holder's",
    );

    put_scoped_setting_row(&vault, &owner, &scope, &row(SettingMode::Seed, 8000.0))
        .expect("the owner raises the cap");
    assert_eq!(
        cited(&vault),
        (6000.0, "pin".to_owned(), Some(ClaimSource::Observed)),
        "the holder's row was kept, so a cap raised above it revives it",
    );

    put_scoped_setting_row(&vault, &owner, &scope, &row(SettingMode::Pin, 7000.0))
        .expect("the owner's own pin");
    assert_eq!(
        setting_value(&vault, budget()).expect("the value in force"),
        7000.0,
        "the owner's pin replaces the holder's pin at its scope",
    );
}

#[test]
fn an_owner_cap_at_a_wider_scope_leaves_a_holders_project_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, coach) = owner_and_coach(dir.path());
    let project = EntityId::now();

    vault
        .put_setting_row_as_holder(
            coach,
            &SettingScope::Project(project),
            &row(SettingMode::Pin, 6000.0),
        )
        .expect("the Coach's project pin");
    put_scoped_setting_row(
        &vault,
        &owner,
        &SettingScope::Vault,
        &row(SettingMode::Seed, 5000.0),
    )
    .expect("the owner's vault seed");
    assert_eq!(
        setting_value_scoped(&vault, budget(), Some(project), None).expect("the project's value"),
        6000.0,
        "the cap is the owner's row at the holder's own scope, as the holder's door checks",
    );
    assert_eq!(
        setting_value(&vault, budget()).expect("the vault's value"),
        5000.0,
    );
}
