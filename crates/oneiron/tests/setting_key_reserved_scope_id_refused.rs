#![cfg(oneiron_test_support)]
//! A setting write door refuses a scope whose id no reader decodes
//! (SETTING-SCOPE-RESERVED-ID-NOT-ROUND-TRIPPED).
//!
//! The doors checked a scope's kind, not that the row's key reads back. A
//! native caller holding an unchecked reserved `EntityId` (all 0x00, all
//! 0xFF) stored a SETTING, learning SETTING or spawn-choice row that
//! `RowKey::decode` / `parse_row_key` refuse, so no read, list or export saw
//! it. Each door now refuses such a key, and a readable id still writes.
//!
//! * `the_setting_door_refuses_a_reserved_scope_id`: `Vault::set_setting`
//!   by the owner, a pin of `test.owner_number` over a project.
//! * `the_owner_learning_setting_door_refuses_a_reserved_scope_id`:
//!   `put_scoped_setting_row`, the owner's pin of `health.review`.
//! * `the_holder_learning_setting_door_refuses_a_reserved_scope_id`:
//!   `Vault::put_setting_row_as_holder`, the Coach's pin of `health.review`.
//! * `the_choice_door_refuses_a_reserved_scope_id`: `put_choice_row`, the
//!   owner's pin of a spawn width.
//!
//! Red on main dfb702d62d79 (the tests-only commit): each reserved write
//! returns `Ok`. Green on the fix: each is refused and the readable write
//! next to it still lands.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_key_reserved_scope_id_refused`.

use oneiron::edge::EdgeActorClass;
use oneiron::learning_setting::{self, SettingRow};
use oneiron::learning_setting_choice::{self, ChoiceRow, ChoiceValue};
use oneiron::setting::{self, SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::open_owner_carrier_vault;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Error, Vault};

/// The Coach's own review switch: 1 runs it, 0 does not.
const HEALTH_REVIEW: &str = "health.review";

/// The two reserved patterns every id decoder refuses.
fn reserved_ids() -> [EntityId; 2] {
    [
        EntityId::from_bytes_unchecked([0x00; 16]),
        EntityId::from_bytes_unchecked([0xFF; 16]),
    ]
}

/// The vault, its owner as a write actor, and the Coach holding its default
/// grant.
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

/// A pin of `test.owner_number` over `project`.
fn owner_number_pin(project: EntityId, value: u64) -> SetSetting {
    SetSetting {
        key: "test.owner_number".to_owned(),
        item: None,
        scope: setting::SettingScope::Project(project),
        mode: setting::SettingMode::Pin,
        value: Some(serde_json::json!(value)),
        expected_revision: None,
        why: None,
        check_in_ref: None,
        weight_runs: None,
    }
}

/// A pin of the review switch.
fn review_pin(value: f64) -> SettingRow {
    SettingRow {
        key: HEALTH_REVIEW.to_owned(),
        mode: learning_setting::SettingMode::Pin,
        value,
        weight_runs: None,
        at: 10,
        why: "review".to_owned(),
    }
}

#[test]
fn the_setting_door_refuses_a_reserved_scope_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _, _) = owner_and_coach(dir.path());
    let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");

    let readable = vault
        .set_setting(
            SettingCaller::Owner(&owner),
            owner_number_pin(EntityId::now(), 3),
        )
        .expect("a pin over a readable project id applies");
    assert!(
        matches!(
            readable,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the readable pin applies with a sequence: {readable:?}"
    );

    for reserved in reserved_ids() {
        let outcome =
            vault.set_setting(SettingCaller::Owner(&owner), owner_number_pin(reserved, 4));
        assert!(
            matches!(outcome, Err(Error::InvalidConfig(_))),
            "a pin over the reserved id {} stores a row no reader decodes: {outcome:?}",
            reserved.to_hex()
        );
    }
}

#[test]
fn the_owner_learning_setting_door_refuses_a_reserved_scope_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _) = owner_and_coach(dir.path());

    learning_setting::put_scoped_setting_row(
        &vault,
        &owner,
        &learning_setting::SettingScope::Project(EntityId::now()),
        &review_pin(0.0),
    )
    .expect("the owner's pin over a readable project id lands");

    for reserved in reserved_ids() {
        let outcome = learning_setting::put_scoped_setting_row(
            &vault,
            &owner,
            &learning_setting::SettingScope::Project(reserved),
            &review_pin(0.0),
        );
        assert!(
            matches!(outcome, Err(Error::InvalidClaimBody(_))),
            "the owner's pin over the reserved id {} stores a row no reader parses: {outcome:?}",
            reserved.to_hex()
        );
    }
}

#[test]
fn the_holder_learning_setting_door_refuses_a_reserved_scope_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _, coach) = owner_and_coach(dir.path());

    vault
        .put_setting_row_as_holder(
            coach,
            &learning_setting::SettingScope::Project(EntityId::now()),
            &review_pin(0.0),
        )
        .expect("the Coach's pin over a readable project id lands");

    for reserved in reserved_ids() {
        let outcome = vault.put_setting_row_as_holder(
            coach,
            &learning_setting::SettingScope::Project(reserved),
            &review_pin(0.0),
        );
        assert!(
            matches!(outcome, Err(Error::InvalidClaimBody(_))),
            "the Coach's pin over the reserved id {} stores a row no reader parses: {outcome:?}",
            reserved.to_hex()
        );
    }
}

#[test]
fn the_choice_door_refuses_a_reserved_scope_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _) = owner_and_coach(dir.path());
    let width_pin = ChoiceRow {
        mode: learning_setting::SettingMode::Pin,
        value: ChoiceValue::Width(2),
        weight_runs: None,
        at: 10,
        why: "two agents".to_owned(),
    };

    learning_setting_choice::put_choice_row(
        &vault,
        &owner,
        &learning_setting::SettingScope::Project(EntityId::now()),
        &width_pin,
    )
    .expect("the owner's width pin over a readable project id lands");

    for reserved in reserved_ids() {
        let outcome = learning_setting_choice::put_choice_row(
            &vault,
            &owner,
            &learning_setting::SettingScope::Project(reserved),
            &width_pin,
        );
        assert!(
            matches!(outcome, Err(Error::InvalidClaimBody(_))),
            "the owner's width pin over the reserved id {} stores a row no reader parses: {outcome:?}",
            reserved.to_hex()
        );
    }
}
