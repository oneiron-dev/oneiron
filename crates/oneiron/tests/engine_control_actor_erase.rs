//! A hard erase takes the erased actor out of the engine-control receipts
//! (review of #6918; the receipt table is 6.6a's). The owner may give
//! `engine.controls` to any principal that is no base agent, and each change
//! through the door leaves a receipt that names who made it. The table
//! declared no actor scrub on the first head, so the erase sweep never
//! visited it: the receipts of an erased holder, and receipts whose value
//! names it, kept its id.
//!
//! Round 2 found the holder's id in one more place: the witness claim of a
//! holder's learning-setting PUT (6.6b), a claim about the owner that no
//! scrub of the holder reached. Since Setting stage 3 (PLAIN-4) a holder's
//! change to a learned knob writes no such claim and no receipt: it is a
//! setting change row, which names its maker. The erase keeps the holder's
//! changes and the row it set, as they were set, and they no longer name it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_control_actor_erase`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;

use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::learning_setting_sourced::knob_value;
use oneiron::test_doors::setting::setting_change;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{DeleteReason, EntityId};

#[test]
fn a_hard_erase_takes_the_actor_out_of_the_engine_control_receipts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let holder = EntityId::now();
    vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    // Every class: this layer splits the grant into four class verbs.
    let classes: BTreeSet<EngineControlClass> = EngineControlClass::ALL.into_iter().collect();
    vault
        .grant_engine_controls(&owner, holder, &classes)
        .expect("the owner's grant");

    // One change by the holder, one by the owner whose value names the
    // holder, and one by the owner that names no one else.
    let class = EngineControlClass::WakeCadence;
    let by_holder = vault
        .apply_engine_control(
            EngineControlActor::Holder(holder),
            class,
            "DREAMER_PROACTIVITY_CADENCE",
            "{\"period_secs\":43200}",
            |_| Ok(()),
        )
        .expect("the holder's change");
    let naming = serde_json::json!({
        "agent": holder.to_hex(),
        "schedule": {"period_secs": 60},
    })
    .to_string();
    let names_holder = vault
        .apply_engine_control(
            EngineControlActor::Owner(&owner),
            class,
            "DREAMER_FREE_TIME_POLICY",
            &naming,
            |_| Ok(()),
        )
        .expect("the owner's change that names the holder");
    let unrelated = vault
        .apply_engine_control(
            EngineControlActor::Owner(&owner),
            class,
            "DREAMER_PROACTIVITY_CADENCE",
            "{\"period_secs\":86400}",
            |_| Ok(()),
        )
        .expect("the owner's own change");
    let receipts = |vault: &oneiron::Vault| -> BTreeSet<EntityId> {
        vault
            .engine_control_changes(&owner)
            .expect("receipts")
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    };
    assert_eq!(
        receipts(&vault),
        BTreeSet::from([by_holder, names_holder, unrelated]),
        "three receipts before the erase"
    );

    vault
        .delete_entity_with_reason(&holder, DeleteReason::UserHardDelete)
        .expect("hard erase");

    let named = holder.to_hex();
    let left = vault.engine_control_changes(&owner).expect("receipts");
    assert!(
        left.iter().all(|(_, change)| change.by != holder
            && !change.knob.contains(&named)
            && !change.value.contains(&named)),
        "no receipt names the erased actor: {left:?}"
    );
    assert_eq!(
        receipts(&vault),
        BTreeSet::from([unrelated]),
        "the receipt that names no one else stands"
    );
}

/// The audit rate, a learned knob of the `maintenance_cadence` class.
const AUDIT_RATE: &str = "audit.rate";

/// One change of the audit rate at the vault: a seed (a value row with its
/// weight in runs), or a clear (`value` none).
fn audit_rate(value: Option<f64>) -> SetSetting {
    SetSetting {
        key: AUDIT_RATE.to_owned(),
        item: None,
        scope: SettingScope::Vault,
        mode: SettingMode::Value,
        value: value.map(|value| serde_json::json!(value)),
        expected_revision: None,
        why: Some("tuning".to_owned()),
        check_in_ref: None,
        weight_runs: value.map(|_| 4.0),
    }
}

#[test]
fn a_hard_erase_leaves_no_holder_id_in_the_setting_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let holder = EntityId::now();
    vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    // Every class: this layer splits the grant into four class verbs.
    let classes: BTreeSet<EngineControlClass> = EngineControlClass::ALL.into_iter().collect();
    vault
        .grant_engine_controls(&owner_proof, holder, &classes)
        .expect("the owner's grant");

    // Four changes by the holder, through the setter's holder path (its
    // engine.controls class, checked live in the write): the second replaces
    // the first's row, the clear drops the row, and the fourth stands. Each
    // leaves its change row, naming the holder.
    let mut sequences = Vec::new();
    for value in [Some(0.25), Some(0.30), None, Some(0.35)] {
        let outcome = vault
            .set_setting(SettingCaller::Agent(holder), audit_rate(value))
            .expect("the holder's change");
        let SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } = &outcome
        else {
            panic!("the holder's change applies: {outcome:?}");
        };
        sequences.push(*sequence);
    }
    for sequence in &sequences {
        let change = setting_change(&vault, *sequence)
            .expect("the change reads")
            .expect("the change is recorded");
        assert_eq!(change.by, Some(holder), "the change names its maker");
    }
    assert!(
        vault
            .engine_control_changes(&owner_proof)
            .expect("receipts")
            .is_empty(),
        "a knob change is a setting change, with no engine-control receipt"
    );

    vault
        .delete_entity_with_reason(&holder, DeleteReason::UserHardDelete)
        .expect("hard erase");

    let named = holder.to_hex();
    for sequence in &sequences {
        let change = setting_change(&vault, *sequence)
            .expect("the change reads")
            .expect("the change stands: it is the vault's record of the setting");
        assert_eq!(change.by, None, "no change names the erased holder");
        assert!(
            !format!("{change:?}").contains(&named),
            "no change names the erased holder: {change:?}"
        );
    }
    assert_eq!(
        knob_value(&vault, AUDIT_RATE, None).expect("the knob reads"),
        0.35,
        "the row the holder set stands"
    );
}
