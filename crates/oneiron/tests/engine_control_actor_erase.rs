//! A hard erase takes the erased actor out of the engine-control receipts
//! (review of #6918; the receipt table is 6.6a's). The owner may give
//! `engine.controls` to any principal that is no base agent, and each change
//! through the door leaves a receipt that names who made it. The table
//! declared no actor scrub on the first head, so the erase sweep never
//! visited it: the receipts of an erased holder, and receipts whose value
//! names it, kept its id.
//!
//! Round 2 found the holder's id in one more place: the witness claim of a
//! holder's learning-setting PUT (6.6b). That claim is about the owner, on
//! the owner's facet, so no scrub of the holder reaches it. It now names no
//! holder; the setting row and the receipt do, and both are scrubbed.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_control_actor_erase`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::learning_setting::{AUDIT_RATE, SettingMode, SettingRow, SettingScope};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{DeleteReason, EntityId, Vault};

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

/// The learning-setting PUT witnesses the vault holds about `owner`, each as
/// its whole body's debug text.
fn learning_put_witnesses(vault: &Vault, owner: EntityId) -> Vec<String> {
    vault
        .claims_for_subject(&owner)
        .expect("the owner's claims")
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).expect("claim"))
        .filter(|body| body.predicate == "vault.learning_setting.put")
        .map(|body| format!("{body:?}"))
        .collect()
}

#[test]
fn a_hard_erase_leaves_no_holder_id_in_the_learning_put_witnesses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
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
    let before = learning_put_witnesses(&vault, owner_id).len();

    // Three PUTs by the holder: the second overwrites the first's row, the
    // clear drops the row, and the third stands. Each leaves its witness.
    let scope = SettingScope::Vault;
    let put = |value: f64, at: u64| {
        vault
            .put_setting_row_as_holder(
                holder,
                &scope,
                &SettingRow {
                    key: AUDIT_RATE.key.to_owned(),
                    mode: SettingMode::Pin,
                    value,
                    weight_runs: None,
                    at,
                    why: "tuning".to_owned(),
                },
            )
            .expect("the holder's PUT");
    };
    put(0.25, 11);
    put(0.30, 12);
    vault
        .clear_setting_row_as_holder(holder, &scope, AUDIT_RATE.key, SettingMode::Pin)
        .expect("the holder's clear");
    put(0.35, 13);
    assert_eq!(
        learning_put_witnesses(&vault, owner_id).len(),
        before + 3,
        "one witness for each PUT, the overwritten and the cleared rows' included"
    );

    vault
        .delete_entity_with_reason(&holder, DeleteReason::UserHardDelete)
        .expect("hard erase");

    let left = learning_put_witnesses(&vault, owner_id);
    assert_eq!(
        left.len(),
        before + 3,
        "the witnesses stand: they are the owner's record of the settings"
    );
    let named = holder.to_hex();
    assert!(
        left.iter().all(|witness| !witness.contains(&named)),
        "no PUT witness names the erased holder: {left:?}"
    );
}
