//! A hard erase takes the erased actor out of the engine-control receipts
//! (review of #6918; the receipt table is 6.6a's). The owner may give
//! `engine.controls` to any principal that is no base agent, and each change
//! through the door leaves a receipt that names who made it. The table
//! declared no actor scrub on the first head, so the erase sweep never
//! visited it: the receipts of an erased holder, and receipts whose value
//! names it, kept its id.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_control_actor_erase`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
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
    vault
        .grant_engine_controls(&owner, holder)
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
