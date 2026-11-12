//! The owner takes an `engine.controls` grant back through its own door
//! (untangle 6.6; ruling on FIX ENGINE-CONTROLS-GRANT-READS-AS-MEMBERSHIP,
//! Engine 11 Nov). The membership doors no longer move the grant of a
//! principal that is no Steward member, and they were its only way out.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_controls_revoke`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::coach::coach;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};

#[test]
fn the_owner_revokes_an_engine_controls_grant() {
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
    let classes = EngineControlClass::ALL.into_iter().collect();
    let grant = vault
        .grant_engine_controls(&owner, holder, &classes)
        .expect("the owner's grant");
    let class = EngineControlClass::WorkBudget;
    let allowed = |holder| {
        vault
            .engine_control_allowed(EngineControlActor::Holder(holder), class)
            .expect("check")
    };
    assert!(allowed(holder), "the holder tunes while the grant stands");

    assert_eq!(
        vault
            .revoke_engine_controls(&owner, holder)
            .expect("the owner's revoke"),
        [grant],
        "the revoke names the grant it took back"
    );
    assert!(
        !allowed(holder),
        "the holder tunes nothing after the revoke"
    );
    assert!(
        vault
            .revoke_engine_controls(&owner, holder)
            .expect("a second revoke")
            .is_empty(),
        "nothing is left to revoke"
    );

    // A base agent's grant is not this door's.
    let coach = coach(&vault).expect("the Coach");
    assert!(
        vault.revoke_engine_controls(&owner, coach).is_err(),
        "the Coach's grant is narrowed through its own door"
    );
}
