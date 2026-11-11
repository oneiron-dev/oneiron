//! An owner's `engine.controls` grant is no membership (ruling on FIX
//! ENGINE-CONTROLS-GRANT-READS-AS-MEMBERSHIP, Engine 11 Nov; untangle 6.6).
//! The grant is a Steward-role row in the vault's scope, and on a shared
//! vault the membership doors took it for a Steward's membership: the
//! roster listed a person who had never joined, a role change rewrote the
//! row at another role's default, and a removal deleted it.
//!
//! A grant row is a membership only if it was minted as one. The owner
//! gives `engine.controls` through its own door and takes it back through
//! its own (`engine_controls_revoke`); for a principal that is no Steward
//! member the membership doors skip the row.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_controls_grant_is_no_membership`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::federation::{EngineControlActor, EngineControlClass, FederationGrantRole as Role};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner, shared_roster};

const SHARED: u64 = 42;

#[test]
fn an_engine_controls_grant_makes_no_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    vault
        .initialize_shared_vault(&owner, SHARED, None, &[], 1)
        .expect("a shared vault");
    // A person who never joined the vault.
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
    let class = EngineControlClass::WakeCadence;
    vault
        .grant_engine_controls(&owner, holder, &BTreeSet::from([class]))
        .expect("the owner's grant");

    let roster = shared_roster(&vault, SHARED).expect("roster");
    assert!(
        roster.iter().all(|(member, _)| *member != holder),
        "the grant makes no member: the roster does not list its holder: {roster:?}"
    );
    assert!(
        vault
            .change_shared_member_role(&owner, SHARED, holder, Role::Member, None)
            .is_err(),
        "a role change that names the holder is refused: they are no member"
    );
    assert!(
        vault
            .remove_shared_member(&owner, SHARED, holder, None)
            .is_err(),
        "a removal that names the holder is refused: the grant has its own door"
    );
    assert!(
        vault
            .engine_control_allowed(EngineControlActor::Holder(holder), class)
            .expect("check"),
        "the grant stands as the owner gave it"
    );
}
