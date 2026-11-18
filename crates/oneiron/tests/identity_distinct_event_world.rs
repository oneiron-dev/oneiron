//! The ledger event of a distinct fact whose CLAIM sits in a world W sits in
//! W too, so a W kept on this machine keeps the event here with its CLAIM
//! (FIX DISTINCT-EVENT-WORLD-RESIDENCE; DEC-0005, a device-only world's words
//! never leave this device).
//!
//! An `assert_distinct` op asserts through the live `entity.distinct_from`
//! CLAIM of its pair when there already is one, so the pair's CLAIM may sit
//! in a world: here a CLAIM proposed in W, which the owner's assertion
//! promotes in place, so it keeps its world. The op writes a type-74
//! AssertDistinct ledger event that names the pair and that CLAIM, signed by
//! an admission disposition, and FIX DISTINCT-EVENT-DEFAULT-PROJECT-STAMP
//! stamps both rows at the CLAIM's world. A door that judges a row by its
//! world (`Vault::record_world`, and through it what a device-only world
//! keeps: `Vault::export_records_in_scope`) must read those rows in W. Before
//! the fix it read every type-74 row as base reality, so with W kept on this
//! machine the CLAIM stayed here while its event and disposition were
//! exported.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix. The `LEAK:`
//! assertions are the check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_distinct_event_world`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::federation::record_scope::{ScopeView, ScopedRecord};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::identity_topology::{
    AssertDistinctOp, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp,
    PREDICATE_ENTITY_DISTINCT_FROM, StoredIdentityOpAction,
};
use oneiron::registry::{
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::write_envelope::identity_pair::{distinct_claim_value, distinct_pair_key};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            at(1),
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// Asserts `a` and `b` distinct, as the owner does; the ledger event the op
/// writes.
fn assert_distinct(vault: &Vault, a: EntityId, b: EntityId) -> EntityId {
    let outcome = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                a,
                b,
                reason: "two people".to_owned(),
            }),
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            vault.now_recorded_at(),
        )
        .expect("the pair is distinct");
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("FIXTURE: an Auto assertion applies, got {outcome:?}");
    };
    event
}

/// The CLAIM the AssertDistinct event `event` names.
fn asserted_claim(vault: &Vault, event: EntityId) -> EntityId {
    let stored = vault
        .identity_topology_event(&event)
        .expect("event read")
        .expect("FIXTURE: the assertion's event is stored");
    let StoredIdentityOpAction::AssertDistinct { claim, .. } = stored.action else {
        panic!("FIXTURE: the op's event asserts a distinct pair");
    };
    claim
}

/// The admission dispositions that sign `event`, among every stamped row.
fn dispositions_of(vault: &Vault, event: EntityId) -> Vec<EntityId> {
    let top = Scope::top();
    let band = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT]));
    vault
        .records_in_scope(&top, &top, &top, ScopeView::Normal)
        .expect("scoped read")
        .iter()
        .filter(|row| row.scope.as_ref().is_some_and(|scope| scope.bands == band))
        .filter(|row| {
            vault
                .identity_topology_event(&row.id)
                .expect("event read")
                .is_some_and(|stored| {
                    matches!(
                        stored.action,
                        StoredIdentityOpAction::AdmissionDisposition(ref disposition)
                            if disposition.target == event
                    )
                })
        })
        .map(|row| row.id)
        .collect()
}

/// The rows an export to a machine nobody proved carries.
fn exported(vault: &Vault) -> Vec<ScopedRecord> {
    let top = Scope::top();
    vault
        .export_records_in_scope(&top, &top, &top)
        .expect("export")
}

fn held(rows: &[ScopedRecord], ids: &[EntityId]) -> Vec<EntityId> {
    ids.iter()
        .copied()
        .filter(|id| rows.iter().any(|row| row.id == *id))
        .collect()
}

#[test]
fn a_distinct_event_over_a_claim_of_a_kept_world_stays_on_this_machine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(open_member_vault(dir.path(), VaultConfig::device(), &[]).expect("fixture vault"));
    let (_owner, _proof) = embedded_owner(&vault).expect("the owner");
    // The install's machine keys come from its device keystore, as a host's,
    // so the op's signed topology event has a carrier.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_serving_install_profile(
            &oneiron::test_support::test_host_issuer(),
            oneiron::authority::MachineRole::Unanswered,
        )
        .expect("this install's machine profile");
    let world = EntityId::now();
    vault
        .put_entity(&world, ENTITY_TYPE_WORLD, at(1), 1, b"world")
        .expect("put the world");

    // A distinct fact between two people, proposed in W. The raw claim door
    // holds an Approved row of this critical predicate at the gate's floor
    // (no owner proof reaches it: gate.pending.criticality_floor), so the
    // CLAIM lands Proposed, with the source an owner's assertion carries.
    let pair = distinct_pair_key(person(&vault, "Ada"), person(&vault, "Ada"));
    let mut body = ClaimBody::new(
        PREDICATE_ENTITY_DISTINCT_FROM,
        ClaimSubject::Entity(pair.0),
        distinct_claim_value(pair),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("a distinct claim");
    body.source = Some(ClaimSource::UserStated);
    body.world = Some(world);
    let kept_claim = EntityId::now();
    vault
        .put_claim(&kept_claim, &body, at(1), 1)
        .expect("propose the distinct claim in W");
    assert_eq!(
        vault.record_world(&kept_claim).expect("world read"),
        Some(Some(world)),
        "FIXTURE: the pair's CLAIM sits in W"
    );

    // The owner's assertion of the pair promotes that CLAIM in place; another
    // pair's assertion mints its CLAIM in base reality.
    let kept_event = assert_distinct(&vault, pair.0, pair.1);
    assert_eq!(
        asserted_claim(&vault, kept_event),
        kept_claim,
        "FIXTURE: the assertion names the pair's CLAIM in W"
    );
    assert_eq!(
        vault
            .get_claim(&kept_claim)
            .expect("claim read")
            .expect("FIXTURE: the pair's CLAIM is stored")
            .approval,
        ClaimApprovalStatus::Auto,
        "FIXTURE: the owner's assertion promotes the proposed CLAIM"
    );
    assert_eq!(
        vault.record_world(&kept_claim).expect("world read"),
        Some(Some(world)),
        "FIXTURE: the promoted CLAIM still sits in W"
    );
    let open_event = assert_distinct(&vault, person(&vault, "Bo"), person(&vault, "Bo"));
    let open_claim = asserted_claim(&vault, open_event);
    let signed = dispositions_of(&vault, kept_event);
    assert!(
        !signed.is_empty(),
        "FIXTURE: an admission disposition signs the assertion in W"
    );
    let placed: Vec<EntityId> = std::iter::once(kept_event).chain(signed).collect();
    assert_eq!(
        vault.record_world(&open_event).expect("world read"),
        Some(None),
        "FIXTURE: the base pair's event sits in base reality"
    );
    let before = exported(&vault);
    assert_eq!(
        held(&before, &placed),
        placed,
        "FIXTURE: while W goes everywhere, an export carries the assertion in W"
    );

    vault
        .keep_world_on_this_machine_for_test(world, true)
        .expect("keep W on this machine");
    let after = exported(&vault);
    assert!(
        held(&after, &[kept_claim]).is_empty(),
        "FIXTURE: an export leaves out the CLAIM that W keeps"
    );
    assert_eq!(
        held(&after, &[open_event, open_claim]),
        [open_event, open_claim],
        "FIXTURE: an export still carries the base pair's event and CLAIM"
    );

    for row in &placed {
        assert_eq!(
            vault.record_world(row).expect("world read"),
            Some(Some(world)),
            "LEAK: the ledger row {row:?} of the distinct fact in W does not sit in W"
        );
    }
    assert_eq!(
        held(&after, &placed),
        Vec::<EntityId>::new(),
        "LEAK: an export carries the ledger rows of the distinct fact that W keeps"
    );
}
