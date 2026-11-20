//! The owner's retract door names the owner as the close's closer (FIX
//! OWNER-RETRACT-ROUTE-NAMES-NO-CLOSER): `Vault::retract_claim_as_owner`, the
//! door of the server's owner memory retract, closes a Dreamer claim of
//! imported words the owner approved, as `Memory::claim_retract` as the
//! owner does. With no closer, the Gate judged the Dreamer's own envelope and
//! lineage and refused the close.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_retract_as_owner_closer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Settle, Settlement, batch_items, commit,
    open_conflict_with_imported_alternative,
};
use oneiron::test_doors::steward::{dreamer, owner};
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use serde_json::json;

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    person: EntityId,
    turn: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
    }
}

/// Lands one derived claim; its id.
fn landed_claim(fixture: &Fixture, value: &str) -> EntityId {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-first",
        &[Derived::Claim(Claim {
            local: "first",
            predicate: "preference.coffee",
            subject: Named::Stored(fixture.person),
            value: json!(value),
            evidence: vec![Named::Stored(fixture.turn)],
        })],
    )
    .expect("FIXTURE: commit the first claim");
    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(item.landed, "FIXTURE: the first claim lands: {item:?}");
    item.rows[0]
}

/// The Dreamer's Keep of an imported alternative, staged and then approved by
/// the owner: its id.
fn approved_imported_keep(fixture: &Fixture) -> EntityId {
    let first = landed_claim(fixture, "an oat milk flat white");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, first, "a cortado")
            .expect("FIXTURE: an open conflict with an imported alternative");
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-keep-imported",
        &[Derived::Settle(Settle {
            local: "keep_imported",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(alternative)),
        })],
    )
    .expect("FIXTURE: commit the Keep batch");
    let recorded = batch_items(&fixture.vault, committed.batch)
        .expect("read")
        .expect("FIXTURE: the batch record");
    let [settled] = recorded.as_slice() else {
        panic!("FIXTURE: one Keep item: {recorded:?}");
    };
    assert!(
        settled.landed,
        "FIXTURE: the imported Keep stages: {settled:?}"
    );
    let staged = settled.rows[0];
    let staged_body = fixture
        .vault
        .get_claim(&staged)
        .expect("read")
        .expect("FIXTURE: the staged Keep");
    assert_eq!(
        staged_body.approval,
        ClaimApprovalStatus::Proposed,
        "FIXTURE: the Keep waits for approval"
    );
    assert_eq!(
        staged_body.source,
        Some(ClaimSource::Imported),
        "FIXTURE: the Keep restates imported words"
    );

    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    fixture
        .vault
        .approve_machine_claim_as(staged, WriteActor::new(owner_id, EdgeActorClass::Human))
        .expect("FIXTURE: the owner approves the staged Keep");
    let approved = fixture
        .vault
        .get_claim(&staged)
        .expect("read")
        .expect("FIXTURE: the approved Keep");
    assert_eq!(
        approved.approval,
        ClaimApprovalStatus::Approved,
        "FIXTURE: the owner's approval stands"
    );
    assert_eq!(
        approved.lifecycle,
        ClaimLifecycleStatus::Active,
        "FIXTURE: the approved Keep is active"
    );
    staged
}

/// The owner retracts, through the owner's retract door, a Dreamer claim of
/// imported words that the owner approved: the claim is retracted.
#[test]
fn the_owners_retract_door_closes_an_approved_imported_dreamer_claim() {
    let fixture = fixture();
    let keep = approved_imported_keep(&fixture);
    let proof = owner(&fixture.vault).expect("FIXTURE: the owner's proof");

    fixture
        .vault
        .retract_claim_as_owner(&proof, &keep, fixture.vault.now_recorded_at())
        .unwrap_or_else(|error| {
            panic!("the owner's retract door closes the approved Keep; it refused: {error:?}")
        });
    let retracted = fixture
        .vault
        .get_claim(&keep)
        .expect("read")
        .expect("the retracted Keep remains stored");
    assert_eq!(
        retracted.lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the owner's retract door retracts the approved Keep"
    );
}

/// Control: the same claim retracted through `Memory::claim_retract` as the
/// owner, which names the owner as closer, is retracted on main too.
#[test]
fn the_owners_memory_retract_closes_an_approved_imported_dreamer_claim() {
    let fixture = fixture();
    let keep = approved_imported_keep(&fixture);
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");

    fixture
        .vault
        .memory(owner_id, EdgeActorClass::Human)
        .claim_retract(&keep.to_hex())
        .unwrap_or_else(|error| {
            panic!("FIXTURE: the owner's memory retract closes the approved Keep: {error:?}")
        });
    assert_eq!(
        fixture
            .vault
            .get_claim(&keep)
            .expect("read")
            .expect("the retracted Keep remains stored")
            .lifecycle,
        ClaimLifecycleStatus::Retracted,
        "FIXTURE: the memory retract retracts the approved Keep"
    );
}
