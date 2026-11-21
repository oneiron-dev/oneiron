//! The owner's retract door names the owner as the close's closer (FIX
//! OWNER-RETRACT-ROUTE-NAMES-NO-CLOSER): `Vault::retract_claim_as_owner`, the
//! door of the server's owner memory retract, closes a Dreamer claim of
//! imported words the owner approved, as `Memory::claim_retract` as the
//! owner does. With no closer, the Gate judged the Dreamer's own envelope and
//! lineage and refused the close.
//!
//! Review 10097 round 1: the Gate judges and receipts an exact close as its
//! verified closer even when the stored row has no birth envelope (a claim
//! put as a first-party write is receipted as the owner's close), and a
//! human's close is not held to the Dreamer's floors (GATE-13 isolation of a
//! mirroring-prone predicate refused the owner's retract on both doors).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_retract_as_owner_closer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionRecord;
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
/// A mirroring-prone predicate: GATE-13 isolates a Dreamer write of it.
const MIRRORING_PRONE_PREDICATE: &str = "core.opinion.music";

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
fn landed_claim(fixture: &Fixture, predicate: &str, value: &str) -> EntityId {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-first",
        &[Derived::Claim(Claim {
            local: "first",
            predicate,
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
    let first = landed_claim(fixture, "preference.coffee", "an oat milk flat white");
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

    approve_as_owner(fixture, staged);
    staged
}

/// The owner approves the staged claim `staged`: it is Approved and active.
fn approve_as_owner(fixture: &Fixture, staged: EntityId) {
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    fixture
        .vault
        .approve_machine_claim_as(staged, WriteActor::new(owner_id, EdgeActorClass::Human))
        .expect("FIXTURE: the owner approves the staged claim");
    let approved = fixture
        .vault
        .get_claim(&staged)
        .expect("read")
        .expect("FIXTURE: the approved claim");
    assert_eq!(
        approved.approval,
        ClaimApprovalStatus::Approved,
        "FIXTURE: the owner's approval stands"
    );
    assert_eq!(
        approved.lifecycle,
        ClaimLifecycleStatus::Active,
        "FIXTURE: the approved claim is active"
    );
}

/// The Dreamer's claim on a mirroring-prone predicate, which GATE-13 holds
/// for the owner, approved by the owner: its id.
fn approved_mirroring_prone_claim(fixture: &Fixture) -> EntityId {
    let staged = landed_claim(
        fixture,
        MIRRORING_PRONE_PREDICATE,
        "late-night jazz records",
    );
    assert_eq!(
        fixture
            .vault
            .get_claim(&staged)
            .expect("read")
            .expect("FIXTURE: the staged claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "FIXTURE: the mirroring-prone claim waits for the owner"
    );
    approve_as_owner(fixture, staged);
    staged
}

/// A claim put with no write envelope, as a first-party write: its id.
fn claim_put_with_no_envelope(fixture: &Fixture) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        "profile.example",
        ClaimSubject::Entity(fixture.person),
        rmpv::Value::from("reads on the morning train"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: a claim body");
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("FIXTURE: the claim is put");
    id
}

/// Every Gate decision the ledger holds about `claim`, newest first.
fn decisions_about(fixture: &Fixture, claim: EntityId) -> Vec<GateDecisionRecord> {
    fixture
        .vault
        .gate_decisions(4096)
        .expect("read the Gate decisions")
        .into_iter()
        .filter(|record| record.claim_id == Some(*claim.as_bytes()))
        .collect()
}

/// Retracts `claim` through the owner's retract door; panics on a refusal.
fn retract_through_the_owners_door(fixture: &Fixture, claim: EntityId) {
    let proof = owner(&fixture.vault).expect("FIXTURE: the owner's proof");
    fixture
        .vault
        .retract_claim_as_owner(&proof, &claim, fixture.vault.now_recorded_at())
        .unwrap_or_else(|error| {
            panic!("the owner's retract door closes the claim; it refused: {error:?}")
        });
}

/// Retracts `claim` through `Memory::claim_retract` as the owner; panics on
/// a refusal.
fn retract_through_the_owners_memory(fixture: &Fixture, claim: EntityId) {
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    fixture
        .vault
        .memory(owner_id, EdgeActorClass::Human)
        .claim_retract(&claim.to_hex())
        .unwrap_or_else(|error| {
            panic!("the owner's memory retract closes the claim; it refused: {error:?}")
        });
}

fn lifecycle(fixture: &Fixture, claim: EntityId) -> ClaimLifecycleStatus {
    fixture
        .vault
        .get_claim(&claim)
        .expect("read")
        .expect("the claim remains stored")
        .lifecycle
}

/// The owner retracts, through the owner's retract door, a Dreamer claim of
/// imported words that the owner approved: the claim is retracted.
#[test]
fn the_owners_retract_door_closes_an_approved_imported_dreamer_claim() {
    let fixture = fixture();
    let keep = approved_imported_keep(&fixture);

    retract_through_the_owners_door(&fixture, keep);
    assert_eq!(
        lifecycle(&fixture, keep),
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

    retract_through_the_owners_memory(&fixture, keep);
    assert_eq!(
        lifecycle(&fixture, keep),
        ClaimLifecycleStatus::Retracted,
        "FIXTURE: the memory retract retracts the approved Keep"
    );
}

/// The owner retracts, through the owner's retract door, the Dreamer's claim
/// on a mirroring-prone predicate that the owner approved: the claim is
/// retracted. The owner's close is not the Dreamer's write, so GATE-13 does
/// not hold it (review 10097 P1).
#[test]
fn the_owners_retract_door_closes_an_approved_dreamer_claim_on_a_mirroring_prone_predicate() {
    let fixture = fixture();
    let claim = approved_mirroring_prone_claim(&fixture);

    retract_through_the_owners_door(&fixture, claim);
    assert_eq!(
        lifecycle(&fixture, claim),
        ClaimLifecycleStatus::Retracted,
        "the owner's retract door retracts the approved mirroring-prone claim"
    );
}

/// The same claim retracted through `Memory::claim_retract` as the owner is
/// retracted too: both owner doors meet the same Gate.
#[test]
fn the_owners_memory_retract_closes_an_approved_dreamer_claim_on_a_mirroring_prone_predicate() {
    let fixture = fixture();
    let claim = approved_mirroring_prone_claim(&fixture);

    retract_through_the_owners_memory(&fixture, claim);
    assert_eq!(
        lifecycle(&fixture, claim),
        ClaimLifecycleStatus::Retracted,
        "the owner's memory retract retracts the approved mirroring-prone claim"
    );
}

/// The owner retracts, through the owner's retract door, a claim put with no
/// write envelope: the Gate judges and receipts the close as the owner, a
/// human, not as a first-party write (review 10097 P1).
#[test]
fn the_owners_retract_door_receipts_the_close_of_a_claim_put_with_no_envelope_as_the_owner() {
    let fixture = fixture();
    let claim = claim_put_with_no_envelope(&fixture);
    let owner_id = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    let before: Vec<_> = decisions_about(&fixture, claim)
        .into_iter()
        .map(|record| record.decision_id)
        .collect();

    retract_through_the_owners_door(&fixture, claim);
    assert_eq!(
        lifecycle(&fixture, claim),
        ClaimLifecycleStatus::Retracted,
        "the owner's retract door retracts the claim"
    );
    let close: Vec<_> = decisions_about(&fixture, claim)
        .into_iter()
        .filter(|record| !before.contains(&record.decision_id))
        .collect();
    assert!(!close.is_empty(), "the close records its Gate decision");
    let owner_ref = owner_id.to_hex();
    for record in &close {
        assert_eq!(
            (record.actor_class.as_str(), record.actor_ref.as_deref()),
            ("human", Some(owner_ref.as_str())),
            "the close is judged and receipted as the owner: {record:?}"
        );
    }
}
