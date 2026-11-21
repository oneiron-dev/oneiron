//! The vault owner's supersede door names the owner as the old head's closer
//! (FIX OWNER-SUPERSEDE-ROUTE-NAMES-NO-CLOSER, the twin of
//! OWNER-RETRACT-ROUTE-NAMES-NO-CLOSER). `Vault::supersede_claim_as_owner`
//! (the server's core memory supersede) revalidates the owner's proof, and
//! the close is then judged as the owner's act. The case: a Dreamer Keep of
//! imported words the owner approved, so its tray row is gone. Judged under
//! its own envelope, its source trust is still pending with no row left to
//! redeem, and the close does not land as the owner asked. The second case
//! (review 10099 P1): a Dreamer claim on a mirroring-prone predicate the
//! owner approved. The owner's close keeps the Dreamer's birth envelope, but
//! it admits nothing new, so GATE-13 isolation does not pend it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_supersede_as_owner_closer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::ClaimInput;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Settle, Settlement, batch_items, commit,
    open_conflict_with_imported_alternative,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use serde_json::json;

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("FIXTURE: a row");
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
    let vault = open_dreamer_vault(dir.path(), READER).expect("FIXTURE: vault");
    let dreamer = dreamer(&vault).expect("FIXTURE: the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("FIXTURE: a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
    }
}

/// Lands one derived `preference.coffee` claim about the person; its id.
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
    .expect("FIXTURE: commit");
    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(item.landed, "FIXTURE: the first claim lands: {item:?}");
    item.rows[0]
}

/// The Dreamer's Keep of an imported alternative, staged and then approved by
/// the owner: an Approved, Active MACHINE claim of imported lineage whose
/// tray row is gone. Its id, the owner, and the owner's proof.
fn approved_imported_keep(fixture: &Fixture) -> (EntityId, EntityId, AuthenticatedOwner) {
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
        .expect("FIXTURE: read")
        .expect("FIXTURE: the batch record");
    let [keep] = recorded.as_slice() else {
        panic!("FIXTURE: one Keep item: {recorded:?}");
    };
    assert!(keep.landed, "FIXTURE: the imported Keep stages: {keep:?}");
    let [staged, _marker] = keep.rows.as_slice() else {
        panic!("FIXTURE: the staged proposal and the marker: {keep:?}");
    };
    let staged = *staged;
    let proposed = fixture
        .vault
        .get_claim(&staged)
        .expect("FIXTURE: read")
        .expect("FIXTURE: the staged Keep");
    assert_eq!(
        (proposed.approval, proposed.lifecycle),
        (ClaimApprovalStatus::Proposed, ClaimLifecycleStatus::Active),
        "FIXTURE: the imported Keep waits for the owner's approval"
    );
    let (owner, proof) = owner_approves(fixture, staged);
    (staged, owner, proof)
}

/// The Dreamer's `core.opinion.coffee` claim about the person, which GATE-13
/// isolates as mirroring-prone, approved by the owner: an Approved, Active
/// MACHINE claim of a Dreamer birth envelope whose tray row is gone. Its id,
/// the owner, and the owner's proof.
fn approved_isolated_dreamer_claim(fixture: &Fixture) -> (EntityId, EntityId, AuthenticatedOwner) {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-opinion",
        &[Derived::Claim(Claim {
            local: "opinion",
            predicate: "core.opinion.coffee",
            subject: Named::Stored(fixture.person),
            value: json!("a cortado beats a flat white"),
            evidence: vec![Named::Stored(fixture.turn)],
        })],
    )
    .expect("FIXTURE: commit");
    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(
        item.landed && item.approval.as_deref() == Some("proposed"),
        "FIXTURE: GATE-13 isolates the Dreamer's mirroring-prone claim as a proposal: {item:?}"
    );
    let staged = item.rows[0];
    let (owner, proof) = owner_approves(fixture, staged);
    (staged, owner, proof)
}

/// The owner approves the staged proposal `staged`: it is then Approved and
/// Active, with its tray row gone. The owner and the owner's proof.
fn owner_approves(fixture: &Fixture, staged: EntityId) -> (EntityId, AuthenticatedOwner) {
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    fixture
        .vault
        .approve_machine_claim_as(staged, WriteActor::new(owner, EdgeActorClass::Human))
        .expect("FIXTURE: the owner approves the staged proposal");
    let approved = fixture
        .vault
        .get_claim(&staged)
        .expect("FIXTURE: read")
        .expect("FIXTURE: the approved claim");
    assert_eq!(
        (approved.approval, approved.lifecycle),
        (ClaimApprovalStatus::Approved, ClaimLifecycleStatus::Active),
        "FIXTURE: the owner's approval stands and the claim is active"
    );
    let proof = fixture
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    (owner, proof)
}

/// The owner writes an active replacement and supersedes `old` with it
/// through `Vault::supersede_claim_as_owner`; `old` must then be Superseded.
fn owner_supersedes(fixture: &Fixture, owner: EntityId, proof: &AuthenticatedOwner, old: EntityId) {
    let input: ClaimInput = serde_json::from_value(json!({
        "predicate": "note.reviewed",
        "subject_ref": fixture.person.to_hex(),
        "value": "the cortado is settled",
        "confidence": 0.9,
        "source": "user_stated",
    }))
    .expect("FIXTURE: claim input");
    let receipt = fixture
        .vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(proof)
        .claim_upsert(&input)
        .expect("FIXTURE: the owner writes the replacement");
    let replacement = oneiron::memory::resolve_entity_ref(&fixture.vault, &receipt.claim_short_id)
        .expect("FIXTURE: the replacement's id");
    assert_eq!(
        fixture
            .vault
            .get_claim(&replacement)
            .expect("FIXTURE: read")
            .expect("FIXTURE: the replacement")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "FIXTURE: the owner's replacement is active"
    );

    let supersede = fixture.vault.supersede_claim_as_owner(
        proof,
        &replacement,
        &old,
        fixture.vault.now_recorded_at(),
    );
    assert!(
        supersede.is_ok(),
        "the owner's supersede through the vault owner door closes the approved claim as the \
         owner's act: {supersede:?}"
    );
    let superseded = fixture
        .vault
        .get_claim(&old)
        .expect("read")
        .expect("the superseded claim remains stored");
    assert_eq!(
        superseded.lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the owner's supersede closes the approved claim, held for no source trust and no \
         Dreamer isolation"
    );
}

#[test]
fn the_owner_supersedes_an_approved_imported_keep_through_the_vault_owner_door() {
    let fixture = fixture();
    let (staged, owner, proof) = approved_imported_keep(&fixture);
    owner_supersedes(&fixture, owner, &proof, staged);
}

#[test]
fn the_owner_supersedes_an_approved_mirroring_isolated_dreamer_claim() {
    let fixture = fixture();
    let (staged, owner, proof) = approved_isolated_dreamer_claim(&fixture);
    owner_supersedes(&fixture, owner, &proof, staged);
}
