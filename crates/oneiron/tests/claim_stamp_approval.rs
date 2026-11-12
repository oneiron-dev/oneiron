//! FIX CLAIM-SENSITIVITY-STAMP-FORCES-PROPOSED: the approval an owner's
//! claim write asks for routes on its sensitivity stamp's band, never on
//! whether a stamp is present (ARCH-0003 consent matrix: `user_stated` or
//! `observed` at a normal sensitivity routes `auto`; `sensitive` routes
//! `proposed`).
//!
//! Each case writes `profile.name` (a declared, normal-criticality predicate
//! in the default manifest) about the vault's embedded owner, as that owner,
//! through one public claim door, and reads the stored claim back.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test claim_stamp_approval`.

use oneiron::claim::{base_world_id, default_project_id};
use oneiron::memory::{
    AllRelationships, ClaimInput, ClaimRelationships, ClaimScope, CommitOutcome, CommitReceipt,
    ScopedClaimInput, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::{ClaimApprovalStatus, EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const STAMP_APPROVAL_PREDICATE: &str = "profile.name";

struct StampApprovalVault {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn stamp_approval_vault() -> StampApprovalVault {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    StampApprovalVault {
        vault,
        owner,
        _dir: dir,
    }
}

fn scoped_input(
    fixture: &StampApprovalVault,
    id: EntityId,
    source: &str,
    sensitivity: Option<u8>,
) -> ScopedClaimInput {
    ScopedClaimInput {
        id: Some(id.to_hex()),
        predicate: STAMP_APPROVAL_PREDICATE.to_owned(),
        subject_ref: fixture.owner.to_hex(),
        value: json!("Owen"),
        confidence: 1.0,
        source: source.to_owned(),
        scope: ClaimScope {
            world_id: base_world_id().to_hex(),
            scope_facet_id: fixture
                .vault
                .default_facet()
                .expect("owner default facet")
                .to_hex(),
            scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
            scope_project_id: default_project_id().to_hex(),
        },
        sensitivity,
        evidence_turn_refs: Vec::new(),
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

fn plain_input(owner: EntityId, id: EntityId, scope: Option<serde_json::Value>) -> ClaimInput {
    ClaimInput {
        id: Some(id.to_hex()),
        predicate: STAMP_APPROVAL_PREDICATE.to_owned(),
        subject_ref: owner.to_hex(),
        value: json!("Owen"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    }
}

/// Reads the written claim back and checks that the stored body carries the
/// receipt's approval.
fn stored_approval(
    fixture: &StampApprovalVault,
    id: EntityId,
    receipt: &CommitReceipt,
) -> ClaimApprovalStatus {
    let body = fixture
        .vault
        .get_claim(&id)
        .expect("read the stored claim")
        .expect("the claim is stored");
    assert_eq!(
        body.approval.as_str(),
        receipt.approval,
        "the receipt answers the stored approval",
    );
    body.approval
}

fn scoped_write(source: &str, sensitivity: Option<u8>) -> (String, ClaimApprovalStatus) {
    let fixture = stamp_approval_vault();
    let id = EntityId::now();
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_upsert_scoped(&scoped_input(&fixture, id, source, sensitivity))
        .unwrap_or_else(|error| {
            panic!(
                "the owner's {source} claim at band {sensitivity:?} is admitted, got {}: {}",
                error.code, error.message,
            )
        });
    let stored = stored_approval(&fixture, id, &receipt);
    (receipt.approval, stored)
}

#[test]
fn owner_public_stamped_user_stated_claim_lands_auto() {
    let (receipt, stored) = scoped_write("user_stated", Some(0));
    assert_eq!(
        receipt, "auto",
        "a public stamp asks what no stamp asks: the owner's user_stated claim lands auto",
    );
    assert_eq!(stored, ClaimApprovalStatus::Auto);
}

#[test]
fn owner_private_stamped_observed_claim_lands_auto() {
    let (receipt, stored) = scoped_write("observed", Some(1));
    assert_eq!(
        receipt, "auto",
        "private is below sensitive: the owner's observed claim lands auto",
    );
    assert_eq!(stored, ClaimApprovalStatus::Auto);
}

#[test]
fn owner_public_stamp_by_name_on_the_plain_door_lands_auto() {
    let fixture = stamp_approval_vault();
    let id = EntityId::now();
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_upsert(&plain_input(
            fixture.owner,
            id,
            Some(json!({"sensitivity": "public"})),
        ))
        .unwrap_or_else(|error| {
            panic!(
                "the owner's plain upsert is admitted, got {}: {}",
                error.code, error.message,
            )
        });
    assert_eq!(
        receipt.approval, "auto",
        "a stamp spelled \"public\" reads band 0 and asks auto",
    );
    assert_eq!(
        stored_approval(&fixture, id, &receipt),
        ClaimApprovalStatus::Auto
    );
}

#[test]
fn owner_public_stamped_commit_batch_lands_auto() {
    let fixture = stamp_approval_vault();
    let id = EntityId::now();
    let outcomes = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .commit_scoped(&[scoped_input(&fixture, id, "user_stated", Some(0))], false)
        .unwrap_or_else(|error| {
            panic!(
                "the owner's vault.commit is admitted, got {}: {}",
                error.code, error.message,
            )
        });
    let [CommitOutcome::Landed(receipt)] = outcomes.as_slice() else {
        panic!("one landed element, got {outcomes:?}");
    };
    assert_eq!(
        receipt.approval, "auto",
        "vault.commit routes the public stamp as vault.claims.upsert does",
    );
    assert_eq!(
        stored_approval(&fixture, id, receipt),
        ClaimApprovalStatus::Auto
    );
}

#[test]
fn owner_unstamped_user_stated_claim_lands_auto() {
    let (receipt, stored) = scoped_write("user_stated", None);
    assert_eq!(receipt, "auto", "no stamp asks auto, as before");
    assert_eq!(stored, ClaimApprovalStatus::Auto);
}

#[test]
fn owner_sensitive_and_restricted_stamps_park_proposed() {
    for band in [2, 3] {
        let (receipt, stored) = scoped_write("user_stated", Some(band));
        assert_eq!(
            receipt, "proposed",
            "band {band} is sensitive or above: the claim parks proposed",
        );
        assert_eq!(stored, ClaimApprovalStatus::Proposed);
    }
}

#[test]
fn owner_public_stamped_inferred_claim_parks_proposed() {
    // A concluded claim names the TURN it was concluded from.
    let fixture = stamp_approval_vault();
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let turn = memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "call me Owen".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 1_772_400_000,
            assertions: WitnessAssertions::default(),
        })
        .expect("the evidence turn")
        .turn_id;
    let id = EntityId::now();
    let mut input = scoped_input(&fixture, id, "inferred", Some(0));
    input.evidence_turn_refs = vec![turn.to_hex()];
    let receipt = memory.claim_upsert_scoped(&input).unwrap_or_else(|error| {
        panic!(
            "the owner's inferred claim at band 0 is admitted, got {}: {}",
            error.code, error.message,
        )
    });
    assert_eq!(
        receipt.approval, "proposed",
        "only user_stated and observed ask auto; the stamp changes nothing else",
    );
    assert_eq!(
        stored_approval(&fixture, id, &receipt),
        ClaimApprovalStatus::Proposed
    );
}
