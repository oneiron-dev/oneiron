//! E2E MUSE-RECALL-03: a declared multi-cardinality predicate keeps each
//! distinct value standing. ARCH-0022:265-282 multi rows replace only an
//! agreeing answer, an exact row beats its namespace wildcard
//! (`storytelling.pacing` stays single), and an undeclared predicate keeps
//! the single-head default (ARCH-0044 S3).
//!
//! `cargo test --locked -p oneiron --all-features --test claim_declared_cardinality`.

use oneiron::memory::ClaimInput;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault, VaultConfig,
};

const DECISION_VALUES: [&str; 3] = [
    "keep the lighthouse ledger",
    "chart the river crossing",
    "restore the observatory",
];

fn owner_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("create cardinality vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open cardinality vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("ensure cardinality owner actor");
    (dir, vault, owner)
}

fn upsert(vault: &Vault, owner: EntityId, predicate: &str, value: &str) -> EntityId {
    let id = EntityId::now();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: serde_json::json!(value),
            confidence: 0.9,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .expect("upsert owner claim through the public memory facade");
    assert_eq!(receipt.approval, "auto", "the owner's claim must land");
    id
}

fn assert_lifecycle(vault: &Vault, id: EntityId, expected: ClaimLifecycleStatus) {
    let claim = vault
        .get_claim(&id)
        .expect("read claim through the public claims door")
        .expect("upserted claim exists");
    assert_eq!(claim.lifecycle, expected, "claim {id:?} lifecycle");
    if expected == ClaimLifecycleStatus::Active {
        assert!(
            matches!(
                claim.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            ),
            "an active claim must also be approved to stand"
        );
    }
}

#[test]
fn declared_multi_predicate_keeps_each_distinct_value_standing() {
    let (dir, vault, owner) = owner_vault();
    let ids = DECISION_VALUES.map(|value| upsert(&vault, owner, "decision.practical", value));
    for id in ids {
        assert_lifecycle(&vault, id, ClaimLifecycleStatus::Active);
    }

    drop(vault);
    let reopened =
        Vault::open(dir.path(), VaultConfig::device()).expect("reopen cardinality vault");
    for id in ids {
        assert_lifecycle(&reopened, id, ClaimLifecycleStatus::Active);
    }
}

#[test]
fn exact_single_row_beats_namespace_wildcard() {
    let (_dir, vault, owner) = owner_vault();
    let first = upsert(&vault, owner, "storytelling.pacing", "unhurried scenes");
    let second = upsert(&vault, owner, "storytelling.pacing", "rapid scenes");
    assert_lifecycle(&vault, first, ClaimLifecycleStatus::Superseded);
    assert_lifecycle(&vault, second, ClaimLifecycleStatus::Active);
}

#[test]
fn undeclared_predicate_stays_single() {
    let (_dir, vault, owner) = owner_vault();
    // No canon cardinality row declares `profile.cardinality_default`.
    let first = upsert(&vault, owner, "profile.cardinality_default", "first answer");
    let second = upsert(
        &vault,
        owner,
        "profile.cardinality_default",
        "second answer",
    );
    assert_lifecycle(&vault, first, ClaimLifecycleStatus::Superseded);
    assert_lifecycle(&vault, second, ClaimLifecycleStatus::Active);
}

#[test]
fn agreeing_value_still_supersedes_in_a_multi_row() {
    let (_dir, vault, owner) = owner_vault();
    let ids = DECISION_VALUES.map(|value| upsert(&vault, owner, "decision.practical", value));
    let replacement = upsert(
        &vault,
        owner,
        "decision.practical",
        "  KEEP   THE LIGHTHOUSE  LEDGER  ",
    );
    assert_lifecycle(&vault, ids[0], ClaimLifecycleStatus::Superseded);
    assert_lifecycle(&vault, ids[1], ClaimLifecycleStatus::Active);
    assert_lifecycle(&vault, ids[2], ClaimLifecycleStatus::Active);
    assert_lifecycle(&vault, replacement, ClaimLifecycleStatus::Active);
}
