//! The owner settles a claim the owner's own whole-vault restore brought back
//! (pin P1, NOTE ARCHIVE-MACHINE-RESTORE-DESIGN F3, RULING 00:08 13 Nov).
//!
//! The owner door (`import_whole_vault_archive_from_as_owner`) restores
//! every claim Imported + Proposed and keeps its evidence. Settle adds the
//! evidence's `actor_entity_ref` to the proposal's openers and refuses a
//! settler who opened it ("the actor that opened a proposal never settles
//! it"). Every embedded vault carries the same derived owner id
//! (`embedded_owner_actor_id`), so a claim the owner wrote names the very
//! owner who restores it. On main, then, the owner can never settle a claim
//! the owner's own restore brought back, and it stays Proposed (out of
//! recall) for good. Since D5 the owner door stamps each such claim with its
//! restore receipt (`owner_restore_receipt`), and settle leaves the owner the
//! receipt names out of the proposal's openers: the restore opened it.
//!
//! * `an_owner_written_claim_restored_by_the_owner_is_settled_by_the_owner`:
//!   the owner writes a `profile.` claim (the shipped manifest labels that
//!   prefix Normal), exports the whole vault, restores it as the owner into
//!   a fresh vault, reviews the restored proposal and approves it.
//!
//! Public doors only; neutral fixtures (`owen`); vaults in tempdirs. The
//! destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), as in `whole_vault_restore_seeds.rs`.
//!
//! Run with `cargo test --locked -p oneiron --all-features --test archive_restore_owner_settle`.

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use rmpv::Value;

/// A `profile.` predicate: the shipped default policy labels that prefix
/// Normal, so the owner's settle is not parked at the criticality floor.
const PREDICATE: &str = "profile.nickname";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault, id: &EntityId, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode person body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("put person");
}

#[test]
fn an_owner_written_claim_restored_by_the_owner_is_settled_by_the_owner() {
    let (_source_dir, source) = open_vault();
    let source_owner = source
        .ensure_embedded_owner_actor()
        .expect("the source's embedded owner");
    let owen = EntityId::now();
    put_person(&source, &owen, "owen");
    let claim = EntityId::now();
    let written = source
        .memory(source_owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(claim.to_hex()),
            predicate: PREDICATE.to_owned(),
            subject_ref: owen.to_hex(),
            value: serde_json::json!("Owen"),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("the owner writes a claim");
    assert_ne!(
        written.approval, "proposed",
        "the owner's own write lands, it is no proposal"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();

    let (_dest_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let dest_owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    assert_eq!(
        dest_owner, source_owner,
        "every embedded vault carries the same derived owner id"
    );
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
    {
        panic!("the owner's whole archive must restore: {error:?}");
    }
    let restored = dest
        .get_claim(&claim)
        .expect("read the restored claim")
        .expect("the restore keeps the claim's id");
    assert_eq!(restored.predicate, PREDICATE);
    assert_eq!(restored.source, Some(ClaimSource::Imported));
    assert_eq!(
        restored.approval,
        ClaimApprovalStatus::Proposed,
        "the owner door restores a claim as a proposal"
    );

    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let review = memory
        .claim_review_as_owner(
            &owner,
            &ClaimProposalReviewRequest {
                claim_ref: claim.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the restored proposal");
    let settled = memory.claim_settle_as_owner(
        &owner,
        &ClaimSettleRequest {
            claim_ref: claim.to_hex(),
            review_id: review.review_id.clone(),
            decision: ClaimSettleDecision::Approve,
            grant_ref: None,
        },
    );
    let settled = match settled {
        Ok(settled) => settled,
        Err(error) => panic!(
            "the owner settles a claim the owner's own restore brought back \
             (review opener_ref {:?}, owner {}): {error:?}",
            review.opener_ref,
            dest_owner.to_hex()
        ),
    };
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    let live = dest
        .get_claim(&claim)
        .expect("read the settled claim")
        .expect("the settled claim");
    assert_eq!(live.approval, ClaimApprovalStatus::Approved);
    assert_eq!(live.lifecycle, ClaimLifecycleStatus::Active);
}
