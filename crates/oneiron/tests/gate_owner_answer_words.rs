//! UC-03 PR 5 (D2 = A, Engine RULING 13:45 15 Nov; RULING UC03-5-EARLY = A): an owner's own
//! answer is recorded as `approved` or `rejected`, never as a rule's `allow` or `deny`.
//!
//! - `an_owner_archive_restore_reads_approved_and_its_claim_still_settles`: the owner's
//!   whole-vault restore (n7) writes `approved`, and the owner still settles a claim the
//!   restore brought back, because the restore-receipt reads (R16) take the owner's yes. Red on
//!   the base at the last assertion (`allow`); everything before it passes there.
//! - `the_restore_group_read_takes_both_spellings_of_the_owners_yes`: R16 takes a restore
//!   receipt stored as `approved` (written since PR 5) and one stored as `allow` (written before
//!   it, held as it is under M-1), and no other word. Red on the base at `approved`.
//! - `a_cleared_policy_hold_reads_approved`: the human's ruling on a policy hold (n54). Red on
//!   the base (`allow`).
//!
//! The foreign grant (n44) and the owner's correction (n13) are pinned in
//! `tests/gate_receipt_rows.rs`, whose pins PR 5 moves to `approved`.
//!
//! Public doors, plus the `oneiron_test_support` door that calls the restore-group read.
//! Neutral fixtures (`owen`); vaults in tempdirs.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test gate_owner_answer_words`.

#![cfg(oneiron_test_support)]

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict,
};
use oneiron::policy_model::PolicyHoldResolution;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::gate_receipt_rows::{append_held_word_row, owner_restore_receipt_taken};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_store::gate_reason::GateReceiptOutcome;
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The content kind of an owner archive-restore receipt.
const RESTORE_KIND: &str = "owner_archive_restore";

/// A `profile.` predicate: the shipped default policy labels that prefix Normal, so the
/// owner's settle is not parked at the criticality floor.
const PREDICATE: &str = "profile.nickname";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh destination whose engine-seed seconds differ from the source's: any 1100 ms
/// interval crosses a second boundary (as `tests/archive_restore_owner_settle.rs`).
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
fn an_owner_archive_restore_reads_approved_and_its_claim_still_settles() -> TestResult {
    let (_source_dir, source) = open_vault();
    let source_owner = source
        .ensure_embedded_owner_actor()
        .expect("the source's embedded owner");
    let owen = EntityId::now();
    put_person(&source, &owen, "owen");
    let claim = EntityId::now();
    source
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
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
    {
        panic!("the owner's whole archive must restore: {error:?}");
    }
    let restored = dest
        .get_claim(&claim)
        .expect("read the restored claim")
        .expect("the restore keeps the claim's id");
    assert_eq!(restored.source, Some(ClaimSource::Imported));
    assert_eq!(restored.approval, ClaimApprovalStatus::Proposed);

    // R16: the owner the restore receipt names is not an opener, so the owner settles.
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
        Err(error) => {
            panic!("the owner settles a claim the owner's own restore brought back: {error:?}")
        }
    };
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);

    let receipts: Vec<_> = dest
        .gate_decisions(256)?
        .into_iter()
        .filter(|row| row.content_kind == RESTORE_KIND)
        .collect();
    assert_eq!(receipts.len(), 1, "one restore, one receipt: {receipts:?}");
    let receipt = &receipts[0];
    assert!(
        owner_restore_receipt_taken(&dest, receipt.decision_id)?,
        "the restore group's read takes the owner's restore receipt"
    );
    assert_eq!(
        receipt.actor_ref.as_deref(),
        Some(dest_owner.to_hex().as_str())
    );
    assert_eq!(
        receipt.outcome, "approved",
        "the owner's yes, not the rule's allow"
    );
    assert_eq!(receipt.gate_outcome(), Some(GateReceiptOutcome::Approved));
    Ok(())
}

#[test]
fn the_restore_group_read_takes_both_spellings_of_the_owners_yes() -> TestResult {
    let (_dir, vault) = open_vault();
    for (word, taken) in [
        ("allow", true),
        ("approved", true),
        ("approved_amended", false),
        ("deny", false),
        ("rejected", false),
        ("pending", false),
    ] {
        let held = append_held_word_row(&vault, word, RESTORE_KIND)?;
        assert_eq!(
            owner_restore_receipt_taken(&vault, held.decision_id)?,
            taken,
            "a restore receipt stored as {word}"
        );
    }
    Ok(())
}

#[test]
fn a_cleared_policy_hold_reads_approved() {
    assert_eq!(
        PolicyHoldResolution::Cleared.ledger_outcome(),
        GateReceiptOutcome::Approved,
        "the human's yes on a hold"
    );
    assert_eq!(
        PolicyHoldResolution::Declined.ledger_outcome(),
        GateReceiptOutcome::Rejected,
        "the human's no on a hold"
    );
}
