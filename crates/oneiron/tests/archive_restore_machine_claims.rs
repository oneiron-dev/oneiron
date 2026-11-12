//! The owner's whole-vault restore brings back a claim the Dreamer landed,
//! signed as a MACHINE (RULING 00:08 13 Nov on NOTE
//! ARCHIVE-MACHINE-RESTORE-DESIGN, D2-D5).
//!
//! On main every door keeps such a claim as archive data
//! (`MachineSignedClaimNotRestored`), so the restore leaves it out.
//!
//! * `a_dreamer_landed_claim_comes_back_as_the_owners_restore_and_the_owner_approves_it`:
//!   the owner door restores it Imported + Proposed. Its top-level actor is the
//!   restoring owner (class Human), it carries the restore receipt in
//!   `owner_restore_receipt`, its signature and authority frontier have left
//!   the top level, and the MACHINE author and proof ride inert in
//!   `archived_author`. It stays out of recall while proposed; the owner
//!   reviews it as no opener of it, approves it, and it is then recalled.
//! * `the_archived_machine_proof_is_never_read_as_a_signature`: the owner
//!   declines the restored claim. A claim read as MACHINE-signed declines
//!   only through its pending-consent row, which a restore never writes; the
//!   restored claim declines as an ordinary proposal.
//!
//! The actorless door still keeps the claim as archive data:
//! `archive_import_reserved_claims.rs`
//! (`dreamer::a_dreamer_landed_claim_stays_archive_data_in_the_actorless_import`).
//!
//! Public doors plus `test_doors::consolidation` for the Dreamer; neutral
//! fixtures (`owen`); vaults in tempdirs. The destination opens at least one
//! wall-clock second after its source (sleep 1100 ms), as in
//! `whole_vault_restore_seeds.rs`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test archive_restore_machine_claims`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
    Effort, RecallScope,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Memory, Vault, VaultConfig,
};
use rmpv::Value;

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// A source vault whose Dreamer landed one MACHINE-signed claim: the vault,
/// the claim, its archived evidence and the vault's whole archive.
fn dreamer_source() -> (tempfile::TempDir, Vault, EntityId, Value, Vec<u8>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = open_dreamer_vault(dir.path(), "reader").expect("the Dreamer's vault");
    let pass = consolidate_unbound_turn(&source, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let evidence = source
        .get_claim(claim)
        .expect("read the landed claim")
        .expect("the landed claim")
        .evidence
        .expect("the Dreamer stamps its landing");
    assert!(
        field(&evidence, "machine_signature").is_some(),
        "the Dreamer signs its landing as a MACHINE: {evidence:?}"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (dir, source, *claim, evidence, archive)
}

/// A fresh destination, opened at least one wall-clock second after its
/// source, with no embedding model (lexical recall only).
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// The first value a map holds under `key`.
fn field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The archive restored as the destination's bound owner: the vault, its
/// owner, the owner's proof and the restore receipt's ref.
fn restore_as_owner(
    archive: &[u8],
) -> (
    tempfile::TempDir,
    Vault,
    EntityId,
    AuthenticatedOwner,
    String,
) {
    let (dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let dest_owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let receipt = match dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner)
    {
        Ok(receipt) => receipt,
        Err(error) => panic!(
            "the owner's whole archive holding a Dreamer-landed claim must restore: {error:?}"
        ),
    };
    let receipt_ref = receipt
        .owner_restore_receipt_ref
        .expect("the owner door names its restore receipt");
    (dir, dest, dest_owner, owner, receipt_ref)
}

/// Whether the owner's lexical recall of "owen" serves `claim`.
fn recalled(memory: &Memory<'_>, claim: &EntityId) -> bool {
    let hex = claim.to_hex();
    memory
        .recall(
            "owen",
            Effort::Light,
            &RecallScope::default(),
            50,
            None,
            None,
        )
        .expect("the owner's recall")
        .items
        .iter()
        .any(|item| {
            item.record
                .as_ref()
                .is_some_and(|record| record.id == hex && record.kind == "CLAIM")
        })
}

/// The owner reviews `claim` and settles it with `decision`.
fn settle(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    claim: &EntityId,
    decision: ClaimSettleDecision,
) -> ClaimSettlementVerdict {
    let review = memory
        .claim_review_as_owner(
            owner,
            &ClaimProposalReviewRequest {
                claim_ref: claim.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the restored proposal");
    assert_eq!(
        review.opener_ref, None,
        "the owner's restore opened the proposal, not the owner"
    );
    match memory.claim_settle_as_owner(
        owner,
        &ClaimSettleRequest {
            claim_ref: claim.to_hex(),
            review_id: review.review_id,
            decision,
            grant_ref: None,
        },
    ) {
        Ok(settled) => settled.verdict,
        Err(error) => {
            panic!("the owner settles the claim the owner's restore brought back: {error:?}")
        }
    }
}

#[test]
fn a_dreamer_landed_claim_comes_back_as_the_owners_restore_and_the_owner_approves_it() {
    let (_source_dir, _source, claim, archived, archive) = dreamer_source();
    let (_dest_dir, dest, dest_owner, owner, receipt_ref) = restore_as_owner(&archive);

    let restored = dest
        .get_claim(&claim)
        .expect("read the restored claim")
        .expect("the owner's restore brings the Dreamer's claim back");
    assert_eq!(restored.predicate, "profile.name");
    assert_eq!(restored.source, Some(ClaimSource::Imported));
    assert_eq!(
        restored.approval,
        ClaimApprovalStatus::Proposed,
        "a Dreamer inference lands no stronger than the owner's own restored claims"
    );
    let evidence = restored.evidence.as_ref().expect("the restored evidence");
    assert_eq!(
        field(evidence, "actor_entity_ref"),
        Some(&Value::Binary(dest_owner.as_bytes().to_vec())),
        "the restoring owner is the claim's actor: {evidence:?}"
    );
    assert_eq!(
        field(evidence, "actor_class"),
        Some(&Value::from(EdgeActorClass::Human as u8))
    );
    assert_eq!(field(evidence, "machine_signature"), None);
    assert_eq!(field(evidence, "authority_frontier"), None);
    assert_eq!(
        field(evidence, "owner_restore_receipt"),
        Some(&Value::from(receipt_ref.as_str()))
    );
    let author = field(evidence, "archived_author").expect("the archived author rides inert");
    let machine = match field(&archived, "actor_entity_ref") {
        Some(Value::Binary(bytes)) => bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        other => panic!("the Dreamer's landing names its MACHINE: {other:?}"),
    };
    assert_eq!(field(author, "machine"), Some(&Value::from(machine)));
    assert_eq!(
        field(author, "actor_class"),
        field(&archived, "actor_class"),
        "the archived class rides inert"
    );
    match field(author, "machine_proof") {
        Some(Value::Nil) => {}
        Some(proof) => assert_eq!(Some(proof), field(&archived, "machine_signature")),
        None => panic!("the archived proof rides inert: {author:?}"),
    }
    assert!(
        field(author, "source_vault").is_some(),
        "the archived author names its source vault: {author:?}"
    );

    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    assert!(
        !recalled(&memory, &claim),
        "a proposed restored claim stays out of recall"
    );
    assert_eq!(
        settle(&memory, &owner, &claim, ClaimSettleDecision::Approve),
        ClaimSettlementVerdict::Landed
    );
    let approved = dest
        .get_claim(&claim)
        .expect("read the approved claim")
        .expect("the approved claim");
    assert_eq!(approved.approval, ClaimApprovalStatus::Approved);
    assert!(
        recalled(&memory, &claim),
        "the approved restored claim is recalled"
    );
}

#[test]
fn the_archived_machine_proof_is_never_read_as_a_signature() {
    let (_source_dir, _source, claim, _archived, archive) = dreamer_source();
    let (_dest_dir, dest, dest_owner, owner, _receipt_ref) = restore_as_owner(&archive);

    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    assert_eq!(
        settle(&memory, &owner, &claim, ClaimSettleDecision::Reject),
        ClaimSettlementVerdict::Rejected,
        "the restored claim declines as an ordinary proposal, with no consent row"
    );
    let rejected = dest
        .get_claim(&claim)
        .expect("read the declined claim")
        .expect("the declined claim");
    assert_eq!(rejected.approval, ClaimApprovalStatus::Rejected);
}
