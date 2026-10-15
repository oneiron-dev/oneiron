use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;
use serde_json::json;

fn fixture() -> Result<(
    tempfile::TempDir,
    crate::Vault,
    crate::consent::AuthenticatedOwner,
    ImportedClaimBatch,
)> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), VaultConfig::default())?;
    let actor = EntityId::now();
    let subject = EntityId::now();
    let time = TimeRange { start: 1, end: 1 };
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"owner")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, time, 1, b"subject")?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    let batch = ImportedClaimBatch {
        request_id: EntityId::now(),
        source_id: "okf".into(),
        entries: (0..2)
            .map(|i| ImportedClaimBatchEntry {
                claim_id: EntityId::now(),
                subject,
                source_record_id: format!("concept-{i}"),
                predicate: "profile.name".into(),
                value: json!(format!("name-{i}")),
                occurred: time,
                learned_at: 2,
            })
            .collect(),
    };
    Ok((dir, vault, owner, batch))
}

#[test]
fn imported_batch_without_consent_stays_proposed() -> Result<()> {
    let (_dir, vault, owner, batch) = fixture()?;
    let receipt = vault.admit_imported_claim_batch(&owner, &batch)?;
    assert_eq!(receipt.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(receipt.claim_ids.len(), 2);
    assert_eq!(
        receipt.approval_digest,
        vault
            .imported_claim_batch_effect(&owner, &batch)?
            .digest()
            .to_hex()
    );
    assert!(vault.pending_gate_consents(10)?.is_empty());
    for id in receipt.claim_ids {
        let claim = vault.get_claim(&id)?.expect("imported claim");
        assert_eq!(claim.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(claim.source, Some(ClaimSource::Imported));
    }
    Ok(())
}

#[test]
fn one_explicit_bulk_act_admits_exact_batch_and_cannot_be_replayed() -> Result<()> {
    let (_dir, vault, owner, batch) = fixture()?;
    let digest = vault.imported_claim_batch_effect(&owner, &batch)?.digest();
    vault.approve_once(&owner, digest)?;
    let receipt = vault.admit_imported_claim_batch(&owner, &batch)?;
    assert_eq!(receipt.approval, ClaimApprovalStatus::Approved);
    assert_eq!(receipt.approval_digest, digest.to_hex());
    assert!(vault.pending_gate_consents(10)?.is_empty());
    for id in &receipt.claim_ids {
        let claim = vault.get_claim(id)?.expect("approved imported claim");
        assert_eq!(claim.approval, ClaimApprovalStatus::Approved);
        assert_eq!(claim.source, Some(ClaimSource::Imported));
    }
    assert!(vault.approve_once(&owner, digest).is_err());
    Ok(())
}

#[test]
fn failed_exact_batch_keeps_consent_for_retry() -> Result<()> {
    let (_dir, vault, owner, mut batch) = fixture()?;
    let missing = EntityId::now();
    batch.entries[1].subject = missing;
    let digest = vault.imported_claim_batch_effect(&owner, &batch)?.digest();
    vault.approve_once(&owner, digest)?;
    assert!(vault.admit_imported_claim_batch(&owner, &batch).is_err());
    for entry in &batch.entries {
        assert!(vault.get_raw(&entry.claim_id)?.is_none());
    }
    vault.put_entity(
        &missing,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"subject",
    )?;
    let receipt = vault.admit_imported_claim_batch(&owner, &batch)?;
    assert_eq!(receipt.approval, ClaimApprovalStatus::Approved);
    assert_eq!(receipt.approval_digest, digest.to_hex());
    assert!(vault.pending_gate_consents(10)?.is_empty());
    Ok(())
}

#[test]
fn failed_approve_call_leaves_neither_claims_nor_an_approval() -> Result<()> {
    let (_dir, vault, owner, mut batch) = fixture()?;
    let missing = EntityId::now();
    batch.entries[1].subject = missing;
    assert!(vault.approve_imported_claim_batch(&owner, &batch).is_err());
    for entry in &batch.entries {
        assert!(vault.get_raw(&entry.claim_id)?.is_none());
    }
    // The approval rolled back with the admission: the same digest is still unapproved.
    let digest = vault.imported_claim_batch_effect(&owner, &batch)?.digest();
    vault.approve_once(&owner, digest)?;
    Ok(())
}

/// The consent receipts the ledger holds for `batch`'s digest, by outcome.
fn decisions_for(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    batch: &ImportedClaimBatch,
) -> Result<Vec<String>> {
    let digest = vault.imported_claim_batch_effect(owner, batch)?.digest();
    Ok(vault
        .gate_decisions(1_000)?
        .into_iter()
        .filter(|record| record.diff_handle == digest.as_bytes().to_vec())
        .map(|record| record.outcome)
        .collect())
}

/// Another live owner of the same vault, as on a shared vault.
fn second_owner(vault: &crate::Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = EntityId::now();
    let time = TimeRange { start: 1, end: 1 };
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"second owner")?;
    vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
}

#[test]
fn a_batch_carries_one_decision_whichever_owner_comes_first() -> Result<()> {
    let spent = |error: crate::Error| error.kind() == crate::ErrorKind::ConsentApproveOnceSpent;

    // Approved, then declined or approved again by either owner: refused,
    // and the approval stands.
    let (_dir, vault, owner, batch) = fixture()?;
    let other = second_owner(&vault)?;
    let approved = vault.approve_imported_claim_batch(&owner, &batch)?;
    for decider in [&owner, &other] {
        assert!(spent(
            vault
                .decline_imported_claim_batch(decider, &batch)
                .unwrap_err()
        ));
    }
    assert!(spent(
        vault
            .approve_imported_claim_batch(&other, &batch)
            .unwrap_err()
    ));
    for id in &approved.claim_ids {
        let claim = vault.get_claim(id)?.expect("approved imported claim");
        assert_eq!(claim.approval, ClaimApprovalStatus::Approved);
    }
    assert_eq!(decisions_for(&vault, &owner, &batch)?, ["approved"]);
    assert!(decisions_for(&vault, &other, &batch)?.is_empty());

    // Declined, then declined again, approved or admitted by either owner, in
    // one call, as approve_once then admit, or unconsented: refused, and
    // nothing is admitted.
    let (_dir, vault, owner, batch) = fixture()?;
    let other = second_owner(&vault)?;
    let denied = vault.decline_imported_claim_batch(&owner, &batch)?;
    assert_eq!(denied.gate_outcome(), "denied");
    for decider in [&owner, &other] {
        assert!(spent(
            vault
                .decline_imported_claim_batch(decider, &batch)
                .unwrap_err()
        ));
        assert!(spent(
            vault
                .approve_imported_claim_batch(decider, &batch)
                .unwrap_err()
        ));
    }
    // Nor is it admitted as Proposed, with no consent at all.
    for admitter in [&owner, &other] {
        assert!(spent(
            vault
                .admit_imported_claim_batch(admitter, &batch)
                .unwrap_err()
        ));
    }
    let digest = vault.imported_claim_batch_effect(&other, &batch)?.digest();
    vault.approve_once(&other, digest)?;
    assert!(spent(
        vault
            .admit_imported_claim_batch(&other, &batch)
            .unwrap_err()
    ));
    for entry in &batch.entries {
        assert!(vault.get_raw(&entry.claim_id)?.is_none());
    }
    assert_eq!(decisions_for(&vault, &owner, &batch)?, ["denied"]);
    Ok(())
}
