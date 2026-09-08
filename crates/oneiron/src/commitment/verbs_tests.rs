//! Commitment vault-verb, stale-target, rejection and dispatch tests.

use rmpv::Value;

use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::commitment::*;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery};

use super::codec_tests::{envelope, record, schedule, seed_entities, temp_vault, time};

#[test]
fn commitment_claim_structure_requires_entity_obligor_and_valid_time() -> Result<()> {
    let obligor = crate::test_util::entity(0x71);
    let beneficiary = crate::test_util::entity(0x72);
    let record = record(obligor, beneficiary, CommitmentStrength::Decision)?;
    let mut body = crate::claim::ClaimBody::new(
        PREDICATE_COMMITMENT_RECORD,
        crate::claim::ClaimSubject::Entity(beneficiary),
        encode_commitment_value(&record)?,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(20);
    body.valid_to = Some(30);
    assert!(matches!(
        validate_commitment_claim_structure(&body),
        Err(Error::InvalidClaimBody(
            "commitment claim subject must match obligor entity_ref"
        ))
    ));

    body.subject = crate::claim::ClaimSubject::Entity(obligor);
    for lifecycle in [
        ClaimLifecycleStatus::Active,
        ClaimLifecycleStatus::Superseded,
        ClaimLifecycleStatus::Retracted,
    ] {
        body.lifecycle = lifecycle;
        body.valid_from = None;
        assert!(matches!(
            validate_commitment_claim_structure(&body),
            Err(Error::InvalidClaimBody(
                "commitment claim must carry valid-time from/to"
            ))
        ));
        body.valid_from = Some(30);
        body.valid_to = None;
        assert!(matches!(
            validate_commitment_claim_structure(&body),
            Err(Error::InvalidClaimBody(
                "commitment claim must carry valid-time from/to"
            ))
        ));
    }
    body.valid_from = Some(30);
    body.valid_to = Some(20);
    body.lifecycle = ClaimLifecycleStatus::Active;
    assert!(matches!(
        validate_commitment_claim_structure(&body),
        Err(Error::InvalidClaimBody(
            "commitment claim valid-time is inverted"
        ))
    ));
    body.lifecycle = ClaimLifecycleStatus::Superseded;
    assert!(validate_commitment_claim_structure(&body).is_ok());
    Ok(())
}

#[test]
fn put_commitment_claim_accepts_future_valid_time_and_stores_metadata() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x73);
    let beneficiary = crate::test_util::entity(0x74);
    let id = crate::test_util::entity(0x75);
    seed_entities(&vault, &[actor, beneficiary])?;
    vault.put_commitment_claim(
        &id,
        &record(actor, beneficiary, CommitmentStrength::Decision)?,
        &envelope(actor)?,
        time(1_000, 1_100),
        100,
    )?;
    let body = vault.get_claim(&id)?.expect("future commitment claim");
    assert_eq!(body.valid_from, Some(1_000));
    assert_eq!(body.valid_to, Some(1_100));
    let raw = vault.get_raw(&id)?.expect("future commitment raw");
    let header = EntityMetadataHeader::parse(&raw).expect("entity header");
    assert_eq!(header.occurred_start, 1_000);
    assert_eq!(header.occurred_end, 1_100);
    assert_eq!(header.learned_at, 100);
    Ok(())
}

#[test]
fn extractor_strength_is_used_without_explicit_override() {
    assert_eq!(
        CommitmentStrength::resolve(
            CommitmentObligorKind::ThirdParty,
            CommitmentStrength::Decision,
            None,
        ),
        CommitmentStrength::Decision
    );
}

#[test]
fn agent_obligor_is_always_commitment_strength() -> Result<()> {
    let agent = crate::test_util::entity(0x76);
    let beneficiary = crate::test_util::entity(0x77);
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Agent, agent),
        beneficiary,
        CommitmentContent::new("x", None)?,
        schedule(1),
        CommitmentStrength::StatedIntention,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:x")?,
    )?;
    assert_eq!(record.strength, CommitmentStrength::Commitment);
    let mut encoded = encode_commitment_value(&record)?;
    let Value::Map(entries) = &mut encoded else {
        unreachable!()
    };
    let (_, strength) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("strength"))
        .expect("strength field");
    *strength = Value::from("decision");
    assert!(matches!(
        decode_commitment_value(&encoded),
        Err(Error::InvalidClaimBody(
            "agent-owed commitments must have commitment strength"
        ))
    ));
    Ok(())
}

#[test]
fn terminal_status_retry_adds_no_receipt() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x78);
    let beneficiary = crate::test_util::entity(0x79);
    seed_entities(&vault, &[actor, beneficiary])?;
    let env = envelope(actor)?;
    for (id, first, retry) in [
        (
            crate::test_util::entity(0x7A),
            CommitmentStatus::Fulfilled,
            CommitmentStatus::Fulfilled,
        ),
        (
            crate::test_util::entity(0x7B),
            CommitmentStatus::Released,
            CommitmentStatus::Released,
        ),
        (
            crate::test_util::entity(0x7C),
            CommitmentStatus::Superseded,
            CommitmentStatus::Superseded,
        ),
    ] {
        vault.put_commitment_claim(
            &id,
            &record(actor, beneficiary, CommitmentStrength::Decision)?,
            &env,
            time(10, 20),
            1,
        )?;
        match first {
            CommitmentStatus::Fulfilled => vault.fulfill_commitment(&id, &env, 2)?,
            CommitmentStatus::Released => vault.release_commitment(&id, &env, 2)?,
            CommitmentStatus::Superseded => vault.supersede_commitment(&id, &env, 2)?,
            _ => unreachable!(),
        }
        let before = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        let result = match retry {
            CommitmentStatus::Fulfilled => vault.fulfill_commitment(&id, &env, 3),
            CommitmentStatus::Released => vault.release_commitment(&id, &env, 3),
            CommitmentStatus::Superseded => vault.supersede_commitment(&id, &env, 3),
            _ => unreachable!(),
        };
        assert!(matches!(
            result,
            Err(Error::InvalidClaimBody(
                "commitment status transition requires open source status"
            ))
        ));
        let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        assert_eq!(after.len(), before.len());
        assert_eq!(
            after
                .iter()
                .map(|receipt| &receipt.receipt_id)
                .collect::<Vec<_>>(),
            before
                .iter()
                .map(|receipt| &receipt.receipt_id)
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn stale_fulfill_returns_write_verb_target_stale() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x81);
    let beneficiary = crate::test_util::entity(0x82);
    let stale_id = crate::test_util::entity(0x83);
    let successor = crate::test_util::entity(0x84);
    seed_entities(&vault, &[actor, beneficiary])?;
    let env = envelope(actor)?;
    let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
    vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
    vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
    vault.supersede_claim(&successor, &stale_id, 1_050)?;
    vault
        .require_named_claim_target_active(&stale_id)
        .expect_err("stale target");
    let old_raw = vault.get_raw(&stale_id)?;
    let successor_raw = vault.get_raw(&successor)?;
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    let err = vault
        .fulfill_commitment(&stale_id, &env, 1_060)
        .expect_err("stale fulfill");
    assert!(
        matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
    );
    assert_eq!(vault.get_raw(&stale_id)?, old_raw);
    assert_eq!(vault.get_raw(&successor)?, successor_raw);
    assert_eq!(
        vault.get_claim(&stale_id)?.expect("stale").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .get_commitment_claim(&successor)?
            .expect("successor")
            .status,
        CommitmentStatus::Open
    );
    let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert_eq!(after.len(), receipts.len());
    assert_eq!(
        after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
        receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn stale_release_returns_write_verb_target_stale() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x85);
    let beneficiary = crate::test_util::entity(0x86);
    let stale_id = crate::test_util::entity(0x87);
    let successor = crate::test_util::entity(0x88);
    seed_entities(&vault, &[actor, beneficiary])?;
    let env = envelope(actor)?;
    let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
    vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
    vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
    vault.supersede_claim(&successor, &stale_id, 1_050)?;
    vault
        .require_named_claim_target_active(&stale_id)
        .expect_err("stale target");
    let old_raw = vault.get_raw(&stale_id)?;
    let successor_raw = vault.get_raw(&successor)?;
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    let err = vault
        .release_commitment(&stale_id, &env, 1_060)
        .expect_err("stale release");
    assert!(
        matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
    );
    assert_eq!(vault.get_raw(&stale_id)?, old_raw);
    assert_eq!(vault.get_raw(&successor)?, successor_raw);
    assert_eq!(
        vault.get_claim(&stale_id)?.expect("stale").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .get_commitment_claim(&successor)?
            .expect("successor")
            .status,
        CommitmentStatus::Open
    );
    let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert_eq!(after.len(), receipts.len());
    assert_eq!(
        after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
        receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn stale_supersede_returns_write_verb_target_stale() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x89);
    let beneficiary = crate::test_util::entity(0x8A);
    let stale_id = crate::test_util::entity(0x8B);
    let successor = crate::test_util::entity(0x8C);
    seed_entities(&vault, &[actor, beneficiary])?;
    let env = envelope(actor)?;
    let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
    vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
    vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
    vault.supersede_claim(&successor, &stale_id, 1_050)?;
    vault
        .require_named_claim_target_active(&stale_id)
        .expect_err("stale target");
    let old_raw = vault.get_raw(&stale_id)?;
    let successor_raw = vault.get_raw(&successor)?;
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    let err = vault
        .supersede_commitment(&stale_id, &env, 1_060)
        .expect_err("stale supersede");
    assert!(
        matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
    );
    assert_eq!(vault.get_raw(&stale_id)?, old_raw);
    assert_eq!(vault.get_raw(&successor)?, successor_raw);
    assert_eq!(
        vault.get_claim(&stale_id)?.expect("stale").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .get_commitment_claim(&successor)?
            .expect("successor")
            .status,
        CommitmentStatus::Open
    );
    let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert_eq!(after.len(), receipts.len());
    assert_eq!(
        after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
        receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn status_verbs_reject_non_commitment_claims_without_rewriting() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x91);
    let beneficiary = crate::test_util::entity(0x92);
    let id = crate::test_util::entity(0x93);
    seed_entities(&vault, &[actor, beneficiary])?;
    // `profile.note` is gate-normal under the default policy manifest (the
    // `profile.` prefix rule pins criticality/sensitivity to normal), so the
    // public `put_claim` seed is gate-allowed; the commitment-decodable
    // value under a foreign predicate is the trap the guard must reject.
    let body = crate::claim::ClaimBody::new(
        "profile.note",
        crate::claim::ClaimSubject::Entity(actor),
        encode_commitment_value(&record(actor, beneficiary, CommitmentStrength::Decision)?)?,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&id, &body, time(10, 20), 1)?;
    let raw = vault.get_raw(&id)?;
    let env = envelope(actor)?;
    for result in [
        vault.fulfill_commitment(&id, &env, 2),
        vault.release_commitment(&id, &env, 3),
        vault.supersede_commitment(&id, &env, 4),
    ] {
        assert!(matches!(
            result,
            Err(Error::InvalidClaimBody(
                "claim predicate is not commitment.record"
            ))
        ));
        assert_eq!(vault.get_raw(&id)?, raw);
    }
    Ok(())
}

#[test]
fn commitment_registry_dispatch_and_criticality_are_explicit() {
    assert_eq!(
        crate::claim::CLAIM_PREDICATE_REGISTRY
            .iter()
            .filter(|&&p| p == PREDICATE_COMMITMENT_RECORD)
            .count(),
        1
    );
    assert!(crate::claim::PREDICATE_LAYER_NAMESPACES.contains(&"commitment"));
    assert!(crate::serialize::is_critical_claim_predicate(
        PREDICATE_COMMITMENT_RECORD
    ));
    assert!(!crate::serialize::is_critical_claim_predicate(
        "core.unrelated"
    ));
}

#[test]
fn commitment_dispatch_rejects_structurally_invalid_body() -> Result<()> {
    let actor = crate::test_util::entity(0x94);
    let beneficiary = crate::test_util::entity(0x95);
    let body = crate::claim::ClaimBody::new(
        PREDICATE_COMMITMENT_RECORD,
        crate::claim::ClaimSubject::Entity(beneficiary),
        encode_commitment_value(&record(actor, beneficiary, CommitmentStrength::Decision)?)?,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let bytes = crate::claim::encode_claim_body(&body)?;
    assert!(matches!(
        crate::claim::validate_claim_body_and_decode(&bytes, false),
        Err(Error::InvalidClaimBody(
            "commitment claim must carry valid-time from/to"
        ))
    ));
    Ok(())
}
