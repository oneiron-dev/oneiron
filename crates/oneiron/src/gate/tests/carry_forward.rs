//! ONE-2032: four forward kinds round-trip the shared claim Gate.
use super::*;
use crate::Vault;
use crate::write_envelope::carry_forward::{
    CarryForwardClaim, CarryForwardKind, FORWARD_CONFIDENCE_FLOOR,
};

fn forward_envelope(
    vault: &Vault,
    approval: ClaimApprovalStatus,
) -> Result<(EntityId, WriteEnvelope)> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    Ok((
        owner,
        WriteEnvelope::new(
            WriteActor::new(owner, EdgeActorClass::Human),
            crate::ClaimSource::UserStated,
            WriteProvenance::new(Value::from("follow-up observation"))?,
            approval,
        ),
    ))
}

#[test]
fn all_four_forward_kinds_round_trip_through_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x80), &policy)?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    for (i, kind) in [
        CarryForwardKind::EventCheckIn,
        CarryForwardKind::DeadlineCheck,
        CarryForwardKind::CareCheckIn,
        CarryForwardKind::OpenLoop,
    ]
    .into_iter()
    .enumerate()
    {
        let id = test_id(0x81 + i as u8);
        let detail = format!("follow up on item {i}");
        vault.put_carry_forward_claim(
            &id,
            CarryForwardClaim {
                kind,
                subject,
                detail: detail.clone(),
                confidence: kind.auto_floor(),
            },
            &envelope,
            test_time(10),
            10,
        )?;
        let body = vault.get_claim(&id)?.expect("claim persisted");
        assert_eq!(body.predicate, kind.predicate());
        assert_eq!(body.value.as_str(), Some(detail.as_str()));
        assert_eq!(body.subject, ClaimSubject::Entity(subject));
        assert_eq!(body.confidence, kind.auto_floor());
        assert_eq!(body.approval, ClaimApprovalStatus::Auto);
        assert_eq!(body.source, Some(crate::ClaimSource::UserStated));
        assert!(body.evidence.is_some(), "envelope stamps provenance");
    }
    Ok(())
}

#[test]
fn care_has_higher_bar_and_low_confidence_stays_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x90), &policy)?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    let care_id = test_id(0x91);
    vault.put_carry_forward_claim(
        &care_id,
        CarryForwardClaim {
            kind: CarryForwardKind::CareCheckIn,
            subject,
            detail: "check in after the appointment".into(),
            confidence: FORWARD_CONFIDENCE_FLOOR,
        },
        &envelope,
        test_time(10),
        10,
    )?;
    let care = vault.get_claim(&care_id)?.expect("care proposal persisted");
    assert_eq!(care.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(care.confidence, FORWARD_CONFIDENCE_FLOOR);
    let receipt = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|row| row.claim_id == Some(*care_id.as_bytes()))
        .expect("Gate evaluated low-confidence care");
    assert_eq!(receipt.outcome, "pending");
    assert_eq!(
        receipt.reason_codes,
        ["gate.pending.carry_forward_confidence"]
    );

    let event_id = test_id(0x92);
    vault.put_carry_forward_claim(
        &event_id,
        CarryForwardClaim {
            kind: CarryForwardKind::EventCheckIn,
            subject,
            detail: "check in after the event".into(),
            confidence: FORWARD_CONFIDENCE_FLOOR,
        },
        &envelope,
        test_time(10),
        10,
    )?;
    assert_eq!(
        vault
            .get_claim(&event_id)?
            .expect("event persisted")
            .approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[test]
fn generic_and_raw_doors_cannot_auto_commit_low_confidence_care() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x78), &policy)?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    let id = test_id(0x79);
    let candidate = CarryForwardClaim {
        kind: CarryForwardKind::CareCheckIn,
        subject,
        detail: "check in".into(),
        confidence: FORWARD_CONFIDENCE_FLOOR,
    }
    .into_candidate()?;
    let error = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(10), 10)
        .commit()
        .expect_err("generic Auto cannot bypass confidence floor");
    assert!(
        matches!(&error, Error::Gate(crate::error::GateError::GateWriteRejected {
        outcome: "pending", reason_codes
    }) if reason_codes.as_slice() == ["gate.pending.carry_forward_confidence"]),
        "{error:?}"
    );
    assert!(vault.get_claim(&id)?.is_none());

    // The raw put has no typed writer to lower approval for it. Its stored
    // shape must also refuse an Auto row whose care confidence is too low.
    let raw_id = test_id(0x7a);
    let mut raw = ClaimBody::new(
        CarryForwardKind::CareCheckIn.predicate(),
        ClaimSubject::Entity(subject),
        Value::from("check in"),
        FORWARD_CONFIDENCE_FLOOR,
        ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    );
    raw.source = Some(crate::ClaimSource::UserStated);
    let raw_error = vault
        .put_claim(&raw_id, &raw, test_time(10), 10)
        .expect_err("raw Auto cannot bypass the confidence floor");
    assert!(
        matches!(raw_error, Error::InvalidClaimBody(_)),
        "{raw_error:?}"
    );
    assert!(vault.get_claim(&raw_id)?.is_none());
    Ok(())
}
