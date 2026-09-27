//! ONE-2032: four forward kinds round-trip the shared claim Gate.
use super::*;
use crate::Vault;
use crate::write_envelope::carry_forward::{
    CARE_CONFIDENCE_FLOOR, CarryForwardClaim, CarryForwardKind, FORWARD_CONFIDENCE_FLOOR,
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
    for approval in [ClaimApprovalStatus::Approved, ClaimApprovalStatus::Rejected] {
        let terminal = WriteEnvelope::new(
            envelope.actor(),
            envelope.source(),
            envelope.provenance().clone(),
            approval,
        );
        let err = vault
            .put_carry_forward_claim(
                &test_id(if approval == ClaimApprovalStatus::Approved {
                    0x7d
                } else {
                    0x7e
                }),
                CarryForwardClaim {
                    kind: CarryForwardKind::CareCheckIn,
                    subject,
                    detail: "check in".into(),
                    confidence: FORWARD_CONFIDENCE_FLOOR,
                },
                &terminal,
                test_time(10),
                10,
            )
            .expect_err("typed creation is not an owner consent door");
        assert!(matches!(err, Error::InvalidClaimBody(_)), "{err:?}");
    }
    for approval in [ClaimApprovalStatus::Approved, ClaimApprovalStatus::Rejected] {
        let birth = test_id(if approval == ClaimApprovalStatus::Approved {
            0x7b
        } else {
            0x7c
        });
        let mut forged = raw.clone();
        forged.approval = approval;
        if approval == ClaimApprovalStatus::Rejected {
            forged.lifecycle = crate::ClaimLifecycleStatus::Retracted;
        }
        let err = vault
            .put_claim(&birth, &forged, test_time(10), 10)
            .expect_err("raw terminal approval without a prior proposal must fail");
        assert!(matches!(err, Error::InvalidClaimBody(_)), "{err:?}");
        assert!(vault.get_claim(&birth)?.is_none());
    }
    Ok(())
}

/// Park a real Dreamer proposal with a run binding and resolvable evidence.
fn park_forward_care(vault: &Vault, id: EntityId, subject: EntityId, run: &str) -> Result<()> {
    let mut body = ClaimBody::new(
        CarryForwardKind::CareCheckIn.predicate(),
        ClaimSubject::Entity(subject),
        Value::from("check in after the visit"),
        FORWARD_CONFIDENCE_FLOOR,
        ClaimApprovalStatus::Proposed,
        crate::ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(precommit_evidence(vec![subject]));
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(vault, &body, test_id(0x40), run)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()
}

#[test]
fn owner_accepts_low_confidence_care_without_rewriting_confidence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "forward-care-approve";
    let id = test_id(0x30);
    park_forward_care(&vault, id, test_id(0x50), run)?;
    assert_eq!(
        vault.get_claim(&id)?.expect("proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Approve,
        9,
    )?;
    let approved = vault.get_claim(&id)?.expect("owner-approved care");
    assert_eq!(approved.approval, ClaimApprovalStatus::Approved);
    assert_eq!(approved.confidence, FORWARD_CONFIDENCE_FLOOR);
    assert!(!has_pending_gate_consent(&vault, &id)?);
    // Owner-approved low-confidence claims must also remain curatable.
    assert_eq!(
        vault.apply_claim_demotion(
            &id,
            crate::claim::ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.1
            },
            10
        )?,
        crate::claim::ClaimDemotionRung::Decayed
    );
    assert_eq!(
        vault.apply_claim_demotion(
            &id,
            crate::claim::ClaimDemotionAction::Weaken {
                new_confidence: 0.6
            },
            11
        )?,
        crate::claim::ClaimDemotionRung::Weakened
    );
    let weakened = vault.get_claim(&id)?.expect("approved and weakened care");
    assert_eq!(weakened.approval, ClaimApprovalStatus::Approved);
    assert_eq!(weakened.confidence, 0.6);
    Ok(())
}

#[test]
fn owner_declines_low_confidence_care_bundle_without_touching_other_run() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x70), &encode_policy_manifest(vec![]))?;
    let run = "forward-care-decline";
    let first = test_id(0x30);
    let second = test_id(0x31);
    let sibling = test_id(0x32);
    park_forward_care(&vault, first, test_id(0x50), run)?;
    park_forward_care(&vault, second, test_id(0x51), run)?;
    park_forward_care(&vault, sibling, test_id(0x52), "another-run")?;
    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    let receipt = vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Decline,
        9,
    )?;
    assert_eq!(receipt.member_claim_ids, vec![first, second]);
    for id in [first, second] {
        let closed = vault.get_claim(&id)?.expect("declined care");
        assert_eq!(closed.approval, ClaimApprovalStatus::Rejected);
        assert_eq!(closed.lifecycle, crate::ClaimLifecycleStatus::Retracted);
        assert_eq!(closed.confidence, FORWARD_CONFIDENCE_FLOOR);
        assert!(!has_pending_gate_consent(&vault, &id)?);
    }
    assert_eq!(
        vault
            .get_claim(&sibling)?
            .expect("unaffected sibling")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &sibling)?);
    Ok(())
}

#[test]
fn admitted_auto_care_can_decay_and_weaken_below_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x70), &policy)?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    let id = test_id(0x30);
    vault.put_carry_forward_claim(
        &id,
        CarryForwardClaim {
            kind: CarryForwardKind::CareCheckIn,
            subject,
            detail: "follow up after the visit".into(),
            confidence: CARE_CONFIDENCE_FLOOR,
        },
        &envelope,
        test_time(3),
        3,
    )?;
    assert_eq!(
        vault.get_claim(&id)?.expect("admitted").approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(
        vault.apply_claim_demotion(
            &id,
            crate::claim::ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.1
            },
            10
        )?,
        crate::claim::ClaimDemotionRung::Decayed
    );
    assert_eq!(
        vault.apply_claim_demotion(
            &id,
            crate::claim::ClaimDemotionAction::Weaken {
                new_confidence: 0.8
            },
            11
        )?,
        crate::claim::ClaimDemotionRung::Weakened
    );
    let weakened = vault.get_claim(&id)?.expect("weakened claim");
    assert_eq!(weakened.confidence, 0.8);
    assert_eq!(weakened.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        vault.apply_claim_demotion(&id, crate::claim::ClaimDemotionAction::MarkStale, 12)?,
        crate::claim::ClaimDemotionRung::Stale
    );
    assert!(vault.get_claim(&id)?.expect("stale claim").stale);
    Ok(())
}
