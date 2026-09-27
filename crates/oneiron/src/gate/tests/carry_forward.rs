//! ONE-2032: four forward kinds round-trip the shared claim Gate.
use super::*;
use crate::Vault;
use crate::gate::carry_forward_policy::{
    DEFAULT_CARE as CARE_CONFIDENCE_FLOOR, DEFAULT_ORDINARY as FORWARD_CONFIDENCE_FLOOR,
};
use crate::write_envelope::carry_forward::{CarryForwardClaim, CarryForwardKind};

pub(super) fn forward_envelope(
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
                confidence: crate::gate::carry_forward_policy::Floors::default().for_kind(kind),
            },
            &envelope,
            test_time(10),
            10,
        )?;
        let body = vault.get_claim(&id)?.expect("claim persisted");
        assert_eq!(body.predicate, kind.predicate());
        assert_eq!(body.value.as_str(), Some(detail.as_str()));
        assert_eq!(body.subject, ClaimSubject::Entity(subject));
        assert_eq!(
            body.confidence,
            crate::gate::carry_forward_policy::Floors::default().for_kind(kind)
        );
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
pub(super) fn park_forward_care(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    run: &str,
) -> Result<()> {
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
    vault.retract_claim(&id, 13)?;
    let closed = vault.get_claim(&id)?.expect("retracted below-floor head");
    assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
    assert_eq!(closed.confidence, 0.8);
    assert_eq!(closed.lifecycle, crate::ClaimLifecycleStatus::Retracted);
    assert_eq!(closed.valid_to, Some(13));
    Ok(())
}

#[test]
fn weakened_auto_care_can_be_superseded() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x70), &policy)?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    let old = test_id(0x30);
    let replacement = test_id(0x31);
    for (id, detail) in [(old, "initial care"), (replacement, "newer care")] {
        vault.put_carry_forward_claim(
            &id,
            CarryForwardClaim {
                kind: CarryForwardKind::CareCheckIn,
                subject,
                detail: detail.into(),
                confidence: CARE_CONFIDENCE_FLOOR,
            },
            &envelope,
            test_time(3),
            3,
        )?;
    }
    vault.apply_claim_demotion(
        &old,
        crate::claim::ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        10,
    )?;
    vault.apply_claim_demotion(
        &old,
        crate::claim::ClaimDemotionAction::Weaken {
            new_confidence: 0.8,
        },
        11,
    )?;
    vault.supersede_claim(&replacement, &old, 12)?;
    let closed = vault.get_claim(&old)?.expect("superseded below-floor head");
    assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
    assert_eq!(closed.confidence, 0.8);
    assert_eq!(closed.lifecycle, crate::ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.valid_to, Some(12));
    assert_eq!(
        vault.get_claim(&replacement)?.expect("new head").lifecycle,
        crate::ClaimLifecycleStatus::Active
    );
    Ok(())
}

fn confidence_manifest(vault_care: f32, precedence: &str, holders: Vec<Value>) -> Vec<u8> {
    let mut policy = encode_policy_manifest(vec![(
        Value::from("carry_forward_confidence"),
        Value::Map(vec![
            (Value::from("precedence"), Value::from(precedence)),
            (
                Value::from("vault"),
                Value::Map(vec![
                    (Value::from("ordinary"), Value::F32(0.7)),
                    (Value::from("care"), Value::F32(vault_care)),
                ]),
            ),
            (Value::from("holders"), Value::Array(holders)),
        ]),
    )]);
    trust_human_candidate_actor(&mut policy);
    policy
}

fn holder_row(actor: EntityId, parent: Option<EntityId>, care: f32) -> Value {
    let mut fields = vec![
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (
            Value::from("floors"),
            Value::Map(vec![
                (Value::from("ordinary"), Value::F32(0.7)),
                (Value::from("care"), Value::F32(care)),
            ]),
        ),
    ];
    if let Some(parent) = parent {
        fields.push((Value::from("parent_ref"), Value::from(parent.to_hex())));
    }
    Value::Map(fields)
}

#[test]
fn manifest_floor_changes_typed_generic_and_raw_admission() -> Result<()> {
    let (_dir, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.95, "nested_narrowing", Vec::new()),
    )?;
    let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    let claim = || CarryForwardClaim {
        kind: CarryForwardKind::CareCheckIn,
        subject,
        detail: "check in".into(),
        confidence: 0.9,
    };
    let typed_id = test_id(0x71);
    vault.put_carry_forward_claim(&typed_id, claim(), &envelope, test_time(10), 10)?;
    assert_eq!(
        vault
            .get_claim(&typed_id)?
            .expect("typed proposal")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    let generic_id = test_id(0x72);
    let err = vault
        .batch()
        .claim_candidate(
            &generic_id,
            claim().into_candidate()?,
            &envelope,
            test_time(10),
            10,
        )
        .commit()
        .expect_err("manifest holds generic Auto");
    assert!(
        matches!(&err, Error::Gate(crate::error::GateError::GateWriteRejected {
        outcome: "pending", reason_codes
    }) if reason_codes.as_slice() == ["gate.pending.carry_forward_confidence"]),
        "{err:?}"
    );
    let raw_id = test_id(0x73);
    let mut body = ClaimBody::new(
        CarryForwardKind::CareCheckIn.predicate(),
        ClaimSubject::Entity(subject),
        Value::from("check in"),
        0.9,
        ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    );
    body.source = Some(crate::ClaimSource::UserStated);
    let err = vault
        .put_claim(&raw_id, &body, test_time(10), 10)
        .expect_err("manifest holds raw Auto");
    assert!(matches!(err, Error::InvalidClaimBody(_)), "{err:?}");
    let allowed = test_id(0x74);
    vault.put_carry_forward_claim(
        &allowed,
        CarryForwardClaim {
            confidence: 0.95,
            ..claim()
        },
        &envelope,
        test_time(11),
        11,
    )?;
    assert_eq!(
        vault.get_claim(&allowed)?.expect("threshold Auto").approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[test]
fn nested_narrowing_and_holder_override_cannot_loosen_vault_floor() -> Result<()> {
    for (precedence, expected_floor) in
        [("nested_narrowing", 0.98), ("holder_override_capped", 0.96)]
    {
        let (_dir, vault) = temp_vault();
        let (subject, envelope) = forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
        let parent = test_id(0x60);
        put_policy_manifest_bytes(
            &vault,
            test_id(0x70),
            &confidence_manifest(
                0.95,
                precedence,
                vec![
                    holder_row(parent, None, 0.98),
                    holder_row(envelope.actor().entity_ref(), Some(parent), 0.96),
                ],
            ),
        )?;
        let policy =
            vault.with_write_txn(|txn| crate::gate::resolve_policy_manifest(&vault.store, txn))?;
        assert_eq!(
            policy.carry_forward_floor(
                CarryForwardKind::CareCheckIn,
                Some(envelope.actor().entity_ref())
            ),
            expected_floor
        );
        // The holder cannot loosen the vault's .95 minimum, even if its own
        // row asks for less; nested mode also inherits its stricter parent.
        let id = test_id(0x71);
        vault.put_carry_forward_claim(
            &id,
            CarryForwardClaim {
                kind: CarryForwardKind::CareCheckIn,
                subject,
                detail: "check in".into(),
                confidence: 0.95,
            },
            &envelope,
            test_time(10),
            10,
        )?;
        assert_eq!(
            vault.get_claim(&id)?.expect("held holder claim").approval,
            ClaimApprovalStatus::Proposed
        );
        let allowed = test_id(0x72);
        vault.put_carry_forward_claim(
            &allowed,
            CarryForwardClaim {
                kind: CarryForwardKind::CareCheckIn,
                subject,
                detail: "check in again".into(),
                confidence: expected_floor,
            },
            &envelope,
            test_time(11),
            11,
        )?;
        assert_eq!(
            vault
                .get_claim(&allowed)?
                .expect("at holder floor")
                .approval,
            ClaimApprovalStatus::Auto
        );
    }
    Ok(())
}

#[test]
fn vault_row_can_replace_shipped_default_and_moves_policy_frontier() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let before = vault.with_write_txn(|txn| {
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        Ok((
            policy.carry_forward_floor(CarryForwardKind::CareCheckIn, None),
            policy.read_frontier_hash()?,
        ))
    })?;
    assert_eq!(before.0, CARE_CONFIDENCE_FLOOR);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.8, "nested_narrowing", Vec::new()),
    )?;
    let after = vault.with_write_txn(|txn| {
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        Ok((
            policy.carry_forward_floor(CarryForwardKind::CareCheckIn, None),
            policy.read_frontier_hash()?,
        ))
    })?;
    assert_eq!(
        after.0, 0.8,
        "shipped defaults are not an unchangeable floor"
    );
    assert_ne!(
        after.1, before.1,
        "consent binds the changed policy frontier"
    );
    Ok(())
}

#[test]
fn malformed_precedence_and_conflicting_vault_rows_fail_closed() -> Result<()> {
    let (_dir, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.95, "nested_narrowing", Vec::new()),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &confidence_manifest(0.96, "holder_override_capped", Vec::new()),
    )?;
    let policy =
        vault.with_write_txn(|txn| crate::gate::resolve_policy_manifest(&vault.store, txn))?;
    assert!(policy.is_fail_closed());
    let (_dir, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.95, "unknown", Vec::new()),
    )?;
    let policy =
        vault.with_write_txn(|txn| crate::gate::resolve_policy_manifest(&vault.store, txn))?;
    assert!(policy.is_fail_closed());
    Ok(())
}
