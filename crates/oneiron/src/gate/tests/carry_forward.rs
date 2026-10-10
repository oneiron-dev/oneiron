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
    forward_envelope_as(vault, approval, crate::ClaimSource::UserStated)
}

/// The owner's forward claim, stamped `source`. The Dreamer weakens only a
/// claim that is not user truth, so a weakening fixture records an
/// observation.
pub(super) fn forward_envelope_as(
    vault: &Vault,
    approval: ClaimApprovalStatus,
    source: crate::ClaimSource,
) -> Result<(EntityId, WriteEnvelope)> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    Ok((
        owner,
        WriteEnvelope::new(
            WriteActor::new(owner, EdgeActorClass::Human),
            source,
            WriteProvenance::new(Value::from("follow-up observation"))?,
            approval,
        ),
    ))
}

/// Puts `policy` with the Dreamer allowed to curate under it: its signer is
/// provisioned, it has an auto ceiling, and it may auto-write `Generated`
/// claims. A weakening is the Dreamer's own write (ARCH-0026 Curate), gated
/// under its own ceiling and permits.
pub(super) fn let_dreamer_curate(vault: &Vault, mut policy: Vec<u8>) -> Result<()> {
    crate::test_util::provision_engine_machines(vault);
    let dreamer = vault.dreamer_authority()?.entity_ref().to_hex();
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("system", &dreamer, "auto"),
    );
    let (key, permits) = source_trust_entry(crate::ClaimSource::Generated, 3);
    rewrite_policy_manifest_entries(&mut policy, |entries| entries.push((key, permits)));
    put_policy_manifest_bytes(vault, test_id(0x70), &policy)
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
    )
    .unwrap();
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
    )
    .unwrap();
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
        vault
            .apply_claim_demotion(
                &id,
                crate::claim::ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.1
                },
                10
            )?
            .rung,
        crate::claim::ClaimDemotionRung::Decayed
    );
    // A weakening supersedes; its successor carries the lower confidence.
    let_dreamer_curate(&vault, encode_policy_manifest(vec![]))?;
    let weakening = vault.apply_claim_demotion(
        &id,
        crate::claim::ClaimDemotionAction::Weaken {
            new_confidence: 0.6,
        },
        11,
    )?;
    assert_eq!(weakening.rung, crate::claim::ClaimDemotionRung::Weakened);
    let id = weakening.claim;
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
    let_dreamer_curate(&vault, policy)?;
    let (subject, envelope) = forward_envelope_as(
        &vault,
        ClaimApprovalStatus::Auto,
        crate::ClaimSource::Observed,
    )?;
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
        vault
            .apply_claim_demotion(
                &id,
                crate::claim::ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.1
                },
                10
            )?
            .rung,
        crate::claim::ClaimDemotionRung::Decayed
    );
    // A weakening supersedes; its successor carries the lower confidence.
    let weakening = vault.apply_claim_demotion(
        &id,
        crate::claim::ClaimDemotionAction::Weaken {
            new_confidence: 0.8,
        },
        11,
    )?;
    assert_eq!(weakening.rung, crate::claim::ClaimDemotionRung::Weakened);
    let id = weakening.claim;
    let weakened = vault.get_claim(&id)?.expect("weakened claim");
    assert_eq!(weakened.confidence, 0.8);
    assert_eq!(weakened.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        vault
            .apply_claim_demotion(&id, crate::claim::ClaimDemotionAction::MarkStale, 12)?
            .rung,
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
    let_dreamer_curate(&vault, policy)?;
    let (subject, envelope) = forward_envelope_as(
        &vault,
        ClaimApprovalStatus::Auto,
        crate::ClaimSource::Observed,
    )?;
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
    let old = vault
        .apply_claim_demotion(
            &old,
            crate::claim::ClaimDemotionAction::Weaken {
                new_confidence: 0.8,
            },
            11,
        )?
        .claim;
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

fn stricter_care_fixture() -> Result<(tempfile::TempDir, Vault, EntityId, WriteEnvelope, EntityId)>
{
    stricter_care_fixture_as(crate::ClaimSource::UserStated)
}

fn stricter_care_fixture_as(
    source: crate::ClaimSource,
) -> Result<(tempfile::TempDir, Vault, EntityId, WriteEnvelope, EntityId)> {
    let (dir, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.9, "nested_narrowing", Vec::new()),
    )?;
    let (subject, envelope) = forward_envelope_as(&vault, ClaimApprovalStatus::Auto, source)?;
    let id = test_id(0x71);
    vault.put_carry_forward_claim(
        &id,
        CarryForwardClaim {
            kind: CarryForwardKind::CareCheckIn,
            subject,
            detail: "care before change".into(),
            confidence: 0.9,
        },
        &envelope,
        test_time(10),
        10,
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &confidence_manifest(0.95, "nested_narrowing", Vec::new()),
    )?;
    Ok((dir, vault, subject, envelope, id))
}

#[test]
fn stricter_policy_does_not_block_canonical_decay_weaken_stale_or_retract() -> Result<()> {
    // The Dreamer weakens only a claim that is not user truth.
    let (_dir, vault, subject, _envelope, id) =
        stricter_care_fixture_as(crate::ClaimSource::Observed)?;
    let_dreamer_curate(
        &vault,
        confidence_manifest(0.95, "nested_narrowing", Vec::new()),
    )?;
    assert_eq!(
        vault
            .apply_claim_demotion(
                &id,
                crate::claim::ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.1
                },
                20
            )?
            .rung,
        crate::claim::ClaimDemotionRung::Decayed
    );
    let edge = vault
        .edges_out(&id)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ClaimOf && edge.target == subject)
        .expect("claim_of edge");
    assert_eq!(edge.weight, 0.1);
    // A weakening supersedes; its successor carries the lower confidence.
    let weakening = vault.apply_claim_demotion(
        &id,
        crate::claim::ClaimDemotionAction::Weaken {
            new_confidence: 0.8,
        },
        21,
    )?;
    assert_eq!(weakening.rung, crate::claim::ClaimDemotionRung::Weakened);
    let id = weakening.claim;
    vault.apply_claim_demotion(&id, crate::claim::ClaimDemotionAction::MarkStale, 22)?;
    vault.retract_claim(&id, 23)?;
    let closed = vault
        .get_claim(&id)?
        .expect("closed after policy tightening");
    assert_eq!(closed.confidence, 0.8);
    assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
    assert!(closed.stale);
    assert_eq!(closed.lifecycle, crate::ClaimLifecycleStatus::Retracted);
    assert_eq!(closed.valid_to, Some(23));
    Ok(())
}

#[test]
fn stricter_policy_does_not_block_canonical_supersession() -> Result<()> {
    let (_dir, vault, subject, envelope, old) = stricter_care_fixture()?;
    let new_id = test_id(0x72);
    vault.put_carry_forward_claim(
        &new_id,
        CarryForwardClaim {
            kind: CarryForwardKind::CareCheckIn,
            subject,
            detail: "revised care".into(),
            confidence: 0.95,
        },
        &envelope,
        test_time(11),
        11,
    )?;
    vault.supersede_claim(&new_id, &old, 20)?;
    let closed = vault.get_claim(&old)?.expect("closed old head");
    assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
    assert_eq!(closed.lifecycle, crate::ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.valid_to, Some(20));
    assert_eq!(closed.confidence, 0.9);
    assert_eq!(
        vault.get_claim(&new_id)?.expect("replacement").lifecycle,
        crate::ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn sealed_transition_cannot_be_borrowed_by_fresh_changed_or_stale_claim() -> Result<()> {
    use crate::batch::{
        ApplyOpsGateMode, BatchOp, ClaimMaterialization, ENTITY_METADATA_HEADER_LEN,
    };
    let (_dir, vault, _subject, _envelope, id) = stricter_care_fixture()?;
    let mut closed = vault.get_claim(&id)?.expect("current head");
    closed.lifecycle = crate::ClaimLifecycleStatus::Retracted;
    closed.valid_to = Some(20);
    let operation = BatchOp::Put {
        id,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange { start: 10, end: 20 },
        learned_at: 10,
        data: crate::claim::encode_claim_body(&closed)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    };
    let proof = vault.with_write_txn(|txn| {
        let (_, proof) = ClaimMaterialization::verified_lifecycle(&vault.store, txn, &operation)?;
        Ok(proof)
    })?;
    let run = |op: BatchOp, proof: crate::batch::VerifiedClaimTransition| {
        vault.with_write_txn(|txn| {
            crate::batch::apply_ops_with_gate_mode(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                txn,
                vec![op],
                false,
                ApplyOpsGateMode::new(false, false).with_verified_claim_transitions(vec![proof]),
            )
        })
    };
    let fresh_id = test_id(0x79);
    let mut fresh = operation.clone();
    if let BatchOp::Put { id, .. } = &mut fresh {
        *id = fresh_id;
    }
    assert!(run(fresh, proof.clone()).is_err());
    assert!(vault.get_claim(&fresh_id)?.is_none());
    let mut changed = operation.clone();
    if let BatchOp::Put { data, .. } = &mut changed {
        let mut body = crate::claim::decode_claim_body(data, false)?;
        body.value = Value::from("substituted body");
        *data = crate::claim::encode_claim_body(&body)?;
    }
    assert!(run(changed, proof.clone()).is_err());
    let raw = vault.get_raw(&id)?.expect("unchanged current row");
    vault.apply_claim_demotion(
        &id,
        crate::claim::ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.5,
        },
        21,
    )?;
    assert!(
        run(operation, proof).is_err(),
        "stale predecessor cannot reuse proof"
    );
    assert_ne!(vault.get_raw(&id)?.expect("decayed"), raw);
    assert_eq!(
        vault.get_claim(&id)?.expect("still active").lifecycle,
        crate::ClaimLifecycleStatus::Active
    );
    // Same raw header offset remains a store invariant, not a proof axis.
    assert!(vault.get_raw(&id)?.expect("claim raw").len() > ENTITY_METADATA_HEADER_LEN);
    Ok(())
}

#[test]
fn canonical_demotion_rejects_wrong_or_increasing_edge_delta_after_tightening() -> Result<()> {
    use crate::batch::{BatchOp, ClaimMaterialization};
    let (_dir, vault, subject, _envelope, id) = stricter_care_fixture()?;
    vault.apply_claim_demotion(
        &id,
        crate::claim::ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.5,
        },
        20,
    )?;
    let raw = vault.get_raw(&id)?.expect("decayed");
    let next = vault.get_claim(&id)?.expect("decayed body");
    let put = BatchOp::Put {
        id,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange { start: 10, end: 21 },
        learned_at: 10,
        data: crate::claim::encode_claim_body(&next)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    };
    for (target, weight) in [(subject, 0.8), (test_id(0x79), 0.1)] {
        let error = vault
            .with_write_txn(|txn| {
                ClaimMaterialization::apply_demotion(
                    &vault,
                    txn,
                    vec![
                        put.clone(),
                        BatchOp::SetEdgeWeight {
                            src: id,
                            kind: EdgeKind::ClaimOf,
                            tgt: target,
                            weight,
                        },
                    ],
                )
            })
            .expect_err("invalid edge bundle cannot mint a proof");
        assert!(matches!(error, Error::InvalidClaimBody(_)), "{error:?}");
        assert_eq!(vault.get_raw(&id)?.expect("no partial put"), raw);
    }
    Ok(())
}
