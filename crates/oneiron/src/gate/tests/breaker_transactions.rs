use super::*;

#[test]
fn staged_breaker_outcome_materializes_once() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-staged-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    let before = breaker_row(&vault, run, &actor)?
        .expect("row")
        .event_timestamps()
        .len();

    // The demoted claim: preflight books it once, phase 2 enforces the staged
    // verdict instead of asking the gate again.
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    assert_eq!(
        breaker_row(&vault, run, &actor)?
            .expect("row")
            .event_timestamps()
            .len(),
        before + 1,
        "preflight plus phase 2 append exactly one breaker timestamp"
    );
    let decisions = claim_gate_decisions(&vault, &test_id(0x31))?;
    assert_eq!(decisions.len(), 1, "exactly one ordinary gate record");
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(decisions[0].reason_codes, vec![GATE_BREAKER_REASON_PENDING]);

    let rtxn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&rtxn, &test_id(0x31))?
        .expect("staged pending row");
    drop(rtxn);
    assert_eq!(pending.decision_id, decisions[0].decision_id);
    assert_eq!(pending.diff_handle, decisions[0].diff_handle);
    assert_eq!(pending.read_frontier_hash, decisions[0].read_frontier_hash);
    assert_eq!(pending.dreamer_run_id.as_deref(), Some(run));
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x31))?.approval,
        ClaimApprovalStatus::Proposed,
        "the materialized body is canonically re-encoded as Proposed"
    );
    Ok(())
}

#[test]
fn selective_gate_error_restores_breaker_side_effects() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-selective-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;

    let mut first = public_stamped(source_trust_claim(ClaimSource::Generated));
    first.subject = ClaimSubject::Entity(test_id(0x50));
    first.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let (first_candidate, first_envelope) =
        dreamer_claim_candidate_write_parts(&vault, &first, actor, run)?;
    let mut second = public_stamped(source_trust_claim(ClaimSource::Generated));
    second.subject = ClaimSubject::Entity(test_id(0x51));
    second.evidence = Some(precommit_evidence(vec![test_id(0x51)]));
    let (second_candidate, second_envelope) =
        dreamer_claim_candidate_write_parts(&vault, &second, actor, run)?;
    // Refused by the GATE-12 evidence floor, which is a DENIAL and therefore
    // the one receipt the preflight intentionally commits.
    let mut denied = public_stamped(source_trust_claim(ClaimSource::Generated));
    denied.subject = ClaimSubject::Entity(test_id(0x52));
    denied.evidence = None;
    let (denied_candidate, denied_envelope) =
        dreamer_claim_candidate_write_parts(&vault, &denied, actor, run)?;

    let err = vault
        .batch()
        .claim_candidate(
            &test_id(0x30),
            first_candidate,
            &first_envelope,
            test_time(3),
            3,
        )
        .claim_candidate(
            &test_id(0x31),
            second_candidate,
            &second_envelope,
            test_time(4),
            4,
        )
        .claim_candidate(
            &test_id(0x32),
            denied_candidate,
            &denied_envelope,
            test_time(5),
            5,
        )
        .commit()
        .expect_err("the evidence-free member must refuse the batch");
    assert_gate_rejected(err, "deny", &["gate.deny.dreamer_precommit.no_evidence"]);

    assert_eq!(
        breaker_run_row_count(&vault, run)?,
        0,
        "every discarded staged decision's breaker mutation is reversed"
    );
    assert!(breaker_trip_receipts(&vault)?.is_empty());
    for claim in [test_id(0x30), test_id(0x31), test_id(0x32)] {
        assert!(vault.get_raw(&claim)?.is_none());
        assert!(!has_pending_gate_consent(&vault, &claim)?);
    }
    let remaining = vault.store.gate_decisions(256)?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].outcome, "deny");
    assert_eq!(remaining[0].claim_id, Some(*test_id(0x32).as_bytes()));
    Ok(())
}

#[test]
fn resume_on_owner_approve() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let other_actor = test_id(0x41);
    let run = "breaker-resume-approve-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor, other_actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    breaker_write(
        &vault,
        test_id(0x32),
        other_actor,
        0x52,
        run,
        ClaimApprovalStatus::Auto,
        5,
    )?;
    assert_eq!(breaker_run_row_count(&vault, run)?, 2);
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);

    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    assert_eq!(bundle.members.len(), 1);
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    let trip_receipts_before = breaker_trip_receipts(&vault)?.len();
    vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Approve,
        9,
    )?;

    assert_eq!(
        breaker_run_row_count(&vault, run)?,
        0,
        "both actor rows clear inside the resolution transaction"
    );
    assert!(!vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x31))?.approval,
        ClaimApprovalStatus::Approved
    );
    assert!(!has_pending_gate_consent(&vault, &test_id(0x31))?);
    assert_eq!(consent_bundle_receipts(&vault)?.len(), 1);
    assert_eq!(
        breaker_trip_receipts(&vault)?.len(),
        trip_receipts_before,
        "owner-authenticated replay does not retrip"
    );

    // The next original write starts a fresh window.
    breaker_write(
        &vault,
        test_id(0x33),
        actor,
        0x53,
        run,
        ClaimApprovalStatus::Auto,
        10,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x33))?.approval,
        ClaimApprovalStatus::Auto
    );
    let fresh = breaker_row(&vault, run, &actor)?.expect("fresh row");
    assert_eq!(fresh.event_timestamps().len(), 1);
    assert_eq!(fresh.tripped_at(), None);
    Ok(())
}

#[test]
fn resume_on_owner_decline() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-resume-decline-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);

    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        run,
        GateConsentBundleAction::Decline,
        9,
    )?;

    assert_eq!(breaker_run_row_count(&vault, run)?, 0);
    assert!(!vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    let declined = stored_claim_body(&vault, &test_id(0x31))?;
    assert_eq!(declined.approval, ClaimApprovalStatus::Rejected);
    assert_eq!(declined.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(declined.valid_to, Some(9));
    assert!(!has_pending_gate_consent(&vault, &test_id(0x31))?);
    assert_eq!(consent_bundle_receipts(&vault)?.len(), 1);

    breaker_write(
        &vault,
        test_id(0x32),
        actor,
        0x52,
        run,
        ClaimApprovalStatus::Auto,
        10,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x32))?.approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[test]
fn failed_bundle_resolution_keeps_breaker_tripped() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-failed-resolution-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
    let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
    let tripped = breaker_row_bytes(&vault, run, &actor)?.expect("tripped row");

    // Fail AFTER the clear point: the actor ceiling is withdrawn, so the
    // member replay the approve performs is refused by the live gate. The
    // bundle digest is untouched, so validation still passes and the clear has
    // already run when the failure lands.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::Generated, 0),
            signatures_entry(),
        ]),
    )?;
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    // The digest itself still matches — it binds the STORED pending rows — so
    // validation passes and the clear has already run when the per-member
    // consent binding is recomputed under the new frontier and refuses.
    assert!(matches!(
        vault.resolve_gate_consent_bundle(
            &owner,
            bundle.bundle_id,
            run,
            GateConsentBundleAction::Approve,
            9,
        ),
        Err(Error::GateConsentStale { .. })
    ));

    assert_eq!(
        breaker_row_bytes(&vault, run, &actor)?.as_deref(),
        Some(tripped.as_slice()),
        "rollback restores every breaker row"
    );
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    assert!(has_pending_gate_consent(&vault, &test_id(0x31))?);
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x31))?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(consent_bundle_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn non_run_and_owner_writes_bypass_breaker() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-bypass-run";
    let mut data = breaker_manifest(&[actor], Some((1, 600)));
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x70), &data)?;

    // Owner-interactive writes: more than the configured threshold, and no
    // breaker key, receipt, demotion, or pause anywhere.
    for (ordinal, claim) in [test_id(0x30), test_id(0x31), test_id(0x32)]
        .into_iter()
        .enumerate()
    {
        let mut body = public_stamped(source_trust_claim(ClaimSource::UserStated));
        body.subject = ClaimSubject::Entity(test_id(0x50 + ordinal as u8));
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &envelope,
                test_time(3 + ordinal as u64),
                3 + ordinal as u64,
            )
            .commit()?;
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Auto
        );
    }
    assert_eq!(breaker_run_row_count(&vault, run)?, 0);
    assert!(breaker_trip_receipts(&vault)?.is_empty());
    assert!(!vault.gate_breaker_run_projection(run)?.gate_breaker_paused);

    // An agent write with NO Dreamer run surface: `gate-test` provenance
    // carries no run id, so the breaker never sees it.
    for (ordinal, claim) in [test_id(0x33), test_id(0x34), test_id(0x35)]
        .into_iter()
        .enumerate()
    {
        let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
        body.subject = ClaimSubject::Entity(test_id(0x55 + ordinal as u8));
        body.evidence = Some(precommit_evidence(vec![test_id(0x55 + ordinal as u8)]));
        let (candidate, envelope) =
            claim_candidate_write_parts_for_actor(&vault, &body, actor, EdgeActorClass::Agent)?;
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &envelope,
                test_time(7 + ordinal as u64),
                7 + ordinal as u64,
            )
            .commit()?;
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Auto
        );
    }
    assert_eq!(breaker_run_row_count(&vault, run)?, 0);
    assert!(breaker_trip_receipts(&vault)?.is_empty());
    Ok(())
}
