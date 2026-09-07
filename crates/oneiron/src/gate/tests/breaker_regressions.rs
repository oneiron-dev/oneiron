use super::*;

#[test]
fn bundle_overflow_never_resumes_a_partially_visible_run() -> Result<()> {
    for action in [
        GateConsentBundleAction::Approve,
        GateConsentBundleAction::Decline,
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x40);
        let run = "breaker-overflow-run";
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
        let reviewed = vault.review_gate_consent_bundle(&reviewer, run)?;
        let before = breaker_row_bytes(&vault, run, &actor)?;
        let owner = consent_bundle_owner(&vault, test_id(0x60))?;
        // The visible member sorts first. Unrelated rows fill the global
        // window, then another member of this run sorts beyond it.
        vault.with_write_txn(|wtxn| {
            let first = vault
                .store
                .pending_gate_consent_in_txn(wtxn, &test_id(0x31))?
                .expect("pending triggering write");
            for index in 0..10_000_u32 {
                let mut record = first.clone();
                let mut id = [0xD0; 16];
                id[12..].copy_from_slice(&index.to_be_bytes());
                record.claim_id = id;
                record.decision_id = crate::store::GateDecisionId::now();
                record.created_at = first.created_at + 1 + u64::from(index);
                record.dreamer_run_id = Some(if index == 9_999 {
                    run.to_owned()
                } else {
                    "unrelated-run".to_owned()
                });
                vault.store.put_pending_gate_consent_in_txn(wtxn, &record)?;
            }
            Ok(())
        })?;
        assert!(matches!(
            vault.review_gate_consent_bundle(&reviewer, run),
            Err(Error::InvalidClaimBody(
                "gate consent bundle scan limit exceeded"
            ))
        ));
        assert!(matches!(
            vault.resolve_gate_consent_bundle(&owner, reviewed.bundle_id, run, action, 9),
            Err(Error::InvalidClaimBody(
                "gate consent bundle scan limit exceeded"
            ))
        ));
        assert_eq!(breaker_row_bytes(&vault, run, &actor)?, before);
        assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
        assert_eq!(vault.store.pending_gate_consents(10_002)?.len(), 10_001);
        assert_eq!(
            stored_claim_body(&vault, &test_id(0x31))?.approval,
            ClaimApprovalStatus::Proposed
        );
        assert!(consent_bundle_receipts(&vault)?.is_empty());
    }
    Ok(())
}

#[test]
fn repeated_candidates_keep_their_own_staged_verdict_and_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-repeated-candidates";
    let claim = test_id(0x30);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor], Some((1, 600))),
    )?;
    let mut first = public_stamped(source_trust_claim(ClaimSource::Generated));
    first.subject = ClaimSubject::Entity(test_id(0x50));
    first.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let mut second = first.clone();
    second.value = Value::from("second body");
    second.predicate = "health.status".to_owned();
    second.approval = ClaimApprovalStatus::Proposed;
    let (first_candidate, first_envelope) =
        dreamer_claim_candidate_write_parts(&vault, &first, actor, run)?;
    let (second_candidate, second_envelope) =
        dreamer_claim_candidate_write_parts(&vault, &second, actor, run)?;
    vault
        .batch()
        .claim_candidate(&claim, first_candidate, &first_envelope, test_time(3), 3)
        .claim_candidate(&claim, second_candidate, &second_envelope, test_time(4), 4)
        .commit()?;
    let body = stored_claim_body(&vault, &claim)?;
    assert_eq!(body.value, second.value);
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    let decisions = claim_gate_decisions(&vault, &claim)?;
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions.iter().filter(|r| r.outcome == "allow").count(), 1);
    let decision = decisions
        .iter()
        .find(|r| r.outcome == "pending")
        .expect("second pending");
    let rtxn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&rtxn, &claim)?
        .expect("pending");
    let (diff, frontier) = crate::gate::claim_consent_binding_parts(&vault.store, &rtxn, &body)?;
    assert_eq!(pending.decision_id, decision.decision_id);
    assert_eq!(pending.diff_handle, diff);
    assert_eq!(pending.read_frontier_hash, frontier);
    drop(rtxn);
    assert_eq!(
        breaker_row(&vault, run, &actor)?
            .expect("row")
            .event_timestamps()
            .len(),
        2
    );
    assert_eq!(breaker_trip_receipts(&vault)?.len(), 1);
    Ok(())
}

#[test]
fn repeated_raw_put_does_not_borrow_later_candidate_demotion() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let run = "breaker-raw-then-candidate";
    let claim = test_id(0x31);
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
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.subject = ClaimSubject::Entity(test_id(0x51));
    body.evidence = Some(precommit_evidence(vec![test_id(0x51)]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(&vault, &body, actor, run)?;
    let mut raw = body.clone();
    raw.source = None;
    raw.evidence = None;
    raw.approval = ClaimApprovalStatus::Proposed;
    raw.value = Value::from("earlier source-less body");
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &crate::claim::encode_claim_body(&raw)?,
        )
        .claim_candidate(&claim, candidate, &envelope, test_time(5), 5)
        .commit()?;
    let stored = stored_claim_body(&vault, &claim)?;
    assert_eq!(stored.value, body.value);
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    let rtxn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&rtxn, &claim)?
        .expect("candidate pending");
    let (diff, _) = crate::gate::claim_consent_binding_parts(&vault.store, &rtxn, &stored)?;
    assert_eq!(pending.diff_handle, diff);
    assert_eq!(pending.dreamer_run_id.as_deref(), Some(run));
    Ok(())
}

#[test]
fn production_run_tree_read_projects_pause_and_owner_resume() -> Result<()> {
    for action in [
        GateConsentBundleAction::Approve,
        GateConsentBundleAction::Decline,
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = test_id(0x40);
        let run = "breaker-read-projection";
        let runner = crate::dreamer_runner::DreamerRunnerStore::new(&vault);
        runner.enqueue(crate::dreamer_runner::EnqueueDreamerAttempt {
            attempt_type: "orchestrator".to_owned(),
            input: Value::from("projection fixture"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(run.to_owned()),
            now: 1,
        })?;
        let adapter = crate::run_tree::RunTreeAdapter::new(&vault);
        let before = adapter.read_run(run)?;
        assert!(!before.roots[0].gate_breaker_paused);
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
        let mut paused = adapter.read_run(run)?;
        assert!(paused.roots[0].gate_breaker_paused);
        assert_eq!(
            serde_json::to_string(&paused)
                .expect("serialize")
                .matches("\"gate_breaker_paused\":true")
                .count(),
            1
        );
        paused.set_gate_breaker_paused_marker(false);
        assert_eq!(
            paused, before,
            "breaker projection changes no attempt lifecycle data"
        );
        let reviewer = WriteActor::new(actor, EdgeActorClass::Agent);
        let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
        let owner = consent_bundle_owner(&vault, test_id(0x60))?;
        vault.resolve_gate_consent_bundle(&owner, bundle.bundle_id, run, action, 9)?;
        assert_eq!(adapter.read_run(run)?, before);
    }
    Ok(())
}
