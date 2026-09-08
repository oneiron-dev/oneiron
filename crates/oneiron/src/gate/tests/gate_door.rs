//! Write-door chokepoint: consent lifecycle, session bundles, batch atomicity, and edge provenance.

use super::*;

#[test]
fn policy_manifest_signature_frontier_covers_first_party_auto_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&vault, test_id(0xBE), &data)?;
    let policy = resolve(&vault)?;
    let signed_auto_frontier = policy.read_frontier_hash()?;

    assert_eq!(policy.signatures().len(), 1);
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
        PolicyApprovalCeiling::Auto
    );

    let (_revoked_tmp, revoked_vault) = temp_vault();
    let mut revoked_data = encode_first_party_eiri_default_policy_manifest();
    append_actor_ceiling(
        &mut revoked_data,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "proposed"),
    );
    put_policy_manifest_bytes(&revoked_vault, test_id(0xBF), &revoked_data)?;
    let revoked_policy = resolve(&revoked_vault)?;

    assert_eq!(revoked_policy.signatures().len(), 1);
    assert_eq!(
        revoked_policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
        PolicyApprovalCeiling::Proposed
    );
    assert_ne!(signed_auto_frontier, revoked_policy.read_frontier_hash()?);
    Ok(())
}

#[test]
fn gate_chokepoint_active_policy_source_denial_is_typed_gate_rejection() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x84), &data)?;

    assert_auto_source_gate_rejected(
        &vault,
        0x85,
        ClaimSource::ToolOutput,
        "pending",
        &["gate.pending.source_trust"],
    )
}

#[test]
fn gate_decision_ledger_survives_rejected_standalone_write() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x90), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x91);
    let body = source_trust_claim(ClaimSource::UserStated);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("pending auto write must be rejected");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before + 1,
        "a committed denial receipt must emit exactly one decision metric"
    );
    assert!(
        vault.get_raw(&id)?.is_none(),
        "rejected entity write must not stage the claim"
    );

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(decisions[0].claim_id, Some(*id.as_bytes()));
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.pending.actor_ceiling"]
    );
    Ok(())
}

#[test]
fn pending_gate_consent_survives_reopen() -> Result<()> {
    let (tmp, vault) = temp_vault();
    {
        put_policy_manifest_bytes(&vault, test_id(0x92), &encode_policy_manifest(vec![]))?;

        let id = test_id(0x93);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;
    }
    drop(vault);

    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let id = test_id(0x93);
    let pending = reopened.with_write_txn(|wtxn| {
        reopened
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.claim_id, *id.as_bytes());
    assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
    Ok(())
}

#[test]
fn retraction_closes_custom_policy_pending_without_rebinding_or_reparking() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x97), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x98);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    vault.retract_claim(&id, 4)?;

    let retracted = vault.get_claim(&id)?.expect("retracted claim remains");
    assert_eq!(retracted.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(!has_pending_gate_consent(&vault, &id)?);
    let closure = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|record| record.outcome == "retracted")
        .expect("terminal retraction receipt");
    assert_eq!(closure.claim_id, Some(*id.as_bytes()));
    assert_eq!(closure.reason_codes, vec!["gate.pending.claim_retracted"]);
    assert_eq!(closure.diff_handle, pending.diff_handle);
    assert_eq!(closure.read_frontier_hash, pending.read_frontier_hash);
    Ok(())
}

#[test]
fn pending_gate_consent_groups_interleaved_dreamer_runs_with_default_lane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xA0), &encode_policy_manifest(vec![]))?;

    let run_a = "dreamer-run-a";
    let run_b = "dreamer-run-b";
    // 0x81..0x85: [0xA1; 16]..[0xA5; 16] are write-door-reserved system-agent
    // actor ids (ONE-1444).
    let run_a_first = test_id(0x81);
    let run_b_first = test_id(0x82);
    let default_id = test_id(0x83);
    let run_a_second = test_id(0x84);
    let run_b_second = test_id(0x85);

    let pending_body = |subject_seed: u8, value: &'static str, source: ClaimSource| {
        let mut body = source_trust_claim(source);
        body.subject = ClaimSubject::Entity(test_id(subject_seed));
        body.value = Value::from(value);
        body.approval = ClaimApprovalStatus::Proposed;
        // Dreamer-authored bodies satisfy the evidence floor with their own
        // seeded subject entity; UserStated writes are not floor-checked.
        if source == ClaimSource::Generated {
            body.evidence = Some(precommit_evidence(vec![test_id(subject_seed)]));
        }
        body
    };

    let body_a_first = pending_body(0xB1, "run-a-1", ClaimSource::Generated);
    let body_b_first = pending_body(0xB2, "run-b-1", ClaimSource::Generated);
    let body_default = pending_body(0xB3, "default", ClaimSource::UserStated);
    let body_a_second = pending_body(0xB4, "run-a-2", ClaimSource::Generated);
    let body_b_second = pending_body(0xB5, "run-b-2", ClaimSource::Generated);

    for (claim_id, actor, run_id, body) in [
        (run_a_first, test_id(0xC1), run_a, &body_a_first),
        (run_b_first, test_id(0xC2), run_b, &body_b_first),
    ] {
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        std::thread::sleep(Duration::from_millis(2));
    }

    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body_default)?;
    vault
        .batch()
        .claim_candidate(&default_id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    std::thread::sleep(Duration::from_millis(2));

    for (claim_id, actor, run_id, body) in [
        (run_a_second, test_id(0xC4), run_a, &body_a_second),
        (run_b_second, test_id(0xC5), run_b, &body_b_second),
    ] {
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
            .commit()?;
        std::thread::sleep(Duration::from_millis(2));
    }

    let pending = vault.pending_gate_consents(10)?;
    assert_eq!(pending.len(), 5);
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *run_a_first.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        Some(run_a)
    );
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *run_b_first.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        Some(run_b)
    );
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *default_id.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        None
    );

    let groups = vault.pending_gate_consent_groups(10)?;
    assert_eq!(groups.len(), 3);
    let group_ids = |run_id: Option<&str>| -> Vec<[u8; ENTITY_ID_LEN]> {
        groups
            .iter()
            .find(|group| group.dreamer_run_id.as_deref() == run_id)
            .expect("group exists")
            .records
            .iter()
            .map(|record| record.claim_id)
            .collect()
    };
    assert_eq!(
        group_ids(Some(run_a)),
        vec![*run_a_first.as_bytes(), *run_a_second.as_bytes()]
    );
    assert_eq!(
        group_ids(Some(run_b)),
        vec![*run_b_first.as_bytes(), *run_b_second.as_bytes()]
    );
    assert_eq!(group_ids(None), vec![*default_id.as_bytes()]);

    let mut approved_a_first = body_a_first;
    approved_a_first.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &approved_a_first, test_id(0xC1), run_a)?;
    vault
        .batch()
        .claim_candidate(&run_a_first, candidate, &envelope, test_time(5), 5)
        .commit()?;

    assert!(!has_pending_gate_consent(&vault, &run_a_first)?);
    assert!(has_pending_gate_consent(&vault, &run_a_second)?);
    assert_eq!(
        vault
            .get_claim(&run_a_first)?
            .expect("approved claim")
            .approval,
        ClaimApprovalStatus::Approved
    );

    let groups = vault.pending_gate_consent_groups(10)?;
    let run_a_after = groups
        .iter()
        .find(|group| group.dreamer_run_id.as_deref() == Some(run_a))
        .expect("run A group remains");
    assert_eq!(run_a_after.records.len(), 1);
    assert_eq!(run_a_after.records[0].claim_id, *run_a_second.as_bytes());
    Ok(())
}

#[test]
fn approved_gate_consent_rejects_drifted_diff() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x94), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x95);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let mut drifted = proposed;
    drifted.value = Value::from("Grace");
    drifted.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &drifted)?;
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()
        .expect_err("approval must bind to original pending diff");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.claim_id, *id.as_bytes());
    Ok(())
}

#[test]
fn allowed_gate_consent_resolution_rejects_drifted_source_trust_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![signatures_entry()]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row(LOCAL_WRITE_ACTOR_CLASS, "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xD6), &data)?;

    let id = test_id(0xA7);
    let mut proposed = source_trust_claim(ClaimSource::Generated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    proposed.evidence = Some(precommit_evidence(vec![test_id(0xA8)]));
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &proposed, test_id(0xA8), "run-a")?;
    vault.put_claim_candidate_without_lexical_query_reconcile(
        &id,
        candidate,
        &envelope,
        test_time(3),
        3,
    )?;

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.reason_codes, vec!["gate.pending.source_trust"]);

    let stored = vault.get_claim(&id)?.expect("pending claim");
    let mut drifted = stored.clone();
    drifted.value = Value::from("Grace");
    drifted.approval = ClaimApprovalStatus::Approved;
    let err = vault
        .put_claim(&id, &drifted, test_time(4), 4)
        .expect_err("allow-path approval must bind to original pending diff");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));
    assert!(has_pending_gate_consent(&vault, &id)?);

    let mut approved = stored;
    approved.approval = ClaimApprovalStatus::Approved;
    vault.put_claim(&id, &approved, test_time(5), 5)?;

    assert!(!has_pending_gate_consent(&vault, &id)?);
    assert_eq!(
        vault.get_claim(&id)?.expect("approved claim").approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn approved_gate_consent_followup_succeeds_and_clears_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x96), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x97);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    assert!(has_pending_gate_consent(&vault, &id)?);

    let mut approved = proposed;
    approved.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &approved)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()?;

    assert!(!has_pending_gate_consent(&vault, &id)?);
    assert_eq!(
        vault.get_claim(&id)?.expect("approved claim").approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn session_bundle_review_merge() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xC8);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC2), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);
    let producer = test_id(0x20);

    let session_tag = "agent:alpha/session:42";
    let first = test_id(0xC3);
    let second = test_id(0xC4);
    for (id, learned_at) in [(first, 3), (second, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    let review = vault.review_session_bundle(&reviewer, &producer, session_tag)?;
    assert_eq!(review.session_tag, session_tag);
    assert_eq!(
        review
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert!(
        review
            .claims
            .iter()
            .all(|claim| claim.body.approval == ClaimApprovalStatus::Proposed)
    );

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let merged = vault.merge_session_bundle(&reviewer, &producer, session_tag)?;
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before + 2,
        "committed bundle decisions must emit metrics exactly once per member"
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| claim.body.approval == ClaimApprovalStatus::Approved)
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| claim.body.session_tag.as_deref() == Some(session_tag))
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| crate::claim::session_claim_producer(&claim.body) == Some(producer))
    );
    assert_eq!(
        vault
            .get_claim(&first)?
            .expect("first merged claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .get_claim(&second)?
            .expect("second merged claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert!(!has_pending_gate_consent(&vault, &first)?);
    assert!(!has_pending_gate_consent(&vault, &second)?);
    assert!(
        vault
            .review_session_bundle(&reviewer, &producer, session_tag)?
            .claims
            .is_empty()
    );
    Ok(())
}

#[test]
fn session_bundle_review_and_merge_reject_unauthorized_caller_with_fresh_consent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let authorized_id = test_id(0xCC);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &authorized_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC9), &policy)?;

    let session_tag = "agent:alpha/session:unauthorized";
    let id = test_id(0xCA);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    let producer = envelope.actor().entity_ref();
    let unauthorized_id = test_id(0xCB);
    vault.put_entity(
        &unauthorized_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"unrelated valid session bundle caller",
    )?;
    let unauthorized = WriteActor::new(unauthorized_id, EdgeActorClass::Human);
    vault
        .batch()
        .claim_candidate(
            &id,
            candidate,
            &envelope.with_session_tag(session_tag),
            test_time(3),
            3,
        )
        .commit()?;
    assert!(has_pending_gate_consent(&vault, &id)?);

    let err = vault
        .review_session_bundle(&unauthorized, &producer, session_tag)
        .expect_err("proposed claim bodies must not be disclosed to an unauthorized caller");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);

    let err = vault
        .merge_session_bundle(&unauthorized, &producer, session_tag)
        .expect_err("fresh consent must not elevate an unauthorized caller");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert_eq!(
        vault.get_claim(&id)?.expect("proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &id)?);
    Ok(())
}

#[test]
fn session_tagged_raw_claim_rejects_a_spoofed_producer_stamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xD6);
    let spoofed_producer = test_id(0x5D);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Proposed;
    body.session_tag = Some("agent:spoofed/session:tag".to_owned());
    body.evidence = Some(Value::Map(vec![(
        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::Binary(spoofed_producer.as_bytes().to_vec()),
    )]));
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .put_entity(&id, ENTITY_TYPE_CLAIM, test_time(3), 3, &data)
        .expect_err("raw claim writes must not self-assert a session producer");
    assert!(
        matches!(
            err,
            Error::InvalidClaimBody("raw claim put requires WriteEnvelope")
        ),
        "unexpected error: {err:?}"
    );
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[test]
fn session_bundle_excludes_same_tag_claims_from_another_producer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xD0);
    let producer_a = test_id(0xD1);
    let producer_b = test_id(0xD2);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xD3), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);

    let session_tag = "agent:shared/session:collision";
    let first = test_id(0xD4);
    let injected = test_id(0xD5);
    for (id, producer, learned_at) in [(first, producer_a, 3), (injected, producer_b, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &vault,
            &proposed,
            producer,
            EdgeActorClass::Human,
        )?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    let review = vault.review_session_bundle(&reviewer, &producer_a, session_tag)?;
    assert_eq!(
        review
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first],
        "a raw session-tag collision must not inject another actor's claim"
    );

    let merged = vault.merge_session_bundle(&reviewer, &producer_a, session_tag)?;
    assert_eq!(
        merged
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first]
    );
    assert_eq!(
        vault
            .get_claim(&first)?
            .expect("first producer claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .get_claim(&injected)?
            .expect("second producer claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "the colliding second-producer claim must not be approved"
    );
    Ok(())
}

#[test]
fn atomic_bundle_commit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xC9);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC5), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);
    let producer = test_id(0x20);

    let session_tag = "agent:alpha/session:atomic";
    let first = test_id(0xC6);
    let second = test_id(0xC7);
    for (id, learned_at) in [(first, 3), (second, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    vault.with_write_txn(|wtxn| {
        let mut pending = vault
            .store
            .pending_gate_consent_in_txn(wtxn, &second)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))?;
        pending.diff_handle = vec![0xFF];
        vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
    })?;

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let err = vault
        .merge_session_bundle(&reviewer, &producer, session_tag)
        .expect_err("a stale member must abort the whole session bundle");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == second));
    assert_eq!(
        vault.get_claim(&first)?.expect("first proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.get_claim(&second)?.expect("second proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &first)?);
    assert!(has_pending_gate_consent(&vault, &second)?);
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before,
        "rolled-back bundle decisions must not emit gate metrics"
    );
    Ok(())
}

#[test]
fn same_batch_proposed_then_approved_rejects_without_pending_consent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x98), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x99);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (proposed_candidate, proposed_envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    let mut approved = proposed;
    approved.approval = ClaimApprovalStatus::Approved;
    let (approved_candidate, approved_envelope) = claim_candidate_write_parts(&vault, &approved)?;

    let err = vault
        .batch()
        .claim_candidate(&id, proposed_candidate, &proposed_envelope, test_time(3), 3)
        .claim_candidate(&id, approved_candidate, &approved_envelope, test_time(4), 4)
        .commit()
        .expect_err("same batch approval must not consume same batch consent");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&id)?.is_none());
    assert!(!has_pending_gate_consent(&vault, &id)?);
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(
        decisions.len(),
        1,
        "rejected batch must persist only the rejecting gate decision"
    );
    assert_eq!(decisions[0].claim_id, Some(*id.as_bytes()));
    assert_eq!(decisions[0].outcome, "pending");
    Ok(())
}

#[test]
fn gate_chokepoint_batch_claim_denial_aborts_without_partial_writes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x76), &data)?;

    let prior_id = test_id(0x77);
    let claim_id = test_id(0x78);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "health.allergy".to_owned();
    body.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let err = vault
        .batch()
        .put(&prior_id, ENTITY_TYPE_PERSON, test_time(7), 7, b"prior")
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()
        .expect_err("critical local claim must stop at Gate");

    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    assert!(vault.get_raw(&prior_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_batch_policy_delete_cannot_weaken_later_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    let policy_id = test_id(0x95);
    put_policy_manifest_bytes(&vault, test_id(0x95), &data)?;

    let claim_id = test_id(0x96);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "health.allergy".to_owned();
    body.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let err = vault
        .batch()
        .delete(&policy_id)
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()
        .expect_err("policy delete must not weaken same-batch Gate checks");

    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(
        vault.get_raw(&policy_id)?.is_some(),
        "failed batch must not delete the active policy manifest"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_allows_proposed_claims_for_review_under_pending_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x97), &data)?;

    let claim_id = test_id(0x98);
    let mut body = source_trust_claim(ClaimSource::ToolOutput);
    body.predicate = "health.allergy".to_owned();
    body.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.predicate, "health.allergy");
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_uses_actor_gate_before_persistence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x79), &data)?;

    let src = test_id(0x7A);
    let tgt = test_id(0x7B);
    let actor = test_id(0x7C);
    let claim_id = test_id(0x7D);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)
        .expect_err("unlisted actor class must stop at Gate");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_retract_uses_gate_before_reserved_reput() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let src = test_id(0x90);
    let tgt = test_id(0x91);
    let actor = test_id(0x92);
    let claim_id = test_id(0x93);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)?;

    let before_body = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(before_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );

    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x94), &data)?;

    let err = vault
        .retract_edge_provenance(&claim_id, 10)
        .expect_err("retraction must stop at Gate before reserved re-put");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    let after_body = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(after_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_supersede_checks_closed_prior_before_reput() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // 0x94/0x95: [0xA4; 16]/[0xA5; 16] are write-door-reserved system-agent
    // actor ids (ONE-1444).
    let src = test_id(0x94);
    let tgt = test_id(0x95);
    let human_actor = test_id(0xD6);
    let agent_actor = test_id(0xA7);
    let prior_claim_id = test_id(0xA8);
    let new_claim_id = test_id(0xA9);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&human_actor, ENTITY_TYPE_PERSON, occurred, 8, b"human")?;
    vault.put_entity(&agent_actor, ENTITY_TYPE_PERSON, occurred, 8, b"agent")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let prior_body = EdgeProvenanceClaimBody::new(human_actor, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(
        &prior_claim_id,
        &subject,
        &prior_body,
        EdgeActorClass::Human,
        9,
    )?;

    let before_body = stored_claim_body(&vault, &prior_claim_id)?;
    assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(before_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );

    let mut policy = encode_policy_manifest(vec![]);
    replace_actor_ceilings(
        &mut policy,
        vec![
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row("agent", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0xAA), &policy)?;

    let new_body = EdgeProvenanceClaimBody::new(agent_actor, 0.8, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(
            &new_claim_id,
            &subject,
            &new_body,
            EdgeActorClass::Agent,
            10,
        )
        .expect_err("superseded prior closure must stop at Gate before reserved re-put");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&new_claim_id)?.is_none());
    let after_body = stored_claim_body(&vault, &prior_claim_id)?;
    assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(after_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );
    Ok(())
}
