//! Secret scan, policy consent and claim write-envelope gates.

use super::*;

fn first_party_eiri_connector_actor_id() -> Result<EntityId> {
    EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .map_err(|_| Error::InvariantViolation("invalid first-party Eiri actor fixture id"))
}

fn first_party_eiri_connector_actor_ref() -> String {
    crate::gate::first_party_eiri_connector_actor_ref()
}

const GITHUB_PAT_SECRET_FIXTURE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

#[test]
fn secret_scan_rejects_known_secret_fixture_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(10, 10);

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .commit()
        .expect_err("known secret fixture must reject before any batch write");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

#[test]
fn secret_scan_allows_non_secret_write_unchanged() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let occurred = test_time_range(20, 20);
    let data = b"ordinary memory body";

    vault
        .batch()
        .put(&id, ENTITY_TYPE_PERSON, occurred, 20, data)
        .text(&id, &[("body", "ordinary memory body")])
        .commit()?;

    assert_eq!(vault.get(&id)?.as_deref(), Some(&data[..]));
    assert_eq!(vault.search_text("ordinary", 10)?.len(), 1);
    Ok(())
}

#[test]
fn secret_scan_rejects_phonetic_payload_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let phonetic_id = EntityId::now();
    let occurred = test_time_range(25, 25);
    let secret_code =
        std::str::from_utf8(GITHUB_PAT_SECRET_FIXTURE).expect("secret fixture is UTF-8");

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            25,
            b"ordinary memory",
        )
        .phonetic(&phonetic_id, &[secret_code])
        .commit()
        .expect_err("known secret fixture in phonetic payload must reject before batch write");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    assert!(vault.get(&safe_id)?.is_none());

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .phonetic_index
            .get(&rtxn, secret_code.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .phonetic_forward
            .get(&rtxn, phonetic_id.as_bytes())?
            .is_none()
    );
    Ok(())
}

#[test]
fn txn_batch_secret_scan_rejects_before_staging_writes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(30, 30);
    let mut wtxn = vault.store.env.write_txn()?;

    let err = vault
        .batch_in()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .apply(&mut wtxn)
        .expect_err("txn batch secret fixture must reject before staging writes");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    wtxn.commit()?;

    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

fn evidence_entry<'a>(evidence: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = evidence else {
        panic!("expected write envelope evidence map, got {evidence:?}");
    };
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| {
            (entry_key.as_str() == Some(key)).then_some(entry_value)
        })
        .unwrap_or_else(|| panic!("missing evidence key {key:?} in {evidence:?}"))
}

/// Deliberate gate consequence of the ONE-1645 provenance floor: unstamped
/// ToolOutput queues for consent under the default manifest.
///
/// `default_policy_manifest()` ships ToolOutput `max_auto_sensitivity: 0`.
/// Before the floor, an unstamped claim read band 0 and slipped under that
/// ceiling — the unstamped = public = auto-write fail-open ONE-1645 exists to
/// close. Post-floor the same claim reads band 2, exceeds the ceiling, and the
/// write is rejected `pending` with `gate.pending.source_trust`.
///
/// The manifest ceiling is NOT raised to restore the old outcome: that would
/// re-open the hole. The actor-ceiling grant this fixture also pins is still
/// live and still `Auto` — the second arm proves it by stamping `public` and
/// reaching auto through the very same default manifest.
#[test]
fn fresh_default_policy_manifest_queues_unstamped_tool_output_for_consent() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    let first_party_eiri_actor = first_party_eiri_connector_actor_id()?;
    let first_party_eiri_actor_ref = first_party_eiri_connector_actor_ref();
    let policy = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_actor_ref)),
        crate::gate::PolicyApprovalCeiling::Auto
    );
    assert_eq!(policy.signatures().len(), 1);
    let signed_auto_frontier = policy.read_frontier_hash()?;

    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(
        &first_party_eiri_actor,
        ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"first-party Eiri connector",
    )?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(first_party_eiri_actor, EdgeActorClass::Agent),
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
        .expect_err("unstamped ToolOutput must queue for consent, not auto-write");
    match &err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(*outcome, "pending");
            assert_eq!(reason_codes.as_slice(), ["gate.pending.source_trust"]);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "a consent-queued write must not land"
    );

    // Same actor, same default manifest, same source — only an explicit
    // `public` stamp differs. The actor-ceiling grant is intact; it was the
    // sensitivity ceiling, not the ceiling for this actor, that queued the
    // first write.
    let stamped_claim = EntityId::now();
    let stamped_candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    )
    .with_scope(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));

    vault
        .batch()
        .claim_candidate(
            &stamped_claim,
            stamped_candidate,
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;

    let stored = vault
        .get_claim(&stamped_claim)?
        .expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

    let decisions = vault.store.gate_decisions(10)?;
    let claim_decisions: Vec<_> = decisions
        .iter()
        .filter(|decision| decision.claim_id == Some(*stamped_claim.as_bytes()))
        .collect();
    assert_eq!(
        claim_decisions.len(),
        1,
        "successful claim write must persist exactly one gate decision"
    );
    let decision = claim_decisions[0];
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_eiri_actor_ref.as_str())
    );

    let policy_after_write = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        signed_auto_frontier,
        policy_after_write.read_frontier_hash()?
    );
    Ok(())
}

#[test]
fn write_envelope_validation_rejects_missing_required_axes() -> Result<()> {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let provenance = WriteProvenance::new(Value::from("fixture"))?;

    let err = WriteEnvelope::try_new(
        None,
        Some(ClaimSource::UserStated),
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("actor is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing actor")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        None,
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("source is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing source")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        None,
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("provenance is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        Some(provenance),
        None,
    )
    .expect_err("approval is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing approval")
    ));

    let err = WriteProvenance::new(Value::Nil).expect_err("nil provenance must reject");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));
    Ok(())
}

#[test]
fn claim_candidate_phase_two_validation_failure_leaves_no_orphan_gate_decision() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::now();
    let missing_actor = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(missing_actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    );

    let metric_emissions_before = crate::gate::gate_metric_emission_count_for_test();
    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(1, 1), 2)
        .commit()
        .expect_err("missing actor entity must reject");
    assert!(matches!(err, Error::EntityNotFound));
    assert_eq!(
        crate::gate::gate_metric_emission_count_for_test(),
        metric_emissions_before,
        "a rolled-back gate receipt must not emit committed-decision metrics"
    );
    assert!(vault.get_claim(&claim)?.is_none());
    assert_eq!(
        vault.store.gate_decisions(10)?.len(),
        0,
        "phase-2 validation failure must roll back the gate decision with the claim"
    );
    Ok(())
}

#[test]
fn claim_candidate_write_stamps_approved_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let provenance = Value::Map(vec![(
        Value::from("source_record_id"),
        Value::from("fixture-approved-1"),
    )]);
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(provenance.clone())?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    )
    .with_salience(0.4);

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
    assert_eq!(stored.source, Some(ClaimSource::UserStated));
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.salience, Some(0.4));

    let evidence = stored.evidence.as_ref().expect("envelope evidence");
    match evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
        Value::Binary(bytes) => assert_eq!(bytes.as_slice(), actor.as_bytes()),
        other => panic!("actor evidence must be binary, got {other:?}"),
    }
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).as_u64(),
        Some(EdgeActorClass::Human as u64)
    );
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
        &provenance
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn affect_trigger_batch_helper_writes_and_conflict_uses_claim_lifecycle() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let occurred = test_time_range(1, 1);
    let actor = EntityId::now();
    let person = EntityId::now();
    let trigger = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"person")?;
    vault.put_entity(
        &trigger,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let envelope = test_write_envelope(actor)?;

    let affect_claim = EntityId::now();
    let trigger_value = crate::affect::AffectTriggerValue::new(
        person,
        trigger,
        crate::affect::VadDelta::new(-0.2, 0.4, -0.3)?,
        0.75,
        2,
        9,
    )?;
    vault
        .batch()
        .affect_trigger_claim(
            &affect_claim,
            trigger_value.clone(),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;

    let stored = vault
        .get_claim(&affect_claim)?
        .expect("affect trigger claim stored");
    assert_eq!(
        crate::affect::decode_affect_trigger_claim(&stored)?,
        Some(trigger_value)
    );
    assert_eq!(stored.subject, ClaimSubject::Entity(person));
    assert_eq!(vault.claims_for_subject(&person)?, vec![affect_claim]);

    let open_conflict = EntityId::now();
    let resolved_conflict = EntityId::now();
    vault
        .batch()
        .conflict_open_claim(
            &open_conflict,
            person,
            Value::from("open conflict"),
            0.7,
            &envelope,
            test_time_range(20, 20),
            21,
        )
        .conflict_resolved_claim(
            &resolved_conflict,
            person,
            Value::from("resolved conflict"),
            0.8,
            &envelope,
            test_time_range(22, 22),
            23,
        )
        .commit()?;
    vault.supersede_claim(&resolved_conflict, &open_conflict, 30)?;

    let open_stored = vault
        .get_claim(&open_conflict)?
        .expect("open conflict preserved");
    let resolved_stored = vault
        .get_claim(&resolved_conflict)?
        .expect("resolved conflict active");
    assert_eq!(open_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(resolved_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(open_stored.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(resolved_stored.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn raw_public_batch_put_rejects_claim_without_write_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    let data = crate::claim::encode_claim_body(&body)?;

    let batch_claim = EntityId::now();
    let err = vault
        .batch()
        .put(
            &batch_claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &data,
        )
        .commit()
        .expect_err("raw batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&batch_claim)?.is_none());

    let txn_claim = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(
                    &txn_claim,
                    ENTITY_TYPE_CLAIM,
                    test_time_range(1, 1),
                    2,
                    &data,
                )
                .apply(wtxn)
        })
        .expect_err("raw transaction-batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&txn_claim)?.is_none());
    Ok(())
}

#[test]
fn raw_public_put_rejects_legacy_generated_code_revision_without_auto_permit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "code.revision",
        ClaimSubject::Entity(subject),
        Value::from("finalized"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    let data = crate::claim::encode_claim_body(&body)?;

    let claim = EntityId::now();
    let err = vault
        .put_entity(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .expect_err("generated source requires explicit auto permit");
    assert!(matches!(
        err,
        Error::SourceNotTrustedForAuto {
            claim_source: "generated"
        }
    ));
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

#[test]
fn claim_candidate_overwrite_reconciles_claim_of_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject_a = EntityId::now();
    let subject_b = EntityId::now();
    let edge_source = EntityId::now();
    let edge_target = EntityId::now();
    let occurred = test_time_range(1, 1);
    for (id, body) in [
        (actor, b"actor".as_slice()),
        (subject_a, b"subject-a".as_slice()),
        (subject_b, b"subject-b".as_slice()),
        (edge_source, b"edge-source".as_slice()),
        (edge_target, b"edge-target".as_slice()),
    ] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred, 1, body)?;
    }

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_a),
                Value::from("Alice"),
                0.9,
            ),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;
    assert_eq!(vault.claims_for_subject(&subject_a)?, vec![claim]);

    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_b),
                Value::from("Bob"),
                0.8,
            ),
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_a)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject_b)?, vec![claim]);

    let edge_subject = ClaimSubject::Edge {
        source: edge_source,
        kind: EdgeKind::Supports,
        target: edge_target,
    };
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "graph.observation",
                edge_subject,
                Value::from("supports"),
                0.7,
            ),
            &envelope,
            test_time_range(14, 14),
            15,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_b)?.is_empty());
    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.subject, edge_subject);
    assert!(
        vault
            .edges_out(&claim)?
            .iter()
            .all(|edge| edge.kind != EdgeKind::ClaimOf),
        "edge-subject overwrite must remove stale ClaimOf rows"
    );
    Ok(())
}
