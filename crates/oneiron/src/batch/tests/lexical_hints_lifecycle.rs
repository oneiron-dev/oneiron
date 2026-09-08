//! Lexical-hint side-record write/read/replace/delete lifecycle.

use super::*;

fn seed_claim_of_edge(vault: &Vault, claim: &EntityId, subject: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    apply_edge(
        &vault.store,
        &mut wtxn,
        *claim,
        EdgeKind::ClaimOf,
        *subject,
        1.0,
        Vad::NEUTRAL,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn lh_prefixed_id(fill: u8) -> Result<EntityId> {
    let mut raw = [fill; ENTITY_ID_LEN];
    raw[0] = b'L';
    raw[1] = b'H';
    EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid LH fixture id"))
}

#[test]
fn claim_candidate_lexical_hints_write_read_and_search_source_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &[
                "green tea preferences",
                "  matcha order history  ",
                "green tea preferences",
            ],
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);
    let mut stored_queries = Vec::new();
    for hint_claim in &hint_claims {
        assert!(
            hint_claim
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
        );
        assert!(
            !has_pending_embedding_marker(&vault, hint_claim)?,
            "lexical hint side claims must not be queued for embeddings"
        );
        let stored = vault
            .get_claim(hint_claim)?
            .expect("lexical hint claim stored");
        assert_eq!(stored.predicate, crate::claim::PREDICATE_LEXICAL_QUERY_HINT);
        assert!(stored.stale, "lexical hint side claims are derived data");
        assert_eq!(stored.source, Some(ClaimSource::UserStated));
        assert!(stored.evidence.is_some());
        let value = crate::claim::decode_lexical_query_hint_value(&stored.value)?;
        assert_eq!(value.target, claim);
        stored_queries.push(value.query);
    }
    stored_queries.sort();
    assert_eq!(
        stored_queries,
        vec!["green tea preferences", "matcha order history"]
    );

    let hits = vault.search_text("matcha order", 10)?;
    assert_eq!(hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint docs must collapse to the source claim"
    );
    let ppr_hits = vault.query().search_ppr(&[claim], 2).run()?;
    assert!(
        !ppr_hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint side claims must not surface through PPR"
    );
    let rtxn = vault.store.env.read_txn()?;
    for hint in &hint_claims {
        assert!(
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "lexical hint side claims must not receive public short ids"
        );
    }
    Ok(())
}

#[test]
fn lexical_hint_claim_of_edges_do_not_dilute_ppr_claim_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["ppr synthetic one", "ppr synthetic two"],
        )
        .commit()?;
    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);

    let real_neighbor = EntityId::now();
    let real_neighbor_body = ClaimBody::new(
        "profile.related",
        ClaimSubject::Entity(claim),
        Value::from("real ppr neighbor"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &real_neighbor, real_neighbor_body)?;
    seed_claim_of_edge(&vault, &real_neighbor, &claim)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = crate::ppr::ppr_compute(&vault.store, &rtxn, &[claim], 1, 0.15)?;
    let score_for = |id: EntityId| -> f32 {
        scores
            .iter()
            .find(|scored| scored.id == id)
            .map_or(0.0, |scored| scored.score)
    };
    assert!(
        score_for(real_neighbor) > 0.84,
        "real ClaimOf neighbor should receive the full inbound ClaimOf mass"
    );
    for hint in hint_claims {
        assert_eq!(
            score_for(hint),
            0.0,
            "lexical hint ClaimOf rows must not receive PPR mass"
        );
    }
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_replace_and_delete_stale_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["retireduniquealpha", "liveuniquebeta"])?;
    let obsolete_hint = lexical_query_hint_claim_id(&claim, "retireduniquealpha")?;
    let live_hint = lexical_query_hint_claim_id(&claim, "liveuniquebeta")?;
    assert!(vault.get_claim(&obsolete_hint)?.is_some());
    assert!(vault.get_claim(&live_hint)?.is_some());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&obsolete_hint)?.is_none());
    assert!(vault.get_claim(&live_hint)?.is_some());
    assert_eq!(vault.claims_for_subject(&claim)?, vec![live_hint]);
    assert!(vault.search_text("retireduniquealpha", 10)?.is_empty());
    assert_eq!(
        vault
            .search_text("liveuniquebeta", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let plain_candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(
            &claim,
            plain_candidate,
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&live_hint)?.is_some());

    vault.batch().delete(&claim).commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());
    Ok(())
}

#[test]
fn local_raw_claim_put_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["rawputretiredunique"],
        )
        .commit()?;

    let hint = lexical_query_hint_claim_id(&claim, "rawputretiredunique")?;
    assert!(vault.get_claim(&hint)?.is_some());
    assert_eq!(
        vault
            .search_text("rawputretiredunique", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("gyokuro"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &replacement, test_time_range(12, 12), 13)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("rawputretiredunique", 10)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn soft_delete_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["soft delete lexical hint"],
        )
        .commit()?;
    let hint = lexical_query_hint_claim_id(&claim, "soft delete lexical hint")?;

    vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("soft delete lexical", 10)?.is_empty());
    Ok(())
}

#[test]
fn plain_overwrite_removes_orphan_lexical_hint_without_claim_of() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stale_query = "legacy orphan lexical hint";
    let orphan_hint = lexical_query_hint_claim_id(&claim, stale_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, stale_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", stale_query)])
        .commit()?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "fixture intentionally omits the legacy hint ClaimOf edge"
    );
    assert_eq!(
        vault
            .search_text(stale_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("hojicha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, replacement, &envelope, test_time_range(12, 12), 13)
        .commit()?;

    assert!(vault.get_claim(&orphan_hint)?.is_none());
    assert!(vault.search_text(stale_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn raw_claim_put_rejects_malformed_lexical_hint_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let hint = EntityId::now();
    let body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        Value::from("not a typed lexical hint value"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("malformed lexical hint values must reject at the write door");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn raw_lexical_hint_put_rejects_non_lh_prefixed_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let target_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &target, target_body)?;

    let mut raw = [0x44; ENTITY_ID_LEN];
    raw[ENTITY_ID_LEN - 1] &= 0x7F;
    let hint =
        EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid test id"))?;
    assert!(
        !hint
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    );
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non lh id hint"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("lexical.query_hint records must live under derived LH ids");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn legacy_cyclic_lexical_hints_delete_without_recursive_cleanup() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let hint_a = lexical_query_hint_claim_id(&EntityId::now(), "cycle a")?;
    let hint_b = lexical_query_hint_claim_id(&EntityId::now(), "cycle b")?;
    let mut body_a = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_b),
        crate::claim::encode_lexical_query_hint_value(&hint_b, "cycle a"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_a.stale = true;
    let mut body_b = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_a),
        crate::claim::encode_lexical_query_hint_value(&hint_a, "cycle b"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_b.stale = true;
    seed_raw_claim_record(&vault, &hint_a, body_a)?;
    seed_raw_claim_record(&vault, &hint_b, body_b)?;
    seed_claim_of_edge(&vault, &hint_a, &hint_b)?;
    seed_claim_of_edge(&vault, &hint_b, &hint_a)?;

    vault.batch().delete(&hint_a).commit()?;

    assert!(vault.get_claim(&hint_a)?.is_none());
    assert!(vault.get_claim(&hint_b)?.is_none());

    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "legacy self")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "legacy self"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    seed_raw_claim_record(&vault, &self_hint, self_body)?;
    seed_claim_of_edge(&vault, &self_hint, &self_hint)?;

    vault.batch().delete(&self_hint).commit()?;

    assert!(vault.get_claim(&self_hint)?.is_none());
    Ok(())
}

#[test]
fn lh_prefixed_normal_ids_are_not_treated_as_synthetic_hints() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let normal_entity = lh_prefixed_id(0x11)?;
    vault.put_entity(
        &normal_entity,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"ordinary LH-prefixed entity",
    )?;
    vault
        .batch()
        .text(&normal_entity, &[("body", "ordinary LH text")])
        .commit()?;
    assert_eq!(
        vault
            .search_text("ordinary LH text", 10)?
            .first()
            .map(|hit| hit.id),
        Some(normal_entity)
    );
    vault.put_vector(&normal_entity, &[1.0, 0.0, 0.0, 0.0])?;
    assert_eq!(
        vault.get_vector(&normal_entity)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );

    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(2, 2);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 2, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 2, b"subject")?;

    let claim = lh_prefixed_id(0x22)?;
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["normal LH source claim hint"],
        )
        .commit()?;

    assert_eq!(
        vault
            .search_text("normal LH source", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hint_ids_are_order_stable() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["spring roadmap migration", "account recovery plan"])?;
    let mut first_hint_claims = vault.claims_for_subject(&claim)?;
    first_hint_claims.sort();
    assert_eq!(first_hint_claims.len(), 2);

    write_hints(&["account recovery plan", "spring roadmap migration"])?;
    let mut reordered_hint_claims = vault.claims_for_subject(&claim)?;
    reordered_hint_claims.sort();
    assert_eq!(reordered_hint_claims, first_hint_claims);
    assert!(reordered_hint_claims.iter().all(|hint_claim| {
        hint_claim
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    }));

    let roadmap_hits = vault.search_text("spring roadmap migration", 10)?;
    assert_eq!(roadmap_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !roadmap_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );

    let recovery_hits = vault.search_text("account recovery plan", 10)?;
    assert_eq!(recovery_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !recovery_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_are_capped() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    let hints = [
        "hint zero",
        "hint one",
        "hint two",
        "hint three",
        "hint four",
        "hint five",
        "hint six",
        "hint seven",
        "hint eight",
        "hint nine",
    ];

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &hints,
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(
        hint_claims.len(),
        crate::claim::MAX_LEXICAL_QUERY_HINTS_PER_CLAIM
    );
    assert!(
        vault
            .search_text("seven", 10)?
            .iter()
            .any(|hit| hit.id == claim)
    );
    assert!(vault.search_text("nine", 10)?.is_empty());
    Ok(())
}
