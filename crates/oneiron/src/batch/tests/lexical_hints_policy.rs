//! Lexical-hint policy gates, replication deferral and BM25 indexing.

use super::*;

fn seed_stale_vector_state(vault: &Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for component in vector {
        bytes.extend_from_slice(&component.to_le_bytes());
    }
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vectors.put(&mut wtxn, id.as_bytes(), &bytes)?;
    let mut pending_rebuild = false;
    crate::hnsw::hnsw_insert_batched(
        &vault.store,
        &vault.config,
        &mut wtxn,
        id,
        vector,
        &mut pending_rebuild,
    )?;
    crate::hnsw::run_pending_legacy_rebuild(
        &vault.store,
        &vault.config,
        &mut wtxn,
        pending_rebuild,
    )?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn raw_lexical_hint_put_does_not_bypass_policy_gate() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
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

    let query = "raw policy lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(20, 20), 21, &data)
        .commit()
        .expect_err("raw lexical hint puts must still pass ordinary policy");
    assert_matches!(err, Error::GateWriteRejected { .. });
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_self_and_synthetic_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "self target")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "self target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    let self_data = crate::claim::encode_claim_body(&self_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: self_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data: self_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("self-target lexical hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&self_hint)?.is_none());

    let source = EntityId::now();
    let source_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &source, source_body)?;
    let synthetic_target = lexical_query_hint_claim_id(&source, "synthetic target")?;
    let mut synthetic_target_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(source),
        crate::claim::encode_lexical_query_hint_value(&source, "synthetic target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_target_body.stale = true;
    seed_raw_claim_record(&vault, &synthetic_target, synthetic_target_body)?;
    let outer_hint = lexical_query_hint_claim_id(&source, "outer target")?;
    let mut synthetic_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(synthetic_target),
        crate::claim::encode_lexical_query_hint_value(&synthetic_target, "outer target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_body.stale = true;
    let synthetic_data = crate::claim::encode_claim_body(&synthetic_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: outer_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(22, 22),
            learned_at: 23,
            data: synthetic_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints targeting synthetic hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&outer_hint)?.is_none());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_non_claim_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    vault.put_entity(
        &target,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"not a claim",
    )?;
    let hint = lexical_query_hint_claim_id(&target, "non claim target")?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non claim target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints must target claim records");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_indexes_query_text_and_deletes_without_claim_of() -> Result<()> {
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

    let query = "replicated rematerialized hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "regression fixture starts without a hint ClaimOf edge"
    );
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &hint)?,
        "replayed lexical hint side claims must not be queued for embeddings"
    );
    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );

    vault.batch().delete(&claim).commit()?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_defers_until_target_claim_materializes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::from_bytes([0x7A; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::Put {
                id: claim,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(10, 10),
                learned_at: 11,
                data: claim_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
        ],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn deferred_lexical_hint_materialization_fails_closed_when_text_index_untrusted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let subject = EntityId::now();
    let claim = EntityId::from_bytes([0x7B; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred trust replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;

    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    {
        let vault = Vault::open(dir.path(), embedding_test_config())?;
        vault
            .batch()
            .put(
                &subject,
                ENTITY_TYPE_PERSON,
                test_time_range(1, 1),
                1,
                b"subject",
            )
            .text(&subject, &[("body", "trusted seed text")])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            }],
            true,
            false,
            false,
        )?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .text_forward
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "missing-target replicated hint must defer text indexing"
        );
    }

    let mut cfg = embedding_test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(dir.path(), cfg)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: claim,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(30, 30),
            learned_at: 31,
            data: claim_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        false,
        false,
        false,
    )
    .expect_err("target-only replay must not index deferred hints while untrusted");
    assert_matches!(err, Error::CorruptedIndex(_));
    drop(wtxn);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, hint.as_bytes())?
            .is_none(),
        "failed deferred materialization must leave hint text unindexed"
    );
    drop(rtxn);
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "failed target replay transaction must not commit the target claim"
    );
    Ok(())
}

#[test]
fn bm25_drops_orphan_and_inactive_lexical_hint_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let missing_hint_query = "missingrowuniquealpha";
    let missing_hint = lexical_query_hint_claim_id(&EntityId::now(), missing_hint_query)?;
    vault
        .batch()
        .text(&missing_hint, &[("query_hint", missing_hint_query)])
        .commit()?;
    assert_eq!(
        vault
            .search_text(missing_hint_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(missing_hint)
    );

    let missing_claim = EntityId::now();
    let orphan_query = "orphanrowuniquebeta";
    let orphan_hint = lexical_query_hint_claim_id(&missing_claim, orphan_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(missing_claim),
        crate::claim::encode_lexical_query_hint_value(&missing_claim, orphan_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", orphan_query)])
        .commit()?;
    assert!(vault.search_text(orphan_query, 10)?.is_empty());

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

    let inactive_query = "inactiverowuniquegamma";
    let inactive_hint = lexical_query_hint_claim_id(&claim, inactive_query)?;
    let mut inactive_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, inactive_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Superseded,
    );
    inactive_body.stale = true;
    seed_raw_claim_record(&vault, &inactive_hint, inactive_body)?;
    vault
        .batch()
        .text(&inactive_hint, &[("query_hint", inactive_query)])
        .commit()?;
    assert!(vault.search_text(inactive_query, 10)?.is_empty());

    let soft_deleted_query = "softdeletedrowuniquedelta";
    let soft_deleted_hint = lexical_query_hint_claim_id(&claim, soft_deleted_query)?;
    let payload =
        crate::test_util::entity_record(ENTITY_TYPE_CLAIM, test_time_range(30, 30), 31, &[]);
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, soft_deleted_hint.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &soft_deleted_hint);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    vault
        .batch()
        .text(&soft_deleted_hint, &[("query_hint", soft_deleted_query)])
        .commit()?;
    assert!(vault.search_text(soft_deleted_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn retained_lexical_hint_reput_clears_stale_vector_and_embedding_state() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = || -> Result<()> {
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
                &["retained vector cleanup hint"],
            )
            .commit()
    };

    write_hints()?;
    let hint = lexical_query_hint_claim_id(&claim, "retained vector cleanup hint")?;
    let err = vault
        .put_vector(&hint, &[1.0, 0.0, 0.0, 0.0])
        .expect_err("synthetic lexical hint vectors must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_vector(&hint)?.is_none());
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "rejected vector writes must never expose lexical hints"
    );

    seed_stale_vector_state(&vault, &hint, &[1.0, 0.0, 0.0, 0.0])?;
    overwrite_pending_embedding_marker(&vault, &hint, b"stale lexical hint marker")?;

    assert_eq!(
        vault.get_vector(&hint)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(raw_pending_embedding_marker(&vault, &hint)?.is_some());
    assert!(
        vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "seeded stale vector must be reachable before the retained hint re-put"
    );

    write_hints()?;

    assert!(
        raw_pending_embedding_marker(&vault, &hint)?.is_none(),
        "retained lexical hint re-put must clear stale embedding marker state"
    );
    assert!(
        vault.get_vector(&hint)?.is_none(),
        "retained lexical hint re-put must delete stale vector rows"
    );
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "retained lexical hint must not remain reachable through vector search"
    );
    assert_eq!(
        vault
            .search_text("retained vector cleanup hint", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim),
        "lexical hint text must remain searchable after vector cleanup"
    );
    Ok(())
}
