//! Pending-embedding markers, vector fill and vector row codec.

use super::*;

#[test]
fn claim_candidate_commit_writes_pending_embedding_marker_before_vector_exists() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();

    commit_claim_candidate_fixture(&vault, claim)?;

    assert!(vault.get_claim(&claim)?.is_some(), "claim must be durable");
    assert!(
        vault.get_vector(&claim)?.is_none(),
        "claim commit must not fabricate a vector row"
    );
    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "claim commit must mark embedding as pending"
    );
    Ok(())
}

#[test]
fn batch_vector_rejects_non_finite_without_persisting_vectors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let good = EntityId::now();
    let bad = EntityId::now();

    let err = vault
        .batch()
        .vector(&good, &[1.0, 0.0, 0.0, 0.0])
        .vector(&bad, &[0.0, f32::NEG_INFINITY, 0.0, 0.0])
        .commit()
        .expect_err("non-finite batch vector must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_negative()
    );
    assert!(vault.get_vector(&good)?.is_none());
    assert!(vault.get_vector(&bad)?.is_none());
    Ok(())
}

#[test]
fn vector_fill_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "vector fill must clear the pending marker"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "token-proven vector fill must remove durable marker state"
    );
    Ok(())
}

#[test]
fn pending_vector_fill_rejects_non_finite_without_clearing_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    let err = vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, f32::INFINITY, 0.0, 0.0], &token)
        .commit()
        .expect_err("non-finite pending vector fill must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_positive()
    );
    assert!(vault.get_vector(&claim)?.is_none());
    assert_eq!(pending_embedding_token(&vault, &claim)?, token);
    Ok(())
}

#[test]
fn duplicate_vector_fill_keeps_pending_embedding_marker_cleared() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "duplicate fills must be idempotent"
    );
    assert_eq!(
        vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn plain_vector_fill_keeps_current_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        token,
        "un-tokened vector fills cannot prove they embedded the current claim body"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_claim_materialization_writes_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("replicated Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "replicated claim materialization must request embedding"
    );
    assert!(
        !pending_embedding_token(&vault, &claim)?.is_empty(),
        "replicated marker must carry a body token"
    );
    Ok(())
}

#[test]
fn unrelated_vector_fill_does_not_invalidate_pending_tokens() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = EntityId::now();
    let second = EntityId::now();
    commit_claim_candidate_with_value(&vault, first, "first")?;
    commit_claim_candidate_with_value(&vault, second, "second")?;
    let first_token = pending_embedding_token(&vault, &first)?;

    vault
        .batch()
        .vector_for_pending_embedding(
            &second,
            &[0.0, 1.0, 0.0, 0.0],
            &pending_embedding_token(&vault, &second)?,
        )
        .commit()?;

    assert_eq!(pending_embedding_token(&vault, &first)?, first_token);

    vault
        .batch()
        .vector_for_pending_embedding(&first, &[1.0, 0.0, 0.0, 0.0], &first_token)
        .commit()?;
    assert_eq!(
        vault.get_vector(&first)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(!has_pending_embedding_marker(&vault, &first)?);
    Ok(())
}

#[test]
fn stale_vector_fill_does_not_clear_or_overwrite_newer_claim_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &old_token)
        .commit()?;
    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &old_token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "stale fill must not overwrite the current vector row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "stale fill must leave the newer marker token pending"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &new_token)
        .commit()?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "current-token fill must clear the marker"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([0.0, 1.0, 0.0, 0.0].as_slice())
    );
    Ok(())
}

#[test]
fn plain_vector_fill_does_not_clear_stale_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );
    overwrite_pending_embedding_marker(&vault, &claim, &old_token)?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "stale marker token must not report as current pending work"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(old_token.as_slice()),
        "plain vector fills must not clear stale markers by id alone"
    );
    Ok(())
}

#[test]
fn plain_vector_fill_after_claim_overwrite_keeps_newer_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "legacy vector path still writes the row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "un-tokened vector fills must not clear a newer pending marker"
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(new_token.as_slice()),
        "the durable marker row must remain for the current claim body"
    );
    Ok(())
}

#[test]
fn same_batch_claim_then_vector_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "same-batch vector after claim materialization proves freshness"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "same-batch vector after claim must remove durable marker state"
    );
    Ok(())
}

#[test]
fn same_batch_delete_clears_pending_embedding_token_cache_before_plain_vector() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .delete(&claim)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        vault.get_claim(&claim)?.is_none(),
        "delete must remove the same-batch claim materialization"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "delete must not leave a stale same-batch token that drops later vectors"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "delete must clear durable pending marker state"
    );
    Ok(())
}

#[test]
fn same_batch_vector_then_claim_leaves_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "vector before claim materialization cannot prove it embedded the claim"
    );
    Ok(())
}

#[test]
fn soft_delete_removes_pending_embedding_state_for_claim_shell() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    assert!(has_pending_embedding_marker(&vault, &claim)?);

    let outcome = vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "soft-erased header-only claims must not remain pending"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "soft delete must remove the durable marker row, not only hide API-visible pending state"
    );
    Ok(())
}

#[test]
fn vector_row_v1_round_trip_widens_to_f32() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let id = EntityId::now();
    let input = [1.0_f32, -0.5, 0.0, 3.25];
    vault.put_vector(&id, &input)?;
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault.store.vectors.get(&rtxn, id.as_bytes())?.expect("row");
    assert_eq!(raw.first(), Some(&crate::store::VECTOR_ROW_FORMAT_F16_V1));
    assert_eq!(raw.len(), 1 + 2 * vault.config.dimensions);
    drop(rtxn);
    let expected: Vec<f32> = input
        .iter()
        .map(|v| half::f16::from_f32(*v).to_f32())
        .collect();
    assert_eq!(vault.get_vector(&id)?.expect("vector"), expected);
    let overflow = EntityId::now();
    let err = vault
        .put_vector(&overflow, &[1.0e10, 0.0, 0.0, 0.0])
        .expect_err("f16 overflow");
    assert!(matches!(err, Error::InvalidConfig(_)));
    assert!(vault.get_vector(&overflow)?.is_none());
    Ok(())
}

#[test]
fn mixed_format_vault_reads_legacy_f32_and_v1_f16() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let legacy = EntityId::now();
    let modern = EntityId::now();
    let old = [0.25_f32, -1.0, 0.0, 2.0];
    let mut old_raw = Vec::new();
    for value in old {
        old_raw.extend_from_slice(&value.to_le_bytes());
    }
    vault.put_entity(&legacy, 1, test_time_range(1, 1), 1, b"legacy")?;
    vault.put_entity(&modern, 1, test_time_range(1, 1), 1, b"modern")?;
    vault.with_write_txn(|wtxn| {
        vault.store.vectors.put(wtxn, legacy.as_bytes(), &old_raw)?;
        crate::hnsw::hnsw_insert(&vault.store, &vault.config, wtxn, &legacy, &old)
    })?;
    vault.put_vector(&modern, &[1.5, 0.5, -0.25, 0.0])?;
    assert_eq!(vault.get_vector(&legacy)?, Some(old.to_vec()));
    assert_eq!(vault.get_vector(&modern)?, Some(vec![1.5, 0.5, -0.25, 0.0]));
    let retrieved: Vec<EntityId> = vault
        .search_vector(&[0.25, -1.0, 0.0, 2.0], 2)?
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    assert!(retrieved.contains(&legacy));
    assert!(retrieved.contains(&modern));
    Ok(())
}
