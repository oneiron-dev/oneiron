//! Pending-embedding markers, vector fill and vector row codec.

use super::*;

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
    struct IdleFill {
        claim: EntityId,
        body: Vec<u8>,
    }
    impl crate::memory::IndexedRevisionEmbedder for IdleFill {
        fn embed_revision(&self, input: &crate::memory::IndexedRevisionInput) -> Result<Vec<f32>> {
            assert_eq!(input.entity, self.claim);
            assert_eq!(input.body, self.body);
            Ok(vec![0.0, 1.0, 0.0, 0.0])
        }
    }

    let (_dir, vault) = open_test_vault();
    // Open seeds bootstrap skills whose revisions wait for idle publication;
    // publish them first so the idle pass below embeds only this claim.
    vault.set_indexed_idle_delay_ms(0)?;
    vault.refresh_staged_indexed_at_idle(u64::MAX)?;
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
    assert!(has_pending_embedding_marker(&vault, &claim)?);
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    let idle = IdleFill {
        claim,
        body: vault.get(&claim)?.unwrap(),
    };
    let report = vault.refresh_indexed_at_idle(u64::MAX, &idle)?;
    assert_eq!(report.refreshed.len(), 1);
    assert!(!has_pending_embedding_marker(&vault, &claim)?);
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([0.0, 1.0, 0.0, 0.0].as_slice())
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
        None,
        "a bare vector cannot be labelled as the indexed revision after an edit"
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
