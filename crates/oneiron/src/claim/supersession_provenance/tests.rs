use super::*;
use crate::claim::ClaimLifecycleStatus;

#[test]
fn existing_companion_is_idempotent_only_for_matching_stamped_payload() -> Result<()> {
    let (_tmp, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let new = EntityId::now();
    let old = EntityId::now();
    for id in [new, old] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let mut body = ClaimBody::new(
        "pref.favorite",
        ClaimSubject::Entity(new),
        Value::from("blue"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let envelope = WriteEnvelope::new(
        WriteActor::new(new, crate::edge::EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Proposed,
    );
    let write = |txn: &mut heed::RwTxn<'_>| {
        write_companion(&vault, txn, &new, &old, &body, &body, &envelope, 2)
    };
    vault.with_write_txn(write)?;
    let companion = companion_id(&new, &old, PREDICATE)?;
    let original = vault.get_claim(&companion)?.expect("companion");
    vault.with_write_txn(write)?;
    assert_eq!(vault.get_claim(&companion)?, Some(original.clone()));
    let mut collision = original;
    let Value::Map(ref mut values) = collision.value else {
        unreachable!()
    };
    values
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("old"))
        .unwrap()
        .1 = Value::Binary(EntityId::now().as_bytes().to_vec());
    // This is structurally self-consistent provenance but not the expected pair.
    validate(&collision)?;
    vault
        .batch()
        .put_replicated(
            &companion,
            crate::registry::ENTITY_TYPE_CLAIM,
            crate::TimeRange { start: 2, end: 2 },
            2,
            &crate::claim::encode_claim_body(&collision)?,
        )
        .commit()?;
    assert!(matches!(
        vault.with_write_txn(write),
        Err(Error::InvalidClaimBody(_))
    ));
    assert_eq!(vault.get_claim(&companion)?, Some(collision));
    Ok(())
}
