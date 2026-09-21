use super::*;
use crate::feedback::{FeedbackBundle, FeedbackPlatform, encode_feedback_bundle};
#[test]
fn duplicates_queue_once_and_digest_retains_source_entities() -> Result<()> {
    let config = crate::VaultConfig {
        dimensions: 2,
        ..crate::test_util::embedding_test_config()
    };
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let bundle = FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current())
        .with_user_note("recall omitted the recent note");
    let a = encode_feedback_bundle(&bundle).unwrap();
    let mut variant = bundle;
    variant.user_note = Some("recent note missing from recall".into());
    let b = encode_feedback_bundle(&variant).unwrap();
    let dial = FeedbackDedup::new(0.9)?;
    let first = vault.ingest_feedback(&a, &[1.0, 0.0], dial, 10)?;
    assert_eq!(vault.ingest_feedback(&a, &[1.0, 0.0], dial, 11)?, first);
    let merged = vault.ingest_feedback(&b, &[0.99, 0.01], dial, 12)?;
    assert_eq!(merged.id, first.id);
    assert_eq!(merged.bundles.len(), 2);
    assert_eq!(vault.feedback_digest()?, vec![merged.clone()]);
    for (id, expected) in merged.bundles.iter().zip([&a, &b]) {
        assert_eq!(&vault.get(id)?.unwrap(), expected);
    }
    // The host receives typed queue data. This unit test does not pretend to
    // prove the separate agent-authored policy/chat acceptance case.
    let digest = serde_json::to_value(vault.feedback_digest()?).unwrap();
    assert_eq!(digest[0]["category"], "bug");
    assert_eq!(digest[0]["bundles"].as_array().unwrap().len(), 2);
    vault.close_feedback_review(&merged.id)?;
    assert!(vault.feedback_digest()?.is_empty());
    assert!(FeedbackDedup::new(f32::NAN).is_err());
    assert!(
        vault
            .ingest_feedback(b"invalid", &[1.0, 0.0], dial, 13)
            .is_err()
    );
    Ok(())
}

#[test]
fn identical_feedback_refuses_deleted_or_replaced_evidence() -> Result<()> {
    let config = crate::VaultConfig {
        dimensions: 2,
        ..crate::test_util::embedding_test_config()
    };
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let bundle = FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current());
    let bytes = encode_feedback_bundle(&bundle).unwrap();
    let dial = FeedbackDedup::new(0.9)?;
    let item = vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 10)?;
    let id = item.bundles[0];
    vault.batch().delete(&id).commit()?;
    assert!(matches!(
        vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 11),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(vault.get(&id)?.is_none());
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_ASSET,
            TimeRange { start: 12, end: 12 },
            12,
            b"replacement",
        )
        .commit()?;
    assert!(matches!(
        vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 13),
        Err(Error::CorruptedIndex(_))
    ));
    assert_eq!(vault.get(&id)?.unwrap(), b"replacement");
    Ok(())
}

#[test]
fn queue_identity_mismatch_is_refused_by_every_reader_and_mutator() -> Result<()> {
    let config = crate::VaultConfig {
        dimensions: 2,
        ..crate::test_util::embedding_test_config()
    };
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let mut bundle = FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current());
    let bytes = encode_feedback_bundle(&bundle).unwrap();
    let dial = FeedbackDedup::new(0.9)?;
    let item = vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 10)?;
    let key = [QUEUE, item.id.as_bytes()].concat();
    let mut forged = item.clone();
    forged.id = EntityId::now();
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &encode(&forged)?)?;
        Ok(())
    })?;
    assert!(matches!(
        vault.feedback_digest(),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        vault.close_feedback_review(&item.id),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 11),
        Err(Error::CorruptedIndex(_))
    ));
    bundle.user_note = Some("distinct bundle".into());
    let variant = encode_feedback_bundle(&bundle).unwrap();
    assert!(matches!(
        vault.ingest_feedback(&variant, &[1.0, 0.0], dial, 12),
        Err(Error::CorruptedIndex(_))
    ));
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &encode(&item)?)?;
        Ok(())
    })?;
    assert_eq!(vault.feedback_digest()?, vec![item]);
    Ok(())
}

#[test]
fn feedback_digest_omits_proposals_with_dead_or_changed_bundle_evidence() -> Result<()> {
    for reason in [
        Some(crate::DeleteReason::UserHardDelete),
        Some(crate::DeleteReason::UserDelete),
        None,
    ] {
        let config = crate::VaultConfig {
            dimensions: 2,
            ..crate::test_util::embedding_test_config()
        };
        let (_dir, vault) = crate::test_util::open_test_vault_with(config);
        let mut bundle =
            FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current());
        let a = encode_feedback_bundle(&bundle).unwrap();
        let dial = FeedbackDedup::new(0.9)?;
        let first = vault.ingest_feedback(&a, &[1.0, 0.0], dial, 10)?;
        bundle.user_note = Some("second source for the same proposal".into());
        let b = encode_feedback_bundle(&bundle).unwrap();
        let merged = vault.ingest_feedback(&b, &[1.0, 0.0], dial, 11)?;
        assert_eq!(merged.id, first.id);
        assert_eq!(merged.bundles.len(), 2);
        bundle.user_note = Some("independent proposal".into());
        let c = encode_feedback_bundle(&bundle).unwrap();
        let sibling = vault.ingest_feedback(&c, &[-1.0, 0.0], dial, 12)?;
        assert_eq!(
            vault.feedback_digest()?,
            vec![merged.clone(), sibling.clone()]
        );
        let deleted = merged.bundles[1];
        if let Some(reason) = reason {
            vault.delete_entity_with_reason(&deleted, reason)?;
        } else {
            // A different live ASSET under the old reference is not the original evidence.
            vault
                .batch()
                .put(
                    &deleted,
                    crate::registry::ENTITY_TYPE_ASSET,
                    TimeRange { start: 13, end: 13 },
                    13,
                    &c,
                )
                .commit()?;
        }
        assert_eq!(vault.feedback_digest()?, vec![sibling]);
        assert_eq!(vault.get(&merged.bundles[0])?.unwrap(), a);
    }
    Ok(())
}
