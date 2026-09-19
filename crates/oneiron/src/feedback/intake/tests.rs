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
    let mut variant = bundle.clone();
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
