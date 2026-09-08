//! Retrieval-quality facade metadata regressions.

use super::*;

#[test]
fn retrieval_quality_facade_metadata_defaults_preserve_old_pack_json() {
    use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalQuality};

    let old = serde_json::json!({
        "items": [],
        "scope_honesty": {"out_of_scope_worlds": []},
        "retrieval_meta": {
            "sparse": true,
            "total_candidates": 0,
            "claims_returned": 0,
            "deep_pending": null
        },
        "pack_version": 1,
        "rendered": null
    });
    let pack: MemoryPack = serde_json::from_value(old).expect("old facade pack");
    assert_eq!(pack.retrieval_meta.quality, RetrievalQuality::Passthrough);
    assert!(pack.retrieval_meta.degradation.is_empty());
    assert_eq!(
        pack.retrieval_meta.confidence_adjustment,
        ConfidenceAdjustment::PASSTHROUGH
    );
    let wire = serde_json::to_value(&pack).expect("facade JSON");
    assert_eq!(wire["retrieval_meta"]["quality"], "passthrough");
    assert_eq!(wire["retrieval_meta"]["confidenceAdjustment"], -0.35);
    assert!(
        wire["retrieval_meta"]
            .get("confidence_adjustment")
            .is_none()
    );
    assert!(wire["retrieval_meta"].get("degradation").is_none());
}

#[test]
fn retrieval_quality_facade_recall_projects_report_without_changing_item_confidence() {
    use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x78);
    let facade = facade_for(&vault, actor);
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x79; 16]).expect("id").to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "quality recall needle",
            )],
            occurred_at: 1500,
        })
        .expect("witness");
    let minimal = facade
        .recall(
            "quality recall needle",
            Effort::Minimal,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("minimal recall");
    assert!(!minimal.items.is_empty());
    assert_eq!(
        minimal.retrieval_meta.quality,
        RetrievalQuality::Passthrough
    );
    assert!(minimal.retrieval_meta.degradation.is_empty());
    let standard = facade
        .recall(
            "quality recall needle",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("standard recall");
    assert_eq!(standard.retrieval_meta.quality, RetrievalQuality::Degraded);
    assert_eq!(
        standard.retrieval_meta.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
    assert_eq!(
        standard.retrieval_meta.confidence_adjustment,
        ConfidenceAdjustment::DEGRADED
    );
    for item in &minimal.items {
        let same = standard
            .items
            .iter()
            .find(|other| other.short_id == item.short_id)
            .expect("same item survives standard recall");
        assert_eq!(same.confidence.to_bits(), item.confidence.to_bits());
        assert_eq!(same.hedge_bucket, item.hedge_bucket);
    }
    let empty = facade
        .recall(
            "unmatchedqualitytoken",
            Effort::Minimal,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("empty recall");
    assert!(empty.items.is_empty());
    assert_eq!(empty.retrieval_meta.quality, RetrievalQuality::Passthrough);
    assert!(empty.retrieval_meta.degradation.is_empty());
}
