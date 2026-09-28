use super::*;
use oneiron::retrieval_quality::{
    PprCacheOutcome, RetrievalDiagnostics, RetrievalQualityReport, classify_retrieval_quality,
};
use oneiron::store::RetrievalSignal;

fn report(cache: PprCacheOutcome) -> RetrievalQualityReport {
    let channels = vec![
        RetrievalSignal::Vector,
        RetrievalSignal::Text,
        RetrievalSignal::Phonetic,
        RetrievalSignal::Temporal,
        RetrievalSignal::Ppr,
    ];
    classify_retrieval_quality(&RetrievalDiagnostics {
        attempted: channels.clone(),
        succeeded: channels,
        ppr_cache: Some(cache),
        ..Default::default()
    })
}

#[test]
fn retrieval_quality_memory_reason_projection_preserves_full_degraded_and_minimal() {
    for quality in [
        report(PprCacheOutcome::Hit),
        report(PprCacheOutcome::Miss),
        RetrievalQualityReport::default(),
    ] {
        let retrieved = DepthSearchResult {
            retrieval_quality: quality.clone(),
            queries_run: vec!["unchanged query".to_owned()],
            tokens_used: 8,
            ..Default::default()
        };
        for effort in [Effort::Light, Effort::Medium, Effort::High] {
            let answered = AnsweredRead {
                answer: "unchanged answer".to_owned(),
                sources: vec!["source:ab".to_owned()],
                confidence: 0.82,
                gaps: vec!["existing gap".to_owned()],
                tokens_used: 13,
            };
            let response = reason_response(effort, &retrieved, answered, 21);
            assert_eq!(response.confidence.to_bits(), 0.82_f32.to_bits());
            assert_eq!(response.quality, quality.quality);
            assert_eq!(response.degradation, quality.degradation);
            assert_eq!(
                response.confidence_adjustment,
                quality.confidence_adjustment
            );
            assert_eq!(response.reasoning.is_none(), effort == Effort::Light);
            let wire = serde_json::to_value(&response).unwrap();
            assert_eq!(wire["answer"], "unchanged answer");
            assert_eq!(wire["sources"], json!(["source:ab"]));
            assert_eq!(wire["gaps"], json!(["existing gap"]));
            assert_eq!(wire["tokensUsed"], 21);
            assert_eq!(
                wire["confidenceAdjustment"],
                serde_json::to_value(quality.confidence_adjustment).unwrap()
            );
            assert_eq!(
                wire.get("degradation").is_none(),
                quality.degradation.is_empty()
            );
            assert!(wire.get("confidence_adjustment").is_none());
            assert_eq!(
                serde_json::from_value::<MemoryReasonResponse>(wire).unwrap(),
                response
            );
        }
    }
}

#[test]
fn retrieval_quality_memory_reason_no_data_preserves_full_or_degraded_report() {
    // Synthetic projection fixtures only: the frozen depth executor does not
    // execute all five original channels and must not claim this full result.
    for quality in [report(PprCacheOutcome::Hit), report(PprCacheOutcome::Miss)] {
        let request: MemoryReasonRequest =
            serde_json::from_value(json!({"query": "no data"})).unwrap();
        let retrieved = DepthSearchResult {
            retrieval_quality: quality.clone(),
            ..Default::default()
        };
        let answered = answer_from(&request, "no data", 4000, &[], None).unwrap();
        let response = reason_response(Effort::Medium, &retrieved, answered, 0);
        assert!(response.sources.is_empty());
        assert_eq!(response.confidence, 0.0);
        assert_eq!(response.gaps.len(), 1);
        assert_eq!(response.quality, quality.quality);
        assert_eq!(response.degradation, quality.degradation);
        assert_eq!(
            response.confidence_adjustment,
            quality.confidence_adjustment
        );
        assert_eq!(response.tokens_used, 0);
    }
}

#[test]
fn evidence_keeps_the_ranked_revision_when_idle_publication_wins_the_race() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
    // First open seeds the bootstrap skills, whose activation edits wait for
    // idle publication too. Publish them so the race observes only this row.
    vault.set_indexed_idle_delay_ms(0).unwrap();
    vault.refresh_staged_indexed_at_idle(u64::MAX).unwrap();
    let id = EntityId::now();
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    // A claim revision carries its own record scope. An edited non-claim
    // revision has no digest-bound stamp left to prove its historical read.
    let put = |text: &str, at: u64| {
        let body = oneiron::ClaimBody::new(
            "evidence.race",
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        vault
            .put_claim(&id, &body, oneiron::TimeRange { start: at, end: at }, at)
            .unwrap();
    };
    put("ranked zebra", 1);
    vault
        .batch()
        .text(&id, &[("content", "ranked zebra")])
        .commit()
        .unwrap();
    let before = vault.indexed_revision(&id).unwrap().unwrap();
    let scoped = vault.scoped_read(crate::test_credentials::host_reader(&vault));
    let mut retrieved = scoped
        .search_with_effort(&DepthSearchRequest {
            probe: SearchProbe::Text {
                query: "zebra".into(),
            },
            effort: Effort::Light,
            limit: 10,
            session_scope: None,
            lease: None,
            backend: None,
            token_budget: None,
            deadline: None,
        })
        .unwrap();
    assert_eq!(retrieved.hits.len(), 1);
    assert_eq!(retrieved.revisions.get(&id), Some(&before));
    put("published yak", 2);
    vault.set_indexed_idle_delay_ms(0).unwrap();
    assert_eq!(
        vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .unwrap()
            .refreshed
            .len(),
        1
    );
    assert_ne!(vault.indexed_revision(&id).unwrap(), Some(before));
    let evidence = collect_evidence(&vault, &scoped, &mut retrieved).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].text, "ranked zebra");
    assert_eq!(
        evidence[0].short_id,
        vault
            .pinned_short_ref_with_mode(&id, oneiron::memory::ReadMode::Pinned(before))
            .unwrap()
    );
}
