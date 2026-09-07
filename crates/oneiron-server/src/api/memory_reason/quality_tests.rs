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
        for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
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
            assert_eq!(response.reasoning.is_none(), effort == Effort::Minimal);
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
        let response = reason_response(Effort::Standard, &retrieved, answered, 0);
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
