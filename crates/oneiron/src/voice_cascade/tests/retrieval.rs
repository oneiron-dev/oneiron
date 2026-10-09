use super::*;
use crate::speculative::SpeculativeFireDecision;
use crate::store::RetrievalAction;

#[test]
fn empty_host_enrichment_skips_partial_and_runs_normal_final_retrieval() -> Result<()> {
    for enrichment in [
        PartialEnrichment::default(),
        PartialEnrichment {
            entity_labels: vec![" ".to_owned()],
            salient_terms: vec!["\t".to_owned(), String::new()],
            query_vector: None,
        },
    ] {
        let (_dir, vault) = vault();
        let result_ref = put_text(&vault, 5, "Tokyo launch")?;
        let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
        let handle = bridge.open_utterance("empty", SpeculativeSessionConfig::default())?;
        let mut enricher = Enricher {
            value: enrichment,
            texts: Vec::new(),
        };
        // Provider text is not a fallback meaning signature. The host pass still runs.
        for revision in [1, 2] {
            let partial =
                bridge.observe_partial(&handle, revision, "Tokyo launch", &mut enricher)?;
            assert_eq!(
                partial.decision,
                SpeculativeFireDecision::SkippedEmptySignature
            );
            assert!(partial.context.is_none());
            assert_eq!(bridge.fires_used(&handle)?, 0);
        }
        assert!(vault.retrieval_runs(200)?.is_empty());
        assert!(
            bridge
                .observe_partial(&handle, 2, "duplicate", &mut enricher)
                .is_err(),
            "an empty-signature skip still advances the revision"
        );
        assert_eq!(enricher.texts, ["Tokyo launch", "Tokyo launch"]);
        let context = bridge.finalize(&handle, 3, "Tokyo launch", &mut enricher)?;
        assert!(!context.promoted);
        assert_eq!(context.result_refs, [result_ref]);
        assert!(context.run_id.is_some());
        let runs = vault.retrieval_runs(200)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].action, RetrievalAction::Pipeline);
        assert_eq!(
            enricher.texts,
            ["Tokyo launch", "Tokyo launch", "Tokyo launch"]
        );
        assert!(!bridge.is_open(&handle));
    }
    Ok(())
}
