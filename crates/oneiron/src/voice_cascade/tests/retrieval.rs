use super::*;
use crate::speculative::SpeculativeFireDecision;
use crate::store::RetrievalAction;

#[derive(Default)]
struct FailingEnricher {
    texts: Vec<String>,
}

impl PartialEnricher for FailingEnricher {
    fn enrich_speculative_partial(&mut self, text: &str) -> Result<PartialEnrichment> {
        self.texts.push(text.to_owned());
        Err(Error::InvalidConfig("test enricher failure".to_owned()))
    }
}

#[test]
fn real_fire_and_normalized_unchanged_signature_promote_refs_only() -> Result<()> {
    let (_dir, vault) = vault();
    let first_ref = put_text(&vault, 1, "Tokyo launch alpha")?;
    let second_ref = put_text(&vault, 2, "Tokyo launch beta")?;
    let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
    let handle = bridge.open_utterance("u1", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let first = bridge.observe_partial(&handle, 1, "Tokyo launch", &mut enricher)?;
    assert!(matches!(
        first.decision,
        SpeculativeFireDecision::Fired { .. }
    ));
    let warm = first.context.expect("fire context");
    assert!(warm.result_refs.contains(&first_ref));
    assert!(warm.result_refs.contains(&second_ref));

    enricher.value.entity_labels = vec![" PERSON:MIKA ".to_owned(), "PERSON:MIKA".to_owned()];
    enricher.value.salient_terms = vec![" tokyo LAUNCH ".to_owned()];
    let same = bridge.observe_partial(&handle, 2, "Tokyo launch plan", &mut enricher)?;
    assert_eq!(same.decision, SpeculativeFireDecision::SkippedUnchanged);
    assert!(same.context.is_none());
    assert_eq!(bridge.fires_used(&handle)?, 1);
    let before_final = vault.retrieval_runs(200)?.len();
    let final_context = bridge.finalize(&handle, 3, "Tokyo launch plans", &mut enricher)?;
    assert!(final_context.promoted);
    assert_eq!(final_context.result_refs, warm.result_refs);
    assert_eq!(final_context.run_id, warm.run_id);
    assert_eq!(vault.retrieval_runs(200)?.len(), before_final);
    assert!(!bridge.is_open(&handle));
    assert_eq!(
        enricher.texts,
        ["Tokyo launch", "Tokyo launch plan", "Tokyo launch plans"]
    );

    let wire = serde_json::to_value(final_context).expect("refs projection");
    let object = wire.as_object().expect("object");
    assert_eq!(object.len(), 3);
    assert!(object.contains_key("result_refs"));
    assert!(object.contains_key("promoted"));
    assert!(object.contains_key("run_id"));
    assert!(!wire.to_string().contains("private entity body"));
    Ok(())
}

#[test]
fn actual_engine_caps_four_fires_and_final_promotes_last_fired_not_last_seen() -> Result<()> {
    let (_dir, vault) = vault();
    let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
    let handle = bridge.open_utterance("cap", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let mut last_run = None;
    for revision in 0..6 {
        enricher.value.salient_terms = vec![format!("meaning-{revision}")];
        let observed = bridge.observe_partial(&handle, revision, "Tokyo launch", &mut enricher)?;
        if revision < 4 {
            assert!(matches!(
                observed.decision,
                SpeculativeFireDecision::Fired { .. }
            ));
            last_run = observed.context.expect("fire").run_id;
        } else {
            assert_eq!(
                observed.decision,
                SpeculativeFireDecision::SkippedCapExhausted
            );
        }
    }
    assert_eq!(bridge.fires_used(&handle)?, 4);
    let runs = vault.retrieval_runs(200)?;
    assert_eq!(
        runs.iter()
            .filter(|run| run.action == RetrievalAction::Speculative)
            .count(),
        4
    );
    // Returning to the last FIRED signature is promotion, even after capped diffs.
    enricher.value.salient_terms = vec!["meaning-3".to_owned()];
    let final_context = bridge.finalize(&handle, 6, "Tokyo launch", &mut enricher)?;
    assert!(final_context.promoted);
    assert_eq!(final_context.run_id, last_run);
    assert_eq!(vault.retrieval_runs(200)?.len(), runs.len());
    Ok(())
}

#[test]
fn changed_final_uses_real_fresh_pass_then_warm_order() -> Result<()> {
    let (_dir, vault) = vault();
    let warm_ref = put_text(&vault, 3, "orchid orchard")?;
    let fresh_ref = put_text(&vault, 4, "cobalt launch")?;
    let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
    let handle = bridge.open_utterance("fresh", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    enricher.value.salient_terms = vec!["orchid".to_owned()];
    let partial = bridge.observe_partial(&handle, 1, "orchid", &mut enricher)?;
    assert_eq!(
        partial.context.expect("warm").result_refs.as_slice(),
        std::slice::from_ref(&warm_ref)
    );
    let before = vault.retrieval_runs(200)?.len();
    enricher.value.salient_terms = vec!["cobalt".to_owned()];
    let final_context = bridge.finalize(&handle, 2, "cobalt", &mut enricher)?;
    assert!(!final_context.promoted);
    assert_eq!(final_context.result_refs, [fresh_ref, warm_ref]);
    assert_eq!(vault.retrieval_runs(200)?.len(), before + 1);
    assert_eq!(
        vault
            .retrieval_runs(200)?
            .iter()
            .filter(|run| run.action == RetrievalAction::Pipeline)
            .count(),
        1
    );
    Ok(())
}

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

#[test]
fn enrichment_is_mandatory_and_errors_leave_partial_retryable() -> Result<()> {
    let (_dir, vault) = vault();
    let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
    let handle = bridge.open_utterance("enriched", SpeculativeSessionConfig::default())?;
    let mut failing = FailingEnricher::default();
    // Meaningful-looking provider text cannot bypass a failed host pass.
    assert!(
        bridge
            .observe_partial(&handle, 7, "Tokyo launch", &mut failing)
            .is_err()
    );
    assert_eq!(failing.texts, ["Tokyo launch"]);
    assert_eq!(bridge.fires_used(&handle)?, 0);
    assert!(vault.retrieval_runs(200)?.is_empty());
    let mut enricher = Enricher::default();
    enricher.value.query_vector = Some(vec![f32::NAN, 0.0, 0.0, 0.0]);
    assert!(
        bridge
            .observe_partial(&handle, 7, "Tokyo launch", &mut enricher)
            .is_err()
    );
    assert_eq!(bridge.fires_used(&handle)?, 0);
    enricher.value.query_vector = None;
    let observed = bridge.observe_partial(&handle, 7, "Tokyo launch", &mut enricher)?;
    assert!(matches!(
        observed.decision,
        SpeculativeFireDecision::Fired { .. }
    ));
    assert_eq!(enricher.texts.len(), 2);
    assert!(
        bridge
            .observe_partial(&handle, 7, "duplicate", &mut enricher)
            .is_err()
    );
    assert_eq!(
        enricher.texts.len(),
        2,
        "late revision never reaches host/model"
    );
    Ok(())
}

#[test]
fn finalize_error_consumes_real_session_but_enricher_error_is_retryable() -> Result<()> {
    let (_dir, vault) = vault();
    let mut bridge = SpeculativeRetrievalBridge::new(vault);
    let handle = bridge.open_utterance("error", SpeculativeSessionConfig::default())?;
    let mut failing = FailingEnricher::default();
    assert!(
        bridge
            .finalize(&handle, 1, "Tokyo launch", &mut failing)
            .is_err()
    );
    assert_eq!(failing.texts, ["Tokyo launch"]);
    assert!(bridge.is_open(&handle));
    let mut enricher = Enricher::default();
    enricher.value.query_vector = Some(vec![f32::NAN, 0.0, 0.0, 0.0]);
    assert!(
        bridge
            .finalize(&handle, 1, "Tokyo launch", &mut enricher)
            .is_err()
    );
    assert!(!bridge.is_open(&handle));
    assert!(bridge.finalize(&handle, 2, "late", &mut enricher).is_err());
    Ok(())
}

#[test]
fn closed_reused_and_foreign_utterance_handles_never_hit_retrieval() -> Result<()> {
    let (_dir, vault) = vault();
    let mut bridge = SpeculativeRetrievalBridge::new(Arc::clone(&vault));
    let old = bridge.open_utterance("reused", SpeculativeSessionConfig::default())?;
    assert!(
        bridge
            .open_utterance("another", SpeculativeSessionConfig::default())
            .is_err()
    );
    assert!(bridge.close_utterance(&old));
    let current = bridge.open_utterance("reused", SpeculativeSessionConfig::default())?;
    let mut other = SpeculativeRetrievalBridge::new(vault);
    let foreign = other.open_utterance("reused", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    for stale in [&old, &foreign] {
        assert!(!bridge.close_utterance(stale));
        assert!(
            bridge
                .observe_partial(stale, 100, "late", &mut enricher)
                .is_err()
        );
    }
    assert!(enricher.texts.is_empty());
    assert!(bridge.is_open(&current));
    bridge.close();
    bridge.close();
    assert!(!bridge.is_open(&current));
    Ok(())
}
