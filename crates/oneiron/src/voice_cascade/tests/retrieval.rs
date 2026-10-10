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

/// Call mode on ASR partials: every fire and the finalize pass answer by the
/// session's deadline. A slow stage that yields cuts its fire short, and a
/// promotion of that fire stays partial; a stalled one misses the deadline,
/// which keeps the warm pack, and a finalize that misses it answers with
/// that warm pack.
#[test]
fn speculative_passes_answer_by_the_session_deadline() -> Result<()> {
    use crate::retrieval_depth::SlowRetrievalStage;
    use crate::speculative::{SpeculativeFinal, SpeculativePartial, SpeculativeSession};
    use crate::store::RetrievalSignal;
    use std::time::Instant;

    const DEADLINE: Duration = Duration::from_secs(3);
    // The waiting caller wakes at the deadline; this is scheduling slack.
    const WAKE: Duration = Duration::from_millis(500);
    fn heard(terms: &[String]) -> SpeculativePartial<'_> {
        SpeculativePartial {
            text: "Tokyo launch",
            query_vector: None,
            entity_labels: &[],
            salient_terms: terms,
        }
    }
    let (_dir, vault) = vault();
    let tokyo = put_text(&vault, 7, "Tokyo launch")?;
    let config = || SpeculativeSessionConfig {
        deadline: Some(DEADLINE),
        ..SpeculativeSessionConfig::default()
    };
    let [tokyo_terms, launch_terms, osaka_terms] =
        ["tokyo", "launch", "osaka"].map(|term| vec![term.to_owned()]);
    let ids = |scores: &[crate::pipeline::ScoredEntity]| -> Vec<String> {
        scores.iter().map(|scored| scored.id.to_hex()).collect()
    };

    // A fire that lands; then a stalled stage, which the fire waits out only
    // until its deadline.
    let mut session = SpeculativeSession::new(Arc::clone(&vault), config());
    assert!(matches!(
        session.observe_partial(heard(&tokyo_terms))?,
        SpeculativeFireDecision::Fired { partial: false, .. }
    ));
    assert_eq!(ids(session.warm_candidates()), [tokyo.as_str()]);
    vault.arm_slow_retrieval_stage_for_test(Some(SlowRetrievalStage {
        signal: RetrievalSignal::Text,
        duration: Duration::from_secs(6),
        yields: false,
    }));
    let started = Instant::now();
    assert_eq!(
        session.observe_partial(heard(&launch_terms))?,
        SpeculativeFireDecision::MissedDeadline
    );
    assert!(
        started.elapsed() < DEADLINE + WAKE,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(session.fires_used(), 2);
    assert_eq!(ids(session.warm_candidates()), [tokyo.as_str()]);
    let started = Instant::now();
    let SpeculativeFinal::Finalized {
        scores,
        run_id,
        warm_appended,
        partial: cut,
    } = session.finalize(heard(&osaka_terms))?
    else {
        panic!("a changed signature runs the finalize pass");
    };
    assert!(
        started.elapsed() < DEADLINE + WAKE,
        "{:?}",
        started.elapsed()
    );
    assert!(cut && run_id.is_none());
    assert_eq!((ids(&scores), warm_appended), (vec![tokyo], 1));

    // A slow stage that yields at its share of the deadline: the fire lands
    // in time, cut short, without the slow stage's hits.
    vault.arm_slow_retrieval_stage_for_test(Some(SlowRetrievalStage {
        signal: RetrievalSignal::Text,
        duration: Duration::from_secs(30),
        yields: true,
    }));
    let mut session = SpeculativeSession::new(Arc::clone(&vault), config());
    let started = Instant::now();
    assert!(matches!(
        session.observe_partial(heard(&tokyo_terms))?,
        SpeculativeFireDecision::Fired { partial: true, .. }
    ));
    assert!(started.elapsed() < DEADLINE, "{:?}", started.elapsed());
    assert!(session.warm_candidates().is_empty());
    vault.arm_slow_retrieval_stage_for_test(None);
    assert!(matches!(
        session.finalize(heard(&tokyo_terms))?,
        SpeculativeFinal::Promoted { partial: true, .. }
    ));
    Ok(())
}
