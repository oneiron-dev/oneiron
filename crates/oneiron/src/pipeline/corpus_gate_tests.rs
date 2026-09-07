use super::super::super::corpus_filter::CorpusFilter;
use super::super::super::filters::{
    apply_claim_status_gate, claim_status_gate_allows, import_claim_gate_decisions_for_scores,
    pipeline_candidate_matches_filters_and_gate,
};
use super::*;

#[test]
fn corpus_candidate_probe_and_post_fusion_reuse_decoded_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x41);
    put_claim_with_vector_corpus(&vault, id, FACET_QUERY, Some(corpus(0x96)))?;
    let builder = vault.query().corpus(CorpusScope::Corpus(corpus(0x95)));
    let filter = CorpusFilter::new(&builder.corpus_scope)?;
    let config = filter.config(&builder, None);
    let rtxn = vault.store.env.read_txn()?;
    let mut metadata = EntityMetadataCache::default();
    let mut probe = ClaimStatusGateCache::default();
    assert!(claim_status_gate_allows(
        &vault.store,
        &rtxn,
        &id,
        &mut metadata,
        &mut probe
    )?);
    assert_eq!(probe.body_loads, 1);

    // White-box sentinel: only the decoded memo carries the selected corpus.
    // A repeated LMDB lookup/decode would read the other corpus and fail these
    // assertions. Production never mutates this body within the read snapshot.
    probe
        .decisions
        .get_mut(&id)
        .expect("memoized")
        .as_mut()
        .expect("live body")
        .scope = Some(scope_with_corpus_id(None, corpus(0x95))?);
    assert!(pipeline_candidate_matches_filters_and_gate(
        &vault.store,
        &rtxn,
        &id,
        config,
        &mut metadata,
        &mut probe,
    )?);
    let mut scores = vec![ScoredEntity { id, score: 1.0 }];
    truncate_widened_channel_results_to_scope(
        &mut scores,
        &vault.store,
        &rtxn,
        1,
        config,
        &mut metadata,
        &mut probe,
    )?;
    assert_eq!(scores.len(), 1);
    assert_eq!(probe.body_loads, 1);

    let mut gate = ClaimStatusGateCache::default();
    import_claim_gate_decisions_for_scores(&mut gate, &mut probe, &scores);
    apply_claim_status_gate(&mut scores, &vault.store, &rtxn, &mut metadata, &mut gate)?;
    let traced = filter_retrieval_trace_scores(
        &scores,
        &vault.store,
        &rtxn,
        config,
        &mut metadata,
        &mut gate,
        1,
    )?;
    assert_eq!(traced, scores);
    assert_eq!(
        filter.apply(
            &mut scores,
            &vault.store,
            &rtxn,
            &mut metadata,
            &mut gate,
            None
        )?,
        None
    );
    assert_eq!(scores.len(), 1);
    assert_eq!(
        gate.body_loads, 0,
        "imported decisions must not load/decode again"
    );
    assert_eq!(
        crate::claim::claim_corpus_id(gate.decisions[&id].as_ref().expect("hydration body"))?,
        Some(corpus(0x95))
    );
    Ok(())
}

#[test]
fn corpus_bounded_vector_and_temporal_reuse_run_claim_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x41);
    let selected = corpus(0x95);
    // This helper writes both the vector and an occurred timestamp of 1.
    put_claim_with_vector_corpus(&vault, id, FACET_QUERY, Some(selected))?;
    let builder = vault
        .query()
        .search_vector(&FACET_QUERY, 1)
        .search_temporal_with_sigma(1, 1, 10, TemporalAnchorMode::Occurred, 1)
        .temporal_adaptive(false)
        .corpus(CorpusScope::Corpus(selected))
        .world(WorldScope::All)
        .capture_retrieval_trace(false);
    let filter = CorpusFilter::new(&builder.corpus_scope)?;
    let config = filter.config(&builder, None);
    let rtxn = vault.store.env.read_txn()?;
    let mut metadata = EntityMetadataCache::default();
    let mut gate = ClaimStatusGateCache::default();

    // Use the production bounded-channel sequence in one read transaction.
    // Each helper creates its own probe; the first must populate the run gate.
    let (query, limit) = builder.vector_search.as_ref().expect("vector channel");
    let vector =
        builder.scoped_vector_results(&rtxn, query, *limit, config, &mut metadata, &mut gate)?;
    assert_eq!(
        vector.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![id]
    );
    assert_eq!(metadata.claim_body_loads, 1);
    assert_eq!(gate.decisions.len(), 1);
    assert_eq!(
        crate::claim::claim_corpus_id(gate.decisions[&id].as_ref().expect("imported live body"))?,
        Some(selected)
    );

    let temporal = builder.scoped_temporal_results(
        &rtxn,
        builder.temporal_search.as_ref().expect("temporal channel"),
        10,
        config,
        &mut metadata,
        &mut gate,
    )?;
    assert_eq!(
        temporal.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![id]
    );
    // Unlike gate-local counts, this observes loads in discarded probes too.
    // A fresh empty temporal probe loads the overlapping claim a second time.
    assert_eq!(metadata.claim_body_loads, 1);
    assert_eq!(gate.decisions.len(), 1);
    Ok(())
}

#[test]
fn corpus_cache_preserves_all_no_op_and_suppression() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let dead = entity_id(0x41);
    let malformed = entity_id(0x45);
    let event = entity_id(0x43);
    put_status_claim(
        &vault,
        dead,
        "corpusdead",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_with_vector_corpus(&vault, malformed, FACET_QUERY, None)?;
    overwrite_entity_record(&vault, &malformed, ENTITY_TYPE_CLAIM, b"invalid body")?;
    put_entity(&vault, event, ENTITY_TYPE_EVENT, 1, 1, 1)?;
    let rtxn = vault.store.env.read_txn()?;
    let mut metadata = EntityMetadataCache::default();
    let mut gate = ClaimStatusGateCache::default();
    let original = vec![
        ScoredEntity {
            id: dead,
            score: 3.0,
        },
        ScoredEntity {
            id: malformed,
            score: 2.0,
        },
        ScoredEntity {
            id: event,
            score: 1.0,
        },
    ];
    let mut scores = original.clone();
    apply_corpus_filter(
        &mut scores,
        &vault.store,
        &rtxn,
        &CorpusScope::All,
        &mut metadata,
        &mut gate,
    )?;
    assert_eq!(scores, original);
    assert_eq!(gate.body_loads, 0);
    assert!(gate.decisions.is_empty());
    apply_corpus_filter(
        &mut scores,
        &vault.store,
        &rtxn,
        &CorpusScope::Unscoped,
        &mut metadata,
        &mut gate,
    )?;
    assert_eq!(scores, vec![original[2]]);
    assert_eq!(gate.body_loads, 2);
    assert_eq!(gate.decisions.len(), 2, "non-claim bodies are opaque");
    for id in [dead, malformed] {
        assert!(gate.decisions[&id].is_none());
        assert!(!pipeline_candidate_matches_corpus_filter(
            &vault.store,
            &rtxn,
            &id,
            &CorpusScope::Unscoped,
            &mut metadata,
            &mut gate
        )?);
    }
    assert_eq!(gate.body_loads, 2, "suppressed decisions are memoized too");
    Ok(())
}
