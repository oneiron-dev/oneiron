use super::super::super::corpus_filter::CorpusFilter;
use super::*;

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
    let rtxn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    let authority =
        crate::gate::narrow_retrieval_filter(&policy.retrieval_floor_for_actor(None), None)?;
    let config = filter.config(&builder, None, &authority);
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
    assert_eq!(scores.len(), original.len());
    for (actual, expected) in scores.iter().zip(&original) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.score, expected.score);
    }
    assert_eq!(gate.body_loads, 0);
    apply_corpus_filter(
        &mut scores,
        &vault.store,
        &rtxn,
        &CorpusScope::Unscoped,
        &mut metadata,
        &mut gate,
    )?;
    assert_eq!(scores.len(), 1);
    assert_eq!(scores[0].id, event);
    assert_eq!(scores[0].score, original[2].score);
    assert_eq!(gate.body_loads, 2);
    for id in [dead, malformed] {
        assert!(!pipeline_candidate_matches_corpus_filter(
            &vault.store,
            &rtxn,
            &id,
            &CorpusScope::Unscoped,
            &mut metadata,
            &mut gate,
        )?);
    }
    assert_eq!(gate.body_loads, 2, "suppressed decisions are memoized too");
    Ok(())
}
