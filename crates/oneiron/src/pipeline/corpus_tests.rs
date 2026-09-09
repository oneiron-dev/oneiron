use super::super::corpus_filter::{apply_corpus_filter, pipeline_candidate_matches_corpus_filter};
use super::*;

// ── ONE-1914 · corpus scope filter ──────────────────────────────────────

fn corpus(byte: u8) -> CorpusId {
    CorpusId::from_entity_id(entity_id(byte))
}

/// A live CLAIM body carrying an optional corpus scope (`None` =
/// unscoped/core). Built through the pinned claim encoder so the nested
/// `corpus_id` entry is the real 16-byte binary the read side decodes.
fn corpus_claim_body(corpus_scope: Option<CorpusId>) -> Result<Vec<u8>> {
    let mut body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    if let Some(corpus_scope) = corpus_scope {
        body.scope = Some(scope_with_corpus_id(None, corpus_scope)?);
    }
    Ok(crate::claim::encode_claim_body(&body).expect("encode claim body"))
}

/// A vector-ranked corpus-scoped CLAIM.
fn put_claim_with_vector_corpus(
    vault: &Vault,
    id: EntityId,
    vector: [f32; 4],
    corpus_scope: Option<CorpusId>,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &corpus_claim_body(corpus_scope)?,
        )
        .vector(&id, &vector)
        .commit()
}

/// A text-indexed corpus-scoped CLAIM — the BM25 analog of
/// [`put_claim_with_vector_corpus`], for the prefix-expansion pin below.
fn put_claim_text_corpus(
    vault: &Vault,
    id: EntityId,
    text: &str,
    corpus_scope: Option<CorpusId>,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &corpus_claim_body(corpus_scope)?,
        )
        .text(&id, &[("body", text)])
        .commit()
}

struct CorpusFixture {
    corpus_a: CorpusId,
    corpus_b: CorpusId,
    claim_core: EntityId,
    claim_a: EntityId,
    claim_b: EntityId,
    event: EntityId,
}

/// Three claims — unscoped, corpus A, corpus B — plus one non-CLAIM row, all
/// reachable from [`FACET_QUERY`].
fn setup_corpus_fixture(vault: &Vault) -> Result<CorpusFixture> {
    let fixture = CorpusFixture {
        corpus_a: corpus(0x95),
        corpus_b: corpus(0x96),
        claim_core: entity_id(0x31),
        claim_a: entity_id(0x32),
        claim_b: entity_id(0x33),
        event: entity_id(0x34),
    };

    put_claim_with_vector_corpus(vault, fixture.claim_core, [1.0, 0.0, 0.0, 0.0], None)?;
    put_claim_with_vector_corpus(
        vault,
        fixture.claim_a,
        [0.8, 0.6, 0.0, 0.0],
        Some(fixture.corpus_a),
    )?;
    put_claim_with_vector_corpus(
        vault,
        fixture.claim_b,
        [0.6, 0.8, 0.0, 0.0],
        Some(fixture.corpus_b),
    )?;
    vault
        .batch()
        .put(
            &fixture.event,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&fixture.event, &[0.0, 1.0, 0.0, 0.0])
        .commit()?;

    Ok(fixture)
}

/// The selection contract: unscoped claims are universal inside a selected
/// corpus, another corpus's claims are removed, and non-CLAIM rows never
/// participate.
#[test]
fn corpus_scope_selects_audience_and_keeps_unscoped_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_corpus_fixture(&vault)?;
    let ids = |scope: Option<CorpusScope>| -> Result<HashSet<EntityId>> {
        let mut query = vault.query().search_vector(&FACET_QUERY, 10);
        if let Some(scope) = scope {
            query = query.corpus(scope);
        }
        Ok(query.run()?.iter().map(|entry| entry.id).collect())
    };

    // Default (no `.corpus()` call) and the explicit All scope both span
    // every corpus.
    for scope in [None, Some(CorpusScope::All)] {
        let all = ids(scope)?;
        assert_eq!(
            all,
            HashSet::from([
                fixture.claim_core,
                fixture.claim_a,
                fixture.claim_b,
                fixture.event
            ]),
            "All must span every corpus"
        );
    }

    // Corpus(A): A's claims + unscoped core + the non-claim row; B is gone.
    let in_a = ids(Some(CorpusScope::Corpus(fixture.corpus_a)))?;
    assert_eq!(
        in_a,
        HashSet::from([fixture.claim_core, fixture.claim_a, fixture.event]),
        "Corpus(A) keeps A + unscoped + non-claims, drops B"
    );

    // Unscoped: core only — every corpus-scoped claim is removed.
    let unscoped = ids(Some(CorpusScope::Unscoped))?;
    assert_eq!(
        unscoped,
        HashSet::from([fixture.claim_core, fixture.event]),
        "Unscoped keeps core knowledge and drops every corpus-scoped claim"
    );

    // AnyOf spans the named corpora, still alongside unscoped core.
    let any_of = ids(Some(CorpusScope::AnyOf(vec![
        fixture.corpus_a,
        fixture.corpus_b,
    ])))?;
    assert_eq!(
        any_of,
        HashSet::from([
            fixture.claim_core,
            fixture.claim_a,
            fixture.claim_b,
            fixture.event
        ]),
        "AnyOf(A, B) keeps both corpora plus unscoped"
    );
    Ok(())
}

/// An exact text hit belonging to ANOTHER corpus must not consume the only
/// result slot. The corpus conjunct on the candidate scan marks that posting
/// out of scope, so BM25 prefix expansion still reaches the in-corpus claim —
/// the corpus analog of
/// [`exact_other_world_text_hit_does_not_suppress_world_prefix`].
#[test]
fn exact_other_corpus_text_hit_does_not_suppress_corpus_prefix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let corpus_active = corpus(0x95);
    let corpus_other = corpus(0x96);
    let other_corpus_exact = entity_id(0x61);
    let active_corpus_prefix = entity_id(0x22);

    put_claim_text_corpus(
        &vault,
        other_corpus_exact,
        "corpusprefix",
        Some(corpus_other),
    )?;
    put_claim_text_corpus(
        &vault,
        active_corpus_prefix,
        "corpusprefixalpha",
        Some(corpus_active),
    )?;

    let results = vault
        .query()
        .search_text("corpusprefix", 1)
        .corpus(CorpusScope::Corpus(corpus_active))
        .run()?;

    assert!(results.iter().any(|entry| entry.id == active_corpus_prefix));
    assert!(!results.iter().any(|entry| entry.id == other_corpus_exact));
    Ok(())
}

/// Naming zero corpora fails the run closed instead of silently behaving
/// like [`CorpusScope::Unscoped`].
#[test]
fn empty_corpus_any_of_fails_the_run_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    setup_corpus_fixture(&vault)?;

    assert_matches!(
        vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .corpus(CorpusScope::AnyOf(Vec::new()))
            .run(),
        Err(Error::InvalidConfig(_))
    );
    Ok(())
}

// E1: channel_limit=1, not just result_limit=1. The per-channel trace proves
// that recovery happened before fusion rather than through another channel.
fn assert_corpus_channel_hit(
    vault: &Vault,
    builder: PipelineBuilder<'_>,
    signal: RetrievalSignal,
    expected: EntityId,
) -> Result<()> {
    let output = builder.capture_retrieval_trace(true).run_with_telemetry()?;
    assert_eq!(
        output.value.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![expected]
    );
    let trace = vault
        .retrieval_run(output.run_id.expect("run id"))?
        .expect("run")
        .trace
        .expect("trace");
    let channel = trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == signal)
        .expect("requested channel");
    assert_eq!(
        channel
            .candidates
            .iter()
            .map(|row| row.result_id)
            .collect::<Vec<_>>(),
        vec![*expected.as_bytes()]
    );
    Ok(())
}

#[test]
fn corpus_vector_limit_one_recovers_lower_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let excluded = entity_id(0x41);
    let eligible = entity_id(0x43);
    put_claim_with_vector_corpus(&vault, excluded, FACET_QUERY, Some(corpus(0x96)))?;
    put_claim_with_vector_corpus(&vault, eligible, [0.8, 0.6, 0.0, 0.0], Some(corpus(0x95)))?;
    let query = || {
        vault
            .query()
            .search_vector(&FACET_QUERY, 1)
            .with_temporal_now(10)
            .limit(1)
    };
    let baseline = query().run()?;
    assert_eq!(baseline[0].id, excluded);
    assert_eq!(baseline, query().corpus(CorpusScope::All).run()?);
    for scope in [
        CorpusScope::Corpus(corpus(0x95)),
        CorpusScope::AnyOf(vec![corpus(0x95); 2]),
    ] {
        assert_corpus_channel_hit(
            &vault,
            query().corpus(scope),
            RetrievalSignal::Vector,
            eligible,
        )?;
    }
    Ok(())
}

#[test]
fn corpus_hyde_limit_one_recovers_lower_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let excluded = entity_id(0x41);
    let eligible = entity_id(0x43);
    put_claim_with_vector_corpus(&vault, excluded, FACET_QUERY, Some(corpus(0x96)))?;
    put_claim_with_vector_corpus(&vault, eligible, [0.8, 0.6, 0.0, 0.0], Some(corpus(0x95)))?;
    let host = StubHyde {
        embedding: FACET_QUERY.to_vec(),
        subqueries: vec![],
        insufficient: false,
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };
    // No text postings: only HyDE can supply a candidate. No retry can mask a
    // lost first-attempt hit by increasing the requested channel limit.
    let query = || {
        vault
            .query()
            .search_text("corpushydeneedle", 1)
            .hyde(
                &host,
                GroundingContext::default(),
                HydeOptions {
                    channel_limit: 1,
                    retry_once: false,
                },
            )
            .with_temporal_now(10)
            .limit(1)
    };
    let baseline = query().run()?;
    assert_eq!(baseline[0].id, excluded);
    assert_eq!(baseline, query().corpus(CorpusScope::All).run()?);
    assert_corpus_channel_hit(
        &vault,
        query().corpus(CorpusScope::Corpus(corpus(0x95))),
        RetrievalSignal::Hyde,
        eligible,
    )?;
    Ok(())
}

#[test]
fn corpus_temporal_limit_one_recovers_lower_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let excluded = entity_id(0x41);
    let eligible = entity_id(0x43);
    for (id, at, scope) in [(excluded, 100, corpus(0x96)), (eligible, 110, corpus(0x95))] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: at, end: at },
            100,
            &corpus_claim_body(Some(scope))?,
        )?;
    }
    let query = || {
        vault
            .query()
            .search_temporal_with_sigma(100, 100, 10, TemporalAnchorMode::Occurred, 1)
            .temporal_adaptive(false)
            .with_temporal_now(120)
            .limit(1)
    };
    let baseline = query().run()?;
    assert_eq!(baseline[0].id, excluded);
    assert_eq!(baseline, query().corpus(CorpusScope::All).run()?);
    assert_corpus_channel_hit(
        &vault,
        query().corpus(CorpusScope::Corpus(corpus(0x95))),
        RetrievalSignal::Temporal,
        eligible,
    )?;
    Ok(())
}

#[test]
fn corpus_bounded_channels_keep_zero_limits_empty() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    setup_corpus_fixture(&vault)?;
    for query in [
        vault.query().search_vector(&FACET_QUERY, 0),
        vault.query().search_temporal(1, 1, 0),
    ] {
        assert!(
            query
                .corpus(CorpusScope::Corpus(corpus(0x95)))
                .run()?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn corpus_trace_forks_equal_candidates_by_canonical_selection() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_claim_text_corpus(&vault, entity_id(0x41), "corpusforkneedle", None)?;
    let trace = |scope| {
        captured_retrieval_trace(
            &vault,
            vault
                .query()
                .search_text("corpusforkneedle", 1)
                .with_temporal_now(10)
                .corpus(scope),
        )
    };
    let scopes = [
        CorpusScope::All,
        CorpusScope::Unscoped,
        CorpusScope::Corpus(corpus(0x95)),
        CorpusScope::Corpus(corpus(0x96)),
        CorpusScope::AnyOf(vec![corpus(0x95), corpus(0x96)]),
    ];
    let traces = scopes.into_iter().map(trace).collect::<Result<Vec<_>>>()?;
    let expected = &traces[0].final_stage.candidates;
    assert!(!expected.is_empty());
    for current in &traces {
        assert_eq!(&current.final_stage.candidates, expected);
        assert_eq!(current.per_channel, traces[0].per_channel);
        assert_eq!(current.fused, traces[0].fused);
        assert_eq!(current.blended, traces[0].blended);
    }
    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.fork_hash)
            .collect::<HashSet<_>>()
            .len(),
        traces.len()
    );
    let equivalent = trace(CorpusScope::AnyOf(vec![
        corpus(0x96),
        corpus(0x95),
        corpus(0x96),
    ]))?;
    assert_eq!(equivalent.fork_hash, traces[4].fork_hash);
    assert!(matches!(
        trace(CorpusScope::AnyOf(vec![])),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

#[path = "corpus_gate_tests.rs"]
mod corpus_gate_tests;

#[path = "corpus_coping_tests.rs"]
mod corpus_coping_tests;
