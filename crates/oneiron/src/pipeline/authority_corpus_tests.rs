//! Current-main corpus channels and ONE-1388 authority must narrow together.

use super::*;
use crate::corpus::{CorpusId, CorpusScope, scope_with_corpus_id};
use crate::pipeline::tests::captured_retrieval_trace;
use crate::store::RetrievalSignal;
use crate::temporal::{TemporalAnchorMode, TimeRange};

fn put_authority_corpus_claims(vault: &Vault, selected: CorpusId) -> Result<EntityId> {
    let other = CorpusId::from_entity_id(entity_id(0xE5));
    let eligible = entity_id(0x43);
    // Both excluded rows outrank the eligible stale row. One fails only the
    // authority clamp; the other fails only corpus selection.
    for (id, corpus, confidence, stale, at, vector, text) in [
        (
            entity_id(0x41),
            selected,
            0.1,
            false,
            1,
            [1.0, 0.0, 0.0, 0.0],
            "authorityneedle authorityneedle",
        ),
        (
            entity_id(0x44),
            other,
            0.9,
            true,
            1,
            [1.0, 0.0, 0.0, 0.0],
            "authorityneedle authorityneedle",
        ),
        (
            eligible,
            selected,
            0.9,
            true,
            3,
            [0.8, 0.6, 0.0, 0.0],
            "authorityneedle extra unrelated tokens",
        ),
    ] {
        let mut body = claim();
        body.confidence = confidence;
        body.stale = stale;
        body.scope = Some(scope_with_corpus_id(body.scope, corpus)?);
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: at, end: at },
                1,
                &crate::claim::encode_claim_body(&body)?,
            )
            .text(&id, &[("body", text)])
            .vector(&id, &vector)
            .commit()?;
    }
    Ok(eligible)
}

#[test]
fn authority_and_corpus_conjoin_before_channel_limits_and_trace() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let selected = CorpusId::from_entity_id(entity_id(0xE4));
    install_grant(
        &vault,
        map(vec![
            ("include_stale", Value::Boolean(true)),
            ("min_confidence", Value::F32(0.8)),
            ("max_sensitivity_band", Value::from(1)),
        ]),
    )?;
    let eligible = put_authority_corpus_claims(&vault, selected)?;
    let authority = resolve_reader_filter(&vault, None)?;
    let candidate = |_store: &crate::store::Store, _txn: &heed::RoTxn<'_>, _id: &EntityId| Ok(true);
    for (query, signal) in [
        (
            vault.query().search_vector(&[1.0, 0.0, 0.0, 0.0], 1),
            RetrievalSignal::Vector,
        ),
        (
            vault.query().search_text("authorityneedle", 1),
            RetrievalSignal::Text,
        ),
        (
            vault
                .query()
                .filter_candidates(&candidate)
                .search_text("authorityneedle", 1),
            RetrievalSignal::Text,
        ),
        (
            vault
                .query()
                .search_temporal_with_sigma(1, 1, 10, TemporalAnchorMode::Occurred, 1)
                .temporal_adaptive(false),
            RetrievalSignal::Temporal,
        ),
    ] {
        let trace = captured_retrieval_trace(
            &vault,
            query
                .filter_types(&[ENTITY_TYPE_CLAIM])
                .authority_filter(authority.clone())
                .corpus(CorpusScope::Corpus(selected))
                .with_temporal_now(10)
                .limit(1),
        )?;
        let expected = vec![*eligible.as_bytes()];
        let channel = trace
            .per_channel
            .iter()
            .find(|row| row.signal == signal)
            .expect("channel");
        assert_eq!(
            channel
                .candidates
                .iter()
                .map(|row| row.result_id)
                .collect::<Vec<_>>(),
            expected
        );
        for stage in [
            &trace.fused,
            &trace.blended,
            &trace.reranked,
            &trace.final_stage,
        ] {
            assert_eq!(
                stage
                    .candidates
                    .iter()
                    .map(|row| row.result_id)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn authority_and_corpus_both_fork_equal_candidate_traces() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    put_claim(&vault, entity_id(0x43), &claim())?;
    let a = CorpusId::from_entity_id(entity_id(0xE4));
    let b = CorpusId::from_entity_id(entity_id(0xE5));
    let floor = resolve_reader_filter(&vault, None)?;
    let narrowed = resolve_reader_filter(
        &vault,
        Some(&RetrievalFilter {
            min_confidence: Some(0.8),
            ..RetrievalFilter::default()
        }),
    )?;
    let trace = |authority, scope| {
        captured_retrieval_trace(
            &vault,
            vault
                .query()
                .search_text("authorityneedle", 1)
                .filter_types(&[ENTITY_TYPE_CLAIM])
                .authority_filter(authority)
                .corpus(scope)
                .with_temporal_now(10)
                .limit(1),
        )
    };
    let mut traces = Vec::new();
    for authority in [&floor, &narrowed] {
        for scope in [CorpusScope::Corpus(a), CorpusScope::AnyOf(vec![a, b])] {
            traces.push(trace(authority.clone(), scope)?);
        }
    }
    assert!(!traces[0].final_stage.candidates.is_empty());
    for current in &traces {
        assert_eq!(current.per_channel, traces[0].per_channel);
        assert_eq!(current.fused, traces[0].fused);
        assert_eq!(current.blended, traces[0].blended);
        assert_eq!(current.final_stage, traces[0].final_stage);
    }
    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.fork_hash)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let equivalent = trace(narrowed, CorpusScope::AnyOf(vec![b, a, b]))?;
    assert_eq!(equivalent.fork_hash, traces[3].fork_hash);
    Ok(())
}
