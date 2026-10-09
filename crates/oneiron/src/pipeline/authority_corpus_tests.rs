//! Current-main corpus channels and ONE-1388 authority must narrow together.

use super::*;
use crate::corpus::CorpusScope;
use crate::pipeline::tests::captured_retrieval_trace;
use crate::store::RetrievalSignal;
use crate::temporal::{TemporalAnchorMode, TimeRange};

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn put_authority_corpus_claims(
        vault: &Vault,
        selected: EntityId,
    ) -> Result<EntityId> {
        let other = entity_id(0xE5);
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
            body.scope_project = corpus;
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
}
use tests::put_authority_corpus_claims;

#[test]
fn authority_and_corpus_conjoin_before_channel_limits_and_trace() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let selected = entity_id(0xE4);
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
