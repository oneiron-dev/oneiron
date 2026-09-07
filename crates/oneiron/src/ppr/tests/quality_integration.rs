use super::*;
use crate::ppr_community::CommunityBoostContext;
use crate::retrieval_quality::{RetrievalDegradation, RetrievalQuality};

#[test]
fn retrieval_quality_community_vad_diagnostics_preserve_score_adapter_and_cache_state() -> Result<()>
{
    for beta in [0.0, 0.2] {
        for alpha in [0.0, 0.4] {
            let mut config = embedding_test_config();
            config.ppr_community.beta = beta;
            config.ppr_vad_alpha = alpha;
            let (_dir, vault) = open_test_vault_with(config);
            community_store_for_quality(&vault)?;
            let usage = HashMap::new();
            let evidence = [ScoredEntity {
                id: entity(1),
                score: 1.0,
            }];
            let context = CommunityBoostContext {
                ordered_seeds: &evidence,
                result_limit: 10,
                session_usage: &usage,
            };
            let seeds = [entity(1)];
            let request = || CommunityPprRequest {
                seeds: &seeds,
                depth: 1,
                teleport_alpha: 0.15,
                weighting: SeedWeighting::Uniform,
                config: &vault.config,
                context: &context,
            };
            let cold = {
                let txn = vault.store.env.read_txn()?;
                let (cold, _) =
                    ppr_expand_in_txn_with_community_diagnostics(&vault.store, &txn, request())?;
                let (scores, _, _) =
                    ppr_expand_in_txn_with_community_deferred_cache(&vault.store, &txn, request())?;
                assert_eq!(cold.cache, PprCacheOutcome::Miss);
                assert_eq!(score_bits(&cold.scores), score_bits(&scores));
                cold
            };
            flush_deferred_ppr_cache_writes(
                &vault.store,
                &[cold.deferred_cache_write.expect("cold cache write")],
            )?;
            let txn = vault.store.env.read_txn()?;
            let (warm, _) =
                ppr_expand_in_txn_with_community_diagnostics(&vault.store, &txn, request())?;
            assert_eq!(warm.cache, PprCacheOutcome::Hit);
            assert!(warm.deferred_cache_write.is_none());
            assert_eq!(score_bits(&warm.scores), score_bits(&cold.scores));
        }
    }
    Ok(())
}

fn community_store_for_quality(vault: &Vault) -> Result<()> {
    community_ppr_fixture(vault)?;
    vault.put_edge(&entity(1), EdgeKind::Mentions, &entity(2), 1.0)?;
    vault.set_edge_vad(
        &entity(1),
        EdgeKind::Mentions,
        &entity(2),
        Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    Ok(())
}

#[test]
fn retrieval_quality_community_pipeline_reports_actual_cache_without_changing_scores() -> Result<()>
{
    let mut config = embedding_test_config();
    config.ppr_community.beta = 0.2;
    config.ppr_vad_alpha = 0.4;
    let (_dir, vault) = open_test_vault_with(config);
    community_store_for_quality(&vault)?;
    vault
        .batch()
        .text(&entity(1), &[("body", "qualitycommunity")])
        .commit()?;
    let query = || {
        vault
            .query()
            .search_text("qualitycommunity", 10)
            .expand_ppr(&[entity(1)], 1)
            .with_temporal_now(1)
            .limit(10)
    };
    let cold = query().run_with_telemetry()?;
    let warm = query().run_with_telemetry()?;
    assert!(!cold.value.is_empty());
    assert_eq!(score_bits(&cold.value), score_bits(&warm.value));
    assert_eq!(cold.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert_eq!(warm.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert_eq!(
        cold.retrieval_quality.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
    assert!(warm.retrieval_quality.degradation.is_empty());
    Ok(())
}
