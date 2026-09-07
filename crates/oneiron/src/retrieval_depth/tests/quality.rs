use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::*;
use crate::TimeRange;
use crate::claim::ScopedReadActorKey;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::retrieval_quality::{
    ConfidenceAdjustment, PprCacheOutcome, RetrievalDegradation, RetrievalQuality,
};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn request<'a>(probe: SearchProbe, effort: Effort) -> DepthSearchRequest<'a> {
    DepthSearchRequest {
        probe,
        effort,
        limit: 10,
        session_scope: None,
        lease: None,
        backend: None,
        token_budget: None,
    }
}

fn text_request<'a>(effort: Effort) -> DepthSearchRequest<'a> {
    request(
        SearchProbe::Text {
            query: "qualitydepth".to_owned(),
        },
        effort,
    )
}

fn put_text(vault: &Vault, byte: u8, text: &str) -> Result<EntityId> {
    let id = entity(byte);
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .commit()?;
    Ok(id)
}

fn score_bits(hits: &[ScoredEntity]) -> Vec<(EntityId, u32)> {
    hits.iter()
        .map(|hit| (hit.id, hit.score.to_bits()))
        .collect()
}

#[test]
fn retrieval_quality_depth_minimal_records_completed_empty_channels() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    for (probe, signal) in [
        (
            SearchProbe::Text {
                query: "absentqualitydepth".to_owned(),
            },
            RetrievalSignal::Text,
        ),
        (
            SearchProbe::Vector {
                embedding: vec![1.0, 0.0, 0.0, 0.0],
                query_text: None,
            },
            RetrievalSignal::Vector,
        ),
    ] {
        let result = scoped.search_with_effort(&request(probe, Effort::Minimal))?;
        assert!(result.hits.is_empty());
        assert_eq!(result.retrieval_diagnostics.attempted, vec![signal]);
        assert_eq!(result.retrieval_diagnostics.succeeded, vec![signal]);
        assert_eq!(result.retrieval_diagnostics.ppr_cache, None);
        assert_eq!(
            result.retrieval_quality.quality,
            RetrievalQuality::Passthrough
        );
        assert!(result.retrieval_quality.degradation.is_empty());
        assert_eq!(
            result.retrieval_quality.confidence_adjustment,
            ConfidenceAdjustment::PASSTHROUGH
        );
        assert!(!result.backend_used);
        assert_eq!(result.tokens_used, 0);
    }
    Ok(())
}

#[test]
fn retrieval_quality_depth_minimal_preserves_direct_score_bits_and_order() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let first = put_text(&vault, 0x61, "qualitydepth qualitydepth")?;
    let second = put_text(&vault, 0x62, "qualitydepth other")?;
    vault.put_vector(&first, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&second, &[0.8, 0.2, 0.0, 0.0])?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let text = scoped.search_text("qualitydepth", 10, None)?;
    let result = scoped.search_with_effort(&text_request(Effort::Minimal))?;
    assert!(!text.is_empty());
    assert_eq!(score_bits(&result.hits), score_bits(&text));
    let vector = vec![1.0, 0.0, 0.0, 0.0];
    let direct = scoped.search_vector(&vector, 10, None)?;
    let result = scoped.search_with_effort(&request(
        SearchProbe::Vector {
            embedding: vector,
            query_text: None,
        },
        Effort::Minimal,
    ))?;
    assert_eq!(score_bits(&result.hits), score_bits(&direct));
    Ok(())
}

#[test]
fn retrieval_quality_depth_standard_uses_real_disabled_ppr_without_false_miss() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = put_text(&vault, 0x63, "qualitydepth")?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let direct = scoped.search_text("qualitydepth", 10, None)?;
    assert_eq!(direct.len(), 1);
    let expanded = {
        let txn = vault.store.env.read_txn()?;
        crate::ppr::ppr_query_scoped_in_txn(
            &vault.store,
            &txn,
            &[seed],
            STANDARD_PPR_DEPTH,
            STANDARD_PPR_ALPHA,
            vault.config.ppr_vad_alpha,
            SeedWeighting::Specificity,
            &scoped,
        )?
    };
    let expected = direct[0]
        .score
        .max(expanded.iter().find(|hit| hit.id == seed).unwrap().score);
    let result = scoped.search_with_effort(&text_request(Effort::Standard))?;
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].id, seed);
    assert_eq!(result.hits[0].score.to_bits(), expected.to_bits());
    assert_eq!(
        result.retrieval_diagnostics.attempted,
        vec![RetrievalSignal::Text, RetrievalSignal::Ppr]
    );
    assert_eq!(
        result.retrieval_diagnostics.succeeded,
        result.retrieval_diagnostics.attempted
    );
    assert_eq!(
        result.retrieval_diagnostics.ppr_cache,
        Some(PprCacheOutcome::Disabled)
    );
    assert_eq!(result.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert!(result.retrieval_quality.degradation.is_empty());
    assert_eq!(
        result.retrieval_quality.confidence_adjustment,
        ConfidenceAdjustment::DEGRADED
    );
    let txn = vault.store.env.read_txn()?;
    assert_eq!(vault.store.ppr_cache.len(&txn)?, 0);
    Ok(())
}

#[test]
fn retrieval_quality_depth_empty_standard_does_not_invent_graph_or_full_completion() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let result = scoped.search_with_effort(&request(
        SearchProbe::Text {
            query: "absentqualitydepth anotherabsenttoken".to_owned(),
        },
        Effort::Standard,
    ))?;
    assert!(result.hits.is_empty());
    assert!(result.queries_run.len() > 1);
    assert_eq!(
        result.retrieval_diagnostics.attempted,
        vec![RetrievalSignal::Text]
    );
    assert_eq!(
        result.retrieval_diagnostics.succeeded,
        vec![RetrievalSignal::Text]
    );
    assert_eq!(result.retrieval_diagnostics.ppr_cache, None);
    assert_eq!(
        result.retrieval_quality.quality,
        RetrievalQuality::Passthrough
    );
    assert!(result.retrieval_quality.degradation.is_empty());
    Ok(())
}

struct ReverseBackend {
    lease_id: String,
    decompose_calls: AtomicUsize,
    rerank_calls: AtomicUsize,
    only_candidate: Option<EntityId>,
}

impl DeepSearchBackend for ReverseBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        assert_eq!(lease.id(), self.lease_id);
        self.decompose_calls.fetch_add(1, Ordering::SeqCst);
        Ok(BackendSpend {
            value: Vec::new(),
            tokens_used: 3,
        })
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate<'_>],
        _token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        assert_eq!(lease.id(), self.lease_id);
        self.rerank_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(only) = self.only_candidate {
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].id, only);
        }
        Ok(BackendSpend {
            value: (0..candidates.len()).map(|index| index as f32).collect(),
            tokens_used: 5,
        })
    }
}

#[test]
fn retrieval_quality_depth_deep_tracks_rerank_without_rewriting_engine_scores() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    put_text(&vault, 0x64, "qualitydepth qualitydepth")?;
    put_text(&vault, 0x65, "qualitydepth other")?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let standard = scoped.search_with_effort(&text_request(Effort::Standard))?;
    assert_eq!(standard.hits.len(), 2);
    let guard =
        BudgetGuard::with_reserve_units("depth-quality", 100, 10, BudgetExhaustionPolicy::Suspend);
    let admission = guard.admit().unwrap();
    let backend = ReverseBackend {
        lease_id: admission.lease.id().to_owned(),
        decompose_calls: AtomicUsize::new(0),
        rerank_calls: AtomicUsize::new(0),
        only_candidate: None,
    };
    let mut deep = text_request(Effort::Deep);
    deep.lease = Some(&admission.lease);
    deep.backend = Some(&backend);
    let result = scoped.search_with_effort(&deep)?;
    let mut expected = score_bits(&standard.hits);
    expected.reverse();
    assert_eq!(score_bits(&result.hits), expected);
    assert_eq!(result.retrieval_quality, standard.retrieval_quality);
    assert_eq!(
        result.retrieval_diagnostics.attempted,
        vec![
            RetrievalSignal::Text,
            RetrievalSignal::Ppr,
            RetrievalSignal::Rerank
        ]
    );
    assert_eq!(
        result.retrieval_diagnostics.succeeded,
        result.retrieval_diagnostics.attempted
    );
    assert!(result.backend_used);
    assert_eq!(result.tokens_used, 8);
    assert_eq!(backend.decompose_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.rerank_calls.load(Ordering::SeqCst), 1);
    guard
        .settle_usage(&admission.lease, result.tokens_used)
        .unwrap();
    assert_eq!(guard.read().used_units, 8);
    assert_eq!(guard.read().reserved_units, 0);
    Ok(())
}

#[test]
fn retrieval_quality_depth_session_narrows_before_backend_and_diagnostics() -> TestResult {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let included = put_text(&vault, 0x66, "qualitydepth")?;
    put_text(&vault, 0x67, "qualitydepth qualitydepth")?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let guard = BudgetGuard::with_reserve_units(
        "scoped-depth-quality",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
    );
    let admission = guard.admit().unwrap();
    let backend = ReverseBackend {
        lease_id: admission.lease.id().to_owned(),
        decompose_calls: AtomicUsize::new(0),
        rerank_calls: AtomicUsize::new(0),
        only_candidate: Some(included),
    };
    let scope = SessionScope {
        document_short_ids: vec![short_ref_or_hex(&vault, &included)?],
        ..Default::default()
    };
    let mut deep = text_request(Effort::Deep);
    deep.limit = 1;
    deep.session_scope = Some(&scope);
    deep.lease = Some(&admission.lease);
    deep.backend = Some(&backend);
    let result = scoped.search_with_effort(&deep)?;
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].id, included);
    assert_eq!(result.retrieval_quality.quality, RetrievalQuality::Degraded);
    assert!(result.retrieval_quality.degradation.is_empty());
    guard
        .settle_usage(&admission.lease, result.tokens_used)
        .unwrap();
    Ok(())
}

#[test]
fn retrieval_quality_depth_report_finish_preserves_full_and_degraded_no_data() {
    // Projection boundary fixture, not a claim that the frozen depth executor
    // runs all five channels. A healthy empty result must keep its supplied facts.
    let channels = vec![
        RetrievalSignal::Vector,
        RetrievalSignal::Text,
        RetrievalSignal::Phonetic,
        RetrievalSignal::Temporal,
        RetrievalSignal::Ppr,
    ];
    let mut full = DepthAccumulator::default();
    let mut degraded = DepthAccumulator::default();
    for signal in channels {
        full.attempt(signal);
        full.complete(signal);
        degraded.attempt(signal);
        degraded.complete(signal);
    }
    full.retrieval_diagnostics.ppr_cache = Some(PprCacheOutcome::Hit);
    degraded.retrieval_diagnostics.ppr_cache = Some(PprCacheOutcome::Miss);
    let full = full.finish(10);
    let degraded = degraded.finish(10);
    assert!(full.hits.is_empty());
    assert!(degraded.hits.is_empty());
    assert_eq!(full.retrieval_quality.quality, RetrievalQuality::Full);
    assert_eq!(
        full.retrieval_quality.confidence_adjustment,
        ConfidenceAdjustment::FULL
    );
    assert!(full.retrieval_quality.degradation.is_empty());
    assert_eq!(
        degraded.retrieval_quality.quality,
        RetrievalQuality::Degraded
    );
    assert_eq!(
        degraded.retrieval_quality.degradation,
        vec![RetrievalDegradation::PprCacheMiss]
    );
}

#[test]
fn retrieval_quality_depth_deep_still_refuses_missing_lease_before_channels() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let scoped = vault.scoped_read(ScopedReadActorKey::new("depth-reader").unwrap());
    let error = scoped
        .search_with_effort(&text_request(Effort::Deep))
        .unwrap_err();
    assert!(error.to_string().contains(MEMORY_CODE_LEASE_REQUIRED));
    assert_eq!(error.tokens_used, 0);
}

#[test]
fn retrieval_quality_depth_budget_usage_is_additive_and_idempotent() {
    let guard = BudgetGuard::with_reserve_units(
        "depth-quality-settlement",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
    );
    let first = guard.admit().unwrap();
    let second = guard.admit().unwrap();
    guard.settle_usage(&first.lease, 3).unwrap();
    guard.settle_usage(&second.lease, 5).unwrap();
    guard.settle_usage(&first.lease, 3).unwrap();
    assert_eq!(guard.read().used_units, 8);
    assert_eq!(guard.read().reserved_units, 0);
}
