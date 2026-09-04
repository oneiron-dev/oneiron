use std::collections::{HashMap, HashSet};
use std::time::Instant;

use heed::RoTxn;

use crate::bm25::Bm25Config;
use crate::claim::ClaimBody;
use crate::context_pack::EmptyReason;
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::fusion;
use crate::query_expansion::{
    CompletionCandidate, CompletionRequest, EvidenceVerdict, HydeRequest, ground_query,
    normalized_subqueries, retry_channel_limit,
};
use crate::rerank::RerankCandidate;
use crate::store::{
    RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTrace, RetrievalTraceChannelRecord, RetrievalTraceStage, Store,
};
use crate::temporal::{TemporalExpressionParseError, temporal_expression_from_query};

use super::blend::{
    AccessFactorApplication, RetrievalBlendConfig, RetrievalChannelIndexes,
    blended_retrieval_scores, boost_contiguity, filter_blended_scores_to_allowed_ids,
    retrieval_blend_weights_for_scoring, score_id_set,
};
use super::budget::{apply_context_pack_retrieval_budget, context_pack_evidence_abstains};
use super::builder::PipelineBuilder;
use super::channels::{
    execute_phonetic, execute_temporal, scoped_entity_channel_limit, scoped_text_channel_limit,
    scoped_vector_channel_limit, truncate_widened_channel_results_to_scope,
};
use super::filters::{
    apply_claim_status_gate, apply_corpus_filter, apply_facet_filter, apply_filters,
    apply_relationship_filter, apply_world_filter, claim_status_gate_allows,
    import_claim_gate_decisions_for_scores, pipeline_candidate_matches_filters_and_gate,
};
use super::support::normalize_range;
use super::trace::{
    add_signal_score_components, filter_retrieval_trace_scores, retrieval_trace_candidate_set,
    retrieval_trace_channel_record, retrieval_trace_fork_hash, retrieval_trace_fused_scores,
    retrieval_trace_stage_record, retrieval_trace_top_scores, telemetry_score_breakdown,
};
use super::types::{
    ClaimStatusGateCache, EntityMetadataCache, FacetMode, PER_SCAN_CAP_FACTOR, PPR_DAMPING,
    PendingVectorEmbedding, PipelineFilterConfig, PipelineOutput, RelMode, ScoredEntity,
    WorldScope,
};

/// Detailed pipeline output for the context-pack path.
///
/// `claim_bodies` carries every claim body decoded (once) by the D19 gate
/// that PASSED it; `claims_suppressed` counts the unique type-0 records the
/// gate excluded (status-failed or undecodable). Bodies were decoded under
/// the pipeline's read transaction; the context pack hydrates under a fresh
/// transaction, so reusing them keeps projection consistent with the gate
/// decision (the same seam the score/hydration split already has).
struct HydeAttemptOverrides<'a> {
    widen_channel_limits: bool,
    extra_text_queries: &'a [String],
    skip_ret01_abstain: bool,
}

struct RetrievalTxnOutput {
    scores: Vec<ScoredEntity>,
    pending_vectors: Vec<PendingVectorEmbedding>,
    claim_gate: ClaimStatusGateCache,
    deferred_ppr_cache_writes: Vec<crate::ppr::DeferredPprCacheWrite>,
    cosine_ghosts_dampened: usize,
    total_in_scope: usize,
    empty_reason: Option<EmptyReason>,
    signal_components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    /// The applied read-side multiplier per candidate, from the run's
    /// single decay-applying blend. Empty when no blend ran.
    access_factors: HashMap<EntityId, f32>,
    rerank_merged_components: Option<HashMap<EntityId, Vec<RetrievalScoreComponent>>>,
    retrieval_trace: Option<RetrievalTrace>,
    ppr_expand_executed: bool,
    early_empty_no_telemetry: bool,
}

impl PipelineBuilder<'_> {
    #[expect(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_retrieval_txn_attempt(
        &self,
        occurred_range: Option<(u64, u64)>,
        bm25_config: &Bm25Config,
        rerank_query: Option<&str>,
        hyde_expansion: Option<&crate::query_expansion::HydeExpansion>,
        temporal_now: u64,
        recency: Option<u64>,
        explicit_time_dependent_now: Option<u64>,
        overrides: HydeAttemptOverrides<'_>,
    ) -> Result<RetrievalTxnOutput> {
        let no_data_fallback_eligible = self.no_data_fallback_eligible();
        let mut ppr_expand_executed = false;
        let capture_retrieval_trace = self.capture_retrieval_trace;
        let trace_candidate_limit = self.result_limit;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }
        {
            let mut ranked_lists = Vec::new();
            let mut signal_components = HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
            let mut trace_channels = Vec::<RetrievalTraceChannelRecord>::new();
            let mut trace_ranked_lists = Vec::<Vec<ScoredEntity>>::new();
            let mut trace_claim_gate = ClaimStatusGateCache::default();
            let mut fused_trace_scores = None;
            let mut blended_trace_scores = None;
            let mut vector_channel_index = None;
            let mut text_channel_index = None;
            let rtxn = self.vault.store.env.read_txn()?;
            let blend_weights = retrieval_blend_weights_for_scoring(&self.vault.store, &rtxn)?;
            let mut metadata_cache = EntityMetadataCache::default();
            let mut claim_gate = ClaimStatusGateCache::default();
            let mut deferred_ppr_cache_writes = Vec::new();
            let codebase_scope_active = self.has_codebase_scope_filter();
            // ONE-1914: canonicalize the audience scope ONCE per run, before
            // the first candidate is scanned, so the candidate-scan conjunct
            // stays a pure predicate and an empty `AnyOf` fails the run closed
            // on that path exactly as it does post-fusion.
            let corpus_scope = self.corpus_scope.clone().canonicalize()?;
            let filter_config = PipelineFilterConfig {
                type_filter: self.type_filter.as_deref(),
                since_filter: self.since_filter,
                occurred_range,
                learned_range: self.learned_range,
                repo_ref_filter: self.repo_ref_filter.as_ref(),
                project_id_filter: self.project_id_filter.as_deref(),
                facet_filter: self.facet_filter,
                relationship_filter: self.relationship_filter,
                world_scope: self.world_scope,
                corpus_scope: &corpus_scope,
            };
            // D19 is always active. For final-token prefix queries, a dead
            // claim can outrank a live prefix hit in BM25, then be removed
            // after fusion; overfetch prevents that dead hit from consuming
            // the only text-channel slot. Live exact claims already satisfy
            // the D19 gate, so they must not widen ordinary
            // `search_text(..., limit)` calls.
            let mut claim_gate_widening_probe = ClaimStatusGateCache::default();
            let claim_gate_text_widening_active = if let Some((query, limit)) = &self.text_search
                && *limit > 0
            {
                let text_query = hyde_expansion.as_ref().map_or(query.as_str(), |expansion| {
                    expansion.grounded_query.as_str()
                });
                let exact_posting_fails_claim_gate = {
                    let mut exact_posting_fails_claim_gate = |id: &EntityId| {
                        claim_status_gate_allows(
                            &self.vault.store,
                            &rtxn,
                            id,
                            &mut metadata_cache,
                            &mut claim_gate_widening_probe,
                        )
                        .map(|allowed| !allowed)
                    };
                    crate::bm25::final_token_exact_posting_matches(
                        &self.vault.store,
                        &rtxn,
                        &self.vault.analyzer,
                        bm25_config,
                        text_query,
                        &mut exact_posting_fails_claim_gate,
                    )?
                };
                if exact_posting_fails_claim_gate {
                    true
                } else {
                    let mut classify_prefix_posting = |id: &EntityId| {
                        let rejected_by_gate = !claim_status_gate_allows(
                            &self.vault.store,
                            &rtxn,
                            id,
                            &mut metadata_cache,
                            &mut claim_gate_widening_probe,
                        )?;
                        let matches_scope = !rejected_by_gate
                            && pipeline_candidate_matches_filters_and_gate(
                                &self.vault.store,
                                &rtxn,
                                id,
                                filter_config,
                                &mut metadata_cache,
                                &mut claim_gate_widening_probe,
                            )?;
                        Ok(crate::bm25::PrefixExpansionPostingDecision {
                            matches_scope,
                            rejected_by_gate,
                        })
                    };
                    crate::bm25::final_token_prefix_expansion_has_scoped_and_rejected_postings(
                        &self.vault.store,
                        &rtxn,
                        &self.vault.analyzer,
                        bm25_config,
                        text_query,
                        &mut classify_prefix_posting,
                    )?
                }
            } else {
                false
            };
            let text_scope_widening_active = codebase_scope_active
                || self.has_strict_text_scope_filter()
                || occurred_range.is_some()
                || claim_gate_text_widening_active;

            if let Some((query_vector, limit)) = &self.vector_search {
                // EMB-2: a `fast_dims`-length query is a first-class prefix
                // query on the funnel read path.
                if query_vector.len() != self.vault.config.dimensions
                    && self.vault.config.fast_dims.map(usize::from) != Some(query_vector.len())
                {
                    return Err(Error::DimensionMismatch {
                        expected: self.vault.config.dimensions,
                        got: query_vector.len(),
                    });
                }
                if let Some(error) = Error::invalid_vector_component(query_vector) {
                    return Err(error);
                }

                let channel_limit = scoped_vector_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(*limit)
                    } else {
                        *limit
                    },
                    codebase_scope_active,
                )?;
                let vector_results = crate::hnsw::hnsw_search(
                    &self.vault.store,
                    &self.vault.config,
                    &rtxn,
                    query_vector,
                    channel_limit,
                    self.skip_vector_rescore,
                )?;
                let mut vector_probe_claim_gate = ClaimStatusGateCache::default();
                import_claim_gate_decisions_for_scores(
                    &mut claim_gate,
                    &mut vector_probe_claim_gate,
                    &vector_results,
                );
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Vector,
                    &vector_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &vector_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Vector,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                vector_channel_index = Some(ranked_lists.len());
                ranked_lists.push(vector_results);
            }

            if let Some(expansion) = hyde_expansion.as_ref() {
                let limit = self
                    .hyde
                    .as_ref()
                    .expect("hyde expansion has config")
                    .2
                    .channel_limit;
                let channel_limit = scoped_vector_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(limit)
                    } else {
                        limit
                    },
                    codebase_scope_active,
                )?;
                let hyde_results = crate::hnsw::hnsw_search(
                    &self.vault.store,
                    &self.vault.config,
                    &rtxn,
                    &expansion.embedding,
                    channel_limit,
                    self.skip_vector_rescore,
                )?;
                let mut hyde_probe_claim_gate = ClaimStatusGateCache::default();
                import_claim_gate_decisions_for_scores(
                    &mut claim_gate,
                    &mut hyde_probe_claim_gate,
                    &hyde_results,
                );
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Hyde,
                    &hyde_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &hyde_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Hyde,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                ranked_lists.push(hyde_results);
            }

            if let Some((query, limit)) = &self.text_search {
                let scoped_text_limit = scoped_text_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(*limit)
                    } else {
                        *limit
                    },
                    text_scope_widening_active,
                )?;
                let text_channel_limit = if recency.is_some() {
                    scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
                } else {
                    scoped_text_limit
                };
                let mut prefix_probe_claim_gate = claim_gate_widening_probe;
                let mut exact_posting_matches_scope = |id: &EntityId| {
                    pipeline_candidate_matches_filters_and_gate(
                        &self.vault.store,
                        &rtxn,
                        id,
                        filter_config,
                        &mut metadata_cache,
                        &mut prefix_probe_claim_gate,
                    )
                };
                let text_query = hyde_expansion.as_ref().map_or(query.as_str(), |expansion| {
                    expansion.grounded_query.as_str()
                });
                let mut text_results = crate::bm25::search_text_scoped_with_recency(
                    &self.vault.store,
                    &rtxn,
                    &self.vault.analyzer,
                    bm25_config,
                    text_query,
                    text_channel_limit,
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut exact_posting_matches_scope,
                    },
                )?;
                if text_channel_limit > *limit && text_scope_widening_active {
                    let scoped_result_limit = if recency.is_some() {
                        limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                    } else {
                        *limit
                    };
                    truncate_widened_channel_results_to_scope(
                        &mut text_results,
                        &self.vault.store,
                        &rtxn,
                        scoped_result_limit,
                        filter_config,
                        &mut metadata_cache,
                        &mut prefix_probe_claim_gate,
                    )?;
                }
                import_claim_gate_decisions_for_scores(
                    &mut claim_gate,
                    &mut prefix_probe_claim_gate,
                    &text_results,
                );
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Text,
                    &text_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &text_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Text,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                text_channel_index = Some(ranked_lists.len());
                ranked_lists.push(text_results);
                for query in overrides.extra_text_queries {
                    let retry_scoped_text_limit = scoped_text_channel_limit(
                        &self.vault.store,
                        &rtxn,
                        retry_channel_limit(*limit),
                        text_scope_widening_active,
                    )?;
                    let retry_text_channel_limit = if recency.is_some() {
                        retry_scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
                    } else {
                        retry_scoped_text_limit
                    };
                    let mut retry_prefix_probe_claim_gate = ClaimStatusGateCache::default();
                    let mut retry_exact_posting_matches_scope = |id: &EntityId| {
                        pipeline_candidate_matches_filters_and_gate(
                            &self.vault.store,
                            &rtxn,
                            id,
                            filter_config,
                            &mut metadata_cache,
                            &mut retry_prefix_probe_claim_gate,
                        )
                    };
                    let mut results = crate::bm25::search_text_scoped_with_recency(
                        &self.vault.store,
                        &rtxn,
                        &self.vault.analyzer,
                        bm25_config,
                        query,
                        retry_text_channel_limit,
                        crate::bm25::Bm25SearchOptions {
                            recency: None,
                            exact_posting_matches_scope: &mut retry_exact_posting_matches_scope,
                        },
                    )?;
                    if retry_text_channel_limit > *limit && text_scope_widening_active {
                        let scoped_result_limit = if recency.is_some() {
                            limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                        } else {
                            *limit
                        };
                        truncate_widened_channel_results_to_scope(
                            &mut results,
                            &self.vault.store,
                            &rtxn,
                            scoped_result_limit,
                            filter_config,
                            &mut metadata_cache,
                            &mut retry_prefix_probe_claim_gate,
                        )?;
                    }
                    import_claim_gate_decisions_for_scores(
                        &mut claim_gate,
                        &mut retry_prefix_probe_claim_gate,
                        &results,
                    );
                    add_signal_score_components(
                        &mut signal_components,
                        RetrievalSignal::Text,
                        &results,
                    );
                    if capture_retrieval_trace {
                        let trace_results = filter_retrieval_trace_scores(
                            &results,
                            &self.vault.store,
                            &rtxn,
                            filter_config,
                            &mut metadata_cache,
                            &mut trace_claim_gate,
                            trace_candidate_limit,
                        )?;
                        trace_channels.push(retrieval_trace_channel_record(
                            RetrievalSignal::HydeRetry,
                            &trace_results,
                            trace_candidate_limit,
                        ));
                        trace_ranked_lists.push(trace_results);
                    }
                    ranked_lists.push(results);
                }
            }

            if let Some(codes) = &self.phonetic_search {
                let phonetic_results = execute_phonetic(&self.vault.store, &rtxn, codes)?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Phonetic,
                    &phonetic_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &phonetic_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Phonetic,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                ranked_lists.push(phonetic_results);
            }

            if let Some(config) = &self.temporal_search {
                let mut scoped_config = config.clone();
                scoped_config.limit = scoped_entity_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(config.limit)
                    } else {
                        config.limit
                    },
                    codebase_scope_active,
                )?;
                let temporal_results = execute_temporal(
                    &self.vault.store,
                    &rtxn,
                    &scoped_config,
                    temporal_now,
                    &mut metadata_cache,
                )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Temporal,
                    &temporal_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &temporal_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Temporal,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                ranked_lists.push(temporal_results);
            }

            if let Some((seeds, depth)) = &self.ppr_search {
                // ARCH-0039 Layer 2: seed specificity applies ONLY to
                // search_ppr — seeds are weighted 1/ln(1 + passage_count)
                // instead of uniform 1/n.
                let (ppr_results, deferred_cache_write) =
                    crate::ppr::ppr_query_in_txn_with_deferred_cache(
                        &self.vault.store,
                        &rtxn,
                        seeds,
                        *depth,
                        PPR_DAMPING,
                        crate::ppr::SeedWeighting::Specificity,
                    )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Ppr,
                    &ppr_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &ppr_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Ppr,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                if let Some(deferred_cache_write) = deferred_cache_write {
                    deferred_ppr_cache_writes.push(deferred_cache_write);
                }
                ranked_lists.push(ppr_results);
            }

            if ranked_lists.is_empty() {
                return Ok(RetrievalTxnOutput {
                    scores: Vec::new(),
                    pending_vectors: Vec::new(),
                    claim_gate: ClaimStatusGateCache::default(),
                    deferred_ppr_cache_writes: Vec::new(),
                    cosine_ghosts_dampened: 0,
                    total_in_scope: 0,
                    empty_reason: None,
                    signal_components: HashMap::new(),
                    blend_components: HashMap::new(),
                    access_factors: HashMap::new(),
                    rerank_merged_components: None,
                    retrieval_trace: None,
                    ppr_expand_executed: false,
                    early_empty_no_telemetry: true,
                });
            }

            // The run's single decay-applying blend config. Every other
            // blend call derives from it with `Deferred` substituted in.
            let blend_config = RetrievalBlendConfig {
                recency_now_secs: recency,
                salience: self.apply_salience,
                confidence: self.apply_confidence,
                gravity: self.apply_gravity,
                access_factor_overrides: self.access_factor_overrides,
                access_factor_application: AccessFactorApplication::Apply,
            };
            if capture_retrieval_trace {
                fused_trace_scores = Some(retrieval_trace_fused_scores(
                    &trace_ranked_lists,
                    trace_candidate_limit,
                ));
            }
            // The blend also populates read-side decay across the fused
            // union, sharing `claim_gate` so each claim body decodes once
            // and reusing the run's resolved clock so a frozen clock
            // replays bit-identically.
            //
            // With `expand_ppr` configured this pass is PRELIMINARY: its
            // scores only choose implicit expansion seeds, and the blend
            // below replaces them wholesale. Applying decay here would let
            // a faded claim lose a seed slot it would have won on
            // relevance — silently shrinking the reachable neighborhood —
            // and would then compound with the application on the blend
            // the run actually returns. So the factor is deferred to that
            // single blend.
            let first_blend = blended_retrieval_scores(
                &ranked_lists,
                RetrievalChannelIndexes {
                    vector: vector_channel_index,
                    text: text_channel_index,
                },
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
                RetrievalBlendConfig {
                    access_factor_application: if self.ppr_expand.is_some() {
                        AccessFactorApplication::Deferred
                    } else {
                        AccessFactorApplication::Apply
                    },
                    ..blend_config
                },
                temporal_now,
                blend_weights,
            )?;
            let mut scores = first_blend.scores;
            let mut cosine_ghosts_dampened = first_blend.cosine_ghosts_dampened;
            let mut blend_components = first_blend.components;
            // Both faces of whichever blend produced `scores`. They are
            // replaced together with `scores` below, so at the rerank hook
            // they always describe the run's single Apply blend.
            let mut blend_base_scores = first_blend.base_scores;
            let mut blend_access_factors = first_blend.access_factors;
            let total_in_scope = scores.len();
            let mut empty_reason = None;

            // D19 claim status gate, first application: covers the fused
            // union of every ranked list (vector/HyDE/text/HyDE-retry/
            // phonetic/temporal/PPR) AND runs BEFORE expand_ppr implicit
            // seed selection, so a dead claim never seeds the expansion.
            let before_status_gate = scores.len();
            apply_claim_status_gate(
                &mut scores,
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
            )?;
            if before_status_gate > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::AllActivated);
            }
            let mut blend_allowed_ids = score_id_set(&scores);

            // Implicit seed selection reads the PRELIMINARY blend above,
            // whose scores are decay-free, so seed choice depends only on
            // relevance. The D19 gate has already run, so a dead claim
            // still never seeds; decay simply does not participate.
            if let Some((explicit_seeds, depth)) = &self.ppr_expand {
                let mut seen = HashSet::<EntityId>::new();
                let mut seeds = Vec::<EntityId>::new();
                for seed in explicit_seeds {
                    if seen.insert(*seed) {
                        seeds.push(*seed);
                    }
                }
                if seeds.len() < crate::ppr::MAX_PPR_SEEDS {
                    let implicit_seed_limit = if codebase_scope_active {
                        scores.len()
                    } else {
                        self.result_limit
                    };
                    for scored in scores.iter().take(implicit_seed_limit) {
                        if seen.insert(scored.id) {
                            seeds.push(scored.id);
                            if seeds.len() == crate::ppr::MAX_PPR_SEEDS {
                                break;
                            }
                        }
                    }
                }

                if !seeds.is_empty() {
                    ppr_expand_executed = true;
                    seeds.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

                    // expand_ppr seeds stay UNIFORM — ARCH-0039 Layer-2
                    // specificity weighting is search_ppr-only.
                    let (mut ppr_results, deferred_cache_write) =
                        crate::ppr::ppr_query_in_txn_with_deferred_cache(
                            &self.vault.store,
                            &rtxn,
                            &seeds,
                            *depth,
                            PPR_DAMPING,
                            crate::ppr::SeedWeighting::Uniform,
                        )?;
                    if let Some(deferred_cache_write) = deferred_cache_write {
                        deferred_ppr_cache_writes.push(deferred_cache_write);
                    }
                    // D19 claim status gate, second application: PPR
                    // expansion walks the graph and can pull dead claims
                    // back into the candidate set — gate the expansion
                    // list before fusing it (memoized; claims already
                    // checked above cost nothing). Traversal THROUGH a
                    // dead claim node stays untouched in v1: only the
                    // result surface is gated.
                    apply_claim_status_gate(
                        &mut ppr_results,
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        &mut claim_gate,
                    )?;
                    add_signal_score_components(
                        &mut signal_components,
                        RetrievalSignal::Ppr,
                        &ppr_results,
                    );
                    if capture_retrieval_trace {
                        let trace_results = filter_retrieval_trace_scores(
                            &ppr_results,
                            &self.vault.store,
                            &rtxn,
                            filter_config,
                            &mut metadata_cache,
                            &mut trace_claim_gate,
                            trace_candidate_limit,
                        )?;
                        trace_channels.push(retrieval_trace_channel_record(
                            RetrievalSignal::Ppr,
                            &trace_results,
                            trace_candidate_limit,
                        ));
                        trace_ranked_lists.push(trace_results);
                    }
                    blend_allowed_ids.extend(ppr_results.iter().map(|scored| scored.id));
                    ranked_lists.push(ppr_results);
                    if capture_retrieval_trace {
                        fused_trace_scores = Some(retrieval_trace_fused_scores(
                            &trace_ranked_lists,
                            trace_candidate_limit,
                        ));
                    }
                    // The expanded blend is this run's ONE decay
                    // application: the seeds above were picked from the
                    // neutral preliminary order.
                    let expanded_blend = blended_retrieval_scores(
                        &ranked_lists,
                        RetrievalChannelIndexes {
                            vector: vector_channel_index,
                            text: text_channel_index,
                        },
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        &mut claim_gate,
                        blend_config,
                        temporal_now,
                        blend_weights,
                    )?;
                    scores = filter_blended_scores_to_allowed_ids(
                        expanded_blend.scores,
                        &blend_allowed_ids,
                    );
                    cosine_ghosts_dampened = expanded_blend.cosine_ghosts_dampened;
                    blend_components = expanded_blend.components;
                    blend_base_scores = expanded_blend.base_scores;
                    blend_access_factors = expanded_blend.access_factors;
                } else {
                    // Configured but unseeded: the preliminary blend
                    // deferred the factor, so the run still owes exactly
                    // one Apply blend. Re-blend the UNCHANGED ranked lists
                    // and take every output the expanded branch takes, so
                    // the single-application invariant is structural
                    // rather than an accident of which branch ran. The
                    // ranked lists did not move, so this reproduces the
                    // plain (no `expand_ppr`) run bit for bit, and the
                    // allowed-id filter keeps a gate-dropped claim from
                    // resurfacing through the re-fuse.
                    let applied_blend = blended_retrieval_scores(
                        &ranked_lists,
                        RetrievalChannelIndexes {
                            vector: vector_channel_index,
                            text: text_channel_index,
                        },
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        &mut claim_gate,
                        blend_config,
                        temporal_now,
                        blend_weights,
                    )?;
                    scores = filter_blended_scores_to_allowed_ids(
                        applied_blend.scores,
                        &blend_allowed_ids,
                    );
                    cosine_ghosts_dampened = applied_blend.cosine_ghosts_dampened;
                    blend_components = applied_blend.components;
                    blend_base_scores = applied_blend.base_scores;
                    blend_access_factors = applied_blend.access_factors;
                }
            }

            let before_filters = scores.len();
            apply_filters(
                &mut scores,
                &self.vault.store,
                &rtxn,
                filter_config,
                &mut metadata_cache,
            )?;
            if before_filters > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }

            // Reranking needs the score ladder after post-blend boosts but
            // before access-factor application. Replay those multiplicative
            // boosts over the blend's base-score face so a reassigned rung
            // never carries its previous occupant's factor.
            let mut rerank_ladder_scores = if self.rerank.is_some() {
                let mut ladder_scores = Vec::with_capacity(scores.len());
                for scored in &scores {
                    let Some(base_score) = blend_base_scores.get(&scored.id).copied() else {
                        return Err(Error::InvariantViolation(
                            "rerank candidate missing its blended base score",
                        ));
                    };
                    ladder_scores.push(ScoredEntity {
                        id: scored.id,
                        score: base_score,
                    });
                }
                Some(ladder_scores)
            } else {
                None
            };

            if self.apply_contiguity {
                boost_contiguity(
                    &mut scores,
                    self.temporal_search.as_ref(),
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                )?;
                if let Some(ladder_scores) = rerank_ladder_scores.as_mut() {
                    boost_contiguity(
                        ladder_scores,
                        self.temporal_search.as_ref(),
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                    )?;
                }
            }

            // ARCH-0039 facet filter (ONE-1117): post-fusion / post-boosts,
            // before truncate, same read txn — strict-excluded claims never
            // consume `result_limit` slots.
            if let Some((facet_id, mode)) = self.facet_filter {
                let before_facet = scores.len();
                apply_facet_filter(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    &facet_id,
                    mode,
                )?;
                if let Some(ladder_scores) = rerank_ladder_scores.as_mut() {
                    apply_facet_filter(
                        ladder_scores,
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        &facet_id,
                        mode,
                    )?;
                }
                if before_facet > 0 && scores.is_empty() {
                    empty_reason = Some(EmptyReason::FilterMatchedNone);
                }
            }

            // ARCH-0004 world filter (ONE-1117): same post-fusion stage as the
            // facet filter, before truncate, same read txn. A no-op under the
            // default `WorldScope::All`.
            let before_world = scores.len();
            apply_world_filter(&mut scores, &self.vault.store, &rtxn, self.world_scope)?;
            if before_world > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }

            // ONE-1914 corpus filter: the audience scope, immediately after
            // the epistemic one and still before truncate, same read txn. A
            // no-op under the default `CorpusScope::All`.
            let before_corpus = scores.len();
            apply_corpus_filter(&mut scores, &self.vault.store, &rtxn, &corpus_scope)?;
            if before_corpus > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }
            if let Some((relationship, RelMode::Filter)) = self.relationship_filter {
                let before_relationship = scores.len();
                apply_relationship_filter(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    &relationship,
                    RelMode::Filter,
                )?;
                if before_relationship > 0 && scores.is_empty() {
                    empty_reason = Some(EmptyReason::FilterMatchedNone);
                }
            }
            if capture_retrieval_trace {
                blended_trace_scores =
                    Some(retrieval_trace_top_scores(&scores, trace_candidate_limit));
            }
            let rerank_ladder_scores = rerank_ladder_scores.map(|ladder_scores| {
                ladder_scores
                    .into_iter()
                    .map(|scored| (scored.id, scored.score))
                    .collect::<HashMap<_, _>>()
            });

            let before_limit = scores.len();
            fusion::sort_scored_entities_desc(&mut scores);

            // RET-010 rerank hook: post-sort, pre-budget/pre-truncate, so the
            // reranker sees the blended+filtered ordering over more than
            // `result_limit` candidates and the budget/truncate operate on
            // the final relevance order. Score-ladder reassignment: the block
            // is permuted by (rerank score desc, id bytes asc) but position i
            // keeps the i-th highest POST-BOOST, PRE-DECAY score of the block,
            // multiplied by the RECEIVING entity's own access factor; raw
            // reranker scores survive in the Rerank components.
            //
            // The factor is entity-bound on purpose. A ladder built from
            // already-decayed scores hands position i whatever decay the
            // entity that used to sit there carried: a zero-factor claim
            // promoted to the top would be RESURRECTED with a live
            // neighbor's score, and a live entity demoted into its slot
            // would be punished for someone else's age. The shadow ladder
            // starts from the pre-decay blend and receives the same contiguity
            // and facet-Prefer multipliers as the live scores. Re-multiplying
            // each rung by its receiving entity's factor keeps both those
            // boosts and a single factor application. When every block factor
            // is 1.0 this is the legacy ladder.
            let mut rerank_merged_components = None;
            let mut reranked_trace_scores = None;
            // Empty block: reranking zero candidates is a semantic no-op —
            // never invoke the host impl, so an otherwise-empty retrieval
            // cannot fail on reranker behavior and no needless work happens
            // under the held read txn. (The fail-closed top_n/query
            // validation at the top of run_for_pack still applies.)
            if let Some((reranker, options)) = self.rerank.as_ref()
                && options.top_n.min(scores.len()) > 0
            {
                let query = rerank_query.unwrap_or_default();
                let block_len = options.top_n.min(scores.len());
                let block_ids: Vec<EntityId> =
                    scores[..block_len].iter().map(|scored| scored.id).collect();
                let mut ladder = Vec::with_capacity(block_len);
                for id in &block_ids {
                    let Some(base) = rerank_ladder_scores
                        .as_ref()
                        .and_then(|ladder_scores| ladder_scores.get(id))
                        .copied()
                    else {
                        return Err(Error::InvariantViolation(
                            "rerank block entity missing its blended base score",
                        ));
                    };
                    ladder.push(base);
                }
                ladder.sort_unstable_by(|left, right| right.total_cmp(left));
                let candidates: Vec<RerankCandidate<'_>> = scores[..block_len]
                    .iter()
                    .enumerate()
                    .map(|(index, scored)| RerankCandidate {
                        id: scored.id,
                        score: scored.score,
                        rank: (index + 1).min(u32::MAX as usize) as u32,
                        claim: claim_gate
                            .decisions
                            .get(&scored.id)
                            .and_then(|decision| decision.as_ref()),
                    })
                    .collect();
                let rerank_scores = reranker.rerank(query, &candidates)?;
                drop(candidates);
                if rerank_scores.len() != block_len {
                    return Err(Error::InvariantViolation(
                        "reranker returned mismatched score count",
                    ));
                }
                if rerank_scores.iter().any(|score| !score.is_finite()) {
                    return Err(Error::InvariantViolation(
                        "reranker returned non-finite score",
                    ));
                }

                let mut order: Vec<usize> = (0..block_len).collect();
                order.sort_by(|&left, &right| {
                    rerank_scores[right]
                        .partial_cmp(&rerank_scores[left])
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| block_ids[left].as_bytes().cmp(block_ids[right].as_bytes()))
                });
                let mut rerank_components =
                    HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
                for (new_pos, &old_pos) in order.iter().enumerate() {
                    let Some(access_factor) =
                        blend_access_factors.get(&block_ids[old_pos]).copied()
                    else {
                        return Err(Error::InvariantViolation(
                            "rerank block entity missing its applied access factor",
                        ));
                    };
                    scores[new_pos] = ScoredEntity {
                        id: block_ids[old_pos],
                        score: ladder[new_pos] * access_factor,
                    };
                    rerank_components
                        .entry(block_ids[old_pos])
                        .or_default()
                        .push(RetrievalScoreComponent {
                            signal: RetrievalSignal::Rerank,
                            rank: (new_pos + 1).min(u32::MAX as usize) as u32,
                            score: rerank_scores[old_pos],
                        });
                }

                // Rerank components append AFTER the blend components in each
                // entity's vector (pinned merge order; no dedup, no re-sort).
                let mut merged = blend_components.clone();
                for (id, components) in rerank_components {
                    merged.entry(id).or_default().extend(components);
                }
                rerank_merged_components = Some(merged);

                if capture_retrieval_trace {
                    reranked_trace_scores =
                        Some(retrieval_trace_top_scores(&scores, trace_candidate_limit));
                }
            }

            if let Some((relationship, RelMode::Demote)) = self.relationship_filter {
                apply_relationship_filter(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    &relationship,
                    RelMode::Demote,
                )?;
            }

            // RET-01: abstention is a context-pack assembly decision, never a
            // mutation of stored memory or a behavior change for direct
            // retrieval. Clear the candidate list structurally so hydration
            // cannot surface weak evidence; `BelowThreshold` is carried to
            // the public `ContextPack.empty` response as the typed confidence
            // adjustment.
            if !overrides.skip_ret01_abstain
                && self.context_pack_budget.is_some()
                && context_pack_evidence_abstains(
                    &scores,
                    &signal_components,
                    self.text_search.as_ref().map(|(query, _)| query.as_str()),
                    self.vector_search.is_some(),
                )
            {
                scores.clear();
                empty_reason = Some(EmptyReason::BelowThreshold);
            }

            if let Some(context_pack_budget) = self.context_pack_budget {
                apply_context_pack_retrieval_budget(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    context_pack_budget,
                )?;
            }
            scores.truncate(self.result_limit);
            if before_limit > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::BelowThreshold);
            }
            if no_data_fallback_eligible
                && total_in_scope == 0
                && scores.is_empty()
                && empty_reason.is_none()
            {
                empty_reason = Some(EmptyReason::NoData);
            }
            let pending_vectors = pending_vectors_for_scores(&self.vault.store, &rtxn, &scores)?;
            let retrieval_trace = if capture_retrieval_trace {
                let final_scores = retrieval_trace_top_scores(&scores, trace_candidate_limit);
                let blended_scores = blended_trace_scores.unwrap_or_default();
                let candidate_set = retrieval_trace_candidate_set(
                    &trace_ranked_lists,
                    fused_trace_scores.as_deref().unwrap_or(&[]),
                    &blended_scores,
                    &final_scores,
                );
                let fork_hash = retrieval_trace_fork_hash(
                    self,
                    bm25_config,
                    blend_weights,
                    explicit_time_dependent_now,
                    occurred_range,
                    rerank_query,
                    &candidate_set,
                );
                Some(RetrievalTrace {
                    fork_hash,
                    per_channel: trace_channels,
                    // The fused stage is the pre-blend RRF order, so it
                    // carries no applied multiplier to attribute: an empty
                    // map makes every one of its rows record `None`.
                    fused: retrieval_trace_stage_record(
                        RetrievalTraceStage::Fused,
                        &fused_trace_scores.unwrap_or_default(),
                        &signal_components,
                        &HashMap::new(),
                        &HashMap::new(),
                        trace_candidate_limit,
                    ),
                    blended: retrieval_trace_stage_record(
                        RetrievalTraceStage::Blended,
                        &blended_scores,
                        &signal_components,
                        &blend_components,
                        &blend_access_factors,
                        trace_candidate_limit,
                    ),
                    // Rerank inactive: passthrough mirror of `final` (the
                    // 1186-D5 reserved slot). Active: the post-rerank,
                    // pre-budget/pre-truncate ordering with the rerank
                    // components appended after the blend components.
                    reranked: retrieval_trace_stage_record(
                        RetrievalTraceStage::Reranked,
                        reranked_trace_scores.as_deref().unwrap_or(&final_scores),
                        &signal_components,
                        rerank_merged_components
                            .as_ref()
                            .unwrap_or(&blend_components),
                        &blend_access_factors,
                        trace_candidate_limit,
                    ),
                    final_stage: retrieval_trace_stage_record(
                        RetrievalTraceStage::Final,
                        &final_scores,
                        &signal_components,
                        &blend_components,
                        &blend_access_factors,
                        trace_candidate_limit,
                    ),
                })
            } else {
                None
            };
            Ok(RetrievalTxnOutput {
                scores,
                pending_vectors,
                claim_gate,
                deferred_ppr_cache_writes,
                cosine_ghosts_dampened,
                total_in_scope,
                empty_reason,
                signal_components,
                blend_components,
                access_factors: blend_access_factors,
                rerank_merged_components,
                retrieval_trace,
                ppr_expand_executed,
                early_empty_no_telemetry: false,
            })
        }
    }

    /// Executes the pipeline and returns the detailed [`PipelineOutput`]
    /// the context-pack path consumes (gated scores + the claim bodies the
    /// D19 gate already decoded + the suppression count).
    pub(crate) fn run_for_pack(self) -> Result<PipelineOutput> {
        let started = Instant::now();
        let started_at = crate::unix_seconds_now();
        let temporal_now = self.temporal_now.unwrap_or(started_at);
        let occurred_range = self.resolved_occurred_range(temporal_now)?;
        let telemetry_action = self.telemetry_action;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }

        // Resolve the rank profile before anything else: an invalid
        // profile is a caller bug and fails closed even when no text
        // search would consume it on this run.
        let bm25_config = match self.rank_profile.as_ref() {
            Some(profile) => profile.to_bm25_config()?,
            None => crate::bm25::Bm25Config::default(),
        };

        // ARCH-0039 facet `prefer` boost is a caller-supplied multiplier
        // (ONE-1117): reject a non-finite or non-positive boost fail-closed
        // here, before any work, in the same spirit as the rank profile above.
        if let Some((_, FacetMode::Prefer { boost })) = self.facet_filter
            && (!boost.is_finite() || boost <= 0.0)
        {
            return Err(Error::InvalidConfig(format!(
                "facet prefer boost must be finite and positive, got {boost}"
            )));
        }

        // Read-side decay overrides are a caller-supplied input seam
        // (ONE-1402): an out-of-range factor is a caller bug and fails
        // closed here, before any channel work, like the boost above.
        validate_access_factor_overrides(self.access_factor_overrides)?;

        // RET-010 rerank knobs fail closed before any channel work, in the
        // same spirit as the rank profile above: an invalid `top_n` or a
        // missing query is a caller bug even when the block would be empty
        // on this run.
        let rerank_query = match self.rerank.as_ref() {
            None => None,
            Some((_, options)) => {
                if options.top_n == 0 {
                    return Err(Error::InvalidConfig(
                        "rerank top_n must be greater than zero".to_owned(),
                    ));
                }
                let query = options
                    .query
                    .as_deref()
                    .or_else(|| self.text_search.as_ref().map(|(query, _)| query.as_str()));
                let Some(query) = query else {
                    return Err(Error::InvalidConfig(
                        "rerank requires a query: set RerankOptions::query or search_text"
                            .to_owned(),
                    ));
                };
                Some(query.to_owned())
            }
        };

        let hyde_expansion = match self.hyde.as_ref() {
            None => None,
            Some((expander, grounding, options)) => {
                if options.channel_limit == 0 {
                    return Err(Error::InvalidConfig(
                        "hyde channel_limit must be greater than zero".to_owned(),
                    ));
                }
                let Some((template, _)) = self.text_search.as_ref() else {
                    return Err(Error::InvalidConfig(
                        "hyde requires search_text query".to_owned(),
                    ));
                };
                let query = ground_query(template, grounding)?;
                let expansion = expander.expand(&HydeRequest {
                    query,
                    max_subqueries: crate::query_expansion::HYDE_MAX_SUBQUERIES,
                })?;
                if expansion.embedding.is_empty() {
                    return Err(Error::InvalidConfig(
                        "hyde embedding must not be empty".to_owned(),
                    ));
                }
                if expansion.embedding.len() != self.vault.config.dimensions
                    && self.vault.config.fast_dims.map(usize::from)
                        != Some(expansion.embedding.len())
                {
                    return Err(Error::DimensionMismatch {
                        expected: self.vault.config.dimensions,
                        got: expansion.embedding.len(),
                    });
                }
                if let Some(error) = Error::invalid_vector_component(&expansion.embedding) {
                    return Err(error);
                }
                Some(expansion)
            }
        };

        if self.text_search.is_some() {
            self.vault.ensure_text_index_trusted()?;
        }

        let recency = if self.temporal_search.is_none() && self.recency_blend_enabled {
            Some(temporal_now)
        } else {
            None
        };
        // ONE-1402: read-side decay ages every claim against the run's
        // resolved clock, so EVERY run is time-dependent scoring now — not
        // only the ones that blend recency or search temporally. An
        // explicitly supplied `temporal_now` is therefore always part of
        // the fork's canonical input snapshot; two replays that differ
        // only in that clock score differently and must not collide on one
        // fork hash. An implicit wall clock stays unhashed, as pinned.
        let explicit_time_dependent_now = self.temporal_now;

        let attempt = self.run_retrieval_txn_attempt(
            occurred_range,
            &bm25_config,
            rerank_query.as_deref(),
            hyde_expansion.as_ref(),
            temporal_now,
            recency,
            explicit_time_dependent_now,
            HydeAttemptOverrides {
                widen_channel_limits: false,
                extra_text_queries: &[],
                skip_ret01_abstain: self.hyde.is_some(),
            },
        )?;
        // Preserve the pre-HyDE no-channel fast path: it returns no run row.
        if self.hyde.is_none() && attempt.early_empty_no_telemetry {
            return Ok(PipelineOutput {
                scores: Vec::new(),
                claim_bodies: HashMap::new(),
                pending_vectors: Vec::new(),
                claims_suppressed: 0,
                cosine_ghosts_dampened: 0,
                total_in_scope: 0,
                empty_reason: None,
                telemetry_run_id: None,
                signals: telemetry_signals,
            });
        }
        let mut ppr_expand_executed = attempt.ppr_expand_executed;
        let mut scores = attempt.scores;
        let mut pending_vectors = attempt.pending_vectors;
        let mut claim_gate = attempt.claim_gate;
        let deferred_ppr_cache_writes = attempt.deferred_ppr_cache_writes;
        let mut cosine_ghosts_dampened = attempt.cosine_ghosts_dampened;
        let mut total_in_scope = attempt.total_in_scope;
        let mut empty_reason = attempt.empty_reason;
        let mut signal_components = attempt.signal_components;
        let mut blend_components = attempt.blend_components;
        let mut access_factors = attempt.access_factors;
        let mut rerank_merged_components = attempt.rerank_merged_components;
        let mut retrieval_trace = attempt.retrieval_trace;

        crate::ppr::flush_deferred_ppr_cache_writes(&self.vault.store, &deferred_ppr_cache_writes)?;

        let mut claim_bodies = HashMap::new();
        let mut claims_suppressed = 0_usize;
        for (id, decision) in claim_gate.decisions {
            match decision {
                Some(body) => {
                    claim_bodies.insert(id, body);
                }
                None => claims_suppressed += 1,
            }
        }

        // Host assessment runs only after each read transaction has closed.
        if let (Some((expander, _, options)), Some(expansion)) =
            (self.hyde.as_ref(), hyde_expansion.as_ref())
        {
            let request = |scores: &[ScoredEntity], claims: &HashMap<EntityId, ClaimBody>| {
                CompletionRequest {
                    query: expansion.grounded_query.clone(),
                    candidates: scores
                        .iter()
                        .take(self.result_limit)
                        .map(|scored| CompletionCandidate {
                            id: scored.id,
                            score: scored.score,
                            claim: claims.get(&scored.id).cloned(),
                        })
                        .collect(),
                }
            };
            let verdict = expander.assess_evidence(&request(&scores, &claim_bodies))?;
            let mut second_insufficient = false;
            if matches!(verdict, EvidenceVerdict::Insufficient { .. }) && options.retry_once {
                // Replace every retrieval artifact with the widened fresh transaction.
                let subqueries = normalized_subqueries(&expansion.subqueries);
                let retry = self.run_retrieval_txn_attempt(
                    occurred_range,
                    &bm25_config,
                    rerank_query.as_deref(),
                    hyde_expansion.as_ref(),
                    temporal_now,
                    recency,
                    explicit_time_dependent_now,
                    HydeAttemptOverrides {
                        widen_channel_limits: true,
                        extra_text_queries: &subqueries,
                        skip_ret01_abstain: true,
                    },
                )?;
                crate::ppr::flush_deferred_ppr_cache_writes(
                    &self.vault.store,
                    &retry.deferred_ppr_cache_writes,
                )?;
                scores = retry.scores;
                pending_vectors = retry.pending_vectors;
                claim_gate = retry.claim_gate;
                cosine_ghosts_dampened = retry.cosine_ghosts_dampened;
                total_in_scope = retry.total_in_scope;
                empty_reason = retry.empty_reason;
                signal_components = retry.signal_components;
                blend_components = retry.blend_components;
                access_factors = retry.access_factors;
                rerank_merged_components = retry.rerank_merged_components;
                retrieval_trace = retry.retrieval_trace;
                ppr_expand_executed = retry.ppr_expand_executed;
                claim_bodies.clear();
                claims_suppressed = 0;
                for (id, decision) in &claim_gate.decisions {
                    match decision {
                        Some(body) => {
                            claim_bodies.insert(*id, body.clone());
                        }
                        None => claims_suppressed += 1,
                    }
                }
                second_insufficient = matches!(
                    expander.assess_evidence(&request(&scores, &claim_bodies))?,
                    EvidenceVerdict::Insufficient { .. }
                );
            }
            let abstain = second_insufficient
                || (matches!(verdict, EvidenceVerdict::Insufficient { .. }) && !options.retry_once)
                || (self.context_pack_budget.is_some()
                    && context_pack_evidence_abstains(
                        &scores,
                        &signal_components,
                        self.text_search.as_ref().map(|(query, _)| query.as_str()),
                        self.vector_search.is_some() || hyde_expansion.is_some(),
                    ));
            if abstain {
                scores.clear();
                pending_vectors.clear();
                retrieval_trace = None;
                empty_reason = Some(EmptyReason::BelowThreshold);
            }
        }

        let score_breakdown = telemetry_score_breakdown(
            &scores,
            &signal_components,
            rerank_merged_components
                .as_ref()
                .unwrap_or(&blend_components),
            &access_factors,
        );
        let ppr_search_executed = self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty());
        if !ppr_search_executed && self.ppr_expand.is_some() && !ppr_expand_executed {
            telemetry_signals.retain(|signal| *signal != RetrievalSignal::Ppr);
        }
        let run_id = RetrievalRunId::now();
        let run_record = RetrievalRunRecord::new(
            run_id,
            telemetry_action,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            telemetry_signals.clone(),
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason.map(|reason| format!("{reason:?}")),
        )
        .with_trace(retrieval_trace);
        // ONE-1728 K10: a retrieval issued inside a room registers through the
        // room's door, which writes under the route the run captured — into
        // the room's overlay `VaultMeta` while it is off record (so the base
        // telemetry ledger gains ZERO rows from an OffRecord session, and the
        // row evaporates at close), and under that route's refusal once the
        // room has flipped. Canonical entries carry `None` and take the
        // unchanged base path.
        let provisional = telemetry_action == RetrievalAction::ContextPack;
        let write_result = match self.session {
            Some(session) => session.register_run(&run_record, provisional),
            None if provisional => self
                .vault
                .store
                .record_context_pack_provisional_retrieval_run(&run_record),
            None => self.vault.store.record_retrieval_run(&run_record),
        };
        let telemetry_run_id = match write_result {
            Ok(()) => Some(run_id),
            // A retrieval the caller declared to be INSIDE a room owns its
            // registration. Off record the run row is what close consumes, so
            // swallowing the failure would return a successful retrieval whose
            // durable run is absent from the session-local close set — the one
            // outcome the settle contract forbids outright. On record the room
            // is also the half that can refuse for a STALE ROUTE, and a K10
            // refusal warned past is the same log-and-continue wearing a
            // different hat. Only a CANONICAL entry — no room at all — keeps
            // the best-effort posture: an ordinary retrieval that loses its
            // telemetry row loses nothing its caller depends on.
            Err(error) if self.session.is_some() => return Err(error),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "retrieval telemetry run write failed; continuing retrieval"
                );
                None
            }
        };

        Ok(PipelineOutput {
            scores,
            claim_bodies,
            pending_vectors,
            claims_suppressed,
            cosine_ghosts_dampened,
            total_in_scope,
            empty_reason,
            telemetry_run_id,
            signals: telemetry_signals,
        })
    }

    fn telemetry_signals(&self) -> Vec<RetrievalSignal> {
        let mut signals = Vec::new();
        if self.vector_search.is_some() {
            signals.push(RetrievalSignal::Vector);
        }
        if self.text_search.is_some() {
            signals.push(RetrievalSignal::Text);
        }
        if self.hyde.is_some() {
            signals.push(RetrievalSignal::Hyde);
        }
        if self
            .phonetic_search
            .as_ref()
            .is_some_and(|codes| !codes.is_empty())
        {
            signals.push(RetrievalSignal::Phonetic);
        }
        if self.temporal_search.is_some() {
            signals.push(RetrievalSignal::Temporal);
        }
        if self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self.ppr_expand.is_some()
        {
            signals.push(RetrievalSignal::Ppr);
        }
        signals
    }

    fn no_data_fallback_eligible(&self) -> bool {
        self.vector_search
            .as_ref()
            .is_some_and(|(_, limit)| *limit > 0)
            || self
                .text_search
                .as_ref()
                .is_some_and(|(_, limit)| *limit > 0)
            || self
                .phonetic_search
                .as_ref()
                .is_some_and(|codes| !codes.is_empty())
            || self
                .temporal_search
                .as_ref()
                .is_some_and(|config| config.limit > 0)
            || self
                .ppr_search
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self
                .ppr_expand
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
    }

    fn has_codebase_scope_filter(&self) -> bool {
        self.repo_ref_filter.is_some() || self.project_id_filter.is_some()
    }

    fn has_strict_text_scope_filter(&self) -> bool {
        self.type_filter.is_some()
            || self.since_filter.is_some()
            || self.occurred_range.is_some()
            || self.learned_range.is_some()
            || matches!(self.facet_filter, Some((_, FacetMode::Strict)))
            || matches!(self.relationship_filter, Some((_, RelMode::Filter)))
            || self.world_scope != WorldScope::All
            // ONE-1914: a narrowing audience scope removes text candidates
            // exactly like a narrowing world scope, so it must widen the text
            // channel too. Without this, an out-of-scope exact hit still
            // consumes the only slot at `limit = 1` and the scoped truncate
            // step never runs. `CorpusScope::All` spans every corpus and
            // narrows nothing, so it stays as permissive as `WorldScope::All`.
            || self.corpus_scope != CorpusScope::All
    }

    fn resolved_occurred_range(&self, now: u64) -> Result<Option<(u64, u64)>> {
        if self.occurred_range.is_some() || self.temporal_search.is_some() {
            return Ok(self.occurred_range);
        }

        let Some((query, _)) = self.text_search.as_ref() else {
            return Ok(None);
        };

        temporal_expression_from_query(query)
            .map(|expression| expression.map(|expression| expression.resolve(now)))
            .map(|range| range.map(|range| normalize_range(range.start, range.end)))
            .map_err(invalid_temporal_expression)
    }
}

fn invalid_temporal_expression(error: TemporalExpressionParseError) -> Error {
    Error::InvalidTemporalExpression(error)
}

/// Fail-closed admission of the caller's per-entity read-side decay
/// overrides. The offending entry is chosen by id order so the rejection
/// message does not depend on map iteration order.
fn validate_access_factor_overrides(overrides: Option<&HashMap<EntityId, f32>>) -> Result<()> {
    let Some(overrides) = overrides else {
        return Ok(());
    };

    let invalid = overrides
        .iter()
        .filter(|(_, factor)| !crate::claim::access_factor_override_valid(**factor))
        .min_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if let Some((_, factor)) = invalid {
        return Err(Error::InvalidConfig(format!(
            "access factor override must be finite and within [0, 1], got {factor}"
        )));
    }

    Ok(())
}

fn pending_vectors_for_scores(
    store: &Store,
    rtxn: &RoTxn<'_>,
    scores: &[ScoredEntity],
) -> Result<Vec<PendingVectorEmbedding>> {
    let mut pending = Vec::new();
    for scored in scores {
        if let Some(token) = store.pending_embedding_token(rtxn, &scored.id)? {
            pending.push(PendingVectorEmbedding {
                id: scored.id,
                token,
            });
        }
    }
    pending.sort_unstable_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    pending.dedup_by(|left, right| left.id == right.id);
    Ok(pending)
}
