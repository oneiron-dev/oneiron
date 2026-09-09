//! Channel fan-out for the retrieval transaction: authority, world, and corpus setup plus the vector, HyDE, text, phonetic, temporal, and PPR channels.

mod admit;

use self::admit::{AdmitSignal, ChannelAccumulator};
use super::super::blend::{
    AccessFactorApplication, RetrievalBlendConfig, RetrievalChannelIndexes,
    blended_retrieval_scores, boost_contiguity, filter_blended_scores_to_allowed_ids,
    retrieval_blend_weights_for_scoring, score_id_set,
};
use super::super::budget::{apply_context_pack_retrieval_budget, context_pack_evidence_abstains};
use super::super::builder::PipelineBuilder;
use super::super::channels::{
    execute_phonetic, scoped_text_channel_limit, truncate_widened_channel_results_to_scope,
};
use super::super::corpus_filter::CorpusFilter;
use super::super::filters::{
    apply_claim_status_gate, apply_facet_filter, apply_filters, apply_relationship_filter,
    apply_world_filter, claim_status_gate_allows, import_claim_gate_decisions_for_scores,
    pipeline_candidate_matches_filters_and_gate,
};
use super::super::trace::{
    RetrievalTraceForkEvidence, record_ppr_cache_outcome, retrieval_trace_candidate_set,
    retrieval_trace_fork_hash, retrieval_trace_fused_scores, retrieval_trace_stage_record,
    retrieval_trace_top_scores,
};
use super::super::types::{
    ClaimStatusGateCache, EntityMetadataCache, PER_SCAN_CAP_FACTOR, PPR_DAMPING, RelMode,
    ScoredEntity,
};
use super::super::world_authority::resolve_active_world_authority;
use super::types::{HydeAttemptOverrides, RetrievalTxnOutput, pending_vectors_for_scores};
use crate::bm25::Bm25Config;
use crate::context_pack::EmptyReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::fusion;
use crate::query_expansion::retry_channel_limit;
use crate::rerank::RerankCandidate;
use crate::retrieval_quality::PprCacheOutcome;
use crate::store::{RetrievalScoreComponent, RetrievalSignal, RetrievalTrace, RetrievalTraceStage};
use std::collections::{HashMap, HashSet};

impl PipelineBuilder<'_> {
    // Requested operations, not the legacy signal list: time filters and
    // recency blending do not constitute a Temporal search. Empty inputs still
    // reach their channel operation and may complete with zero candidates.
    #[expect(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn run_retrieval_txn_attempt(
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
        let rtxn = self.vault.store.env.read_txn()?;
        let owner_filter;
        let authority_filter = match self.authority_filter.as_ref() {
            Some(filter) => filter,
            None => {
                let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &rtxn)?;
                let floor: crate::gate::RetrievalPolicyFloor =
                    policy.retrieval_floor_for_actor(None);
                owner_filter = crate::gate::narrow_retrieval_filter(&floor, None)?;
                &owner_filter
            }
        };
        let no_data_fallback_eligible = self.no_data_fallback_eligible();
        let mut diagnostics = self.retrieval_diagnostics();
        let mut ppr_expand_executed = false;
        let capture_retrieval_trace = self.capture_retrieval_trace;
        let trace_candidate_limit = self.result_limit;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }
        {
            let mut acc = ChannelAccumulator::new(
                capture_retrieval_trace,
                trace_candidate_limit,
                authority_filter.include_stale,
            );
            let mut fused_trace_scores = None;
            let mut blended_trace_scores = None;
            let mut vector_channel_index = None;
            let mut text_channel_index = None;
            let blend_weights = retrieval_blend_weights_for_scoring(&self.vault.store, &rtxn)?;
            let mut metadata_cache = EntityMetadataCache::default();
            let mut claim_gate = ClaimStatusGateCache {
                include_stale: authority_filter.include_stale,
                ..ClaimStatusGateCache::default()
            };
            let mut deferred_ppr_cache_writes = Vec::new();
            let mut community_diversity = None;
            let mut community_trace_identity = None;
            let codebase_scope_active = self.has_codebase_scope_filter();
            // ONE-1420: under `WorldScope::ActiveSet` the turn's world
            // authority resolves ONCE here — inside this run's read
            // transaction, at this run's clock — and every per-candidate scope
            // check below borrows the result. Resolving before any channel
            // runs also makes the fail-closed refusals (no selection, a
            // selection outside the owner grant, a malformed authority row)
            // land before the query does any scoring work.
            let world_authority = resolve_active_world_authority(
                &self.vault.store,
                &rtxn,
                self.world_scope,
                self.active_world_selection.as_ref(),
                self.execution_actor,
                temporal_now,
            )?;
            let corpus_filter = CorpusFilter::new(&self.corpus_scope)?;
            let mut filter_config = corpus_filter.config(self, occurred_range, authority_filter);
            filter_config.world_active_set = world_authority
                .as_ref()
                .map(|resolved| &resolved.active_set);
            // Ordinary text uses D19 widening; candidate-filtered text instead
            // applies D19 during bounded scoring and needs no corpus-sized probe.
            let mut claim_gate_widening_probe = ClaimStatusGateCache {
                include_stale: authority_filter.include_stale,
                ..ClaimStatusGateCache::default()
            };
            let claim_gate_text_widening_active = if let Some((query, limit)) = &self.text_search
                && *limit > 0
                && self.candidate_filter.is_none()
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
                let vector_results = self.scoped_vector_results(
                    &rtxn,
                    query_vector,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(*limit)
                    } else {
                        *limit
                    },
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate,
                )?;
                diagnostics.succeeded.push(RetrievalSignal::Vector);
                vector_channel_index = Some(acc.admit_channel(
                    RetrievalSignal::Vector,
                    vector_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?);
            }

            if let Some(expansion) = hyde_expansion.as_ref() {
                let limit = self
                    .hyde
                    .as_ref()
                    .expect("hyde expansion has config")
                    .2
                    .channel_limit;
                let hyde_results = self.scoped_vector_results(
                    &rtxn,
                    &expansion.embedding,
                    if overrides.widen_channel_limits {
                        retry_channel_limit(limit)
                    } else {
                        limit
                    },
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate,
                )?;
                acc.admit_channel(
                    RetrievalSignal::Hyde,
                    hyde_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
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
                let search = if self.candidate_filter.is_some() {
                    crate::bm25::search_text_filtered_with_recency
                } else {
                    crate::bm25::search_text_scoped_with_recency
                };
                let mut text_results = search(
                    &self.vault.store,
                    &rtxn,
                    &self.vault.analyzer,
                    bm25_config,
                    text_query,
                    if self.candidate_filter.is_some() {
                        *limit
                    } else {
                        text_channel_limit
                    },
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut exact_posting_matches_scope,
                    },
                )?;
                diagnostics.succeeded.push(RetrievalSignal::Text);
                if self.candidate_filter.is_none()
                    && text_channel_limit > *limit
                    && text_scope_widening_active
                {
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
                text_channel_index = Some(acc.admit_channel(
                    RetrievalSignal::Text,
                    text_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?);
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
                    let mut retry_prefix_probe_claim_gate = ClaimStatusGateCache {
                        include_stale: authority_filter.include_stale,
                        ..ClaimStatusGateCache::default()
                    };
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
                    acc.admit_channel(
                        AdmitSignal {
                            components: RetrievalSignal::Text,
                            trace: RetrievalSignal::HydeRetry,
                        },
                        results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                    )?;
                }
            }

            if let Some(codes) = &self.phonetic_search {
                let phonetic_results = execute_phonetic(&self.vault.store, &rtxn, codes)?;
                diagnostics.succeeded.push(RetrievalSignal::Phonetic);
                acc.admit_channel(
                    RetrievalSignal::Phonetic,
                    phonetic_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
            }

            if let Some(config) = &self.temporal_search {
                let mut config = config.clone();
                if overrides.widen_channel_limits {
                    config.limit = retry_channel_limit(config.limit);
                }
                let temporal_results = self.scoped_temporal_results(
                    &rtxn,
                    &config,
                    temporal_now,
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate,
                )?;
                diagnostics.succeeded.push(RetrievalSignal::Temporal);
                acc.admit_channel(
                    RetrievalSignal::Temporal,
                    temporal_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
            }

            if let Some((seeds, depth)) = &self.ppr_search {
                // ARCH-0039 Layer 2: seed specificity applies ONLY to
                // search_ppr — seeds are weighted 1/ln(1 + passage_count)
                // instead of uniform 1/n.
                let ppr = crate::ppr::ppr_query_in_txn_with_diagnostics(
                    &self.vault.store,
                    &rtxn,
                    seeds,
                    *depth,
                    PPR_DAMPING,
                    self.vault.config.ppr_vad_alpha,
                    crate::ppr::SeedWeighting::Specificity,
                )?;
                diagnostics.succeeded.push(RetrievalSignal::Ppr);
                record_ppr_cache_outcome(&mut diagnostics, ppr.cache);
                let ppr_results = ppr.scores;
                let deferred_cache_write = ppr.deferred_cache_write;
                acc.admit_channel(
                    RetrievalSignal::Ppr,
                    ppr_results,
                    &self.vault.store,
                    &rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
                if let Some(deferred_cache_write) = deferred_cache_write {
                    deferred_ppr_cache_writes.push(deferred_cache_write);
                }
            }

            // Entity-type authority can narrow each channel before fusion.
            // CLAIM scalar constraints use the decoded post-fusion stage below.
            for scores in &mut acc.ranked_lists {
                super::authority::apply_types(
                    scores,
                    authority_filter,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                )?;
            }
            if acc.ranked_lists.is_empty() {
                return Ok(RetrievalTxnOutput {
                    diagnostics,
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
                    &acc.trace_ranked_lists,
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
                &acc.ranked_lists,
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
                    let ppr = if self.vault.config.ppr_community.beta == 0.0 {
                        // Exact legacy path: no evidence/cache reads or new key namespace.
                        crate::ppr::ppr_query_in_txn_with_diagnostics(
                            &self.vault.store,
                            &rtxn,
                            &seeds,
                            *depth,
                            PPR_DAMPING,
                            self.vault.config.ppr_vad_alpha,
                            crate::ppr::SeedWeighting::Uniform,
                        )?
                    } else {
                        // ID sorting for the base cache must not replace the fused
                        // evidence order. Explicit-only seeds get zero evidence.
                        let ordered_seeds =
                            crate::ppr_community::ordered_seed_evidence(&seeds, &scores)
                                .map_err(|error| Error::InvalidConfig(error.to_string()))?;
                        let empty_usage = HashMap::new();
                        let context = crate::ppr_community::CommunityBoostContext {
                            ordered_seeds: &ordered_seeds,
                            result_limit: self.result_limit,
                            session_usage: self.community_session_usage.unwrap_or(&empty_usage),
                        };
                        let (result, diversity) =
                            crate::ppr::ppr_expand_in_txn_with_community_diagnostics(
                                &self.vault.store,
                                &rtxn,
                                crate::ppr::CommunityPprRequest {
                                    seeds: &seeds,
                                    depth: *depth,
                                    teleport_alpha: PPR_DAMPING,
                                    weighting: crate::ppr::SeedWeighting::Uniform,
                                    config: &self.vault.config,
                                    context: &context,
                                },
                            )?;
                        community_diversity = diversity;
                        if capture_retrieval_trace {
                            community_trace_identity = Some(self.community_trace_identity(
                                &ordered_seeds,
                                crate::ppr::read_graph_version(&self.vault.store, &rtxn)?,
                            ));
                        }
                        result
                    };
                    if !diagnostics.succeeded.contains(&RetrievalSignal::Ppr) {
                        diagnostics.succeeded.push(RetrievalSignal::Ppr);
                    }
                    record_ppr_cache_outcome(&mut diagnostics, ppr.cache);
                    let mut ppr_results = ppr.scores;
                    if let Some(deferred_cache_write) = ppr.deferred_cache_write {
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
                    blend_allowed_ids.extend(ppr_results.iter().map(|scored| scored.id));
                    acc.admit_channel(
                        RetrievalSignal::Ppr,
                        ppr_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                    )?;
                    if capture_retrieval_trace {
                        fused_trace_scores = Some(retrieval_trace_fused_scores(
                            &acc.trace_ranked_lists,
                            trace_candidate_limit,
                        ));
                    }
                    // The expanded blend is this run's ONE decay
                    // application: the seeds above were picked from the
                    // neutral preliminary order.
                    let expanded_blend = blended_retrieval_scores(
                        &acc.ranked_lists,
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
                    record_ppr_cache_outcome(&mut diagnostics, PprCacheOutcome::Disabled);
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
                        &acc.ranked_lists,
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
            super::authority::apply(
                &mut scores,
                authority_filter,
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
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
            // default `WorldScope::All`. ActiveSet reuses the authority already
            // resolved for the per-candidate filters in this transaction.
            let before_world = scores.len();
            apply_world_filter(
                &mut scores,
                &self.vault.store,
                &rtxn,
                self.world_scope,
                filter_config.world_active_set,
            )?;
            if before_world > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }

            empty_reason = corpus_filter.apply(
                &mut scores,
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
                empty_reason,
            )?;
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
                    &acc.signal_components,
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
            // Only admitted final candidates participate. This selection cannot
            // surface hidden bridge nodes, undo filters, or multiply scores twice.
            if let Some(diversity) = community_diversity {
                diversity.apply(
                    &mut scores,
                    self.result_limit,
                    &self.vault.config.ppr_community,
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
                    &acc.trace_ranked_lists,
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
                    RetrievalTraceForkEvidence {
                        candidate_set: &candidate_set,
                        world_authority: world_authority.as_ref(),
                    },
                );
                let fork_hash = if let Some(identity) = community_trace_identity {
                    use sha2::{Digest, Sha256};
                    let mut hash = Sha256::new();
                    hash.update(b"oneiron.retrieval_trace.community.fork.v0");
                    hash.update(fork_hash);
                    hash.update(identity);
                    hash.finalize().into()
                } else {
                    fork_hash
                };
                Some(RetrievalTrace {
                    fork_hash,
                    per_channel: acc.trace_channels,
                    // The fused stage is the pre-blend RRF order, so it
                    // carries no applied multiplier to attribute: an empty
                    // map makes every one of its rows record `None`.
                    fused: retrieval_trace_stage_record(
                        RetrievalTraceStage::Fused,
                        &fused_trace_scores.unwrap_or_default(),
                        &acc.signal_components,
                        &HashMap::new(),
                        &HashMap::new(),
                        trace_candidate_limit,
                    ),
                    blended: retrieval_trace_stage_record(
                        RetrievalTraceStage::Blended,
                        &blended_scores,
                        &acc.signal_components,
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
                        &acc.signal_components,
                        rerank_merged_components
                            .as_ref()
                            .unwrap_or(&blend_components),
                        &blend_access_factors,
                        trace_candidate_limit,
                    ),
                    final_stage: retrieval_trace_stage_record(
                        RetrievalTraceStage::Final,
                        &final_scores,
                        &acc.signal_components,
                        &blend_components,
                        &blend_access_factors,
                        trace_candidate_limit,
                    ),
                })
            } else {
                None
            };
            Ok(RetrievalTxnOutput {
                diagnostics,
                scores,
                pending_vectors,
                claim_gate,
                deferred_ppr_cache_writes,
                cosine_ghosts_dampened,
                total_in_scope,
                empty_reason,
                signal_components: acc.signal_components,
                blend_components,
                access_factors: blend_access_factors,
                rerank_merged_components,
                retrieval_trace,
                ppr_expand_executed,
                early_empty_no_telemetry: false,
            })
        }
    }
}
