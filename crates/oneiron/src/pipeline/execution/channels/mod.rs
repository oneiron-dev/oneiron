//! Channel fan-out for the retrieval transaction: authority, world, and corpus setup plus the vector, HyDE, text, phonetic, temporal, and PPR channels.

mod admit;
mod post_blend;
mod ppr_expand;
mod rerank;
mod text;
mod trace_assembly;

use self::admit::ChannelAccumulator;
use self::post_blend::{PostBlend, PostBlendInputs};
use self::ppr_expand::{PprExpandInputs, PprExpandState};
use self::rerank::{RerankApplied, RerankLadderInputs};
use self::text::TextChannelInputs;
use self::trace_assembly::TraceInputs;
use super::super::blend::{
    AccessFactorApplication, RetrievalBlendConfig, RetrievalChannelIndexes,
    blended_retrieval_scores, retrieval_blend_weights_for_scoring, score_id_set,
};
use super::super::budget::{apply_context_pack_retrieval_budget, context_pack_evidence_abstains};
use super::super::builder::PipelineBuilder;
use super::super::channels::execute_phonetic;
use super::super::corpus_filter::CorpusFilter;
use super::super::filters::{apply_claim_status_gate, apply_relationship_filter};
use super::super::trace::{record_ppr_cache_outcome, retrieval_trace_fused_scores};
use super::super::types::{ClaimStatusGateCache, EntityMetadataCache, PPR_DAMPING, RelMode};
use super::super::world_authority::resolve_active_world_authority;
use super::types::{HydeAttemptOverrides, RetrievalTxnOutput, pending_vectors_for_scores};
use crate::bm25::Bm25Config;
use crate::context_pack::EmptyReason;
use crate::error::Result;
use crate::fusion;
use crate::query_expansion::retry_channel_limit;
use crate::store::RetrievalSignal;
use std::collections::HashMap;

impl PipelineBuilder<'_> {
    // Requested operations, not the legacy signal list: time filters and
    // recency blending do not constitute a Temporal search. Empty inputs still
    // reach their channel operation and may complete with zero candidates.
    #[expect(clippy::too_many_arguments)]
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
            let mut vector_channel_index = None;
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
            let claim_gate_text_widening_active = self.claim_gate_text_widening_probe(
                &rtxn,
                bm25_config,
                hyde_expansion,
                filter_config,
                &mut metadata_cache,
                &mut claim_gate_widening_probe,
            )?;
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

            let text_channel_index = self.run_text_channel(
                &rtxn,
                TextChannelInputs {
                    bm25_config,
                    hyde_expansion,
                    overrides: &overrides,
                    recency,
                    filter_config,
                    authority_filter,
                    text_scope_widening_active,
                    claim_gate_widening_probe,
                },
                &mut acc,
                &mut diagnostics,
                &mut metadata_cache,
                &mut claim_gate,
            )?;

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

            if let Some(outcome) = self.expand_ppr_stage(
                &rtxn,
                &scores,
                PprExpandInputs {
                    filter_config,
                    blend_config,
                    blend_weights,
                    channel_indexes: RetrievalChannelIndexes {
                        vector: vector_channel_index,
                        text: text_channel_index,
                    },
                    temporal_now,
                    codebase_scope_active,
                },
                PprExpandState {
                    acc: &mut acc,
                    blend_allowed_ids: &mut blend_allowed_ids,
                    fused_trace_scores: &mut fused_trace_scores,
                    diagnostics: &mut diagnostics,
                    deferred_ppr_cache_writes: &mut deferred_ppr_cache_writes,
                },
                &mut metadata_cache,
                &mut claim_gate,
            )? {
                scores = outcome.blend.scores;
                cosine_ghosts_dampened = outcome.blend.cosine_ghosts_dampened;
                blend_components = outcome.blend.components;
                blend_base_scores = outcome.blend.base_scores;
                blend_access_factors = outcome.blend.access_factors;
                community_diversity = outcome.community_diversity;
                community_trace_identity = outcome.community_trace_identity;
                ppr_expand_executed = outcome.ppr_expand_executed;
            }

            let PostBlend {
                rerank_ladder_scores,
                blended_trace_scores,
                mut empty_reason,
            } = self.apply_post_blend_filters(
                &rtxn,
                &mut scores,
                empty_reason,
                PostBlendInputs {
                    filter_config,
                    corpus_filter: &corpus_filter,
                    authority_filter,
                    blend_base_scores: &blend_base_scores,
                    capture_retrieval_trace,
                    trace_candidate_limit,
                },
                &mut metadata_cache,
                &mut claim_gate,
            )?;

            let before_limit = scores.len();
            fusion::sort_scored_entities_desc(&mut scores);

            let RerankApplied {
                merged_components: rerank_merged_components,
                reranked_trace_scores,
            } = self.apply_rerank_ladder(
                &mut scores,
                RerankLadderInputs {
                    ladder_scores: rerank_ladder_scores.as_ref(),
                    blend_access_factors: &blend_access_factors,
                    blend_components: &blend_components,
                    claim_gate: &claim_gate,
                    rerank_query,
                    capture_retrieval_trace,
                    trace_candidate_limit,
                },
            )?;

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
                Some(self.assemble_retrieval_trace(TraceInputs {
                    scores: &scores,
                    trace_channels: acc.trace_channels,
                    trace_ranked_lists: &acc.trace_ranked_lists,
                    signal_components: &acc.signal_components,
                    fused_trace_scores,
                    blended_trace_scores,
                    reranked_trace_scores: reranked_trace_scores.as_deref(),
                    rerank_merged_components: rerank_merged_components.as_ref(),
                    blend_components: &blend_components,
                    blend_access_factors: &blend_access_factors,
                    community_trace_identity,
                    world_authority: world_authority.as_ref(),
                    bm25_config,
                    blend_weights,
                    explicit_time_dependent_now,
                    occurred_range,
                    rerank_query,
                    trace_candidate_limit,
                }))
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
