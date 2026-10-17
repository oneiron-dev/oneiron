//! Channel fan-out for the retrieval transaction: authority, world, and corpus setup plus the vector, HyDE, text, phonetic, temporal, and PPR channels.

mod admit;
mod categories;
mod entity_rank;
mod post_blend;
mod ppr_expand;
mod rerank;
mod text;
mod trace_assembly;
mod turn_fold;

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
use super::super::budget::{
    WorldShare, apply_context_pack_retrieval_budget, context_pack_evidence_abstains,
    truncate_under_world_share, withhold_undisclosed,
};
use super::super::builder::PipelineBuilder;
use super::super::capabilities::{memory_candidate_count, partition_capabilities};
use super::super::channels::{execute_phonetic, fusion_fetch_limit};
use super::super::corpus_filter::CorpusFilter;
use super::super::filters::{apply_claim_status_gate, apply_relationship_filter};
use super::super::trace::{
    capture_replay_inputs, record_ppr_cache_outcome, retrieval_trace_fused_scores,
};
use super::super::types::{
    ClaimStatusGateCache, EntityMetadataCache, PPR_DAMPING, RelMode, TurnFold,
};
use super::super::world_authority::resolve_active_world_authority;
use super::types::{HydeAttemptOverrides, RetrievalTxnOutput, pending_vectors_for_scores};
use crate::bm25::Bm25Config;
use crate::context_pack::EmptyReason;
use crate::error::Result;
use crate::fusion;
use crate::query_expansion::retry_channel_limit;
use crate::store::RetrievalSignal;
use std::collections::HashMap;

#[derive(Clone, Copy)]
struct SnapshotInputs<'a> {
    occurred_range: Option<(u64, u64)>,
    bm25_config: &'a Bm25Config,
    rerank_query: Option<&'a str>,
    hyde_expansion: Option<&'a crate::query_expansion::HydeExpansion>,
    temporal_now: u64,
    recency: Option<u64>,
    explicit_time_dependent_now: Option<u64>,
    overrides: HydeAttemptOverrides<'a>,
}

/// The channel stages one snapshot runs, counted down as each opens, so a
/// deadline gives every stage an equal share of the stage time left.
struct StagePlan(usize);

impl StagePlan {
    fn new(planned: [bool; 6]) -> Self {
        Self(planned.into_iter().filter(|planned| *planned).count())
    }
    /// The stages left, this one included; counts this one down.
    fn next(&mut self) -> usize {
        let left = self.0;
        self.0 = self.0.saturating_sub(1);
        left
    }
    fn next_if(&mut self, planned: bool) -> usize {
        if planned { self.next() } else { self.0 }
    }
}

/// One snapshot's actor-bound NOTE admission and the gates that share it.
struct ScopedChannelAdmission {
    private_note_ids: Option<std::sync::Arc<crate::claim::ScopedDiaryCandidates>>,
    accumulator: ChannelAccumulator,
    claim_gate: ClaimStatusGateCache,
    widening_probe: ClaimStatusGateCache,
}

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
        let inputs = SnapshotInputs {
            occurred_range,
            bm25_config,
            rerank_query,
            hyde_expansion,
            temporal_now,
            recency,
            explicit_time_dependent_now,
            overrides,
        };
        if self.context_pack_budget.is_some() && self.result_limit > 0 {
            self.collect_pack_categories(&rtxn, inputs)
        } else {
            self.run_retrieval_snapshot(&rtxn, inputs)
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "replay inputs must be captured under the same retrieval read transaction as the trace"
    )]
    fn run_retrieval_snapshot(
        &self,
        rtxn: &heed::RoTxn<'_>,
        inputs: SnapshotInputs<'_>,
    ) -> Result<RetrievalTxnOutput> {
        let SnapshotInputs {
            occurred_range,
            bm25_config,
            rerank_query,
            hyde_expansion,
            temporal_now,
            recency,
            explicit_time_dependent_now,
            overrides,
        } = inputs;
        let owner_filter;
        let authority_filter = match self.authority_filter.as_ref() {
            Some(filter) => filter,
            None => {
                let policy = crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)?;
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
        let capture_replay_enabled = self.captures_replay();
        let trace_candidate_limit = self.result_limit;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }
        {
            let ScopedChannelAdmission {
                private_note_ids,
                accumulator: mut acc,
                mut claim_gate,
                widening_probe: mut claim_gate_widening_probe,
            } = self.scoped_channel_admission(rtxn, authority_filter)?;
            let mut fused_trace_scores = None;
            let mut vector_channel_index = None;
            let mut phonetic_channel_index = None;
            let blend_weights = retrieval_blend_weights_for_scoring(&self.vault.store, rtxn)?;
            let mut metadata_cache = EntityMetadataCache::default();
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
                rtxn,
                &self.world_scope,
                self.active_world_selection.as_ref(),
                self.execution_actor,
                temporal_now,
            )?;
            let corpus_filter = CorpusFilter::new(&self.corpus_scope)?;
            let device_local = self.device_local_worlds(rtxn)?;
            let mut filter_config = corpus_filter.config(self, occurred_range, authority_filter);
            filter_config.world_active_set = world_authority
                .as_ref()
                .map(|resolved| &resolved.active_set);
            filter_config.device_local = device_local.as_ref();
            let stale_worlds = if matches!(self.world_scope, super::super::types::WorldScope::All) {
                Some(crate::federation::stale_stamped_worlds(
                    &self.vault.store,
                    rtxn,
                )?)
                .filter(|stale| !stale.is_empty())
            } else {
                None
            };
            filter_config.stale_worlds = stale_worlds.as_ref();
            // A scoped scan scores every posting through its scope, D19's gate
            // included. Unscoped text probes for a posting the gate rejects
            // and scans that way too when it finds one; candidate-filtered
            // text always does, and needs no probe.
            let text_scope_active = codebase_scope_active
                || self.has_strict_text_scope_filter()
                || occurred_range.is_some();
            let text_scope_widening_active = text_scope_active
                || self.claim_gate_text_widening_probe(
                    rtxn,
                    bm25_config,
                    hyde_expansion,
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate_widening_probe,
                )?;
            let mut stages = StagePlan::new([
                self.vector_search.is_some(),
                hyde_expansion.is_some(),
                self.text_search.is_some(),
                self.phonetic_search.is_some(),
                self.temporal_search.is_some(),
                self.ppr_search.is_some(),
            ]);

            if let Some((query_vector, limit)) = &self.vector_search
                && let Some(vector_results) =
                    self.run_stage(RetrievalSignal::Vector, stages.next(), || {
                        let limit = fusion_fetch_limit(*limit);
                        self.scoped_vector_results(
                            rtxn,
                            query_vector,
                            if overrides.widen_channel_limits {
                                retry_channel_limit(limit)
                            } else {
                                limit
                            },
                            filter_config,
                            &mut metadata_cache,
                            &mut claim_gate,
                        )
                    })?
            {
                diagnostics.succeeded.push(RetrievalSignal::Vector);
                vector_channel_index = Some(acc.admit_channel(
                    RetrievalSignal::Vector,
                    vector_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?);
            }

            if let Some(expansion) = hyde_expansion.as_ref()
                && let Some(hyde_results) =
                    self.run_stage(RetrievalSignal::Hyde, stages.next(), || {
                        let limit = fusion_fetch_limit(
                            self.hyde
                                .as_ref()
                                .expect("hyde expansion has config")
                                .2
                                .channel_limit,
                        );
                        self.scoped_vector_results(
                            rtxn,
                            &expansion.embedding,
                            if overrides.widen_channel_limits {
                                retry_channel_limit(limit)
                            } else {
                                limit
                            },
                            filter_config,
                            &mut metadata_cache,
                            &mut claim_gate,
                        )
                    })?
            {
                acc.admit_channel(
                    RetrievalSignal::Hyde,
                    hyde_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
            }

            let text_channel_index = self.run_text_channel(
                rtxn,
                stages.next_if(self.text_search.is_some()),
                TextChannelInputs {
                    bm25_config,
                    hyde_expansion,
                    overrides: &overrides,
                    recency,
                    filter_config,
                    authority_filter,
                    text_scope_widening_active,
                    private_note_ids: private_note_ids.as_deref(),
                    claim_gate_widening_probe,
                },
                &mut acc,
                &mut diagnostics,
                &mut metadata_cache,
                &mut claim_gate,
            )?;

            #[cfg(test)]
            if text_channel_index.is_some() {
                let hooks = self.vault.test_hooks();
                let hook = hooks
                    .after_retrieval_text
                    .lock()
                    .expect("retrieval text hook")
                    .take();
                if let Some(hook) = hook {
                    hook();
                }
                if hooks
                    .cancel_deadline_after_retrieval_text
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
                    && let Some(deadline) = self.deadline
                {
                    deadline.cancel();
                }
            }

            if let Some(codes) = &self.phonetic_search
                && let Some(phonetic_results) =
                    self.run_stage(RetrievalSignal::Phonetic, stages.next(), || {
                        execute_phonetic(&self.read, rtxn, codes)
                    })?
            {
                diagnostics.succeeded.push(RetrievalSignal::Phonetic);
                phonetic_channel_index = Some(acc.admit_channel(
                    RetrievalSignal::Phonetic,
                    phonetic_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?);
            }

            if let Some(config) = &self.temporal_search
                && let Some(temporal_results) =
                    self.run_stage(RetrievalSignal::Temporal, stages.next(), || {
                        let mut config = config.clone();
                        config.limit = fusion_fetch_limit(config.limit);
                        if overrides.widen_channel_limits {
                            config.limit = retry_channel_limit(config.limit);
                        }
                        self.scoped_temporal_results(
                            rtxn,
                            &config,
                            temporal_now,
                            filter_config,
                            &mut metadata_cache,
                            &mut claim_gate,
                        )
                    })?
            {
                diagnostics.succeeded.push(RetrievalSignal::Temporal);
                acc.admit_channel(
                    RetrievalSignal::Temporal,
                    temporal_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
            }

            if let Some((seeds, depth)) = &self.ppr_search
                && let Some(ppr) = self.run_stage(RetrievalSignal::Ppr, stages.next(), || {
                    // ARCH-0039 Layer 2: seed specificity applies ONLY to
                    // search_ppr — seeds are weighted 1/ln(1 + passage_count)
                    // instead of uniform 1/n.
                    crate::ppr::ppr_query_in_txn_with_diagnostics(
                        &self.read,
                        rtxn,
                        seeds,
                        *depth,
                        PPR_DAMPING,
                        self.vault.config.ppr_vad_alpha,
                        crate::ppr::SeedWeighting::Specificity,
                    )
                })?
            {
                diagnostics.succeeded.push(RetrievalSignal::Ppr);
                record_ppr_cache_outcome(&mut diagnostics, ppr.cache);
                let ppr_results = ppr.scores;
                let deferred_cache_write = ppr.deferred_cache_write;
                acc.admit_channel(
                    RetrievalSignal::Ppr,
                    ppr_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
                if let Some(deferred_cache_write) = deferred_cache_write {
                    deferred_ppr_cache_writes.push(deferred_cache_write);
                }
            }

            // OF-370: one ranked list per declared media space, never merged
            // with another space's raw scores before fusion.
            for query in &self.media_search {
                if self.deadline_reached() {
                    break;
                }
                let media_results = self.media_space_results(
                    rtxn,
                    query,
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate,
                    &mut acc.media_evidence,
                )?;
                diagnostics.succeeded.push(RetrievalSignal::MediaVector);
                acc.admit_channel(
                    RetrievalSignal::MediaVector,
                    media_results,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                )?;
            }

            // Entity-type authority can narrow each channel before fusion.
            // CLAIM scalar constraints use the decoded post-fusion stage below.
            for scores in &mut acc.ranked_lists {
                if self.memory_category {
                    super::super::capabilities::retain_memory_candidates(scores, &self.read, rtxn)?;
                }
                super::authority::apply_types(
                    scores,
                    authority_filter,
                    self.type_filter.as_deref(),
                    &self.read,
                    rtxn,
                    &mut metadata_cache,
                )?;
            }
            if acc.ranked_lists.is_empty() {
                return Ok(RetrievalTxnOutput {
                    revisions: HashMap::new(),
                    words_bound: Default::default(),
                    diagnostics,
                    scores: Vec::new(),
                    cited_messages: HashMap::new(),
                    capabilities: Vec::new(),
                    pending_vectors: Vec::new(),
                    claim_gate: ClaimStatusGateCache::default(),
                    read_suppressed: metadata_cache.countable_suppressed(
                        self.vault,
                        &self.read,
                        rtxn,
                        authority_filter.credential.as_ref(),
                        filter_config.device_local,
                    )?,
                    deferred_ppr_cache_writes: Vec::new(),
                    cosine_ghosts_dampened: 0,
                    disclosure_clamped: Vec::new(),
                    total_in_scope: 0,
                    empty_reason: None,
                    signal_components: HashMap::new(),
                    media_evidence: Default::default(),
                    blend_components: HashMap::new(),
                    access_factors: HashMap::new(),
                    rerank_merged_components: None,
                    retrieval_trace: None,
                    replay_inputs: capture_replay_enabled.then(|| {
                        capture_replay_inputs(
                            self,
                            bm25_config,
                            blend_weights,
                            authority_filter,
                            world_authority.as_ref(),
                            hyde_expansion,
                            overrides.extra_text_queries,
                            overrides.widen_channel_limits,
                            overrides.skip_ret01_abstain,
                            occurred_range,
                            temporal_now,
                            rerank_query,
                        )
                    }),
                    ppr_expand_executed: false,
                    early_empty_no_telemetry: !capture_replay_enabled,
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
                affect: self.affect_policy,
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
            let expand_allowed = self.ppr_expand.is_some() && !self.deadline_reached();
            let first_blend = blended_retrieval_scores(
                &acc.ranked_lists,
                RetrievalChannelIndexes {
                    vector: vector_channel_index,
                    text: text_channel_index,
                    phonetic: phonetic_channel_index,
                },
                &self.read,
                rtxn,
                &mut metadata_cache,
                &mut claim_gate,
                RetrievalBlendConfig {
                    access_factor_application: if expand_allowed {
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
            let total_in_scope = if self.context_pack_budget.is_some() {
                memory_candidate_count(&self.read, rtxn, &scores)?
            } else {
                scores.len()
            };
            let mut empty_reason = None;

            // D19 claim status gate, first application: covers the fused
            // union of every ranked list (vector/HyDE/text/HyDE-retry/
            // phonetic/temporal/PPR) AND runs BEFORE expand_ppr implicit
            // seed selection, so a dead claim never seeds the expansion.
            let before_status_gate = scores.len();
            apply_claim_status_gate(
                &mut scores,
                &self.read,
                rtxn,
                &mut metadata_cache,
                &mut claim_gate,
            )?;
            if before_status_gate > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::AllActivated);
            }
            let mut blend_allowed_ids = score_id_set(&scores);

            if expand_allowed
                && let Some(outcome) = self.expand_ppr_stage(
                    rtxn,
                    &scores,
                    PprExpandInputs {
                        filter_config,
                        blend_config,
                        blend_weights,
                        channel_indexes: RetrievalChannelIndexes {
                            vector: vector_channel_index,
                            text: text_channel_index,
                            phonetic: phonetic_channel_index,
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
                )?
            {
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
                rtxn,
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
                words_revisions,
            } = self.apply_rerank_ladder(
                rtxn,
                &mut scores,
                &mut metadata_cache,
                &mut claim_gate,
                RerankLadderInputs {
                    ladder_scores: rerank_ladder_scores.as_ref(),
                    blend_access_factors: &blend_access_factors,
                    blend_components: &blend_components,
                    filter_config,
                    rerank_query,
                    capture_retrieval_trace,
                    trace_candidate_limit,
                },
            )?;

            entity_rank::rank_unmatched_entities_below_matches(
                &mut scores,
                &acc.signal_components,
                &self.read,
                rtxn,
                &mut metadata_cache,
            )?;

            if let Some((relationship, RelMode::Demote)) = self.relationship_filter {
                apply_relationship_filter(
                    &mut scores,
                    &self.read,
                    rtxn,
                    &mut metadata_cache,
                    &relationship,
                    RelMode::Demote,
                )?;
            }

            let cited_messages = if self.turn_fold == TurnFold::Off {
                HashMap::new()
            } else {
                turn_fold::fold_messages_into_turns(
                    &mut scores,
                    &mut acc.signal_components,
                    self.turn_fold,
                    &self.read,
                    rtxn,
                    filter_config,
                    &mut metadata_cache,
                    &mut claim_gate,
                )?
            };

            let capabilities = self.prepare_pack_candidates(
                rtxn,
                &mut scores,
                &acc.signal_components,
                &acc.media_evidence,
                &mut empty_reason,
                overrides.skip_ret01_abstain,
            )?;

            // A pack emptied by its disclosure clamp or its world share lost
            // nothing to a threshold.
            let mut emptied_by_policy = false;
            let disclosure_clamped = match self.disclosure_preselect.as_ref() {
                Some(clamp) => {
                    let withheld = withhold_undisclosed(
                        &mut scores,
                        clamp,
                        &self.read,
                        rtxn,
                        &mut metadata_cache,
                        &claim_gate,
                    )?;
                    emptied_by_policy |= !withheld.is_empty() && scores.is_empty();
                    withheld
                }
                None => Vec::new(),
            };
            let world_share = self.context_pack_world_share.map(|fraction| WorldShare {
                fraction,
                claim_gate: &claim_gate,
            });
            if let Some(context_pack_budget) = self.context_pack_budget {
                let share_held_back = apply_context_pack_retrieval_budget(
                    &mut scores,
                    &self.read,
                    rtxn,
                    &mut metadata_cache,
                    context_pack_budget,
                    world_share,
                )?;
                emptied_by_policy |= share_held_back && scores.is_empty();
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
            match world_share {
                Some(share) => {
                    let had_rows = !scores.is_empty();
                    truncate_under_world_share(
                        &mut scores,
                        self.result_limit,
                        share,
                        &self.read,
                        rtxn,
                        &mut metadata_cache,
                    )?;
                    emptied_by_policy |= had_rows && scores.is_empty();
                }
                None => scores.truncate(self.result_limit),
            }
            if before_limit > 0 && scores.is_empty() && !emptied_by_policy {
                empty_reason = Some(EmptyReason::BelowThreshold);
            }
            if no_data_fallback_eligible
                && total_in_scope == 0
                && scores.is_empty()
                && empty_reason.is_none()
            {
                empty_reason = Some(EmptyReason::NoData);
            }
            let pending_vectors =
                pending_vectors_for_scores(&self.vault.store, &self.read, rtxn, &scores)?;
            let retrieval_trace = if capture_retrieval_trace {
                Some(self.assemble_retrieval_trace(TraceInputs {
                    derivation_owner: crate::federation::derivation::owner_in_txn(
                        &self.vault.store,
                        rtxn,
                    )?,
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
            let replay_inputs = capture_replay_enabled.then(|| {
                capture_replay_inputs(
                    self,
                    bm25_config,
                    blend_weights,
                    authority_filter,
                    world_authority.as_ref(),
                    hyde_expansion,
                    overrides.extra_text_queries,
                    overrides.widen_channel_limits,
                    overrides.skip_ret01_abstain,
                    occurred_range,
                    temporal_now,
                    rerank_query,
                )
            });
            // A hit whose indexed revision cannot be read has no pin, so it
            // leaves the pack instead of failing the run. A MESSAGE whose text
            // moved into an entity document is one: the migration replaced its
            // body without retaining the revision its state still names. A
            // reranked hit is pinned where its words were scored.
            let mut revisions = HashMap::new();
            for hit in &scores {
                if let Some(revision) = words_revisions.get(&hit.id) {
                    revisions.insert(hit.id, *revision);
                    continue;
                }
                match self
                    .vault
                    .indexed_revision_from_in_txn(&self.read, rtxn, &hit.id)
                {
                    Ok(Some(revision)) => {
                        revisions.insert(hit.id, revision);
                    }
                    Ok(None) | Err(crate::Error::EntityNotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(RetrievalTxnOutput {
                revisions,
                words_bound: words_revisions.into_keys().collect(),
                diagnostics,
                scores,
                cited_messages,
                capabilities,
                pending_vectors,
                claim_gate,
                read_suppressed: metadata_cache.countable_suppressed(
                    self.vault,
                    &self.read,
                    rtxn,
                    authority_filter.credential.as_ref(),
                    filter_config.device_local,
                )?,
                deferred_ppr_cache_writes,
                cosine_ghosts_dampened,
                disclosure_clamped,
                total_in_scope,
                empty_reason,
                signal_components: acc.signal_components,
                media_evidence: acc.media_evidence,
                blend_components,
                access_factors: blend_access_factors,
                rerank_merged_components,
                retrieval_trace,
                replay_inputs,
                ppr_expand_executed,
                early_empty_no_telemetry: false,
            })
        }
    }

    fn scoped_channel_admission(
        &self,
        rtxn: &heed::RoTxn<'_>,
        filter: &crate::gate::ResolvedRetrievalFilter,
    ) -> Result<ScopedChannelAdmission> {
        let private_note_ids = self
            .scoped_note_reader
            .as_ref()
            .map(|key| {
                self.vault
                    .scoped_read(key.clone())
                    .diary_candidates_in(rtxn, filter)
                    .map(std::sync::Arc::new)
            })
            .transpose()?;
        let mut accumulator = ChannelAccumulator::new(
            self.capture_retrieval_trace,
            self.result_limit,
            filter.include_stale,
        );
        let device_local = self.device_local_worlds(rtxn)?.map(std::sync::Arc::new);
        accumulator.trace_claim_gate.private_note_ids = private_note_ids.clone();
        accumulator
            .trace_claim_gate
            .device_local
            .clone_from(&device_local);
        let new_gate = || ClaimStatusGateCache {
            include_stale: filter.include_stale,
            private_note_ids: private_note_ids.clone(),
            device_local: device_local.clone(),
            ..ClaimStatusGateCache::default()
        };
        let claim_gate = new_gate();
        let widening_probe = new_gate();
        Ok(ScopedChannelAdmission {
            private_note_ids,
            accumulator,
            claim_gate,
            widening_probe,
        })
    }

    fn prepare_pack_candidates(
        &self,
        rtxn: &heed::RoTxn<'_>,
        scores: &mut Vec<super::super::types::ScoredEntity>,
        signal_components: &HashMap<crate::EntityId, Vec<crate::store::RetrievalScoreComponent>>,
        media_evidence: &super::super::budget::MediaEvidence,
        empty_reason: &mut Option<EmptyReason>,
        skip_ret01_abstain: bool,
    ) -> Result<Vec<super::super::types::ScoredEntity>> {
        let mut capabilities = if self.context_pack_budget.is_some() {
            partition_capabilities(
                scores,
                self.vault,
                &self.read,
                rtxn,
                signal_components,
                self.skill_executor.as_deref(),
                self.skill_reliability_query.as_ref(),
            )?
        } else {
            Vec::new()
        };
        if skip_ret01_abstain {
            return Ok(capabilities);
        }
        let floors = self.no_match_floors();
        let mut metadata_cache = EntityMetadataCache::default();
        let mut kind_of = |id: &crate::EntityId| -> Result<Option<u8>> {
            Ok(metadata_cache
                .get(&self.read, rtxn, id)?
                .map(|meta| meta.entity_type))
        };
        if context_pack_evidence_abstains(
            &capabilities,
            signal_components,
            media_evidence,
            self.text_search.as_ref().map(|(query, _)| query.as_str()),
            self.vector_search.is_some(),
            self.vault.evidence_space(),
            &floors,
            &mut kind_of,
        )? {
            capabilities.clear();
        }

        // RET-01: abstention is a context-pack assembly decision, never a
        // mutation of stored memory or a behavior change for direct
        // retrieval. Clear the candidate list structurally so hydration
        // cannot surface weak evidence; `BelowThreshold` is carried to
        // the public `ContextPack.empty` response as the typed confidence
        // adjustment.
        if self.context_pack_budget.is_some()
            && context_pack_evidence_abstains(
                scores,
                signal_components,
                media_evidence,
                self.text_search.as_ref().map(|(query, _)| query.as_str()),
                self.vector_search.is_some(),
                self.vault.evidence_space(),
                &floors,
                &mut kind_of,
            )?
        {
            scores.clear();
            *empty_reason = Some(EmptyReason::BelowThreshold);
        }
        Ok(capabilities)
    }
}
