//! The `expand_ppr` stage: seed selection, the expansion walk and its gate, and the run's single decay-applying blend.

use super::admit::ChannelAccumulator;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::blend::{
    BlendedRetrievalScores, RetrievalBlendConfig, RetrievalChannelIndexes,
    blended_retrieval_scores, filter_blended_scores_to_allowed_ids,
};
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::filters::apply_claim_status_gate;
use crate::pipeline::trace::{record_ppr_cache_outcome, retrieval_trace_fused_scores};
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PPR_DAMPING, PipelineFilterConfig, ScoredEntity,
};
use crate::ppr::{CommunityPprDiversity, DeferredPprCacheWrite};
use crate::retrieval_quality::{PprCacheOutcome, RetrievalDiagnostics};
use crate::store::{RetrievalBlendWeights, RetrievalSignal};
use heed::RoTxn;
use std::collections::{HashMap, HashSet};

/// The run-constant inputs the stage reads.
#[derive(Clone, Copy)]
pub(super) struct PprExpandInputs<'a> {
    pub(super) filter_config: PipelineFilterConfig<'a>,
    /// The run's single decay-applying blend config.
    pub(super) blend_config: RetrievalBlendConfig<'a>,
    pub(super) blend_weights: RetrievalBlendWeights,
    pub(super) channel_indexes: RetrievalChannelIndexes,
    pub(super) temporal_now: u64,
    pub(super) codebase_scope_active: bool,
}

/// The run state the stage extends in place.
pub(super) struct PprExpandState<'a> {
    pub(super) acc: &'a mut ChannelAccumulator,
    pub(super) blend_allowed_ids: &'a mut HashSet<EntityId>,
    pub(super) fused_trace_scores: &'a mut Option<Vec<ScoredEntity>>,
    pub(super) diagnostics: &'a mut RetrievalDiagnostics,
    pub(super) deferred_ppr_cache_writes: &'a mut Vec<DeferredPprCacheWrite>,
}

/// What a configured `expand_ppr` hands back: the run's single Apply blend,
/// every face replaced together and `scores` already narrowed to the
/// allowed ids, plus the community outputs of the expanded branch.
pub(super) struct PprExpandOutcome {
    pub(super) blend: BlendedRetrievalScores,
    pub(super) community_diversity: Option<CommunityPprDiversity>,
    pub(super) community_trace_identity: Option<[u8; 32]>,
    pub(super) ppr_expand_executed: bool,
}

impl PipelineBuilder<'_> {
    // Implicit seed selection reads the PRELIMINARY blend above,
    // whose scores are decay-free, so seed choice depends only on
    // relevance. The D19 gate has already run, so a dead claim
    // still never seeds; decay simply does not participate.
    //
    // Returns `None` when `expand_ppr` is not configured.
    pub(super) fn expand_ppr_stage(
        &self,
        rtxn: &RoTxn<'_>,
        scores: &[ScoredEntity],
        inputs: PprExpandInputs<'_>,
        state: PprExpandState<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Option<PprExpandOutcome>> {
        let Some((explicit_seeds, depth)) = &self.ppr_expand else {
            return Ok(None);
        };
        let mut community_diversity = None;
        let mut community_trace_identity = None;
        let mut seen = HashSet::<EntityId>::new();
        let mut seeds = Vec::<EntityId>::new();
        for seed in explicit_seeds {
            if seen.insert(*seed) {
                seeds.push(*seed);
            }
        }
        if seeds.len() < crate::ppr::MAX_PPR_SEEDS {
            let implicit_seed_limit = if inputs.codebase_scope_active {
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
            seeds.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            // expand_ppr seeds stay UNIFORM — ARCH-0039 Layer-2
            // specificity weighting is search_ppr-only.
            let ppr = if self.vault.config.ppr_community.beta == 0.0 {
                // Exact legacy path: no evidence/cache reads or new key namespace.
                crate::ppr::ppr_query_in_txn_with_diagnostics(
                    &self.vault.store,
                    rtxn,
                    &seeds,
                    *depth,
                    PPR_DAMPING,
                    self.vault.config.ppr_vad_alpha,
                    crate::ppr::SeedWeighting::Uniform,
                )?
            } else {
                // ID sorting for the base cache must not replace the fused
                // evidence order. Explicit-only seeds get zero evidence.
                let ordered_seeds = crate::ppr_community::ordered_seed_evidence(&seeds, scores)
                    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
                let empty_usage = HashMap::new();
                let context = crate::ppr_community::CommunityBoostContext {
                    ordered_seeds: &ordered_seeds,
                    result_limit: self.result_limit,
                    session_usage: self.community_session_usage.unwrap_or(&empty_usage),
                };
                let (result, diversity) = crate::ppr::ppr_expand_in_txn_with_community_diagnostics(
                    &self.vault.store,
                    rtxn,
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
                if state.acc.capture {
                    community_trace_identity = Some(self.community_trace_identity(
                        &ordered_seeds,
                        crate::ppr::read_graph_version(&self.vault.store, rtxn)?,
                    ));
                }
                result
            };
            if !state.diagnostics.succeeded.contains(&RetrievalSignal::Ppr) {
                state.diagnostics.succeeded.push(RetrievalSignal::Ppr);
            }
            record_ppr_cache_outcome(state.diagnostics, ppr.cache);
            let mut ppr_results = ppr.scores;
            if let Some(deferred_cache_write) = ppr.deferred_cache_write {
                state.deferred_ppr_cache_writes.push(deferred_cache_write);
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
                rtxn,
                metadata_cache,
                claim_gate,
            )?;
            state
                .blend_allowed_ids
                .extend(ppr_results.iter().map(|scored| scored.id));
            state.acc.admit_channel(
                RetrievalSignal::Ppr,
                ppr_results,
                &self.vault.store,
                rtxn,
                inputs.filter_config,
                metadata_cache,
            )?;
            if state.acc.capture {
                *state.fused_trace_scores = Some(retrieval_trace_fused_scores(
                    &state.acc.trace_ranked_lists,
                    state.acc.trace_candidate_limit,
                ));
            }
            // The expanded blend is this run's ONE decay
            // application: the seeds above were picked from the
            // neutral preliminary order.
            let mut expanded_blend = blended_retrieval_scores(
                &state.acc.ranked_lists,
                inputs.channel_indexes,
                &self.vault.store,
                rtxn,
                metadata_cache,
                claim_gate,
                inputs.blend_config,
                inputs.temporal_now,
                inputs.blend_weights,
            )?;
            expanded_blend.scores = filter_blended_scores_to_allowed_ids(
                expanded_blend.scores,
                state.blend_allowed_ids,
            );
            Ok(Some(PprExpandOutcome {
                blend: expanded_blend,
                community_diversity,
                community_trace_identity,
                ppr_expand_executed: true,
            }))
        } else {
            record_ppr_cache_outcome(state.diagnostics, PprCacheOutcome::Disabled);
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
            let mut applied_blend = blended_retrieval_scores(
                &state.acc.ranked_lists,
                inputs.channel_indexes,
                &self.vault.store,
                rtxn,
                metadata_cache,
                claim_gate,
                inputs.blend_config,
                inputs.temporal_now,
                inputs.blend_weights,
            )?;
            applied_blend.scores =
                filter_blended_scores_to_allowed_ids(applied_blend.scores, state.blend_allowed_ids);
            Ok(Some(PprExpandOutcome {
                blend: applied_blend,
                community_diversity,
                community_trace_identity,
                ppr_expand_executed: false,
            }))
        }
    }
}
