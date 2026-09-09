//! Retrieval-trace assembly: the fork hash and the per-channel, fused, blended, reranked, and final stage records.

use crate::bm25::Bm25Config;
use crate::entity_id::EntityId;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::trace::{
    RetrievalTraceForkEvidence, retrieval_trace_candidate_set, retrieval_trace_fork_hash,
    retrieval_trace_stage_record, retrieval_trace_top_scores,
};
use crate::pipeline::types::{ResolvedWorldAuthority, ScoredEntity};
use crate::store::{
    RetrievalBlendWeights, RetrievalScoreComponent, RetrievalTrace, RetrievalTraceChannelRecord,
    RetrievalTraceStage,
};
use std::collections::HashMap;

/// Every face the trace records, plus the fork-hash inputs.
pub(super) struct TraceInputs<'a> {
    /// The run's final scores, after budget and truncation.
    pub(super) scores: &'a [ScoredEntity],
    pub(super) trace_channels: Vec<RetrievalTraceChannelRecord>,
    pub(super) trace_ranked_lists: &'a [Vec<ScoredEntity>],
    pub(super) signal_components: &'a HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) fused_trace_scores: Option<Vec<ScoredEntity>>,
    pub(super) blended_trace_scores: Option<Vec<ScoredEntity>>,
    pub(super) reranked_trace_scores: Option<&'a [ScoredEntity]>,
    pub(super) rerank_merged_components:
        Option<&'a HashMap<EntityId, Vec<RetrievalScoreComponent>>>,
    pub(super) blend_components: &'a HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) blend_access_factors: &'a HashMap<EntityId, f32>,
    pub(super) community_trace_identity: Option<[u8; 32]>,
    pub(super) world_authority: Option<&'a ResolvedWorldAuthority>,
    pub(super) bm25_config: &'a Bm25Config,
    pub(super) blend_weights: RetrievalBlendWeights,
    pub(super) explicit_time_dependent_now: Option<u64>,
    pub(super) occurred_range: Option<(u64, u64)>,
    pub(super) rerank_query: Option<&'a str>,
    pub(super) trace_candidate_limit: usize,
}

impl PipelineBuilder<'_> {
    pub(super) fn assemble_retrieval_trace(&self, inputs: TraceInputs<'_>) -> RetrievalTrace {
        let final_scores = retrieval_trace_top_scores(inputs.scores, inputs.trace_candidate_limit);
        let blended_scores = inputs.blended_trace_scores.unwrap_or_default();
        let candidate_set = retrieval_trace_candidate_set(
            inputs.trace_ranked_lists,
            inputs.fused_trace_scores.as_deref().unwrap_or(&[]),
            &blended_scores,
            &final_scores,
        );
        let fork_hash = retrieval_trace_fork_hash(
            self,
            inputs.bm25_config,
            inputs.blend_weights,
            inputs.explicit_time_dependent_now,
            inputs.occurred_range,
            inputs.rerank_query,
            RetrievalTraceForkEvidence {
                candidate_set: &candidate_set,
                world_authority: inputs.world_authority,
            },
        );
        let fork_hash = if let Some(identity) = inputs.community_trace_identity {
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            hash.update(b"oneiron.retrieval_trace.community.fork.v0");
            hash.update(fork_hash);
            hash.update(identity);
            hash.finalize().into()
        } else {
            fork_hash
        };
        RetrievalTrace {
            fork_hash,
            per_channel: inputs.trace_channels,
            // The fused stage is the pre-blend RRF order, so it
            // carries no applied multiplier to attribute: an empty
            // map makes every one of its rows record `None`.
            fused: retrieval_trace_stage_record(
                RetrievalTraceStage::Fused,
                &inputs.fused_trace_scores.unwrap_or_default(),
                inputs.signal_components,
                &HashMap::new(),
                &HashMap::new(),
                inputs.trace_candidate_limit,
            ),
            blended: retrieval_trace_stage_record(
                RetrievalTraceStage::Blended,
                &blended_scores,
                inputs.signal_components,
                inputs.blend_components,
                inputs.blend_access_factors,
                inputs.trace_candidate_limit,
            ),
            // Rerank inactive: passthrough mirror of `final` (the
            // 1186-D5 reserved slot). Active: the post-rerank,
            // pre-budget/pre-truncate ordering with the rerank
            // components appended after the blend components.
            reranked: retrieval_trace_stage_record(
                RetrievalTraceStage::Reranked,
                inputs.reranked_trace_scores.unwrap_or(&final_scores),
                inputs.signal_components,
                inputs
                    .rerank_merged_components
                    .unwrap_or(inputs.blend_components),
                inputs.blend_access_factors,
                inputs.trace_candidate_limit,
            ),
            final_stage: retrieval_trace_stage_record(
                RetrievalTraceStage::Final,
                &final_scores,
                inputs.signal_components,
                inputs.blend_components,
                inputs.blend_access_factors,
                inputs.trace_candidate_limit,
            ),
        }
    }
}
