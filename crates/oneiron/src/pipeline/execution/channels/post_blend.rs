//! Post-blend filters: scope and authority, the rerank shadow ladder, contiguity, facet, world, corpus, and relationship filters.

use crate::context_pack::EmptyReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::authority;
use crate::pipeline::blend::boost_contiguity;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::corpus_filter::CorpusFilter;
use crate::pipeline::filters::{
    apply_facet_filter, apply_filters, apply_relationship_filter, apply_world_filter,
};
use crate::pipeline::trace::retrieval_trace_top_scores;
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, RelMode, ScoredEntity,
};
use heed::RoTxn;
use std::collections::HashMap;

/// The read-only inputs the post-blend filters draw on.
#[derive(Clone, Copy)]
pub(super) struct PostBlendInputs<'a> {
    pub(super) filter_config: PipelineFilterConfig<'a>,
    pub(super) corpus_filter: &'a CorpusFilter,
    pub(super) authority_filter: &'a crate::gate::ResolvedRetrievalFilter,
    /// Each candidate's fused score before the read-side multiplier: the
    /// face the rerank shadow ladder replays the boosts over.
    pub(super) blend_base_scores: &'a HashMap<EntityId, f32>,
    pub(super) capture_retrieval_trace: bool,
    pub(super) trace_candidate_limit: usize,
}

/// What the filters hand back besides the narrowed `scores`.
pub(super) struct PostBlend {
    /// The rerank shadow ladder keyed by entity; `None` without a reranker.
    pub(super) rerank_ladder_scores: Option<HashMap<EntityId, f32>>,
    pub(super) blended_trace_scores: Option<Vec<ScoredEntity>>,
    pub(super) empty_reason: Option<EmptyReason>,
}

impl PipelineBuilder<'_> {
    pub(super) fn apply_post_blend_filters(
        &self,
        rtxn: &RoTxn<'_>,
        scores: &mut Vec<ScoredEntity>,
        mut empty_reason: Option<EmptyReason>,
        inputs: PostBlendInputs<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<PostBlend> {
        let mut blended_trace_scores = None;
        let before_filters = scores.len();
        apply_filters(
            scores,
            &self.vault.store,
            rtxn,
            inputs.filter_config,
            metadata_cache,
        )?;
        authority::apply(
            scores,
            inputs.authority_filter,
            &self.vault.store,
            rtxn,
            metadata_cache,
            claim_gate,
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
            for scored in &*scores {
                let Some(base_score) = inputs.blend_base_scores.get(&scored.id).copied() else {
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
                scores,
                self.temporal_search.as_ref(),
                &self.vault.store,
                rtxn,
                metadata_cache,
            )?;
            if let Some(ladder_scores) = rerank_ladder_scores.as_mut() {
                boost_contiguity(
                    ladder_scores,
                    self.temporal_search.as_ref(),
                    &self.vault.store,
                    rtxn,
                    metadata_cache,
                )?;
            }
        }

        // ARCH-0039 facet filter (ONE-1117): post-fusion / post-boosts,
        // before truncate, same read txn — strict-excluded claims never
        // consume `result_limit` slots.
        if let Some((facet_id, mode)) = self.facet_filter {
            let before_facet = scores.len();
            apply_facet_filter(
                scores,
                &self.vault.store,
                rtxn,
                metadata_cache,
                &facet_id,
                mode,
            )?;
            if let Some(ladder_scores) = rerank_ladder_scores.as_mut() {
                apply_facet_filter(
                    ladder_scores,
                    &self.vault.store,
                    rtxn,
                    metadata_cache,
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
            scores,
            &self.vault.store,
            rtxn,
            self.world_scope,
            inputs.filter_config.world_active_set,
        )?;
        if before_world > 0 && scores.is_empty() {
            empty_reason = Some(EmptyReason::FilterMatchedNone);
        }

        empty_reason = inputs.corpus_filter.apply(
            scores,
            &self.vault.store,
            rtxn,
            metadata_cache,
            claim_gate,
            empty_reason,
        )?;
        if let Some((relationship, RelMode::Filter)) = self.relationship_filter {
            let before_relationship = scores.len();
            apply_relationship_filter(
                scores,
                &self.vault.store,
                rtxn,
                metadata_cache,
                &relationship,
                RelMode::Filter,
            )?;
            if before_relationship > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }
        }
        if inputs.capture_retrieval_trace {
            blended_trace_scores = Some(retrieval_trace_top_scores(
                scores,
                inputs.trace_candidate_limit,
            ));
        }
        let rerank_ladder_scores = rerank_ladder_scores.map(|ladder_scores| {
            ladder_scores
                .into_iter()
                .map(|scored| (scored.id, scored.score))
                .collect::<HashMap<_, _>>()
        });
        Ok(PostBlend {
            rerank_ladder_scores,
            blended_trace_scores,
            empty_reason,
        })
    }
}
