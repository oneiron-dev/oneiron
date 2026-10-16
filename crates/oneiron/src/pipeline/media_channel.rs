//! Typed media retrieval over declared embedding spaces (OF-370; ARCH-0004
//! `#embedding-spaces`).
//!
//! Each media query names one declared space and the tower that encoded it. Its search reads
//! that space's rows alone and becomes its own ranked list, so fusion z-scores it on its own
//! scale beside the text index, keyword, phonetic, graph and time lists: two spaces' raw
//! cosines never meet. RET-01 judges each hit by its own space's floor
//! ([`super::budget::media_space_floor`]).

use std::collections::HashSet;

use heed::RoTxn;

use crate::embed::InputKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::budget::media_space_floor;
use super::builder::PipelineBuilder;
use super::capabilities::CapabilityLane;
use super::channels::fusion_fetch_limit;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity};

/// One media-space query: the space, the tower that encoded the vector, the media kinds it
/// keeps (every kind the space holds when empty) and its list length.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct MediaQuery {
    pub(super) space_id: String,
    pub(super) query_kind: InputKind,
    pub(super) vector: Vec<f32>,
    pub(super) kinds: Vec<InputKind>,
    pub(super) limit: usize,
}

impl PipelineBuilder<'_> {
    /// One media query's admitted results, best first: the space must be declared, the query
    /// must come through one of its towers at its width, and every row passes the run's own
    /// filters and gate before it can take a place. Each hit at or above its space's RET-01
    /// floor lands in `evidence`, which keeps a context pack from abstaining.
    pub(super) fn media_space_results(
        &self,
        rtxn: &RoTxn<'_>,
        query: &MediaQuery,
        filters: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
        evidence: &mut HashSet<EntityId>,
    ) -> Result<Vec<ScoredEntity>> {
        let Some(space) = crate::embed::embedding_space_in_txn(&self.read, rtxn, &query.space_id)?
        else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} is not declared",
                query.space_id
            )));
        };
        space.admit_query(query.query_kind, &query.vector)?;
        let memory = self.memory_category;
        let results = crate::embed::search_media_space_in_txn(
            &self.read,
            rtxn,
            &space,
            &query.vector,
            &query.kinds,
            fusion_fetch_limit(query.limit),
            |id| {
                Ok(pipeline_candidate_matches_filters_and_gate(
                    &self.read,
                    rtxn,
                    id,
                    filters,
                    metadata_cache,
                    claim_gate,
                )? && (!memory || CapabilityLane::Memory.admits(&self.read, rtxn, id)?))
            },
        )?;
        let floors = self.no_match_floors();
        let keyed = floors.keys_space(&space.id);
        for scored in &results {
            let kind = if keyed {
                metadata_cache
                    .get(&self.read, rtxn, &scored.id)?
                    .map(|meta| meta.entity_type)
            } else {
                None
            };
            if scored.score.is_finite() && scored.score >= media_space_floor(&floors, &space, kind)
            {
                evidence.insert(scored.id);
            }
        }
        Ok(results)
    }
}
