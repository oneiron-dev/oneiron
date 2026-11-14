//! The learned phonetic rung's list (CROSS-ARCH-0013 `#ladder` rung 2): the caller's vector of
//! a name, searched by exact cosine against the stored name vectors of its model. It is its own
//! ranked list of the phonetic channel, beside the code rung's, so fusion z-scores it on its own
//! scale and every filter and gate of the run applies before a row takes a place.

use heed::RoTxn;

use crate::error::Result;

use super::builder::PipelineBuilder;
use super::capabilities::CapabilityLane;
use super::channels::fusion_fetch_limit;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity};

/// One learned query: the model the vector is of, the vector, and its list length.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PhoneticVectorQuery {
    pub(super) model_id: String,
    pub(super) vector: Vec<f32>,
    pub(super) limit: usize,
}

impl PipelineBuilder<'_> {
    /// `query`'s admitted results, best first: each entity scores its best name, and only rows
    /// that pass the run's own filters and gate take a place.
    pub(super) fn phonetic_vector_results(
        &self,
        rtxn: &RoTxn<'_>,
        query: &PhoneticVectorQuery,
        filters: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Vec<ScoredEntity>> {
        let memory = self.memory_category;
        crate::phonetic_learned::search_phonetic_vectors_in_txn(
            &self.read,
            rtxn,
            &query.model_id,
            &query.vector,
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
        )
    }
}
