//! The learned phonetic rung's list (CROSS-ARCH-0013 `#ladder` rung 2): the caller's vector of
//! a name, searched by exact cosine against the stored name vectors of its model. It is its own
//! ranked list of the phonetic channel, beside the code rung's, so fusion z-scores it on its own
//! scale and every filter and gate of the run applies before a row takes a place.

use heed::RoTxn;

use crate::error::Result;

use super::builder::PipelineBuilder;
use super::channels::fusion_fetch_limit;
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
    /// the code rung's sound cut would admit take a place: the run's own filters and gate, its
    /// memory lane and its made_by predicate ([`Self::phonetic_candidate_admits`]). The walk
    /// asks with caches of its own, as the sound cut and the narrowed vector walk do, so a row
    /// it passes leaves no decision behind and adds nothing to the pack's suppression counts;
    /// the rows it returns enter the run's caches when the channel admits them.
    pub(super) fn phonetic_vector_results(
        &self,
        rtxn: &RoTxn<'_>,
        query: &PhoneticVectorQuery,
        filters: PipelineFilterConfig<'_>,
        claim_gate: &ClaimStatusGateCache,
    ) -> Result<Vec<ScoredEntity>> {
        let mut metadata = EntityMetadataCache::default();
        let mut gate = claim_gate.fresh(filters.authority_filter.include_stale);
        crate::phonetic_learned::search_phonetic_vectors_in_txn(
            &self.read,
            rtxn,
            &query.model_id,
            &query.vector,
            fusion_fetch_limit(query.limit),
            |id| self.phonetic_candidate_admits(rtxn, id, filters, &mut metadata, &mut gate),
        )
    }
}
