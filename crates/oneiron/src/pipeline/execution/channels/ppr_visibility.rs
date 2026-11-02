//! Caller-visible PPR walks for narrowed retrieval attempts.

use std::cell::RefCell;

use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::filters::pipeline_candidate_matches_filters_and_gate;
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, WorldScope,
};
use crate::ppr::PprNodeVisibility;
use crate::store::StoreRead;

pub(super) struct PipelinePprVisibility<'store, 'filters> {
    store: StoreRead<'store>,
    filters: PipelineFilterConfig<'filters>,
    metadata: RefCell<EntityMetadataCache>,
    claim_gate: RefCell<ClaimStatusGateCache>,
}

/// A narrowed walk must not carry mass through a row the caller cannot read.
/// Canonical owner-wide retrieval keeps its existing cached walk instead.
pub(super) fn pipeline_ppr_visibility<'store, 'filters>(
    builder: &PipelineBuilder<'store>,
    filters: PipelineFilterConfig<'filters>,
    claim_gate: &ClaimStatusGateCache,
) -> Option<PipelinePprVisibility<'store, 'filters>> {
    let narrowed = builder.authority_filter.is_some()
        || builder.scoped_note_reader.is_some()
        || filters.candidate_filter.is_some()
        || filters.type_filter.is_some()
        || filters.criticality.is_some()
        || filters.since_filter.is_some()
        || filters.occurred_range.is_some()
        || filters.learned_range.is_some()
        || filters.repo_ref_filter.is_some()
        || filters.project_id_filter.is_some()
        || filters.facet_filter.is_some()
        || filters.relationship_filter.is_some()
        || !matches!(filters.world_scope, WorldScope::All)
        || filters.world_active_set.is_some()
        || !matches!(filters.corpus_scope, CorpusScope::All)
        || filters.device_local.is_some()
        || filters.disclosure.is_some()
        || filters.stale_worlds.is_some();
    narrowed.then(|| PipelinePprVisibility {
        store: builder.read,
        filters,
        metadata: RefCell::new(EntityMetadataCache::default()),
        claim_gate: RefCell::new(claim_gate.fresh(filters.authority_filter.include_stale)),
    })
}

impl PprNodeVisibility for PipelinePprVisibility<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        pipeline_candidate_matches_filters_and_gate(
            &self.store,
            txn,
            id,
            self.filters,
            &mut self.metadata.borrow_mut(),
            &mut self.claim_gate.borrow_mut(),
        )
    }
}
