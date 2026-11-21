//! Rows a pack's caller names instead of a query ranking them (its working
//! set), through the retrieval gates a ranked candidate passes.

use heed::RoTxn;

use super::builder::PipelineBuilder;
use super::corpus_filter::CorpusFilter;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{ClaimStatusGateCache, EntityMetadataCache};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::provenance::made_by::MadeByPredicate;
use crate::registry::ENTITY_TYPE_CLAIM;

impl PipelineBuilder<'_> {
    /// The ones of `ids` this run admits, in order. Each passes the
    /// candidate predicate every bounded channel applies (the run's
    /// authority floor and claim ceiling, its candidate gate and filter, its
    /// type, time, codebase, criticality, claim-status, disclosure, facet,
    /// world, corpus and relationship selection), then its made-by
    /// selection. Only the ranking is skipped.
    pub(crate) fn admit_named_rows_in(
        &self,
        txn: &RoTxn<'_>,
        ids: &[EntityId],
    ) -> Result<Vec<EntityId>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // Authority (policy, worlds) is the vault's; the rows are read where
        // the run reads, a room's view included.
        let store = &self.vault.store;
        let policy = crate::gate::resolve_policy_manifest(store, txn)?;
        let owner_filter =
            crate::gate::narrow_retrieval_filter(&policy.retrieval_floor_for_actor(None), None)?;
        let authority_filter = self.authority_filter.as_ref().unwrap_or(&owner_filter);
        let now = self.temporal_now.unwrap_or_else(crate::unix_seconds_now);
        let authority = super::world_authority::resolve_active_world_authority(
            store,
            txn,
            &self.world_scope,
            self.active_world_selection.as_ref(),
            self.execution_actor,
            now,
        )?;
        let corpus = CorpusFilter::new(&self.corpus_scope)?;
        let device_local = self.device_local_worlds(txn)?;
        let admission = self.snapshot_admission(txn);
        let mut filters = corpus.config(self, &admission, self.occurred_range, authority_filter);
        filters.world_active_set = authority.as_ref().map(|authority| &authority.active_set);
        filters.device_local = device_local.as_ref();
        // A working set names at most a few dozen rows: the pack's deadline
        // is judged around them, not between them.
        filters.deadline = None;
        let mut metadata = EntityMetadataCache::default();
        let mut gate = ClaimStatusGateCache::default();
        let mut admitted = Vec::with_capacity(ids.len());
        for id in ids {
            if pipeline_candidate_matches_filters_and_gate(
                &self.read,
                txn,
                id,
                filters,
                &mut metadata,
                &mut gate,
            )? && self.made_by_admits_in(txn, id)?
            {
                admitted.push(*id);
            }
        }
        Ok(admitted)
    }

    /// Whether the run's made-by selection keeps `id`, by the rule its
    /// post-blend stage applies (OF-466): the row's stamped birth names its
    /// class, else its claim's source; an unknown class never matches.
    fn made_by_admits_in(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if self.made_by == MadeByPredicate::All {
            return Ok(true);
        }
        let class = match crate::provenance::birth::row_birth_in_txn(&self.read, txn, id)? {
            Some(birth) => Some(birth.made_by.process.class),
            None => crate::ports::EntityStoreRead::port_entity_raw(&self.read, txn, id)?
                .filter(|raw| {
                    EntityMetadataHeader::parse(raw)
                        .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
                })
                .and_then(|raw| {
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).ok()
                })
                .and_then(|body| body.made_by_class()),
        };
        Ok(self.made_by.matches(class))
    }
}
