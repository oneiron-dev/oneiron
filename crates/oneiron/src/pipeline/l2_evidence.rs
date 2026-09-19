//! Unranked, explicitly addressed L2 subject evidence through the retrieval gates.

use super::builder::PipelineBuilder;
use super::corpus_filter::CorpusFilter;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{ClaimStatusGateCache, EntityMetadataCache};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use heed::RoTxn;
use std::collections::BTreeSet;

impl PipelineBuilder<'_> {
    pub(crate) fn l2_evidence_in(
        &self,
        txn: &RoTxn<'_>,
        subjects: &[EntityId],
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let store = &self.vault.store;
        let policy = crate::gate::resolve_policy_manifest(store, txn)?;
        let owner_filter =
            crate::gate::narrow_retrieval_filter(&policy.retrieval_floor_for_actor(None), None)?;
        let authority_filter = self.authority_filter.as_ref().unwrap_or(&owner_filter);
        let now = self.temporal_now.unwrap_or_else(crate::unix_seconds_now);
        let authority = super::world_authority::resolve_active_world_authority(
            store,
            txn,
            self.world_scope,
            self.active_world_selection.as_ref(),
            self.execution_actor,
            now,
        )?;
        let corpus = CorpusFilter::new(&self.corpus_scope)?;
        let mut filters = corpus.config(self, self.occurred_range, authority_filter);
        filters.world_active_set = authority.as_ref().map(|authority| &authority.active_set);
        let stale_worlds = crate::federation::stale_stamped_worlds(store, txn)?;
        let subjects: BTreeSet<_> = subjects.iter().copied().collect();
        let mut ids = BTreeSet::new();
        let mut scanned = 0usize;
        for subject in &subjects {
            let prefix = crate::vault::edge_kind_prefix(subject, EdgeKind::ClaimOf);
            for row in store.edges_in.prefix_iter(txn, prefix.as_slice())? {
                scanned += 1;
                if scanned > 2048 {
                    return Err(Error::IndexOverflow("L2 subject adjacency"));
                }
                let (key, value) = row?;
                ids.insert(crate::vault::parse_edge_record(&key, &value)?.target);
            }
        }
        let mut metadata = EntityMetadataCache::default();
        let mut gate = ClaimStatusGateCache::default();
        let mut evidence = Vec::new();
        let mut evidence_bytes = 0usize;
        for id in ids {
            let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
                continue;
            };
            if raw.len() > 256 * 1024 {
                return Err(Error::IndexOverflow("L2 evidence bytes"));
            }
            if !pipeline_candidate_matches_filters_and_gate(
                store,
                txn,
                &id,
                filters,
                &mut metadata,
                &mut gate,
            )? {
                continue;
            }
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                true,
            )?;
            let ClaimSubject::Entity(subject) = body.subject else {
                continue;
            };
            // Never infer subject membership from ranking or a hostile edge.
            // A stale federated world is not stable persona/user evidence.
            if !subjects.contains(&subject)
                || !crate::claim::claim_surfaceable(&body)
                || body.valid_from.is_some_and(|from| from > now)
                || body.valid_to.is_some_and(|to| to <= now)
                || body
                    .world
                    .is_some_and(|world| stale_worlds.contains_key(&world))
            {
                continue;
            }
            evidence_bytes = evidence_bytes.saturating_add(raw.len());
            if evidence_bytes > 256 * 1024 {
                return Err(Error::IndexOverflow("L2 evidence bytes"));
            }
            if evidence.len() >= 256 {
                return Err(Error::IndexOverflow("L2 evidence claims"));
            }
            evidence.push((id, body));
        }
        Ok(evidence)
    }
}
