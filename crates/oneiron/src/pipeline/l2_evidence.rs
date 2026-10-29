//! Unranked, explicitly addressed L2 subject evidence through the retrieval gates.

use super::builder::PipelineBuilder;
use super::corpus_filter::CorpusFilter;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{ClaimStatusGateCache, EntityMetadataCache};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use heed::RoTxn;
use std::collections::BTreeSet;

impl PipelineBuilder<'_> {
    pub(crate) fn l2_evidence_in(
        &self,
        txn: &RoTxn<'_>,
        subjects: &[EntityId],
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        // Authority (policy, worlds) is the vault's; the evidence is read
        // where the run reads, a room's view included.
        let store = &self.vault.store;
        let content = &self.read;
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
        let stale_worlds = crate::federation::stale_stamped_worlds(store, txn)?;
        let subjects: BTreeSet<_> = subjects.iter().copied().collect();
        let mut ids = BTreeSet::new();
        for subject in &subjects {
            self.answer_checkpoint(Error::IndexOverflow("L2 subject adjacency"))?;
            let scope = [
                &[EdgeDirection::In as u8][..],
                subject.as_bytes(),
                &[EdgeKind::ClaimOf as u8][..],
            ]
            .concat();
            let mut count = crate::scan_check::ScanCount::start(
                content,
                txn,
                crate::scan_check::EngineScan::EdgePeerRows,
                &scope,
            )?;
            for edge in content.port_edges(
                txn,
                subject,
                EdgeDirection::In,
                Some(EdgeKind::ClaimOf),
                None,
            )? {
                self.answer_checkpoint(Error::IndexOverflow("L2 subject adjacency"))?;
                count.row();
                ids.insert(edge?.target);
            }
            count.defer(content);
        }
        let mut metadata = EntityMetadataCache::default();
        let mut gate = ClaimStatusGateCache::default();
        let mut evidence = Vec::new();
        for id in ids {
            self.answer_checkpoint(Error::IndexOverflow("L2 evidence claims"))?;
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(content, txn, &id)?
            else {
                continue;
            };
            if !pipeline_candidate_matches_filters_and_gate(
                content,
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
            // A claim the write door refuses, stored while the owner's scan was
            // off, is no evidence: the L2 rows project it as JSON, which no
            // read follows exactly, so none of it is served.
            if crate::batch::export::write_door_refuses_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            ) {
                continue;
            }
            evidence.push((id, body));
        }
        Ok(evidence)
    }
}
