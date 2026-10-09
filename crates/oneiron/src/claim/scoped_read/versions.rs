//! Explicit read frontiers keep the scoped lane's current and historic gates.

use super::*;
use crate::vault::ReadMode;

/// One admitted revision: the served bytes (the live projection on a live
/// read) and the content hash of the stored revision they came from.
pub(super) struct AdmittedRevision {
    pub(super) raw: Vec<u8>,
    pub(super) content_hash: u8,
}

pub(crate) struct RevisionedHits {
    pub(crate) hits: Vec<ScoredEntity>,
    pub(crate) receipt: ScopedReadReceipt,
    pub(crate) revisions: std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
}

impl ScopedRead<'_> {
    pub(crate) fn search_vector_revisioned(
        &self,
        query: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<RevisionedHits> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(RevisionedHits {
                hits: Vec::new(),
                revisions: Default::default(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, false, true)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .search_vector(query, fetch_limit)
            .limit(fetch_limit)
            .run_for_pack()?;
        let filtered = self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed,
            &results.revisions,
        )?;
        let mut revisions = results.revisions;
        let ids: HashSet<_> = filtered.value.iter().map(|hit| hit.id).collect();
        revisions.retain(|id, _| ids.contains(id));
        Ok(RevisionedHits {
            hits: filtered.value,
            receipt: filtered.receipt,
            revisions,
        })
    }

    pub(crate) fn search_text_revisioned(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<RevisionedHits> {
        self.search_text_revisioned_as_of(query, limit, requested, None)
    }

    pub(crate) fn search_text_revisioned_as_of(
        &self,
        query: &str,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        as_of: Option<u64>,
    ) -> Result<RevisionedHits> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(RevisionedHits {
                hits: Vec::new(),
                revisions: Default::default(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, true, false)?;
        let mut pipeline = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .search_text(query, fetch_limit)
            .limit(fetch_limit);
        if let Some(as_of) = as_of {
            pipeline = pipeline.with_temporal_now(as_of);
        }
        let results = pipeline.run_for_pack()?;
        let filtered = self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed,
            &results.revisions,
        )?;
        let mut revisions = results.revisions;
        let ids: HashSet<_> = filtered.value.iter().map(|hit| hit.id).collect();
        revisions.retain(|id, _| ids.contains(id));
        Ok(RevisionedHits {
            hits: filtered.value,
            receipt: filtered.receipt,
            revisions,
        })
    }

    /// Same-snapshot, live, policy-gated source for callers that must settle
    /// against the exact bytes supplied to an external answerer.
    pub(crate) fn entity_raw_live_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        Ok(self
            .entity_raw_with_mode_in(txn, &policy, &filter, id, ReadMode::Live)?
            .map(|revision| revision.raw))
    }

    /// Historical bytes never inherit a later live body's authority, or vice versa.
    pub(super) fn entity_raw_with_mode_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
        mode: ReadMode,
    ) -> Result<Option<AdmittedRevision>> {
        if !self.is_entity_retrievable_with_policy_in(txn, policy, filter, id)? {
            return Ok(None);
        }
        let raw = match self.session_view {
            Some(view) => crate::vault::entity_revision::read_entity_revision_from_store_in_txn(
                self.vault, view, txn, id, mode,
            )?,
            None => crate::vault::entity_revision::read_entity_revision_in_txn(
                self.vault, txn, id, mode,
            )?,
        };
        let Some(mut raw) = raw else { return Ok(None) };
        // ASSET_TEXT has a fixed intrinsic record scope for a given kind and
        // entity id. A live body edit restamps the current digest while the
        // indexed body deliberately remains behind; requiring that *current*
        // stamp to match the retained bytes would delete an authorized
        // subscription result during index lag. The current row was admitted
        // above, and the revision reader selected only retained vault bytes.
        // CLAIM and NOTE keep their per-body historical admission below.
        let stable_text_scope = mode != ReadMode::Live
            && EntityMetadataHeader::parse(&raw).is_some_and(|header| {
                header.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT
            });
        if !stable_text_scope
            && !self.is_entity_raw_readable_with_filter_in(txn, policy, id, &raw, filter)?
        {
            return Ok(None);
        }
        // The short-reference hash names the stored revision, so it is taken
        // before any live projection replaces the body.
        let content_hash =
            (xxhash_rust::xxh32::xxh32(&raw[ENTITY_METADATA_HEADER_LEN..], 0) % 256) as u8;
        if mode == ReadMode::Live {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            #[cfg(feature = "sync")]
            let resolved = crate::entity_doc::resolve_record_body(
                &self.vault.store,
                txn,
                id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            #[cfg(feature = "sync")]
            let body = resolved.as_slice();
            #[cfg(not(feature = "sync"))]
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let body = crate::note::live_body_in_txn(
                &self.vault.store,
                txn,
                id,
                header.entity_type,
                body,
            )?
            .into_owned();
            raw.truncate(ENTITY_METADATA_HEADER_LEN);
            raw.extend_from_slice(&body);
        }
        Ok(Some(AdmittedRevision { raw, content_hash }))
    }

    pub(super) fn context_entity_revision_is_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        entity: &ContextEntity,
    ) -> Result<bool> {
        let mode = entity
            .source_revision_ref
            .map_or(ReadMode::Live, |revision| {
                ReadMode::Pinned(crate::vault::RevisionRef(revision))
            });
        let Some(revision) = self.entity_raw_with_mode_in(txn, policy, filter, &entity.id, mode)?
        else {
            return Ok(false);
        };
        crate::context_pack::context_entity_matches_read_snapshot(
            self.vault,
            txn,
            entity,
            &revision.raw,
        )
    }
}
