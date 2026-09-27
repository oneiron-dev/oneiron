//! Explicit read frontiers keep the scoped lane's current and historic gates.

use super::*;
use crate::vault::ReadMode;

pub(crate) struct RevisionedHits {
    pub(crate) hits: Vec<ScoredEntity>,
    pub(crate) receipt: ScopedReadReceipt,
    pub(crate) revisions: std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
}

impl ScopedRead<'_> {
    /// Searches within this actor's resolved read authority. Unset means the floor.
    pub fn search(
        &self,
        query: &str,
        vector: &[f32],
        limit: usize,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let (filter, policy) = self.resolve_retrieval_filter(requested)?;
        if filter.deny_all {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt: self.receipt_for(requested, &policy, &filter, 0),
            });
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, true, true)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .search(query, vector, None, fetch_limit)
            .run_for_pack()?;
        self.filter_search_results(
            results.scores,
            limit,
            requested,
            &filter,
            &policy,
            results.read_suppressed,
            &results.revisions,
        )
    }

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
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .scoped_note_reader(self.actor_key.clone())
            .search_text(query, fetch_limit)
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

    /// Same-snapshot, live, policy-gated source for callers that must settle
    /// against the exact bytes supplied to an external answerer.
    pub(crate) fn entity_raw_live_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        self.entity_raw_with_mode_in(txn, &policy, &filter, id, ReadMode::Live)
    }

    /// Historical bytes never inherit a later live body's authority, or vice versa.
    pub(super) fn entity_raw_with_mode_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
        mode: ReadMode,
    ) -> Result<Option<Vec<u8>>> {
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
        if !self.is_entity_raw_readable_with_filter_in(txn, policy, id, &raw, filter)? {
            return Ok(None);
        }
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
        Ok(Some(raw))
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
        let Some(raw) = self.entity_raw_with_mode_in(txn, policy, filter, &entity.id, mode)? else {
            return Ok(false);
        };
        crate::context_pack::context_entity_matches_read_snapshot(self.vault, txn, entity, &raw)
    }
}

impl ScopedRead<'_> {
    #[expect(
        clippy::too_many_arguments,
        reason = "final scoring admission conjoins plan authority, fresh authority and source frontiers"
    )]
    fn filter_search_results(
        &self,
        results: Vec<ScoredEntity>,
        limit: usize,
        requested: Option<&RetrievalFilter>,
        filter: &ResolvedRetrievalFilter,
        policy: &PolicyManifestResolution,
        previously_suppressed: usize,
        revisions: &std::collections::HashMap<EntityId, crate::vault::RevisionRef>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let txn = self.grant_read_txn()?;
        // The scoring txn may have completed before a revocation. The final
        // read must satisfy BOTH the plan authority and this fresh snapshot.
        let (fresh_filter, fresh_policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::new();
        let mut suppressed = 0;
        for result in results {
            let admitted = self.admit_in(&txn, &result.id, || {
                let allowed = self
                    .is_entity_retrievable_with_policy_in(&txn, policy, filter, &result.id)?
                    && self.is_entity_retrievable_with_policy_in(
                        &txn,
                        &fresh_policy,
                        &fresh_filter,
                        &result.id,
                    )?
                    && match revisions.get(&result.id) {
                        Some(revision) => {
                            let mode = crate::vault::ReadMode::Pinned(*revision);
                            self.entity_raw_with_mode_in(&txn, policy, filter, &result.id, mode)?
                                .is_some()
                                && self
                                    .entity_raw_with_mode_in(
                                        &txn,
                                        &fresh_policy,
                                        &fresh_filter,
                                        &result.id,
                                        mode,
                                    )?
                                    .is_some()
                        }
                        None => true,
                    };
                Ok(allowed.then_some(result))
            })?;
            suppressed += admitted.suppression();
            if let Some(row) = admitted.into_option()
                && value.len() < limit
            {
                value.push(row);
            }
        }
        let mut receipt = self.receipt_for(requested, policy, filter, previously_suppressed);
        receipt.restrict_with(&self.receipt_for(
            requested,
            &fresh_policy,
            &fresh_filter,
            suppressed,
        ));
        Ok(ScopedReadResult { value, receipt })
    }

    pub fn filter_scored_entities(
        &self,
        results: Vec<ScoredEntity>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        self.filter_scored_entities_requested(results, None)
    }

    pub(crate) fn filter_scored_entities_requested(
        &self,
        results: Vec<ScoredEntity>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let before = results.len();
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(before);
        let mut suppressed = 0;
        for result in results {
            let admitted = self.admit_in(&txn, &result.id, || {
                self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &result.id)
                    .map(|visible| visible.then_some(result))
            })?;
            suppressed += admitted.suppression();
            if let Some(row) = admitted.into_option() {
                value.push(row);
            }
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult { value, receipt })
    }
}
