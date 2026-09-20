//! Explicit read frontiers keep the scoped lane's current and historic gates.

use super::*;
use crate::vault::ReadMode;

#[derive(Default)]
pub(crate) struct RevisionedHits {
    pub(crate) hits: Vec<ScoredEntity>,
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
            return Ok(RevisionedHits::default());
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, false, true)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .search_vector(query, fetch_limit)
            .limit(fetch_limit)
            .run_for_pack()?;
        Ok(RevisionedHits {
            hits: self.filter_search_results(results.scores, limit, &filter, &policy)?,
            revisions: results.revisions,
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
            return Ok(RevisionedHits::default());
        }
        let fetch_limit = self
            .vault
            .scoped_read_search_candidate_limit(limit, true, false)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .search_text(query, fetch_limit)
            .limit(fetch_limit)
            .run_for_pack()?;
        Ok(RevisionedHits {
            hits: self.filter_search_results(results.scores, limit, &filter, &policy)?,
            revisions: results.revisions,
        })
    }

    /// Exact historical reads retain both current and historical claim gates.
    pub fn get_with_mode(&self, id: &EntityId, mode: ReadMode) -> Result<Option<Vec<u8>>> {
        Ok(self
            .get_entity_parts_with_mode(id, mode)?
            .map(|(_, _, body)| body))
    }

    /// Reads metadata and body from one frontier in one read transaction.
    pub fn get_entity_parts_with_mode(
        &self,
        id: &EntityId,
        mode: ReadMode,
    ) -> Result<Option<(u8, u64, Vec<u8>)>> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(live) = self.entities().get(&txn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&live).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        if self.vault.archive_tombstone_in_txn(&txn, id)?.is_some() {
            return Ok(None);
        }
        if (header.entity_type == ENTITY_TYPE_CLAIM
            && !self.is_claim_raw_readable_in(&txn, id, &live)?)
            || (header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                && !self.note_readable_in(&txn, &live[ENTITY_METADATA_HEADER_LEN..])?)
        {
            return Ok(None);
        }
        if mode == ReadMode::Live {
            return Ok(Some((
                header.entity_type,
                header.learned_at,
                live[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            )));
        }
        let raw = match self.session_view {
            Some(view) => crate::vault::entity_revision::read_entity_revision_from_store_in_txn(
                self.vault, view, &txn, id, mode,
            )?,
            None => crate::vault::entity_revision::read_entity_revision_in_txn(
                self.vault, &txn, id, mode,
            )?,
        };
        let Some(raw) = raw else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if (header.entity_type == ENTITY_TYPE_CLAIM
            && !self.is_claim_raw_readable_in(&txn, id, &raw)?)
            || (header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                && !self.note_readable_in(&txn, &raw[ENTITY_METADATA_HEADER_LEN..])?)
        {
            return Ok(None);
        }
        Ok(Some((
            header.entity_type,
            header.learned_at,
            raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        )))
    }

    /// Short-ref resolution at a pin, followed by the same scoped admission.
    pub fn hydrate_short_id_with_mode(
        &self,
        short_id: &str,
        content_hash: u8,
        mode: ReadMode,
    ) -> Result<Option<crate::HydratedShortId>> {
        let id = if let ReadMode::Pinned(revision) = mode {
            let Some(id) = self.vault.resolve_pinned_entity_reference(
                &format!("{short_id}:{content_hash:02x}"),
                revision,
            )?
            else {
                return Ok(None);
            };
            id
        } else {
            let Some(value) = self.hydrate_short_id(short_id, content_hash)? else {
                return Ok(None);
            };
            value.id
        };
        let Some((entity_type, learned_at, body)) = self.get_entity_parts_with_mode(&id, mode)?
        else {
            return Ok(None);
        };
        Ok(Some(crate::HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion: None,
            body: Some(body),
        }))
    }
    pub(super) fn context_entity_revision_is_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        entity: &ContextEntity,
    ) -> Result<bool> {
        let Some(revision) = entity.source_revision_ref else {
            return Ok(true);
        };
        let mode = ReadMode::Pinned(crate::vault::RevisionRef(revision));
        let raw = match self.session_view {
            Some(view) => crate::vault::entity_revision::read_entity_revision_from_store_in_txn(
                self.vault, view, txn, &entity.id, mode,
            )?,
            None => crate::vault::entity_revision::read_entity_revision_in_txn(
                self.vault, txn, &entity.id, mode,
            )?,
        };
        let Some(raw) = raw else {
            return Ok(false);
        };
        if raw[0] == crate::registry::ENTITY_TYPE_NOTE {
            return self.note_readable_in(txn, &raw[ENTITY_METADATA_HEADER_LEN..]);
        }
        if raw[0] != ENTITY_TYPE_CLAIM {
            return Ok(true);
        }
        self.is_claim_raw_readable_with_policy_in(txn, policy, &entity.id, &raw)
    }
}
