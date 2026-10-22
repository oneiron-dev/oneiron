//! Search, short-id and deletion-ledger adapters.
use super::*;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, encode_short_id_forward_key,
    parse_short_id_value,
};
use crate::deletion::{HydratedShortIdDeletion, HydratedShortIdDeletionSource, TombstoneValueV2};
use crate::entity_id::ENTITY_ID_LEN;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::store::ShortIdAliasTarget;
use crate::vault::require_key_len;
use crate::{EntityId, HydratedShortId, Vault};
use heed::{RoTxn, RwTxn};
impl Vault {
    /// Actor-bound diary ids are evaluated by the scoped query in this read
    /// transaction. The ownerless RetrievalIndex trait always passes None.
    /// `store` is what the search reads: the vault's own accessors, or a
    /// room's view.
    ///
    /// A room stages whole HNSW neighbour lists over base's, and those hide
    /// the nodes base links in later (on record, base keeps growing). So the
    /// walk always runs on base's own graph, and the vectors a room stages are
    /// scored exactly beside it: a room holds few. A hit whose vector the room
    /// replaced or removed takes the room's.
    ///
    /// One walk of `limit` answers: a row this read keeps out, by visibility
    /// or by the caller's `admission`, takes no place among its matches, so
    /// no wider walk is needed for the rows it admits. The page is short when
    /// the walk finds fewer.
    pub(crate) fn scoped_vector_search_quality_in_txn(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &RoTxn<'_>,
        query: &[f32],
        limit: usize,
        skip_rescore: bool,
        (private_note_ids, admission): (
            Option<&crate::claim::ScopedDiaryCandidates>,
            Option<&crate::hnsw::Admission<'_>>,
        ),
    ) -> Result<Vec<ScoredEntity>> {
        let admits = |txn: &RoTxn<'_>, id: &EntityId| -> Result<bool> {
            Ok(visible_in(store, txn, id, private_note_ids)?
                && admission.map_or(Ok(true), |admits| admits(txn, id))?)
        };
        let staged = store
            .vectors
            .staged_rows()
            .map(|staged| self.staged_vectors(store, txn, query, skip_rescore, (staged, &admits)))
            .transpose()?;
        let mut rows = match &staged {
            Some(staged) if staged.clear_base => Vec::new(),
            // A base hit takes the room's vector, or none, and counts only
            // for a row the room still reads.
            Some(staged) => crate::hnsw::hnsw_search(
                store.base(),
                &self.config,
                txn,
                query,
                limit,
                skip_rescore,
                Some(&|txn: &RoTxn<'_>, id: &EntityId| {
                    Ok(!staged.ids.contains(id) && live_in(store, txn, id)? && admits(txn, id)?)
                }),
            )?,
            None => crate::hnsw::hnsw_search(
                store.base(),
                &self.config,
                txn,
                query,
                limit,
                skip_rescore,
                Some(&admits),
            )?,
        };
        if let Some(staged) = staged {
            rows.extend(staged.scored);
            rows.sort_unstable_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
            });
        }
        let mut visible = filter_results(store, txn, rows, private_note_ids)?;
        visible.truncate(limit);
        Ok(visible)
    }
}

/// A hit, base's or the room's, names a row this read finds and has not
/// archived, as base's walk admits only such rows (`hnsw_search`).
fn live_in(store: &crate::store::StoreRead<'_>, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store.entities.get(txn, id.as_bytes())?.is_some()
        && !crate::vault_cleanup::is_archived_in_txn(store, txn, id)?)
}

/// The vectors a room stages: every id whose base vector it replaced or
/// removed, and its live rows the read admits scored against the query.
struct StagedVectors {
    clear_base: bool,
    ids: std::collections::HashSet<EntityId>,
    scored: Vec<ScoredEntity>,
}

impl Vault {
    fn staged_vectors(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &RoTxn<'_>,
        query: &[f32],
        skip_rescore: bool,
        (staged, admits): (
            crate::session_overlay::StagedRows,
            &crate::hnsw::Admission<'_>,
        ),
    ) -> Result<StagedVectors> {
        let mut ids = std::collections::HashSet::with_capacity(staged.rows.len());
        let mut scored = Vec::new();
        for (key, value) in staged.rows {
            let id = <[u8; ENTITY_ID_LEN]>::try_from(key.as_slice())
                .ok()
                .and_then(|bytes| EntityId::from_bytes(bytes).ok())
                .ok_or(Error::CorruptedIndex("staged vector key"))?;
            ids.insert(id);
            let Some(raw) = value else { continue };
            let vector = crate::le_bytes_to_f32_vec(&raw, self.config.dimensions)?;
            if live_in(store, txn, &id)? && admits(txn, &id)? {
                scored.push(ScoredEntity {
                    id,
                    score: crate::hnsw::exact_score(&self.config, query, &vector, skip_rescore)?,
                });
            }
        }
        Ok(StagedVectors {
            clear_base: staged.clear_base,
            ids,
            scored,
        })
    }

    /// [`RetrievalIndex::port_retrieval_vector_get`] read through `store`,
    /// a room's view included.
    pub(crate) fn vector_in_txn(
        &self,
        store: &impl crate::store::ManifestDbs,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<f32>>> {
        let visibility = store.port_deletion_state(txn, id)?;
        if visibility.deleted || visibility.stale {
            return Ok(None);
        }
        let Some(raw) = store.vectors().get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let vector = crate::le_bytes_to_f32_vec(&raw, self.config.dimensions)?;
        if vector.len() != self.config.dimensions {
            return Err(Error::CorruptedIndex("vector value"));
        }
        Ok(Some(vector))
    }
}

impl RetrievalIndex for Vault {
    fn port_retrieval_vector_search_quality(
        &self,
        txn: &RoTxn<'_>,
        query: &[f32],
        limit: usize,
        skip_rescore: bool,
    ) -> Result<Vec<ScoredEntity>> {
        self.scoped_vector_search_quality_in_txn(
            &self.store.read(),
            txn,
            query,
            limit,
            skip_rescore,
            (None, None),
        )
    }

    fn port_retrieval_phonetic_upsert(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        codes: &[&str],
    ) -> Result<()> {
        self.batch_in().phonetic(id, codes).apply(txn)
    }

    fn port_retrieval_vector_get(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<f32>>> {
        self.vector_in_txn(&self.store, txn, id)
    }

    fn port_retrieval_upsert(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        vector: Option<&[f32]>,
        text: Option<&[(&str, &str)]>,
    ) -> Result<()> {
        let mut batch = self.batch_in();
        if let Some(vector) = vector {
            batch = batch.vector(id, vector);
        }
        if let Some(text) = text {
            batch = batch.text(id, text);
        }
        batch.apply(txn)
    }
    fn port_retrieval_mark_stale(&self, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
        crate::workspace_roster::reject_audience_edit_delete(&self.store, txn, id)?;
        super::integrity::mark_stale_in_txn(&self.store, txn, id)
    }
    fn port_retrieval_vector_search(
        &self,
        txn: &RoTxn<'_>,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        self.port_retrieval_vector_search_quality(txn, query, limit, false)
    }
    fn port_retrieval_text_search(
        &self,
        txn: &RoTxn<'_>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        self.ensure_text_index_trusted()?;
        let config = crate::config::Bm25RankProfile::default().to_bm25_config()?;
        let rows =
            crate::bm25::search_text(&self.store, txn, &self.analyzer, &config, query, limit)?;
        filter_results(&self.store, txn, rows, None)
    }
}
fn filter_results(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    rows: Vec<ScoredEntity>,
    private_note_ids: Option<&crate::claim::ScopedDiaryCandidates>,
) -> Result<Vec<ScoredEntity>> {
    let mut result = Vec::new();
    for row in rows {
        if visible_in(store, txn, &row.id, private_note_ids)? {
            result.push(row);
        }
    }
    Ok(result)
}

/// Whether a hit names a row this read returns: not deleted, not stale, and
/// an ordinary entity or one of the reader's own private notes.
fn visible_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    private_note_ids: Option<&crate::claim::ScopedDiaryCandidates>,
) -> Result<bool> {
    Ok(!store.port_deletion_state(txn, id)?.deleted
        && !stale_in_txn(store, txn, id)?
        && (private_note_ids.is_some_and(|ids| ids.contains(id))
            || crate::note::ordinary_entity_visible(store, txn, id)?))
}
impl ShortIdStore for Vault {
    fn port_short_id_get_or_create(&self, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<String> {
        // A normal entity put creates its short id at the batch chokepoint.
        // Reapplying its exact row repairs an absent mapping without a bypass.
        if self
            .store
            .short_ids_reverse
            .get(txn, id.as_bytes())?
            .is_none()
        {
            self.port_entity_get(txn, id)?
                .ok_or(Error::EntityNotFound)?;
            // A live projection is not an immutable storage birth record.
            // Repair the reference from raw storage only after the live fence.
            let row = self
                .port_entity_record(txn, id)?
                .ok_or(Error::EntityNotFound)?;
            self.port_entity_put(txn, id, &row)?;
        }
        let raw = self
            .store
            .short_ids_reverse
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        Ok(parse_short_id_value(&raw)?.0.to_owned())
    }
    fn port_short_id_resolve(
        &self,
        rtxn: &RoTxn<'_>,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>> {
        let forward_key = encode_short_id_forward_key(short_id, content_hash);
        let raw_id = match self.store.short_ids.get(rtxn, &forward_key)? {
            Some(raw_id) => raw_id.to_vec(),
            None => {
                let Some(ShortIdAliasTarget::EntityForwardKey(canonical_key)) =
                    self.store.resolve_short_id_alias(rtxn, short_id)?
                else {
                    // No alias, or one naming a vault — neither resolves to an
                    // entity here.
                    return Ok(None);
                };
                // An alias relocates a NAME; it does not waive the content-hash
                // check that makes a short ref a versioned reference.
                let (_, target_hash) = parse_short_id_value(&canonical_key)?;
                if target_hash != content_hash {
                    return Ok(None);
                }
                let Some(raw_id) = self.store.short_ids.get(rtxn, &canonical_key)? else {
                    return Ok(None);
                };
                raw_id.to_vec()
            }
        };
        require_key_len(&raw_id, ENTITY_ID_LEN, "short id entity id")?;
        let id = EntityId::from_bytes(
            raw_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id entity id"))?,
        )
        .map_err(|_| Error::CorruptedIndex("short id entity id"))?;

        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(Some(HydratedShortId {
                id,
                entity_type: 0,
                learned_at: 0,
                deletion: Some(HydratedShortIdDeletion {
                    source: HydratedShortIdDeletionSource::DanglingShortId,
                    reason: None,
                    deleted_at: None,
                    request_id: None,
                    // No entity row remains to inspect, so hydrate treats this
                    // as an effectively hard deletion and keeps the source explicit.
                    hard: true,
                }),
                body: None,
            }));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let entity_type = header.entity_type;
        let learned_at = header.learned_at;
        if entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        if self.archive_tombstone_in_txn(rtxn, &id)?.is_some() {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: None,
                body: None,
            }));
        }

        if body.is_empty()
            && let Some(deletion) = self.entity_deletion_metadata_in_txn(rtxn, &id, learned_at)?
        {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: Some(deletion),
                body: None,
            }));
        }

        // Hydration must obey the same stale + tombstone fence as normal text.
        // A tombstone can race ahead of body scrubbing and still suppress content.
        let body = super::safe_read_text(self, rtxn, &id)?;
        Ok(Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion: None,
            body,
        }))
    }
}
impl TombstoneStore for Vault {
    fn port_tombstone_create(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        value: TombstoneValueV2,
    ) -> Result<()> {
        // Standalone tombstone carries deletion intent even after active row removal.
        // Publishing to peers and historical erasure remain the deletion facade's job.
        crate::workspace_roster::reject_audience_edit_delete(&self.store, txn, id)?;
        self.store
            .vault_meta
            .put(txn, &super::integrity::tombstone_key(id), &value.encode())?;
        super::integrity::invalidate_source_in_txn(
            &self.store,
            txn,
            id,
            super::DependentWalkDoor::Tombstone,
        )?;
        super::integrity::mark_stale_in_txn(&self.store, txn, id)
    }
    fn port_tombstone_is_deleted(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        Ok(self.port_deletion_state(txn, id)?.deleted)
    }
    fn port_tombstone_clean_expired(
        &self,
        _txn: &mut RwTxn<'_>,
        _now: u64,
        _limit: usize,
    ) -> Result<u64> {
        // Canon has no TTL or authorized regeneration-complete receipt yet.
        // Retention is fail closed; wall time alone must never resurrect text.
        Ok(0)
    }
}

impl super::RetrievalIndexMaintenance for Vault {
    fn port_retrieval_clear_text_for_soft_erase(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::bm25::deindex_text(&self.store, txn, id)
    }

    fn port_retrieval_clear_phonetic_for_soft_erase(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::batch::delete_from_phonetic_postings(&self.store, txn, id)
    }

    fn port_retrieval_clear_vector_for_soft_erase(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let had_vector = self.store.vectors.delete(txn, id.as_bytes())?;
        crate::embed::record_embedding_device_in_txn(&self.store, txn, id, None)?;
        // FIX 8983: its media vectors and their device marks go in the same write.
        crate::embed::delete_media_vectors_in_txn(&self.store, txn, id)?;
        crate::hnsw::hnsw_deindex(&self.store, txn, id)?;
        Ok(had_vector)
    }

    fn port_retrieval_delete_scope_exists(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        Ok(self.store.vectors.get(txn, id.as_bytes())?.is_some()
            || self.store.text_forward.get(txn, id.as_bytes())?.is_some()
            || self.store.text_meta.get(txn, id.as_bytes())?.is_some()
            || self
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .phonetic_forward
                .get(txn, id.as_bytes())?
                .is_some())
    }
    fn port_retrieval_validate_rebuild(&self, txn: &RoTxn<'_>) -> Result<()> {
        for row in self.store.vectors.iter(txn)? {
            let (id, value) = row?;
            crate::maintain::validate_rebuild_vector(self, &id, &value)?;
        }
        Ok(())
    }
}
