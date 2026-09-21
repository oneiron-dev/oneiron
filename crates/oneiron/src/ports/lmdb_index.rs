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
impl RetrievalIndex for Vault {
    fn port_retrieval_vector_search_quality(
        &self,
        txn: &RoTxn<'_>,
        query: &[f32],
        limit: usize,
        skip_rescore: bool,
    ) -> Result<Vec<ScoredEntity>> {
        let population = crate::hnsw::hnsw_entity_count(&self.store, txn)?;
        // A nonzero request still validates an apparently empty index.
        let mut requested = limit.min(population.max(1));
        loop {
            let rows = crate::hnsw::hnsw_search(
                &self.store,
                &self.config,
                txn,
                query,
                requested,
                skip_rescore,
            )?;
            let mut visible = filter_results(self, txn, rows)?;
            visible.truncate(limit);
            if visible.len() >= limit || requested >= population {
                return Ok(visible);
            }
            requested = requested.saturating_mul(2).max(1).min(population);
        }
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
        let visibility = self.port_deletion_state(txn, id)?;
        if visibility.deleted || visibility.stale {
            return Ok(None);
        }
        let Some(raw) = self.store.vectors.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let vector = crate::le_bytes_to_f32_vec(&raw, self.config.dimensions)?;
        if vector.len() != self.config.dimensions {
            return Err(Error::CorruptedIndex("vector value"));
        }
        Ok(Some(vector))
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
        filter_results(self, txn, rows)
    }
}
fn filter_results(
    vault: &Vault,
    txn: &RoTxn<'_>,
    rows: Vec<ScoredEntity>,
) -> Result<Vec<ScoredEntity>> {
    let mut result = Vec::new();
    for row in rows {
        if !vault.port_tombstone_is_deleted(txn, &row.id)?
            && !stale_in_txn(&vault.store, txn, &row.id)?
            && crate::note::ordinary_entity_visible(&vault.store, txn, &row.id)?
        {
            result.push(row);
        }
    }
    Ok(result)
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
            self.port_entity_get(txn, id)?.ok_or(Error::EntityNotFound)?;
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
        self.store
            .vault_meta
            .put(txn, &super::integrity::tombstone_key(id), &value.encode())?;
        super::integrity::invalidate_source_in_txn(&self.store, txn, id)?;
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
    fn port_retrieval_validate_rebuild(&self, txn: &RoTxn<'_>) -> Result<()> {
        for row in self.store.vectors.iter(txn)? {
            let (id, value) = row?;
            crate::maintain::validate_rebuild_vector(self, &id, &value)?;
        }
        Ok(())
    }
}
