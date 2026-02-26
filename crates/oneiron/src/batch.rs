use std::str;

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::error::{Error, Result};
use crate::ppr;
use crate::store::Store;
use crate::types::{short_id_prefix, EdgeKind, EntityId, TimeRange, ENTITY_ID_LEN};
use crate::Vault;

pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = 25;
const SHORT_ID_COUNTER_LEN: usize = 8;
const EDGE_KEY_LEN: usize = 33;
const EDGE_VALUE_LEN: usize = 12;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EntityMetadataHeader {
    pub(crate) entity_type: u8,
    pub(crate) occurred_start: u64,
    pub(crate) occurred_end: u64,
    pub(crate) learned_at: u64,
}

impl EntityMetadataHeader {
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return None;
        }

        let entity_type = raw[0];
        let occurred_start = u64::from_be_bytes(raw[1..9].try_into().ok()?);
        let occurred_end = u64::from_be_bytes(raw[9..17].try_into().ok()?);
        let learned_at = u64::from_be_bytes(raw[17..25].try_into().ok()?);

        Some(Self {
            entity_type,
            occurred_start,
            occurred_end,
            learned_at,
        })
    }
}

/// Builder for atomic multi-database write batches.
pub struct BatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
}

enum BatchOp {
    Put {
        id: EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
    },
    Vector {
        id: EntityId,
        vector: Vec<f32>,
    },
    Edge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
    },
    Text {
        id: EntityId,
        fields: Vec<(String, String)>,
    },
    Phonetic {
        id: EntityId,
        codes: Vec<String>,
    },
    Delete {
        id: EntityId,
    },
    DeleteEdge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
    },
}

impl<'a> BatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
        }
    }

    /// Adds an entity put operation to the batch.
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
        });
        self
    }

    /// Adds a vector write operation to the batch.
    pub fn vector(mut self, id: &EntityId, vector: &[f32]) -> Self {
        self.ops.push(BatchOp::Vector {
            id: *id,
            vector: vector.to_vec(),
        });
        self
    }

    /// Adds a graph edge write operation to the batch.
    pub fn edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId, weight: f32) -> Self {
        self.ops.push(BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
        });
        self
    }

    /// Adds a text indexing operation to the batch.
    pub fn text(mut self, id: &EntityId, fields: &[(&str, &str)]) -> Self {
        self.ops.push(BatchOp::Text {
            id: *id,
            fields: fields
                .iter()
                .map(|(f, v)| ((*f).to_owned(), (*v).to_owned()))
                .collect(),
        });
        self
    }

    /// Adds a phonetic indexing operation to the batch.
    pub fn phonetic(mut self, id: &EntityId, codes: &[&str]) -> Self {
        self.ops.push(BatchOp::Phonetic {
            id: *id,
            codes: codes.iter().map(|c| (*c).to_owned()).collect(),
        });
        self
    }

    /// Adds a full entity delete/deindex operation to the batch.
    pub fn delete(mut self, id: &EntityId) -> Self {
        self.ops.push(BatchOp::Delete { id: *id });
        self
    }

    /// Adds an edge delete operation to the batch.
    pub fn delete_edge(mut self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Self {
        self.ops.push(BatchOp::DeleteEdge {
            src: *src,
            kind,
            tgt: *tgt,
        });
        self
    }

    /// Commits all queued operations atomically in a single LMDB write transaction.
    pub fn commit(self) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        for op in self.ops {
            match op {
                BatchOp::Put {
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    data,
                } => {
                    apply_put(
                        &self.vault.store,
                        &mut wtxn,
                        id,
                        entity_type,
                        occurred,
                        learned_at,
                        &data,
                    )?;
                }
                BatchOp::Vector { id, vector } => {
                    apply_vector(
                        &self.vault.store,
                        &self.vault.config,
                        &mut wtxn,
                        id,
                        &vector,
                    )?;
                    crate::hnsw::hnsw_insert(
                        &self.vault.store,
                        &self.vault.config,
                        &mut wtxn,
                        &id,
                        &vector,
                    )?;
                }
                BatchOp::Edge {
                    src,
                    kind,
                    tgt,
                    weight,
                } => {
                    apply_edge(&self.vault.store, &mut wtxn, src, kind, tgt, weight)?;
                    ppr::invalidate_ppr_for_edge(&self.vault.store, &mut wtxn, &src, &tgt)?;
                }
                BatchOp::Text { id, fields } => {
                    crate::bm25::index_text(&self.vault.store, &mut wtxn, &id, &fields)?;
                }
                BatchOp::Phonetic { id, codes } => {
                    apply_phonetic(&self.vault.store, &mut wtxn, id, &codes)?;
                }
                BatchOp::Delete { id } => {
                    let (_, neighbors) = deindex_entity(&self.vault.store, &mut wtxn, &id)?;
                    ppr::invalidate_ppr_for_delete(&self.vault.store, &mut wtxn, &id, &neighbors)?;
                }
                BatchOp::DeleteEdge { src, kind, tgt } => {
                    apply_delete_edge(&self.vault.store, &mut wtxn, src, kind, tgt)?;
                    ppr::invalidate_ppr_for_edge(&self.vault.store, &mut wtxn, &src, &tgt)?;
                }
            }
        }

        wtxn.commit()?;
        Ok(())
    }
}

pub(crate) fn deindex_entity(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, Vec<EntityId>)> {
    // Clean secondary indexes unconditionally — they may exist even without an
    // entity record (e.g. text indexed via batch().text() without a preceding put()).
    crate::bm25::deindex_text(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    store.temporal_long_intervals.delete(wtxn, id.as_bytes())?;

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok((false, Vec::new()));
    };

    let (entity_type, occurred, learned_at) = parse_entity_metadata(entity_record)?;
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index.delete(wtxn, &type_key)?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start
        .delete(wtxn, &occurred_start_key)?;
    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end
            .delete(wtxn, &occurred_end_key)?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned.delete(wtxn, &learned_key)?;

    let neighbors = delete_related_edges(store, wtxn, id)?;

    if let Some(raw) = store.short_ids.get(wtxn, id.as_bytes())? {
        let (short_id, _) = parse_short_id_value(raw)?;
        let short_id = short_id.to_owned();
        store.short_ids_reverse.delete(wtxn, short_id.as_bytes())?;
        store.short_ids.delete(wtxn, id.as_bytes())?;
    }

    store.entities.delete(wtxn, id.as_bytes())?;
    Ok((true, neighbors))
}

fn apply_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    let mut occurred = occurred;
    if occurred.start > occurred.end {
        std::mem::swap(&mut occurred.start, &mut occurred.end);
    }

    store.temporal_long_intervals.delete(wtxn, id.as_bytes())?;

    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(old_record)?;

        if old_type != entity_type {
            let old_type_key = Store::encode_type_key(old_type, &id);
            store.type_index.delete(wtxn, &old_type_key)?;
        }

        if old_occurred.start != occurred.start {
            let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
            store.temporal_occurred_start.delete(wtxn, &old_start_key)?;
        }

        let old_is_range = old_occurred.start != old_occurred.end;
        let new_is_range = occurred.start != occurred.end;
        if old_is_range && (!new_is_range || old_occurred.end != occurred.end) {
            let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
            store.temporal_occurred_end.delete(wtxn, &old_end_key)?;
        }

        if old_learned != learned_at {
            let old_learned_key = Store::encode_temporal_key(old_learned, &id);
            store.temporal_learned.delete(wtxn, &old_learned_key)?;
        }
    }

    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);

    store.entities.put(wtxn, id.as_bytes(), &payload)?;

    let type_key = Store::encode_type_key(entity_type, &id);
    store.type_index.put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, &id);
    store
        .temporal_occurred_start
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, &id);
        store
            .temporal_occurred_end
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, &id);
    store.temporal_learned.put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let mut value = [0_u8; 16];
        value[..8].copy_from_slice(&occurred.start.to_be_bytes());
        value[8..].copy_from_slice(&occurred.end.to_be_bytes());
        store
            .temporal_long_intervals
            .put(wtxn, id.as_bytes(), &value)?;
    }

    upsert_short_id(store, wtxn, &id, entity_type, data)?;
    Ok(())
}

fn apply_vector(
    store: &Store,
    config: &crate::types::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    vector: &[f32],
) -> Result<()> {
    if vector.len() != config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: vector.len(),
        });
    }
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(Error::InvalidVector);
    }

    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for v in vector {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

fn apply_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
) -> Result<()> {
    if !weight.is_finite() {
        return Err(Error::InvalidEdgeWeight);
    }

    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let value = encode_edge_value(weight, crate::unix_seconds_now());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

fn apply_delete_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    store.edges_out.delete(wtxn, &key_out)?;
    store.edges_in.delete(wtxn, &key_in)?;
    Ok(())
}

fn apply_phonetic(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: &[String],
) -> Result<()> {
    for code in codes {
        let existing = store.phonetic_index.get(wtxn, code.as_bytes())?;
        let mut posting =
            existing.map_or_else(|| Vec::with_capacity(ENTITY_ID_LEN), |bytes| bytes.to_vec());
        if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(Error::InvalidKey);
        }

        if posting
            .chunks_exact(ENTITY_ID_LEN)
            .any(|chunk| chunk == id.as_bytes())
        {
            continue;
        }

        posting.extend_from_slice(id.as_bytes());
        store.phonetic_index.put(wtxn, code.as_bytes(), &posting)?;
    }

    Ok(())
}

fn upsert_short_id(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<()> {
    let content_hash = (xxh32(data, 0) % 256) as u8;

    if let Some(existing) = store.short_ids.get(wtxn, id.as_bytes())? {
        let (short_id, _) = parse_short_id_value(existing)?;
        let mut value = Vec::with_capacity(short_id.len() + 1);
        value.extend_from_slice(short_id.as_bytes());
        value.push(content_hash);
        store.short_ids.put(wtxn, id.as_bytes(), &value)?;
        return Ok(());
    }

    let sentinel_key = short_id_counter_sentinel(entity_type);
    let current = match store.short_ids.get(wtxn, &sentinel_key)? {
        Some(raw) => {
            let buf: [u8; SHORT_ID_COUNTER_LEN] = raw.try_into().map_err(|_| Error::InvalidKey)?;
            u64::from_le_bytes(buf)
        }
        None => 0,
    };

    let next = current.checked_add(1).ok_or(Error::InvalidKey)?;
    store
        .short_ids
        .put(wtxn, &sentinel_key, &next.to_le_bytes())?;

    let short_id = format!("{}{}", short_id_prefix(entity_type), next);
    let mut short_id_value = Vec::with_capacity(short_id.len() + 1);
    short_id_value.extend_from_slice(short_id.as_bytes());
    short_id_value.push(content_hash);

    store.short_ids.put(wtxn, id.as_bytes(), &short_id_value)?;
    store
        .short_ids_reverse
        .put(wtxn, short_id.as_bytes(), id.as_bytes())?;
    Ok(())
}

fn short_id_counter_sentinel(entity_type: u8) -> [u8; ENTITY_ID_LEN] {
    let mut key = [0xFF_u8; ENTITY_ID_LEN];
    key[0] = entity_type;
    key
}

pub(crate) fn parse_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    if value.len() < 2 {
        return Err(Error::InvalidKey);
    }

    let (short_id_bytes, hash_bytes) = value.split_at(value.len() - 1);
    let short_id = str::from_utf8(short_id_bytes).map_err(|_| Error::InvalidKey)?;
    Ok((short_id, hash_bytes[0]))
}

fn parse_entity_metadata(record: &[u8]) -> Result<(u8, TimeRange, u64)> {
    let header = EntityMetadataHeader::parse(record).ok_or(Error::InvalidKey)?;

    Ok((
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    ))
}

fn delete_related_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut outbound = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
        let target = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
        outbound.push((kind, target));
    }

    for (kind, target) in &outbound {
        let out_key = Store::encode_edge_key(id, *kind, target);
        let in_key = Store::encode_edge_key(target, *kind, id);
        store.edges_out.delete(wtxn, &out_key)?;
        store.edges_in.delete(wtxn, &in_key)?;
    }

    let mut inbound = Vec::new();
    for entry in store.edges_in.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
        let source = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
        inbound.push((kind, source));
    }

    for (kind, source) in &inbound {
        let in_key = Store::encode_edge_key(id, *kind, source);
        let out_key = Store::encode_edge_key(source, *kind, id);
        store.edges_in.delete(wtxn, &in_key)?;
        store.edges_out.delete(wtxn, &out_key)?;
    }

    let mut neighbors: Vec<EntityId> = outbound
        .into_iter()
        .map(|(_, id)| id)
        .chain(inbound.into_iter().map(|(_, id)| id))
        .collect();
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok(neighbors)
}

fn delete_from_phonetic_postings(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for entry in store.phonetic_index.iter(wtxn)? {
        let (code, posting) = entry?;
        let Some(updated) = posting_without_entity(posting, id)? else {
            continue;
        };

        if updated.is_empty() {
            deletes.push(code.to_vec());
        } else {
            updates.push((code.to_vec(), updated));
        }
    }

    for code in deletes {
        store.phonetic_index.delete(wtxn, &code)?;
    }

    for (code, posting) in updates {
        store.phonetic_index.put(wtxn, &code, &posting)?;
    }

    Ok(())
}

fn posting_without_entity(posting: &[u8], id: &EntityId) -> Result<Option<Vec<u8>>> {
    if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::InvalidKey);
    }

    let retained: Vec<u8> = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk != id.as_bytes())
        .flat_map(|chunk| chunk.iter().copied())
        .collect();

    Ok((retained.len() != posting.len()).then_some(retained))
}

fn validate_edge_record(key: &[u8], value: &[u8]) -> Result<()> {
    if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
        return Err(Error::InvalidKey);
    }

    if EdgeKind::try_from_u8(key[16]).is_none() {
        return Err(Error::InvalidKey);
    }

    Ok(())
}

fn encode_edge_value(weight: f32, created_at: u64) -> [u8; EDGE_VALUE_LEN] {
    let mut value = [0_u8; EDGE_VALUE_LEN];
    value[..4].copy_from_slice(&weight.to_le_bytes());
    value[4..].copy_from_slice(&created_at.to_le_bytes());
    value
}
