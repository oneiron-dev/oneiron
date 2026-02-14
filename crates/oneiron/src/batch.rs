use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{short_id_prefix, EdgeKind, EntityId, TimeRange};
use crate::Vault;

const ENTITY_METADATA_HEADER_LEN: usize = 25;
const SHORT_ID_COUNTER_LEN: usize = 8;
const EDGE_KEY_LEN: usize = 33;
const EDGE_VALUE_LEN: usize = 12;
const ENTITY_ID_LEN: usize = 16;

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

    /// Adds a text indexing placeholder operation to the batch.
    pub fn text(mut self, id: &EntityId, fields: &[(&str, &str)]) -> Self {
        let mut owned_fields = Vec::with_capacity(fields.len());
        for (field, value) in fields {
            owned_fields.push(((*field).to_owned(), (*value).to_owned()));
        }

        self.ops.push(BatchOp::Text {
            id: *id,
            fields: owned_fields,
        });
        self
    }

    /// Adds a phonetic indexing operation to the batch.
    pub fn phonetic(mut self, id: &EntityId, codes: &[&str]) -> Self {
        let mut owned_codes = Vec::with_capacity(codes.len());
        for code in codes {
            owned_codes.push((*code).to_owned());
        }

        self.ops.push(BatchOp::Phonetic {
            id: *id,
            codes: owned_codes,
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
                }
                BatchOp::Edge {
                    src,
                    kind,
                    tgt,
                    weight,
                } => {
                    apply_edge(&self.vault.store, &mut wtxn, src, kind, tgt, weight)?;
                }
                BatchOp::Text { id, fields } => {
                    let _ = (id, fields);
                }
                BatchOp::Phonetic { id, codes } => {
                    apply_phonetic(&self.vault.store, &mut wtxn, id, &codes)?;
                }
                BatchOp::Delete { id } => {
                    let _ = deindex_entity(&self.vault.store, &mut wtxn, &id)?;
                }
                BatchOp::DeleteEdge { src, kind, tgt } => {
                    apply_delete_edge(&self.vault.store, &mut wtxn, src, kind, tgt)?;
                }
            }
        }

        wtxn.commit()?;
        Ok(())
    }
}

pub(crate) fn deindex_entity(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(false);
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

    delete_related_edges(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    store.vectors.delete(wtxn, id.as_bytes())?;

    if let Some(short_id_value) = store.short_ids.get(wtxn, id.as_bytes())? {
        let short_id = {
            let (short_id, _) = parse_short_id_value(short_id_value)?;
            short_id.to_owned()
        };
        store.short_ids_reverse.delete(wtxn, short_id.as_bytes())?;
        store.short_ids.delete(wtxn, id.as_bytes())?;
    }

    store.entities.delete(wtxn, id.as_bytes())?;
    Ok(true)
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

    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
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
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let value = encode_edge_value(weight, unix_seconds_now());
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
            if raw.len() != SHORT_ID_COUNTER_LEN {
                return Err(Error::InvalidKey);
            }
            let mut buf = [0_u8; SHORT_ID_COUNTER_LEN];
            buf.copy_from_slice(raw);
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

fn parse_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    if value.len() < 2 {
        return Err(Error::InvalidKey);
    }

    let (short_id_bytes, hash_bytes) = value.split_at(value.len() - 1);
    let short_id = str::from_utf8(short_id_bytes).map_err(|_| Error::InvalidKey)?;
    Ok((short_id, hash_bytes[0]))
}

fn parse_entity_metadata(record: &[u8]) -> Result<(u8, TimeRange, u64)> {
    if record.len() < ENTITY_METADATA_HEADER_LEN {
        return Err(Error::InvalidKey);
    }

    let entity_type = record[0];

    let mut start = [0_u8; 8];
    start.copy_from_slice(&record[1..9]);
    let mut end = [0_u8; 8];
    end.copy_from_slice(&record[9..17]);
    let mut learned = [0_u8; 8];
    learned.copy_from_slice(&record[17..25]);

    Ok((
        entity_type,
        TimeRange {
            start: u64::from_be_bytes(start),
            end: u64::from_be_bytes(end),
        },
        u64::from_be_bytes(learned),
    ))
}

fn delete_related_edges(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let mut outbound = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        validate_edge_record(key, value)?;
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
        let target = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
        outbound.push((kind, target));
    }

    for (kind, target) in outbound {
        let out_key = Store::encode_edge_key(id, kind, &target);
        let in_key = Store::encode_edge_key(&target, kind, id);
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

    for (kind, source) in inbound {
        let in_key = Store::encode_edge_key(id, kind, &source);
        let out_key = Store::encode_edge_key(&source, kind, id);
        store.edges_in.delete(wtxn, &in_key)?;
        store.edges_out.delete(wtxn, &out_key)?;
    }

    Ok(())
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

    let mut changed = false;
    let mut retained = Vec::with_capacity(posting.len());
    for chunk in posting.chunks_exact(ENTITY_ID_LEN) {
        if chunk == id.as_bytes() {
            changed = true;
        } else {
            retained.extend_from_slice(chunk);
        }
    }

    if changed {
        Ok(Some(retained))
    } else {
        Ok(None)
    }
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

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
