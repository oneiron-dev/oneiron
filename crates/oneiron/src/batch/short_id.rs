use super::*;

use std::str;

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::edge::parse_strict_edge_record;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;

pub(super) enum ShortIdPlan {
    UpdateExisting {
        short_id: String,
        old_content_hash: u8,
        content_hash: u8,
    },
    InsertNew {
        counter_key: [u8; crate::store::SHORT_ID_COUNTER_KEY_LEN],
        next_counter: u64,
        short_id: String,
        content_hash: u8,
    },
}

pub(super) fn plan_short_id_update(
    store: &impl ManifestDbs,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    short_id_prefix: &str,
    data: &[u8],
) -> Result<ShortIdPlan> {
    let content_hash = (xxh32(data, 0) % 256) as u8;

    if let Some(existing) = store.short_ids_reverse().get(txn, id.as_bytes())? {
        let (short_id, old_content_hash) = parse_short_id_value(&existing)?;
        return Ok(ShortIdPlan::UpdateExisting {
            short_id: short_id.to_owned(),
            old_content_hash,
            content_hash,
        });
    }

    // Per-type counters live in `vault_meta` under the documented
    // `b"sid_counter:" ‖ type_byte` key scheme (store.rs), NOT as sentinel
    // rows inside `short_ids` — that table holds only the ARCH-0019 row n3
    // mapping `(short_id, content_hash)` -> `entity_id`.
    let counter_key = crate::store::short_id_counter_key(entity_type);
    let current = match store.vault_meta().get(txn, &counter_key)? {
        Some(raw) => {
            let buf: [u8; SHORT_ID_COUNTER_LEN] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id counter"))?;
            u64::from_le_bytes(buf)
        }
        None => 0,
    };

    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("short id counter"))?;
    let short_id = format!("{short_id_prefix}{next}");
    Ok(ShortIdPlan::InsertNew {
        counter_key,
        next_counter: next,
        short_id,
        content_hash,
    })
}

pub(super) fn apply_short_id_plan(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    plan: ShortIdPlan,
) -> Result<()> {
    match plan {
        ShortIdPlan::UpdateExisting {
            short_id,
            old_content_hash,
            content_hash,
        } => {
            if old_content_hash != content_hash {
                // The content hash is part of the forward KEY, so a content
                // update must remove the stale forward row before rewriting.
                let old_forward_key = encode_short_id_forward_key(&short_id, old_content_hash);
                store.short_ids().delete(wtxn, &old_forward_key)?;
            }
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
        ShortIdPlan::InsertNew {
            counter_key,
            next_counter,
            short_id,
            content_hash,
        } => {
            store
                .vault_meta()
                .put(wtxn, &counter_key, &next_counter.to_le_bytes())?;
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
    }

    Ok(())
}

pub(super) fn delete_short_id_rows_for_id(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let forward_key = match store.short_ids_reverse().get(wtxn, id.as_bytes())? {
        Some(value) => {
            let (short_id, content_hash) = parse_short_id_value(&value)?;
            Some(encode_short_id_forward_key(short_id, content_hash))
        }
        None => None,
    };
    if let Some(forward_key) = forward_key {
        store.short_ids().delete(wtxn, &forward_key)?;
        store.short_ids_reverse().delete(wtxn, id.as_bytes())?;
    }
    Ok(())
}

/// Writes both pinned ARCH-0019 short-id rows for one entity:
/// row n3 `short_ids`: key `(short_id bytes ‖ content_hash u8)` -> 16-byte
/// entity id; row n4 `short_ids_reverse`: key entity id -> value
/// `(short_id bytes ‖ content_hash u8)` (same bytes as the forward key).
pub(super) fn write_short_id_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    short_id: &str,
    content_hash: u8,
) -> Result<()> {
    let forward_key = encode_short_id_forward_key(short_id, content_hash);
    store.short_ids().put(wtxn, &forward_key, id.as_bytes())?;
    store
        .short_ids_reverse()
        .put(wtxn, id.as_bytes(), &forward_key)?;
    Ok(())
}

/// Encodes the `short_ids` forward key `(short_id bytes ‖ content_hash u8)`
/// pinned by ARCH-0019 manifest row n3. The same byte shape is stored as the
/// `short_ids_reverse` VALUE (row n4) and is parsed back by
/// [`parse_short_id_value`].
pub(crate) fn encode_short_id_forward_key(short_id: &str, content_hash: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(short_id.len() + 1);
    key.extend_from_slice(short_id.as_bytes());
    key.push(content_hash);
    key
}

pub(crate) fn parse_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    if value.len() < 2 {
        return Err(Error::CorruptedIndex("short id value"));
    }

    let Some((&hash, short_id_bytes)) = value.split_last() else {
        return Err(Error::CorruptedIndex("short id value"));
    };
    let short_id =
        str::from_utf8(short_id_bytes).map_err(|_| Error::CorruptedIndex("short id value"))?;
    Ok((short_id, hash))
}

pub(super) fn parse_entity_metadata(record: &[u8]) -> Result<(u8, TimeRange, u64)> {
    let header =
        EntityMetadataHeader::parse(record).ok_or(Error::CorruptedIndex("entity metadata"))?;

    Ok((
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    ))
}

pub(super) fn delete_related_edges(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut outbound = Vec::new();
    for entry in store.edges_out.prefix_iter(wtxn, id.as_bytes())? {
        let (key, value) = entry?;
        let edge = parse_strict_edge_record(&key, &value)?;
        outbound.push((edge.kind, edge.target));
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
        let edge = parse_strict_edge_record(&key, &value)?;
        inbound.push((edge.kind, edge.target));
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
