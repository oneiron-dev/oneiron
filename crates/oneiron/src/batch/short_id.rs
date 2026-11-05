use super::*;

use std::str;

use heed::RwTxn;
use xxhash_rust::xxh32::xxh32;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EdgeStoreStaging};
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;

/// Per-entity-type short-id counter, little-endian `u64`. Key: the entity
/// type byte.
const SHORT_ID_COUNTER: SideTable<[u8; 1], [u8; 8], Raw> =
    SideTable::new(&side_table::SHORT_ID_COUNTER);

/// Per-runtime-kind short-id counter, little-endian `u64` (FIX 7741). Key:
/// the kind's stable short-id prefix, which its name derives. A pack kind's
/// type byte is recycled once its slot is collected; this counter is not, so
/// a kind reinstalled on a fresh byte never reissues a retired short id.
const SHORT_ID_KIND_COUNTER: SideTable<String, [u8; 8], Raw> =
    SideTable::new(&side_table::SHORT_ID_KIND_COUNTER);

/// The counter a new short id advances: a fixed kind's by its type byte, a
/// runtime (pack) kind's by its stable prefix, never by the byte it happens
/// to hold now (FIX 7741).
pub(super) enum ShortIdCounter {
    Type(u8),
    Kind(String),
}

impl ShortIdCounter {
    fn of(entity_type: u8, short_id_prefix: &str) -> Self {
        if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
            Self::Kind(short_id_prefix.to_owned())
        } else {
            Self::Type(entity_type)
        }
    }

    /// The last issued counter; zero before any.
    fn last(&self, store: &impl ManifestDbs, txn: &heed::RwTxn<'_>) -> Result<u64> {
        let stored = match self {
            Self::Type(entity_type) => SHORT_ID_COUNTER.get(store, txn, &[*entity_type])?,
            Self::Kind(prefix) => SHORT_ID_KIND_COUNTER.get(store, txn, prefix)?,
        };
        Ok(stored.map_or(0, u64::from_le_bytes))
    }

    fn put(&self, store: &impl ManifestDbs, wtxn: &mut RwTxn<'_>, counter: u64) -> Result<()> {
        match self {
            Self::Type(entity_type) => {
                SHORT_ID_COUNTER.put(store, wtxn, &[*entity_type], &counter.to_le_bytes())
            }
            Self::Kind(prefix) => {
                SHORT_ID_KIND_COUNTER.put(store, wtxn, prefix, &counter.to_le_bytes())
            }
        }
    }
}

pub(super) enum ShortIdPlan {
    UpdateExisting {
        short_id: String,
        old_content_hash: u8,
        content_hash: u8,
    },
    InsertNew {
        counter: ShortIdCounter,
        next_counter: u64,
        short_id: String,
        content_hash: u8,
    },
}

/// The content-hash byte a short reference to a revision with body `data`
/// carries (`xxh32(data, 0) % 256`).
#[must_use]
pub fn short_id_content_hash(data: &[u8]) -> u8 {
    (xxh32(data, 0) % 256) as u8
}

pub(super) fn plan_short_id_update(
    store: &impl ManifestDbs,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    short_id_prefix: &str,
    data: &[u8],
) -> Result<ShortIdPlan> {
    plan_short_id_update_hashed(
        store,
        txn,
        id,
        entity_type,
        short_id_prefix,
        short_id_content_hash(data),
    )
}

/// [`plan_short_id_update`] for a body whose content-hash byte its writer
/// measured as it streamed (a body file, FIX 3677), so the body need not be
/// read whole again.
pub(super) fn plan_short_id_update_hashed(
    store: &impl ManifestDbs,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    short_id_prefix: &str,
    content_hash: u8,
) -> Result<ShortIdPlan> {
    if let Some((short_id, old_content_hash)) =
        crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, id)?
    {
        return Ok(ShortIdPlan::UpdateExisting {
            short_id,
            old_content_hash,
            content_hash,
        });
    }

    // Counters live in `vault_meta` under the documented
    // `b"sid_counter:" ‖ type_byte` key scheme (store.rs), or for a runtime
    // kind `b"sid_kind_counter:" ‖ prefix` (FIX 7741), NOT as sentinel rows
    // inside `short_ids` — that table holds only the ARCH-0019 row n3
    // mapping `(short_id, content_hash)` -> `entity_id`.
    let counter = ShortIdCounter::of(entity_type, short_id_prefix);
    let next = counter
        .last(store, txn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("short id counter"))?;
    let short_id = format!("{short_id_prefix}{next}");
    Ok(ShortIdPlan::InsertNew {
        counter,
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
            counter,
            next_counter,
            short_id,
            content_hash,
        } => {
            counter.put(store, wtxn, next_counter)?;
            write_short_id_rows(store, wtxn, id, &short_id, content_hash)?;
        }
    }

    Ok(())
}

pub(crate) fn delete_short_id_rows_for_id(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let forward_key = crate::ports::ShortIdStoreRead::port_short_id_reference(store, wtxn, id)?
        .map(|(short_id, content_hash)| encode_short_id_forward_key(&short_id, content_hash));
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
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let store = write.store;
    let outbound: Vec<_> = store
        .port_edges(wtxn, id, EdgeDirection::Out, None, None)?
        .map(|row| row.map(|edge| (edge.kind, edge.target)))
        .collect::<Result<_>>()?;
    let inbound: Vec<_> = store
        .port_edges(wtxn, id, EdgeDirection::In, None, None)?
        .map(|row| row.map(|edge| (edge.kind, edge.target)))
        .collect::<Result<_>>()?;
    // An epoch summary written from `id` loses its edge to it here, as at the
    // batch door: withdrawn for where its words sat, read before any of
    // `id`'s edges go. A deletion that already captured them adds nothing.
    for (kind, source) in &inbound {
        if *kind == crate::edge::EdgeKind::DerivedFrom && source != id {
            crate::ports::withdraw_from_lost_source_in_txn(write, wtxn, source, id)?;
        }
    }
    for (kind, target) in &outbound {
        store.port_remove_edge_rows(wtxn, id, *kind, target)?;
    }
    for (kind, source) in &inbound {
        store.port_remove_edge_rows(wtxn, source, *kind, id)?;
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
