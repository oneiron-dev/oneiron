//! Native touch-source rows owned by an original CLAIM's privacy erase.

use std::collections::BTreeMap;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::TombstoneReason;
use crate::ports::EntityStoreRead;
use crate::secret_custody::CustodyWrite;
use crate::store::Store;
use crate::{EntityId, Result};

use super::scoped_touch::ScopedTouchRecord;

fn source_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    originals: &BTreeMap<EntityId, TombstoneReason>,
) -> Result<BTreeMap<EntityId, TombstoneReason>> {
    if !originals
        .values()
        .any(|reason| reason.erases_checkpoint_payloads())
    {
        return Ok(BTreeMap::new());
    }
    super::note_comm_record_family_scan();
    let mut sources = BTreeMap::new();
    for (source, original) in
        crate::store::checkpoint_payload::instance::scoped_touch_sources_in_txn(store, txn)?
    {
        if let Some(reason) = originals
            .get(&original)
            .filter(|reason| reason.erases_checkpoint_payloads())
        {
            sources.insert(source, *reason);
        }
    }
    for entry in
        store.port_entity_ids_by_type(txn, crate::registry::ENTITY_TYPE_COMM_RECORD, None)?
    {
        let id = entry?;
        let Some(row) = store.port_entity_record(txn, &id)? else {
            continue;
        };
        if row.entity_type == crate::registry::ENTITY_TYPE_COMM_RECORD
            && let Ok(Some(source)) = ScopedTouchRecord::decode(id, &row.body)
            && let Some(reason) = originals
                .get(&source.original_head())
                .filter(|reason| reason.erases_checkpoint_payloads())
        {
            sources.insert(id, *reason);
        }
    }
    Ok(sources)
}

pub(crate) fn scoped_touch_source_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    original: &EntityId,
    reason: Option<TombstoneReason>,
) -> Result<bool> {
    let Some(reason) = reason.filter(|reason| reason.erases_checkpoint_payloads()) else {
        return Ok(false);
    };
    Ok(!source_ids_in_txn(store, txn, &BTreeMap::from([(*original, reason)]))?.is_empty())
}

pub(crate) fn erase_scoped_touch_sources_for_reason_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    original: &EntityId,
    reason: Option<TombstoneReason>,
) -> Result<bool> {
    let Some(reason) = reason.filter(|reason| reason.erases_checkpoint_payloads()) else {
        return Ok(false);
    };
    erase_sources_in_txn(write, txn, &BTreeMap::from([(*original, reason)]))
}

pub(crate) fn erase_scoped_touch_sources_for_native_delete_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    original: &EntityId,
    request_id: Option<&[u8; 16]>,
) -> Result<bool> {
    let reason = crate::deletion::topology_delete_reservation_in_txn(&vault.store, txn, original)?
        .filter(|reserved| request_id.is_none_or(|request| reserved.request_id == *request))
        .map(|reserved| reserved.reason);
    erase_scoped_touch_sources_for_reason_in_txn(&CustodyWrite::of(vault), txn, original, reason)
}

pub(crate) fn erase_scoped_touch_sources_for_erased_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    originals: &BTreeMap<EntityId, TombstoneReason>,
) -> Result<bool> {
    erase_sources_in_txn(&CustodyWrite::of(vault), txn, originals)
}

fn erase_sources_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    originals: &BTreeMap<EntityId, TombstoneReason>,
) -> Result<bool> {
    let store = write.store;
    let sources = source_ids_in_txn(store, txn, originals)?;
    let mut erased = false;
    for (source, reason) in sources {
        crate::deletion::settle_checkpoint_payloads_for_reason_in_txn(
            store,
            txn,
            &source,
            Some(reason),
        )?;
        let Some(raw) = store.port_entity_raw(txn, &source)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("comm source entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_COMM_RECORD {
            continue;
        }
        let Ok(Some(record)) =
            ScopedTouchRecord::decode(source, &raw[ENTITY_METADATA_HEADER_LEN..])
        else {
            continue;
        };
        if !originals
            .get(&record.original_head())
            .is_some_and(|reason| reason.erases_checkpoint_payloads())
        {
            continue;
        }
        if crate::store::legal_hold::held_in_txn(store, txn, source.as_bytes())?
            || crate::world_keys::held_pad_world_in_txn(store, txn, &raw)?
        {
            continue;
        }
        let (existed, vector, graph, neighbors) =
            crate::batch::deindex_entity(write, txn, &source)?;
        erased |= existed;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &source, &neighbors)?;
        if graph {
            crate::store::graph_version::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::store::vector_index::increment_vector_version(store, txn)?;
        }
    }
    Ok(erased)
}
