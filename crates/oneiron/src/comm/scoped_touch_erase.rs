//! Native touch-source rows owned by an original CLAIM's delete.

use std::collections::BTreeSet;

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
    originals: &BTreeSet<EntityId>,
) -> Result<Vec<EntityId>> {
    if originals.is_empty() {
        return Ok(Vec::new());
    }
    super::note_comm_record_family_scan();
    let mut sources = Vec::new();
    for entry in
        store.port_entity_ids_by_type(txn, crate::registry::ENTITY_TYPE_COMM_RECORD, None)?
    {
        let id = entry?;
        let Some(row) = store.port_entity_record(txn, &id)? else {
            continue;
        };
        if row.entity_type == crate::registry::ENTITY_TYPE_COMM_RECORD
            && let Ok(Some(source)) = ScopedTouchRecord::decode(id, &row.body)
            && originals.contains(&source.original_head())
        {
            sources.push(id);
        }
    }
    Ok(sources)
}

/// Only a real privacy reason retires the owned copies' checkpoint leaves.
/// Their own holds keep the staged keys until the native finisher can retire them.
pub(crate) fn settle_scoped_touch_checkpoint_payloads_for_reason_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    original: &EntityId,
    reason: Option<TombstoneReason>,
) -> Result<()> {
    if !reason.is_some_and(TombstoneReason::erases_checkpoint_payloads) {
        return Ok(());
    }
    for source in source_ids_in_txn(store, txn, &BTreeSet::from([*original]))? {
        store.stage_known_history_erase_in_txn(txn, &source)?;
        crate::deletion::settle_checkpoint_payloads_for_reason_in_txn(store, txn, &source, reason)?;
    }
    Ok(())
}

pub(crate) fn erase_scoped_touch_sources_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    original: &EntityId,
) -> Result<()> {
    erase_sources_in_txn(write, txn, &BTreeSet::from([*original]))
}

/// A restore or hold release already supplies the actual erased originals.
pub(crate) fn erase_scoped_touch_sources_for_erased_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    originals: &BTreeSet<EntityId>,
) -> Result<()> {
    erase_sources_in_txn(&CustodyWrite::of(vault), txn, originals)
}

fn erase_sources_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    originals: &BTreeSet<EntityId>,
) -> Result<()> {
    let store = write.store;
    let sources = source_ids_in_txn(store, txn, originals)?;
    for source in sources {
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
        if !originals.contains(&record.original_head()) {
            continue;
        }
        if crate::store::legal_hold::held_in_txn(store, txn, source.as_bytes())?
            || crate::world_keys::held_pad_world_in_txn(store, txn, &raw)?
        {
            continue;
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(write, txn, &source)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &source, &neighbors)?;
        if graph {
            crate::store::graph_version::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::store::vector_index::increment_vector_version(store, txn)?;
        }
    }
    Ok(())
}
