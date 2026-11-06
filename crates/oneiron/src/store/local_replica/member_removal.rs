//! One member's local leaves for the replica tear: its index, projection,
//! vector and edge rows, then its entity row. Custody, provenance, document
//! and control rows stay.

use heed::RwTxn;
use loro::LoroMap;

use super::RemovedReplica;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{
    EdgeDirection, EdgeStoreRead, EdgeStoreStaging, EntityStoreRead, EntityStoreStaging,
    ShortIdStoreRead,
};
use crate::registry;
use crate::store::Store;
use crate::store::loro_document::map_contains_binary;
use crate::store::replica_edge_key::format_edge_key;
use crate::temporal::TimeRange;

/// Tears one member's local rows. Every step is a local index or projection
/// leaf of the physical tear; custody, provenance, document and control rows
/// stay. A released member takes every edge it touches with it.
pub(super) fn remove_member(
    store: &Store,
    txn: &mut RwTxn<'_>,
    edges: &LoroMap,
    id: &EntityId,
    released: bool,
    report: &mut RemovedReplica,
) -> Result<()> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(());
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
    // Thread meta reads the RepliesTo edges, so it is marked dirty first.
    crate::conversation_dag::invalidate_thread_meta_for_turn_put(store, txn, *id)?;
    crate::task_verb::index_owner_fact(store, txn, id, None)?;
    crate::store::text_index::deindex_text(store, txn, id)?;
    crate::vault::entity_revision::remove_entity_revisions(store, txn, id)?;
    crate::batch::delete_from_phonetic_postings(store, txn, id)?;
    crate::code_symbol::delete_code_symbol_manifest_in_txn(store, txn, id)?;
    crate::counterparty_contact::drop_contact_index_rows_in_txn(store, txn, id)?;
    remove_vectors(store, txn, id, report)?;
    let neighbors = remove_member_edges(store, txn, edges, id, released, report)?;
    if let Some((short_id, hash)) = store.port_short_id_reference(txn, id)? {
        let forward = crate::batch::encode_short_id_forward_key(&short_id, hash);
        store.short_ids.delete(txn, &forward)?;
        store.short_ids_reverse.delete(txn, id.as_bytes())?;
    }
    if header.entity_type == registry::ENTITY_TYPE_SKILL
        && let Ok(record) = crate::write_envelope::skill_record::decode_skill_record(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
        && let Some(content_hash) = record.content_hash
    {
        crate::store::skill_content_index::maintain_skill_content_hash_index_for_delete(
            store,
            txn,
            id,
            content_hash,
        )?;
    }
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    crate::batch::delete_entity_index_rows(
        store,
        txn,
        id,
        header.entity_type,
        occurred,
        header.learned_at,
    )?;
    crate::dreamer_runner::deindex_dreamer_milestone_claim(store, txn, id)?;
    crate::llm::deindex_dreamer_step_claim(store, txn, id)?;
    // Both read the stored row, so they run before it goes.
    crate::store::identity_hints::reindex_identity_hints(store, txn, id, None)?;
    crate::ports::reindex_named_entities(store, txn, id, None)?;
    crate::store::blob_fingerprint::invalidate_blob_fingerprint(store, txn, id)?;
    crate::store::claim_projection::remove_claim_projection_index(store, txn, *id)?;
    // A demoted epoch summary keeps its place in its session's count, so a
    // local mint never numbers under it (OF-013).
    crate::compaction::raise_epoch_floor_in_txn(store, txn, &raw)?;
    store.port_remove_entity_row(txn, id)?;
    store
        .l2_base_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .erase(id, store.env.info().last_txn_id);
    crate::store::ppr_cache_invalidation::invalidate_ppr_for_delete(store, txn, id, &neighbors)?;
    report.removed.push(*id);
    Ok(())
}

fn remove_vectors(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    report: &mut RemovedReplica,
) -> Result<()> {
    store.clear_pending_embedding(txn, id)?;
    // The member's queued embed job goes with its marker, in the same txn.
    store.sync_hooks.delete_embed_job_in_txn(store, txn, id)?;
    if store.vectors.delete(txn, id.as_bytes())? {
        report.vectors += 1;
    }
    crate::embed::record_embedding_device_in_txn(store, txn, id, None)?;
    crate::embed::delete_media_vectors_in_txn(store, txn, id)?;
    crate::hnsw::hnsw_deindex(store, txn, id)?;
    Ok(())
}

/// Removes the edges touching `id` that this window's document carries. An
/// edge another window carries stays, as partial residence leaves it, and so
/// does a local-only edge, which no server copy could give back; a released
/// member (`all`) takes every edge it touches, out and in, its neighbours
/// staying (FIX 14534). Returns every neighbour, for cache invalidation.
fn remove_member_edges(
    store: &Store,
    txn: &mut RwTxn<'_>,
    edges: &LoroMap,
    id: &EntityId,
    all: bool,
    report: &mut RemovedReplica,
) -> Result<Vec<EntityId>> {
    let mut incident = Vec::new();
    for direction in [EdgeDirection::Out, EdgeDirection::In] {
        for row in store.port_edges(txn, id, direction, None, None)? {
            let edge = row?;
            let (source, target) = if direction == EdgeDirection::Out {
                (*id, edge.target)
            } else {
                (edge.target, *id)
            };
            incident.push((source, edge.kind, target));
        }
    }
    let mut neighbors = Vec::with_capacity(incident.len());
    for (source, kind, target) in incident {
        neighbors.push(if source == *id { target } else { source });
        if (all || map_contains_binary(edges, &format_edge_key(&source, kind, &target)))
            && store.port_remove_edge_rows(txn, &source, kind, &target)?
        {
            report.edges += 1;
        }
    }
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok(neighbors)
}
