use super::*;

use std::collections::HashSet;

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::ppr;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::Store;

pub(super) fn reject_engine_authored_delete(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Ok(());
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(());
    };
    // Single source of truth: the registry owns the delete-protected kind set
    // (ONE-1741 added the content anchor); the batch/bulk delete door and the
    // deletion path both consult it, so the guards cannot drift out of sync.
    if crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return Err(Error::MaintenanceKindNotWritable(header.entity_type));
    }
    Ok(())
}

pub(crate) fn deindex_entity(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, bool, Vec<EntityId>)> {
    let (mut had_vector, mut had_graph_mutation, mut neighbors) =
        deindex_lexical_query_hints_for_target(store, wtxn, id)?;

    let (existed, entity_had_vector, entity_had_graph_mutation, mut entity_neighbors) =
        deindex_entity_without_lexical_query_hint_cascade(store, wtxn, id)?;
    had_vector |= entity_had_vector;
    had_graph_mutation |= entity_had_graph_mutation;
    neighbors.append(&mut entity_neighbors);
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((existed, had_vector, had_graph_mutation, neighbors))
}

pub(crate) fn deindex_lexical_query_hints_for_target(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, Vec<EntityId>)> {
    let deleted_hints =
        delete_lexical_query_hint_claims_for_target(store, wtxn, id, &HashSet::new())?;
    let mut neighbors = Vec::new();
    for (hint_id, hint_neighbors) in &deleted_hints.deleted {
        ppr::invalidate_ppr_for_delete(store, wtxn, hint_id, hint_neighbors)?;
        neighbors.push(*hint_id);
        neighbors.extend(
            hint_neighbors
                .iter()
                .copied()
                .filter(|neighbor| neighbor != id),
        );
    }
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((
        deleted_hints.had_vector,
        deleted_hints.had_graph_mutation,
        neighbors,
    ))
}

pub(super) fn deindex_entity_without_lexical_query_hint_cascade(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, bool, Vec<EntityId>)> {
    let mut had_vector = false;
    let mut had_graph_mutation = false;
    let mut neighbors = Vec::new();

    // Clean secondary indexes unconditionally — they may exist even without an
    // entity record (e.g. text indexed via batch().text() without a preceding put()).
    crate::bm25::deindex_text(store, wtxn, id)?;
    delete_from_phonetic_postings(store, wtxn, id)?;
    crate::code_revision::delete_code_revision_lifecycle_in_txn(store, wtxn, id)?;
    crate::codebase::delete_codebase_snapshot_in_txn(store, wtxn, id)?;
    // ARCH-0050 R6 L2 (ONE-1608): L2 attachments are metadata rows, not
    // entities, so nothing else in this door reaches them. The deleted id may
    // have been the `CODE_SYMBOL` anchor those rows hang off OR the NOTE/CLAIM
    // payload they point at, and both leave a public reader answering for a
    // dead id. Deliberately above the entity-record fetch so the index-only
    // arm below — where the anchor type can no longer be read back — is
    // covered by the same call.
    crate::code_memory::delete_code_memory_rows_for_entity_in_txn(store, wtxn, id)?;
    let blob_cleanup =
        crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(store, wtxn, id)?;
    had_vector |= blob_cleanup.had_vector;
    had_graph_mutation |= blob_cleanup.had_graph_mutation;
    neighbors.extend(blob_cleanup.neighbors);
    store.clear_pending_embedding(wtxn, id)?;
    had_vector |= store.vectors.delete(wtxn, id.as_bytes())?;
    crate::hnsw::hnsw_deindex(store, wtxn, id)?;
    let related_neighbors = delete_related_edges(store, wtxn, id)?;
    had_graph_mutation |= !related_neighbors.is_empty();
    neighbors.extend(related_neighbors);

    delete_short_id_rows_for_id(store, wtxn, id)?;

    let Some(entity_record) = store.entities.get(wtxn, id.as_bytes())? else {
        let cleanup = crate::affect::delete_vad_annotation_metadata_in_txn(store, wtxn, id)?;
        had_vector |= cleanup.had_vector;
        had_graph_mutation |= cleanup.had_graph_mutation;
        neighbors.extend(cleanup.neighbors);
        neighbors.sort_unstable();
        neighbors.dedup();
        return Ok((false, had_vector, had_graph_mutation, neighbors));
    };
    had_graph_mutation = true;

    let (entity_type, occurred, learned_at) = parse_entity_metadata(&entity_record)?;
    if entity_type == ENTITY_TYPE_SKILL {
        let body = &entity_record[ENTITY_METADATA_HEADER_LEN..];
        match crate::skill::decode_skill_record(body) {
            Ok(record) => {
                if let Some(content_hash) = record.content_hash {
                    crate::skill_hub::maintain_skill_content_hash_index_for_delete(
                        store,
                        wtxn,
                        id,
                        content_hash,
                    )?;
                }
            }
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) => {}
            Err(error) => return Err(error),
        }
    }
    let mut cleanup = crate::affect::VadAnnotationCleanup::default();
    crate::affect::delete_vad_annotation_metadata_for_type_in_txn(
        store,
        wtxn,
        id,
        entity_type,
        &mut cleanup,
    )?;
    had_vector |= cleanup.had_vector;
    had_graph_mutation |= cleanup.had_graph_mutation;
    neighbors.extend(cleanup.neighbors);
    neighbors.sort_unstable();
    neighbors.dedup();

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
    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_long_intervals
            .delete(wtxn, &long_interval_key)?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned.delete(wtxn, &learned_key)?;

    crate::dreamer_runner::deindex_dreamer_milestone_claim(store, wtxn, id)?;
    crate::llm::deindex_dreamer_step_claim(store, wtxn, id)?;
    store.entities.delete(wtxn, id.as_bytes())?;
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok((true, had_vector, had_graph_mutation, neighbors))
}

#[cfg(test)]
pub(crate) fn deindex_entity_for_test(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let _ = deindex_entity_without_lexical_query_hint_cascade(store, wtxn, id)?;
    Ok(())
}
