use super::*;

/// Publish derived arrivals and index versions only after the complete batch.
pub(super) fn finalize_batch_indexes(
    store: &Store,
    config: &crate::config::VaultConfig,
    wtxn: &mut RwTxn<'_>,
    materialized_entity_ids: &BTreeSet<EntityId>,
    pending_hnsw_rebuild: bool,
    had_graph_mutation: bool,
    had_vector_mutation: bool,
) -> Result<()> {
    crate::llm::decision::questions::project_arrivals_in_txn(store, wtxn, materialized_entity_ids)?;

    crate::hnsw::run_pending_legacy_rebuild(store, config, wtxn, pending_hnsw_rebuild)?;

    if had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if had_vector_mutation {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }

    Ok(())
}

pub(super) fn apply_text_index_update(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    id: &EntityId,
    fields: &[(String, String)],
    text_index_trusted: bool,
    text_manifest_checked: &mut bool,
) -> Result<()> {
    if !text_index_trusted {
        return Err(Error::CorruptedIndex(
            "text index handshake bypassed on populated index",
        ));
    }
    if !*text_manifest_checked {
        crate::vault::ensure_text_index_manifest_matches_wtxn(store, wtxn, analyzer)?;
        *text_manifest_checked = true;
    }
    if !crate::vault::entity_revision::defer_index_inputs(
        store,
        wtxn,
        id,
        Some(fields),
        None,
        None,
    )? {
        crate::bm25::index_text(store, wtxn, analyzer, id, fields)?;
    }
    Ok(())
}
