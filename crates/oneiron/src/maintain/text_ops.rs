//! Text-index clear, PPR cleanup, and postings compaction.

use crate::error::Result;
use crate::ports::{EntityStoreRead, IndexRows, RetrievalIndexInventory};
use crate::ppr;
use crate::side_table::{self, Named, SideTable};
use crate::vault::write_text_index_manifest;
use crate::{EntityId, Vault};

/// The text each document was indexed with, kept beside the index so it can
/// be built again. Key: id16.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

pub(super) struct ClearTextIndexCounts {
    pub(super) postings: u64,
    pub(super) meta: u64,
    pub(super) forward: u64,
    pub(super) doc_field_lengths: u64,
    pub(super) field_stats: u64,
    pub(super) reindexed: u64,
}

/// Drops the text index and rewrites its manifest. With `reindex`, the same
/// transaction indexes every live document again from the text it was
/// indexed with, so the index is never seen half built.
pub(super) fn clear_text_index(vault: &Vault, reindex: bool) -> Result<ClearTextIndexCounts> {
    let mut wtxn = vault.store.env.write_txn()?;

    let postings = vault
        .store
        .port_index_row_count(&wtxn, IndexRows::TextPostings)?;
    vault.store.text_postings.clear(&mut wtxn)?;

    let meta = vault
        .store
        .port_index_row_count(&wtxn, IndexRows::TextMeta)?;
    vault.store.text_meta.clear(&mut wtxn)?;

    let forward = vault
        .store
        .port_index_row_count(&wtxn, IndexRows::TextForward)?;
    vault.store.text_forward.clear(&mut wtxn)?;

    let doc_field_lengths = vault
        .store
        .port_index_row_count(&wtxn, IndexRows::TextDocFieldLengths)?;
    vault.store.text_doc_field_lengths.clear(&mut wtxn)?;

    let field_stats = vault
        .store
        .port_index_row_count(&wtxn, IndexRows::TextBm25FieldStats)?;
    vault.store.text_bm25_field_stats.clear(&mut wtxn)?;

    write_text_index_manifest(&vault.store, &mut wtxn, &vault.analyzer)?;

    let mut reindexed = 0;
    if reindex {
        for (id, fields) in INDEX_SOURCE_TEXT.scan(&vault.store, &wtxn)? {
            if !vault.store.port_entity_present(&wtxn, &id)? {
                continue;
            }
            crate::bm25::index_text(&vault.store, &mut wtxn, &vault.analyzer, &id, &fields)?;
            reindexed += 1;
        }
    }

    wtxn.commit()?;

    // The on-disk manifest now matches the in-memory analyzer; subsequent
    // search_text calls within the same Vault instance can proceed. See
    // `Vault::text_index_trusted`.
    vault
        .text_index_trusted
        .store(true, std::sync::atomic::Ordering::Release);

    Ok(ClearTextIndexCounts {
        postings,
        meta,
        forward,
        doc_field_lengths,
        field_stats,
        reindexed,
    })
}

pub(super) fn cleanup_ppr_cache(vault: &Vault, max_age_secs: u64) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = vault.store.clock.now_recorded_at();
    let counts = ppr::cleanup_ppr_cache(&vault.store, &mut wtxn, max_age_secs, now)?;
    wtxn.commit()?;
    Ok(counts)
}

pub(super) fn compact_postings(vault: &Vault) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    // `text_postings` is DUP_SORT (storage ABI v4): `iter` yields one
    // (term, item) pair per duplicate. Remove only the degenerate empty
    // items — a term key whose sole duplicate is empty disappears with
    // it, while valid sibling duplicates are preserved.
    let mut empty_item_terms = Vec::new();
    for entry in vault.store.text_postings.iter(&wtxn)? {
        let (term, posting) = entry?;
        if posting.is_empty() {
            empty_item_terms.push(term.to_vec());
        }
    }

    for term in &empty_item_terms {
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, term, &[])?;
    }

    wtxn.commit()?;
    Ok(empty_item_terms.len() as u64)
}
