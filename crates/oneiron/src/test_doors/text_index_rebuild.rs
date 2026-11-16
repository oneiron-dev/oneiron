//! Doors for `tests/text_index_auto_rebuild.rs` (FIX ANALYZER-BUMP-AUTO-REINDEX):
//! stamp a populated vault as an engine with another analyzer left it, run the
//! rebuild pass a page at a time, stretch a document's stored source text
//! past the text ceiling, and read the rebuild marker and the text index's
//! row counts.

use crate::analyzer::AnalyzerManifest;
use crate::error::{Error, Result, StoreError};
use crate::ports::{IndexRows, RetrievalIndexInventory};
use crate::side_table::{self, Named, SideTable};
use crate::store::text_index::index::MAX_INDEXED_TEXT_BYTES;
use crate::store::{
    TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
};
use crate::vault::text_index_rebuild::read_text_index_rebuild;
use crate::{EntityId, Vault};

/// The text each document was indexed with. Key: id16.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

fn manifest_error(error: serde_json::Error) -> Error {
    Error::Store(StoreError::AnalyzerError(format!("manifest: {error}")))
}

/// Rewrites the stored analyzer manifest and its hash with `change` applied:
/// the stamp an engine whose analyzer differs by that change left.
pub fn restamp_stored_analyzer_manifest(
    vault: &Vault,
    change: impl FnOnce(&mut AnalyzerManifest),
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let stored = vault
        .store
        .vault_meta
        .get(&wtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .ok_or(Error::InvariantViolation("no stored analyzer manifest"))?
        .to_vec();
    let mut manifest: AnalyzerManifest = serde_json::from_slice(&stored).map_err(manifest_error)?;
    change(&mut manifest);
    let json = manifest.canonical_json().map_err(manifest_error)?;
    let hash = manifest.canonical_hash().map_err(manifest_error)?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_KEY, json.as_bytes())?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &hash)?;
    wtxn.commit()?;
    Ok(())
}

/// Rewrites the stored BM25F field-schema hash, or deletes it with `None`.
pub fn restamp_stored_bm25_field_schema_hash(vault: &Vault, hash: Option<[u8; 32]>) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    match hash {
        Some(hash) => {
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &hash)?;
        }
        None => {
            vault
                .store
                .vault_meta
                .delete(&mut wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

/// Pads the first field of `id`'s stored source text past the per-document
/// text ceiling: the row a document indexed before the ceiling left. Its
/// postings stay as they are.
pub fn stretch_source_text_past_ceiling(vault: &Vault, id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut fields = INDEX_SOURCE_TEXT
        .get(&vault.store, &wtxn, id)?
        .ok_or(Error::InvariantViolation("no stored source text"))?;
    let (_, value) = fields
        .first_mut()
        .ok_or(Error::InvariantViolation("stored source text has no field"))?;
    value.push(' ');
    value.push_str(&"x".repeat(MAX_INDEXED_TEXT_BYTES));
    INDEX_SOURCE_TEXT.put(&vault.store, &mut wtxn, id, &fields)?;
    wtxn.commit()?;
    Ok(())
}

/// The rebuild in flight as `(done, total)`, or `None` when none stands.
pub fn text_index_rebuild_progress(vault: &Vault) -> Result<Option<(u64, u64)>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(read_text_index_rebuild(&vault.store, &rtxn)?.map(|marker| (marker.done, marker.total)))
}

/// Runs the rebuild pass `pages` pages of `page` documents at most; returns
/// the documents indexed again and whether no rebuild is left.
pub fn run_text_index_rebuild_pages(
    vault: &Vault,
    page: usize,
    pages: usize,
) -> Result<(u64, bool)> {
    let mut left = pages;
    let run = vault.run_text_index_rebuild(page, || {
        left = left.saturating_sub(1);
        left == 0
    })?;
    Ok((run.reindexed, run.complete))
}

/// Rows in the five text-index databases: postings, meta, forward, per-doc
/// field lengths and field stats.
pub fn text_index_row_counts(vault: &Vault) -> Result<[u64; 5]> {
    let rtxn = vault.store.env.read_txn()?;
    let mut counts = [0; 5];
    for (count, rows) in counts.iter_mut().zip([
        IndexRows::TextPostings,
        IndexRows::TextMeta,
        IndexRows::TextForward,
        IndexRows::TextDocFieldLengths,
        IndexRows::TextBm25FieldStats,
    ]) {
        *count = vault.store.port_index_row_count(&rtxn, rows)?;
    }
    Ok(counts)
}
