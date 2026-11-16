//! The text-index rebuild an analyzer change starts at open (FIX
//! ANALYZER-BUMP-AUTO-REINDEX).
//!
//! An `ANALYZER_VERSION` bump or a `NormalizationPolicy` flag changes the
//! analyzer manifest hash, and a BM25F field change changes the field-schema
//! hash. Postings written under the old hashes cannot be scored under the new
//! analyzer. `Vault::open` refused such a vault until its host ran the manual
//! recovery. Now the writable open clears the text index, rewrites the
//! manifest and writes [`TEXT_INDEX_REBUILD`] in one transaction, so text
//! writes go on at once under the new analyzer. The housekeeping sweep
//! `TextIndexRebuild` then indexes every document again from the text it was
//! indexed with (`INDEX_SOURCE_TEXT`), one page per write transaction: a
//! page's postings and the marker's cursor commit together, and the last page
//! deletes the marker.
//!
//! A crash between pages resumes after the cursor on the next open's first
//! pass; a crash inside a page rolls that page back. Indexing a document is
//! idempotent (`write_index` drops a document's old rows first), so a document
//! a foreground write indexed after the clear ends the same when the pass
//! reaches it, and a document deleted meanwhile has no source row left for the
//! pass to find. A source row past the per-document text ceiling, written
//! before the ceiling, stays unindexed, as the checkpoint restore and the
//! leave's reindex leave it. Text reads fail closed while the marker stands:
//! each read looks for it in its own read transaction, so a rebuild another
//! process's open started, or another process's pass ended, reaches every
//! open handle at its next read.

use std::ops::Bound;

use super::Vault;
use crate::analyzer::MultilingualAnalyzer;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::ports::{EntityStoreRead, IndexRows, RetrievalIndexInventory};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// The rebuild in flight. Key: `()`.
const TEXT_INDEX_REBUILD: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::TEXT_INDEX_REBUILD);
/// The text each document was indexed with. Key: id16.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// Stored source text one page of the pass indexes at most, past its first
/// document: a page of documents at the per-document text ceiling would put
/// gigabytes of postings in one write transaction.
const PAGE_SOURCE_BYTES: usize = 16 * 1024 * 1024;

const MARKER_VERSION: u8 = 1;
/// Version, cursor flag, cursor id16, done and total (u64 LE each).
const MARKER_LEN: usize = 1 + 1 + 16 + 8 + 8;

/// A text-index rebuild in flight, as [`TEXT_INDEX_REBUILD`] stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TextIndexRebuildMarker {
    /// The last document the pass indexed again; `None` before its first page.
    pub(crate) cursor: Option<EntityId>,
    /// Documents indexed again so far.
    pub(crate) done: u64,
    /// Documents with stored source text when the rebuild started: a
    /// start-time count, so a document deleted during the rebuild leaves the
    /// final `done` below it.
    pub(crate) total: u64,
}

impl TextIndexRebuildMarker {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MARKER_LEN);
        out.push(MARKER_VERSION);
        match &self.cursor {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 16]);
            }
        }
        out.extend_from_slice(&self.done.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupt = || Error::CorruptedIndex("text index rebuild marker undecodable");
        if bytes.len() != MARKER_LEN || bytes[0] != MARKER_VERSION {
            return Err(corrupt());
        }
        let cursor = match bytes[1] {
            0 => None,
            1 => {
                let id: [u8; 16] = bytes[2..18].try_into().map_err(|_| corrupt())?;
                Some(EntityId::from_bytes(id).map_err(|_| corrupt())?)
            }
            _ => return Err(corrupt()),
        };
        let done = u64::from_le_bytes(bytes[18..26].try_into().map_err(|_| corrupt())?);
        let total = u64::from_le_bytes(bytes[26..34].try_into().map_err(|_| corrupt())?);
        Ok(Self {
            cursor,
            done,
            total,
        })
    }
}

/// The rebuild in flight, if one stands.
pub(crate) fn read_text_index_rebuild(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<TextIndexRebuildMarker>> {
    TEXT_INDEX_REBUILD
        .get(store, txn, &())?
        .map(|bytes| TextIndexRebuildMarker::decode(&bytes))
        .transpose()
}

/// The rows one text-index clear dropped, by database.
pub(crate) struct ClearedTextIndexRows {
    pub(crate) postings: u64,
    pub(crate) meta: u64,
    pub(crate) forward: u64,
    pub(crate) doc_field_lengths: u64,
    pub(crate) field_stats: u64,
}

/// Drops every text-index row and rewrites the manifest from `analyzer`, in
/// `wtxn`. The stored source text and the rebuild marker stay as they are.
pub(crate) fn clear_text_index_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<ClearedTextIndexRows> {
    let postings = store.port_index_row_count(&*wtxn, IndexRows::TextPostings)?;
    store.text_postings.clear(wtxn)?;
    let meta = store.port_index_row_count(&*wtxn, IndexRows::TextMeta)?;
    store.text_meta.clear(wtxn)?;
    let forward = store.port_index_row_count(&*wtxn, IndexRows::TextForward)?;
    store.text_forward.clear(wtxn)?;
    let doc_field_lengths = store.port_index_row_count(&*wtxn, IndexRows::TextDocFieldLengths)?;
    store.text_doc_field_lengths.clear(wtxn)?;
    let field_stats = store.port_index_row_count(&*wtxn, IndexRows::TextBm25FieldStats)?;
    store.text_bm25_field_stats.clear(wtxn)?;
    super::write_text_index_manifest(store, wtxn, analyzer)?;
    Ok(ClearedTextIndexRows {
        postings,
        meta,
        forward,
        doc_field_lengths,
        field_stats,
    })
}

/// Starts a rebuild in `wtxn`: clears the text index, rewrites its manifest,
/// and writes the marker at the start. Called by the writable open on a stale
/// manifest; a rebuild already in flight starts over.
pub(super) fn start_text_index_rebuild_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    clear_text_index_rows_in_txn(store, wtxn, analyzer)?;
    let total = u64::try_from(INDEX_SOURCE_TEXT.scan_keys(store, &*wtxn, &[])?.len())
        .map_err(|_| Error::ArithmeticOverflow("text index rebuild total"))?;
    let marker = TextIndexRebuildMarker {
        cursor: None,
        done: 0,
        total,
    };
    TEXT_INDEX_REBUILD.put(store, wtxn, &(), &marker.encode())
}

/// Ends any rebuild in `wtxn`. An owner's clear or rebuild of the text index
/// supersedes the background pass.
pub(crate) fn end_text_index_rebuild_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    TEXT_INDEX_REBUILD.delete(store, wtxn, &())?;
    Ok(())
}

/// What one run of the rebuild pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TextIndexRebuildRun {
    /// Documents indexed again.
    pub(crate) reindexed: u64,
    /// Source rows left unindexed: their entity is gone, or their text is
    /// past `MAX_INDEXED_TEXT_BYTES` (written before the ceiling; the write
    /// door refuses such text now).
    pub(crate) skipped: u64,
    /// No rebuild is left: the pass ended it, or none stood.
    pub(crate) complete: bool,
}

impl Vault {
    /// Read paths over the text index refuse to score while it is not
    /// trusted ([`Self::ensure_text_index_trusted`]) or while a rebuild
    /// stands: the documents not yet indexed again would be missing from the
    /// answer with no sign of it. The marker is read in `txn`, the read that
    /// scores: a rebuild another process's open started, or another
    /// process's pass ended, holds for this handle from its next read.
    pub(crate) fn ensure_text_index_searchable(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.ensure_text_index_trusted()?;
        if TEXT_INDEX_REBUILD.get(&self.store, txn, &())?.is_some() {
            return Err(Error::CorruptedIndex("text index rebuild in progress"));
        }
        Ok(())
    }

    /// Runs the rebuild pass from its cursor, one page per write
    /// transaction, until it ends or `stop` says so after a page. A page is
    /// `page` documents, or fewer once their stored source text reaches
    /// [`PAGE_SOURCE_BYTES`]. Each run does at least one page while a
    /// rebuild stands.
    pub(crate) fn run_text_index_rebuild(
        &self,
        page: usize,
        mut stop: impl FnMut() -> bool,
    ) -> Result<TextIndexRebuildRun> {
        let page = page.max(1);
        let mut run = TextIndexRebuildRun::default();
        loop {
            let mut wtxn = self.store.env.write_txn()?;
            let Some(mut marker) = read_text_index_rebuild(&self.store, &wtxn)? else {
                drop(wtxn);
                run.complete = true;
                return Ok(run);
            };
            let start = marker
                .cursor
                .as_ref()
                .map_or(Bound::Unbounded, Bound::Excluded);
            let mut rows = Vec::new();
            let mut page_bytes = 0_usize;
            let mut last_page = true;
            for row in INDEX_SOURCE_TEXT.iter_range(&self.store, &wtxn, start, Bound::Unbounded)? {
                if rows.len() >= page || page_bytes >= PAGE_SOURCE_BYTES {
                    last_page = false;
                    break;
                }
                let (id, fields) = row?;
                page_bytes = fields.iter().fold(page_bytes, |bytes, (_, text)| {
                    bytes.saturating_add(text.len())
                });
                rows.push((id, fields));
            }
            for (id, fields) in &rows {
                if !self.store.port_entity_present(&wtxn, id)? {
                    run.skipped = run.skipped.saturating_add(1);
                    continue;
                }
                match crate::bm25::index_text(&self.store, &mut wtxn, &self.analyzer, id, fields) {
                    Ok(()) => {
                        run.reindexed = run.reindexed.saturating_add(1);
                        marker.done = marker.done.saturating_add(1);
                    }
                    Err(Error::Store(StoreError::IndexedTextTooLarge { bytes, limit })) => {
                        tracing::warn!(
                            entity = %id.to_hex(),
                            bytes,
                            limit,
                            "text index rebuild left a document past the text ceiling out of search"
                        );
                        run.skipped = run.skipped.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
            if last_page {
                end_text_index_rebuild_in_txn(&self.store, &mut wtxn)?;
            } else {
                marker.cursor = rows.last().map(|(id, _)| *id);
                TEXT_INDEX_REBUILD.put(&self.store, &mut wtxn, &(), &marker.encode())?;
            }
            wtxn.commit()?;
            if last_page {
                run.complete = true;
                return Ok(run);
            }
            if stop() {
                return Ok(run);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trips_with_and_without_a_cursor() {
        let id = EntityId::from_bytes([7; 16]).expect("id");
        for marker in [
            TextIndexRebuildMarker {
                cursor: None,
                done: 0,
                total: 3,
            },
            TextIndexRebuildMarker {
                cursor: Some(id),
                done: 2,
                total: 3,
            },
        ] {
            let bytes = marker.encode();
            assert_eq!(bytes.len(), MARKER_LEN);
            assert_eq!(
                TextIndexRebuildMarker::decode(&bytes).expect("decode"),
                marker
            );
        }
        assert!(TextIndexRebuildMarker::decode(&[MARKER_VERSION]).is_err());
    }
}
