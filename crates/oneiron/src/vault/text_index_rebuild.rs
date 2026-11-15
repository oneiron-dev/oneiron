//! The text-index rebuild an analyzer change starts at open (FIX
//! ANALYZER-BUMP-AUTO-REINDEX).
//!
//! An `ANALYZER_VERSION` bump or a `NormalizationPolicy` flag changes the
//! analyzer manifest hash, and a BM25F field change changes the field-schema
//! hash. Postings written under the old hashes cannot be scored under the new
//! analyzer. `Vault::open` refused such a vault until its host ran the manual
//! recovery. Now the writable open clears the text index, rewrites the
//! manifest, lists every document with stored text in
//! [`TEXT_INDEX_REBUILD_ORDER`] and writes [`TEXT_INDEX_REBUILD`] in one
//! transaction, so text writes go on at once under the new analyzer. The
//! housekeeping sweep `TextIndexRebuild` then indexes every listed document
//! again from the text it was indexed with (`INDEX_SOURCE_TEXT`), one page per
//! write transaction: a page's postings, the deletion of its list rows and the
//! marker's count commit together, and the last page deletes the marker.
//!
//! The list runs by the time each document's content last changed
//! (`ENTITY_REVISION_STATE.changed_at_ms`), and the pass takes it newest
//! first, so the documents most recently written are searchable first (the
//! lead, 16 Nov 06:35). The engine stores no per-document read signal to
//! order by: a retrieval run records the documents it returned, but capture
//! is opt-in and its rows are pruned, so they are not used. A document with
//! no revision state goes last.
//!
//! A crash between pages resumes with the rows still listed on the next
//! open's first pass; a crash inside a page rolls that page back. Indexing a
//! document is idempotent (`write_index` drops a document's old rows first),
//! so a document a foreground write indexed after the clear ends the same
//! when the pass reaches it, and a document deleted meanwhile has no source
//! row left for the pass to index. A source row past the per-document text
//! ceiling, written before the ceiling, stays unindexed, as the checkpoint
//! restore and the leave's reindex leave it.
//!
//! While the marker stands, text reads answer from the documents indexed
//! again so far (ruling ANALYZER-REINDEX-SEARCH-DURING-REBUILD = B, the lead
//! 16 Nov 06:3x): no posting written under the old analyzer survives the
//! clear, so no hit is scored under a mixed analyzer. A recall run marks its
//! text arm `RetrievalDegradation::Bm25Stale`, and
//! [`Vault::text_index_status`] and the doctor report carry the progress. The
//! org compliance search alone stays closed until the pass ends
//! ([`Vault::ensure_text_index_complete`]).

use std::ops::Bound;
use std::sync::atomic::Ordering;

use super::Vault;
use super::doctor_manifest::TextIndexRebuildProgress;
use super::entity_revision::content_changed_at_ms_in_txn;
use crate::analyzer::MultilingualAnalyzer;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::ports::{EntityStoreRead, IndexRows, RetrievalIndexInventory};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// The rebuild in flight. Key: `()`.
const TEXT_INDEX_REBUILD: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::TEXT_INDEX_REBUILD);
/// The documents the rebuild has yet to index again. Key: (the document's
/// last content change in ms, id16); the pass takes the highest keys first.
const TEXT_INDEX_REBUILD_ORDER: SideTable<(u64, EntityId), (), Raw> =
    SideTable::new(&side_table::TEXT_INDEX_REBUILD_ORDER);
/// The text each document was indexed with. Key: id16.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// Version 2 orders the pass by [`TEXT_INDEX_REBUILD_ORDER`].
const MARKER_VERSION: u8 = 2;
/// Version, done and total (u64 LE each).
const MARKER_LEN: usize = 1 + 8 + 8;
/// The version-1 marker an engine before the ordered pass left: version,
/// cursor flag, cursor id16 (its pass walked ids in order), done and total.
const MARKER_V1_LEN: usize = 1 + 1 + 16 + 8 + 8;

/// A text-index rebuild in flight, as [`TEXT_INDEX_REBUILD`] stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TextIndexRebuildMarker {
    /// Documents indexed again so far.
    pub(crate) done: u64,
    /// Documents with stored source text when the rebuild started: a
    /// start-time count, so a document deleted during the rebuild leaves the
    /// final `done` below it.
    pub(crate) total: u64,
    /// A version-1 marker, whose rebuild has no list yet: the pass lists
    /// every document with stored text before its next page.
    unlisted: bool,
}

impl TextIndexRebuildMarker {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MARKER_LEN);
        out.push(MARKER_VERSION);
        out.extend_from_slice(&self.done.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupt = || Error::CorruptedIndex("text index rebuild marker undecodable");
        let count = |at: usize| -> Result<u64> {
            let slice = bytes.get(at..at + 8).ok_or_else(corrupt)?;
            Ok(u64::from_le_bytes(slice.try_into().map_err(|_| corrupt())?))
        };
        match (bytes.first(), bytes.len()) {
            (Some(&MARKER_VERSION), MARKER_LEN) => Ok(Self {
                done: count(1)?,
                total: count(9)?,
                unlisted: false,
            }),
            (Some(&1), MARKER_V1_LEN) => Ok(Self {
                done: count(18)?,
                total: count(26)?,
                unlisted: true,
            }),
            _ => Err(corrupt()),
        }
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

/// Whether a rebuild stands in `txn`'s snapshot, whatever its marker holds.
pub(crate) fn text_index_rebuild_stands(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    TEXT_INDEX_REBUILD.contains(store, txn, &())
}

/// The rebuild in flight as the status and the doctor report show it.
pub(crate) fn read_text_index_rebuild_progress(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<TextIndexRebuildProgress>> {
    Ok(
        read_text_index_rebuild(store, txn)?.map(|marker| TextIndexRebuildProgress {
            done: marker.done,
            total: marker.total,
        }),
    )
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

/// Lists every document with stored source text in
/// [`TEXT_INDEX_REBUILD_ORDER`] under its last content change, after
/// dropping any list left before; returns how many it listed.
fn list_text_index_rebuild_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    clear_text_index_rebuild_list_in_txn(store, wtxn)?;
    let ids = INDEX_SOURCE_TEXT.scan_keys(store, &*wtxn, &[])?;
    for id in &ids {
        let changed_at_ms = content_changed_at_ms_in_txn(store, &*wtxn, id)?.unwrap_or(0);
        TEXT_INDEX_REBUILD_ORDER.put(store, wtxn, &(changed_at_ms, *id), &())?;
    }
    u64::try_from(ids.len()).map_err(|_| Error::ArithmeticOverflow("text index rebuild total"))
}

fn clear_text_index_rebuild_list_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    for key in TEXT_INDEX_REBUILD_ORDER.scan_keys(store, &*wtxn, &[])? {
        TEXT_INDEX_REBUILD_ORDER.delete(store, wtxn, &key)?;
    }
    Ok(())
}

/// Starts a rebuild in `wtxn`: clears the text index, rewrites its manifest,
/// lists every document to index again and writes the marker at the start.
/// Called by the writable open on a stale manifest; a rebuild already in
/// flight starts over.
pub(super) fn start_text_index_rebuild_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    clear_text_index_rows_in_txn(store, wtxn, analyzer)?;
    let total = list_text_index_rebuild_in_txn(store, wtxn)?;
    let marker = TextIndexRebuildMarker {
        done: 0,
        total,
        unlisted: false,
    };
    TEXT_INDEX_REBUILD.put(store, wtxn, &(), &marker.encode())
}

/// Ends any rebuild in `wtxn`, its list with it. An owner's clear or rebuild
/// of the text index supersedes the background pass.
pub(crate) fn end_text_index_rebuild_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    clear_text_index_rebuild_list_in_txn(store, wtxn)?;
    TEXT_INDEX_REBUILD.delete(store, wtxn, &())?;
    Ok(())
}

/// What one run of the rebuild pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TextIndexRebuildRun {
    /// Documents indexed again.
    pub(crate) reindexed: u64,
    /// Listed documents left unindexed: their entity or its stored text is
    /// gone, or their text is past `MAX_INDEXED_TEXT_BYTES` (written before
    /// the ceiling; the write door refuses such text now).
    pub(crate) skipped: u64,
    /// No rebuild is left: the pass ended it, or none stood.
    pub(crate) complete: bool,
}

impl Vault {
    /// Whether a text-index rebuild stands on this handle: text reads then
    /// answer from the documents indexed again so far.
    pub(crate) fn text_index_rebuild_in_progress(&self) -> bool {
        self.text_index_rebuilding.load(Ordering::Acquire)
    }

    /// A read whose answer is a record of every match, the org compliance
    /// search (ruling ANALYZER-REINDEX-COMPLIANCE-SEARCH = A, 16 Nov 07:19),
    /// refuses while the text index is not trusted
    /// ([`Self::ensure_text_index_trusted`]) or while a rebuild stands in
    /// `txn`'s snapshot: the documents not yet indexed again would be missing
    /// from its count. The refusal says how far the rebuild is, so the caller
    /// knows when to retry.
    pub(crate) fn ensure_text_index_complete(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::memory::MemoryResult<()> {
        self.ensure_text_index_trusted()?;
        match read_text_index_rebuild_progress(&self.store, txn)? {
            None => Ok(()),
            Some(TextIndexRebuildProgress { done, total }) => Err(crate::memory::MemoryError::new(
                crate::memory::MEMORY_CODE_INVALID_STATE,
                format!(
                    "text index rebuild in progress after an analyzer change: rebuilding, {done} of \
                     {total} documents indexed again; this search answers only from a complete index"
                ),
                &[
                    "Retry when the rebuild ends: the vault doctor report then shows no text_index_rebuild.",
                ],
            )),
        }
    }

    /// Runs the rebuild pass, `page` listed documents per write transaction,
    /// newest content change first, until it ends or `stop` says so after a
    /// page. Each run does at least one page while a rebuild stands. Sets
    /// this handle's rebuild flag from the marker it reads.
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
                self.text_index_rebuilding.store(false, Ordering::Release);
                run.complete = true;
                return Ok(run);
            };
            self.text_index_rebuilding.store(true, Ordering::Release);
            if marker.unlisted {
                marker = TextIndexRebuildMarker {
                    done: 0,
                    total: list_text_index_rebuild_in_txn(&self.store, &mut wtxn)?,
                    unlisted: false,
                };
            }
            let listed = TEXT_INDEX_REBUILD_ORDER
                .iter_rev_range(&self.store, &wtxn, Bound::Unbounded, Bound::Unbounded)?
                .take(page)
                .map(|row| row.map(|(key, ())| key))
                .collect::<Result<Vec<_>>>()?;
            let last_page = listed.len() < page;
            for key in &listed {
                TEXT_INDEX_REBUILD_ORDER.delete(&self.store, &mut wtxn, key)?;
                let (_, id) = key;
                let fields = match INDEX_SOURCE_TEXT.get(&self.store, &wtxn, id)? {
                    Some(fields) if self.store.port_entity_present(&wtxn, id)? => fields,
                    _ => {
                        run.skipped = run.skipped.saturating_add(1);
                        continue;
                    }
                };
                match crate::bm25::index_text(&self.store, &mut wtxn, &self.analyzer, id, &fields) {
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
                TEXT_INDEX_REBUILD.put(&self.store, &mut wtxn, &(), &marker.encode())?;
            }
            wtxn.commit()?;
            if last_page {
                self.text_index_rebuilding.store(false, Ordering::Release);
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
    fn marker_round_trips() {
        for marker in [
            TextIndexRebuildMarker {
                done: 0,
                total: 3,
                unlisted: false,
            },
            TextIndexRebuildMarker {
                done: 2,
                total: 3,
                unlisted: false,
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
        assert!(TextIndexRebuildMarker::decode(&[]).is_err());
    }

    #[test]
    fn a_version_1_marker_reads_as_unlisted_with_its_counts() {
        let mut v1 = vec![1, 1];
        v1.extend_from_slice(&[7; 16]);
        v1.extend_from_slice(&2_u64.to_le_bytes());
        v1.extend_from_slice(&5_u64.to_le_bytes());
        assert_eq!(
            TextIndexRebuildMarker::decode(&v1).expect("a version-1 marker decodes"),
            TextIndexRebuildMarker {
                done: 2,
                total: 5,
                unlisted: true,
            }
        );
        v1.pop();
        assert!(TextIndexRebuildMarker::decode(&v1).is_err());
    }
}
