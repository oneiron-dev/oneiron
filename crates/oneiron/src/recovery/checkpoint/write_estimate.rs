//! The bound a restore's copy claims ahead for what it writes past its
//! bodies and rows (FIX 5613), worked out from the image before anything is
//! made, so a host's floor holds the room for the whole copy from the start
//! and no upload admitted meanwhile can take it.
//!
//! Each part is the image's own rows, or what the restore derives from them,
//! laid out as LMDB pages ([`PageLayout`]), never a guess at a compressed
//! size:
//! - the new environment: its two meta pages and each database's root;
//! - the page layout of every row the image lands, past the rows' bytes;
//! - the type and time index rows the first transaction stages for each
//!   entity, as `stage_entity_index_rows` writes them;
//! - the text index the rebuild makes from each text source the image
//!   carries, from the analyzer's own terms for it, and the phonetic index
//!   from each phonetic source;
//! - every other projection the reopen and the rebuilds derive (embedding
//!   marks and jobs, per-kind indexes, sidecars, revisions, the auxiliary
//!   rebuilds): each comes from rows the image carries and says no more than
//!   they do, so one generation of those rows bounds them
//!   ([`PROJECTION_GENERATIONS`]);
//! - the pages the later transactions copy as they rewrite: the rebuild
//!   stages every index row again and rewrites sources and sidecars among
//!   the side tables, and LMDB copies a page once per transaction, so one
//!   copy of the staged trees and of `vault_meta`;
//! - the restore epoch's row.
//!
//! The host's claim is set to what is left of the bound before each step,
//! less what the copy's file has grown by since its rows landed
//! (`write_budget`), so a step's own pages are never claimed twice.

use super::CheckpointImage;
use crate::analyzer::MultilingualAnalyzer;
use crate::batch::{EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS};
use crate::bm25::TextTree;
use crate::store::{DB_MANIFEST, PageLayout, TreeRows};
use crate::{VaultConfig, side_table};

/// How many generations of the image's rows bound the projections the
/// reopen and the rebuilds derive from them (CALLS RESTORE_DERIVED_ESTIMATE).
const PROJECTION_GENERATIONS: u64 = 1;
/// `Store::encode_type_key`: the entity type, then its id.
const TYPE_KEY: u64 = 1 + 16;
/// `Store::encode_temporal_key`: the stamp, then the id.
const TEMPORAL_KEY: u64 = 8 + 16;
/// A long interval's value: its start stamp.
const LONG_INTERVAL_VALUE: u64 = 8;
/// An entity id, as the text and phonetic indexes key a document.
const DOCUMENT_ID: u64 = 16;

/// What one restore's copy writes past its bodies and rows, each part a
/// bound in bytes.
#[derive(Debug, Default)]
pub(super) struct RestoreWriteEstimate {
    fresh: u64,
    landing: u64,
    staging: u64,
    text: u64,
    projections: u64,
    copies: u64,
    epoch: u64,
    /// What the opened payload rows write past their bytes (KS-7).
    payload: u64,
}

impl RestoreWriteEstimate {
    /// The bound for `image` restored under `config`, in pages of `layout`.
    /// Working it out never refuses a restore.
    pub(super) fn of(image: &CheckpointImage, config: &VaultConfig, layout: PageLayout) -> Self {
        let mut landed = 0_u64;
        let mut row_bytes = 0_u64;
        let mut vault_meta = 0_u64;
        for (name, rows) in &image.databases {
            let mut tree = TreeRows::default();
            for (key, value) in rows {
                let (key, value) = (key.len() as u64, value.len() as u64);
                layout.add(&mut tree, key, value);
                row_bytes = row_bytes.saturating_add(key).saturating_add(value);
            }
            let bytes = layout.bytes(&tree);
            landed = landed.saturating_add(bytes);
            if name.as_str() == "vault_meta" {
                vault_meta = bytes;
            }
        }
        let staged = staging(image, layout);
        Self {
            fresh: (DB_MANIFEST.len() as u64 + 2).saturating_mul(layout.page()),
            landing: landed.saturating_sub(row_bytes),
            staging: staged,
            text: text_indexes(image, config, layout),
            projections: landed.saturating_mul(PROJECTION_GENERATIONS),
            copies: staged.saturating_add(vault_meta),
            epoch: layout.page(),
            payload: 0,
        }
    }

    /// Adds the opened payload rows a restore lands besides the image's
    /// (KS-7), each its key and value lengths, counted as the image's own
    /// rows are: their pages past their bytes, one generation of what is
    /// derived from them, and one copy of their pages. None open while
    /// CHECKPOINT_PAYLOADS_ENABLED is off.
    #[allow(dead_code, reason = "KS7-5 lands the opened payload rows")]
    pub(super) fn with_payload(mut self, rows: &[(u64, u64)], layout: PageLayout) -> Self {
        let mut tree = TreeRows::default();
        for (key, value) in rows {
            layout.add(&mut tree, *key, *value);
        }
        let pages = layout.bytes(&tree);
        let bytes = rows.iter().map(|(key, value)| key.saturating_add(*value));
        self.payload = pages
            .saturating_sub(bytes.fold(0_u64, u64::saturating_add))
            .saturating_add(pages.saturating_mul(PROJECTION_GENERATIONS))
            .saturating_add(pages);
        self
    }

    /// The whole bound.
    pub(super) fn total(&self) -> u64 {
        [
            self.fresh,
            self.landing,
            self.staging,
            self.text,
            self.projections,
            self.copies,
            self.epoch,
            self.payload,
        ]
        .into_iter()
        .fold(0_u64, u64::saturating_add)
    }
}

/// The index rows the first transaction stages for each entity the image
/// carries, laid out by tree: its type key, its time keys, and a long
/// interval's row. A row with no header stages none; the restore refuses it.
fn staging(image: &CheckpointImage, layout: PageLayout) -> u64 {
    let mut kind = TreeRows::default();
    let mut started = TreeRows::default();
    let mut ended = TreeRows::default();
    let mut learned = TreeRows::default();
    let mut long = TreeRows::default();
    for (_, raw) in image.databases.get("entities").into_iter().flatten() {
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            continue;
        };
        layout.add(&mut kind, TYPE_KEY, 0);
        layout.add(&mut started, TEMPORAL_KEY, 0);
        layout.add(&mut learned, TEMPORAL_KEY, 0);
        if header.occurred_start != header.occurred_end {
            layout.add(&mut ended, TEMPORAL_KEY, 0);
        }
        if header.occurred_end.saturating_sub(header.occurred_start) > LONG_INTERVAL_THRESHOLD_SECS
        {
            layout.add(&mut long, TEMPORAL_KEY, LONG_INTERVAL_VALUE);
        }
    }
    [kind, started, ended, learned, long]
        .iter()
        .map(|tree| layout.bytes(tree))
        .fold(0_u64, u64::saturating_add)
}

/// The text and phonetic indexes the rebuild makes from the sources the
/// image carries, laid out by tree. Each text source is analyzed here as the
/// rebuild analyzes it, so its postings are the analyzer's own terms; one the
/// rebuild leaves out of search (past the text ceiling) or cannot read
/// writes none here either. With no analyzer the copy's open refuses before
/// any text lands, so none is counted.
fn text_indexes(image: &CheckpointImage, config: &VaultConfig, layout: PageLayout) -> u64 {
    let text_prefix = side_table::INDEX_SOURCE_TEXT.prefix;
    let phonetic_prefix = side_table::BATCH_PHONETIC_INDEX_SOURCE.prefix;
    let analyzer = MultilingualAnalyzer::discover(&config.dict_search_paths).ok();
    let mut trees = [TreeRows::default(); 6];
    for (key, value) in image.databases.get("vault_meta").into_iter().flatten() {
        if key.starts_with(text_prefix) {
            let Some(analyzer) = &analyzer else {
                continue;
            };
            let Ok(fields) = rmp_serde::from_slice::<Vec<(String, String)>>(value) else {
                continue;
            };
            let Ok(analyzed) = crate::bm25::analyze_text(analyzer, &fields) else {
                continue;
            };
            // A forward row its codec refuses fails the rebuild as well, so
            // what was counted of it stands.
            let _ = analyzed.index_rows(|tree, row_key, row_value| {
                let slot = match tree {
                    TextTree::Postings => 0,
                    TextTree::Forward => 1,
                    TextTree::FieldLengths => 2,
                    TextTree::Meta => 3,
                };
                layout.add(&mut trees[slot], row_key, row_value);
            });
        } else if key.starts_with(phonetic_prefix) {
            let Ok(codes) = rmp_serde::from_slice::<Vec<String>>(value) else {
                continue;
            };
            // Each code's posting holds the document's id; its forward row
            // lists every code.
            let mut forward = 0_u64;
            for code in &codes {
                let code = code.len() as u64;
                layout.add(&mut trees[4], code, DOCUMENT_ID);
                forward = forward.saturating_add(code.saturating_add(4));
            }
            layout.add(&mut trees[5], DOCUMENT_ID, forward);
        }
    }
    // The corpus stats, a row per scored field and the document count, fit
    // one page.
    trees
        .iter()
        .map(|tree| layout.bytes(tree))
        .fold(layout.page(), u64::saturating_add)
}
