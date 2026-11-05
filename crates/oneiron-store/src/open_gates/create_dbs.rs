//! Create-door database phase: open the manifest databases and gate versions.

use std::sync::MutexGuard;

use heed::types::{Bytes, Str};
use heed::{Database, RwTxn};

use crate::overlay_db::OverlayDb;
use oneiron_base::error::Result;

pub struct CreatedDbs {
    pub entities: Database<Bytes, Bytes>,
    pub edges_out: Database<Bytes, Bytes>,
    pub edges_in: Database<Bytes, Bytes>,
    pub vectors: Database<Bytes, Bytes>,
    pub hnsw_neighbors: Database<Bytes, Bytes>,
    pub hnsw_meta: Database<Bytes, Bytes>,
    pub text_postings: Database<Bytes, Bytes>,
    pub text_meta: Database<Bytes, Bytes>,
    pub text_forward: Database<Bytes, Bytes>,
    pub text_bm25_field_stats: Database<Bytes, Bytes>,
    pub text_doc_field_lengths: Database<Bytes, Bytes>,
    pub vault_meta: Database<Bytes, Bytes>,
    pub ppr_cache: Database<Bytes, Bytes>,
    pub ppr_cache_deps: Database<Bytes, Bytes>,
    pub type_index: Database<Bytes, Bytes>,
    pub temporal_occurred_start: Database<Bytes, Bytes>,
    pub temporal_occurred_end: Database<Bytes, Bytes>,
    pub temporal_learned: Database<Bytes, Bytes>,
    pub temporal_long_intervals: Database<Bytes, Bytes>,
    pub phonetic_index: Database<Bytes, Bytes>,
    pub phonetic_forward: Database<Bytes, Bytes>,
    pub short_ids: Database<Bytes, Bytes>,
    pub short_ids_reverse: Database<Bytes, Bytes>,
    pub sync_state: Database<Str, Bytes>,
    pub sync_queue: Database<Bytes, Bytes>,
    pub attempt_records: Database<Bytes, Bytes>,
    pub attempt_ready: Database<Bytes, Bytes>,
    pub attempt_dedupe: Database<Bytes, Bytes>,
}
