//! Core half of `store::text_index`: its store-layer items live in `oneiron_store::text_index` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::text_index::*;

pub(crate) use crate::config::bm25::{Bm25Config, FieldLengthPolicy};
pub(crate) use codec::read_total_docs;
pub(crate) use diagnostics::{Bm25Diagnostics, Bm25DiagnosticsSnapshot};
pub(crate) use index::{
    AnalyzedText, analyze_text, check_indexed_text_bytes, deindex_text, index_analyzed_text,
    index_text,
};

pub(crate) mod codec;
pub(crate) mod index;
