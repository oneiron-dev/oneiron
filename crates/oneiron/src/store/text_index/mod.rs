//! Persisted text-index rows, codecs, analysis and integrity diagnostics.

pub(crate) mod codec;
pub(crate) mod diagnostics;
pub(crate) mod index;
pub(crate) use crate::config::bm25::{Bm25Config, FieldLengthPolicy};
pub(crate) use codec::read_total_docs;
pub(crate) use diagnostics::{Bm25Diagnostics, Bm25DiagnosticsSnapshot};
pub(crate) use index::{
    AnalyzedText, analyze_text, check_indexed_text_bytes, deindex_text, index_analyzed_text,
    index_text,
};

// === Layout constants ===

pub(crate) const ENTITY_ID_LEN: usize = 16;

/// Sum of `field_id_u16_be + tf_u32_le`.
pub(crate) const FIELD_TF_LEN: usize = 6;

/// `doc_count_u32_le + total_length_u64_le`.
pub(crate) const FIELD_STATS_LEN: usize = 12;

/// `field_id_u16_be + length_u32_le`.
pub(crate) const FIELD_LENGTH_LEN: usize = 6;

pub(crate) const DOC_META_LEN: usize = 8;

pub(crate) const TOTAL_DOCS_KEY: [u8; 16] = [0x00; 16];

/// Deprecated total-length sentinel kept as a reserved key so fresh vaults
/// never collide with a legacy entry. Per-field lengths live in
/// `text_bm25_field_stats` (plan §4.1).
pub(crate) const TOTAL_LENGTH_KEY: [u8; 16] = [0xFF; 16];

/// Version of the binary value layout used in `text_postings`.
/// * v1 = concatenated multi-entry blob per term (pre-ONE-299).
/// * v2 = ONE-299 / storage ABI v4: `DUP_SORT` single-entry duplicate
///   items per (term, entity); `text_forward` records carry no `tf`.
pub(crate) const POSTINGS_VALUE_FORMAT_VERSION: u16 = 2;

/// Byte width of the `term_len_u64_le` head of a forward record.
pub(crate) const FORWARD_TERM_LEN_LEN: usize = 8;

/// Byte width of the `field_id_u16_be` trailer of a forward record.
pub(crate) const FORWARD_FIELD_ID_LEN: usize = 2;

pub(crate) const BM25_DIAGNOSTIC_COUNTER_COUNT: usize = 4;
