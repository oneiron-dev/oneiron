//! Analyzer-driven fielded inverted index + BM25F scorer.
//!
//! Indexing and scoring go through [`MultilingualAnalyzer`]. Each emitted
//! [`Token`] lands on exactly one channel (`Surface`, `Stem`,
//! `NormalizedOverlay`, `CjkNgram`); each channel is an independent BM25F
//! field with its own weight, `b`, and length-normalization policy (plan
//! §1.3). Posting lists are still document-granular — `df(t)` counts
//! logical docs in the posting, not per-field occurrences — but each
//! entry carries a small per-field TF map so the scorer can combine
//! channels into a single `x_t,d` per the BM25F formula.
//!
//! Storage (plan §4.1, storage ABI v4 / ONE-299):
//! * `text_postings` is a `DUP_SORT` database. Key: term bytes. Each
//!   duplicate data item is ONE posting entry: `entity_id(16) |
//!   field_count(u8) | (field_id_u16_be | tf_u32_le)*`. LMDB keeps the
//!   duplicate items bytewise sorted, so entries order by entity-id
//!   prefix; indexing appends a dup without reading the existing list
//!   (O(1) per term instead of read-modify-rewrite O(list)), deindexing
//!   deletes exactly one dup, and `df(term)` = the dup count.
//! * `text_forward` value: `[(term_len_u16_le | term_bytes |
//!   field_id_u16_be)*]` — the dead `tf` u32 was dropped in ABI v4;
//!   deindex only needs the (term, field) set.
//! * `text_meta` value: `[doc_len_u32_le | field_count_u32_le]` where
//!   `doc_len` is the sum of [`Token::length_increment`] across all emitted
//!   tokens (for debug / status output; scoring uses the per-field lengths)
//! * `text_bm25_field_stats` value: `[doc_count_u32_le | total_length_u64_le]`
//! * `text_doc_field_lengths` value: `[(field_id_u16_be | length_u32_le)*]`
//!
//! Rank profile weights (`Bm25Config`) are scoring-only and live separate
//! from the index — changing them does not require a reindex.

mod codec;
mod config;
mod diagnostics;
mod index;
mod query;
mod scoped;
mod scoring;

pub(crate) use self::codec::read_total_docs;
use self::codec::{
    corrupted, corrupted_with_diagnostic, decode_field_lengths, decode_posting_entry,
};
pub use self::config::Bm25Formula;
pub(crate) use self::config::{Bm25Config, Bm25RecencyConfig, FieldLengthPolicy};
pub use self::diagnostics::{
    Bm25DiagnosticCounter, Bm25DiagnosticKind, Bm25DiagnosticsSnapshot, bm25_diagnostics_snapshot,
};
pub(crate) use self::index::{deindex_text, index_text};
pub(crate) use self::query::{
    Bm25SearchOptions, PrefixExpansionPostingDecision, final_token_exact_posting_matches,
    final_token_prefix_expansion_has_scoped_and_rejected_postings, search_text,
    search_text_scoped_with_recency,
};
use self::query::{
    QueryTerm, apply_recency_blend, collapse_lexical_query_hint_scores, collect_query_terms,
    compute_avgdl, lexical_query_hint_scope_id,
};
use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::ScoredEntity;
use crate::store::ManifestDbs;
use heed::RoTxn;
pub(crate) use scoped::search_text_filtered_with_recency;
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::codec::{
    PostingLookup, decode_forward, encode_field_lengths, encode_forward, encode_posting_entry,
    find_posting_dup, read_field_stats, write_field_stats, write_total_docs,
};
#[cfg(test)]
pub(crate) use self::config::{BM25_FIELD_COUNT, FieldConfig};
#[cfg(test)]
use self::diagnostics::BM25_DIAGNOSTIC_COUNTERS;
#[cfg(test)]
pub(crate) use self::query::search_text_with_recency;
#[cfg(test)]
use self::query::{
    MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS, MAX_FINAL_TOKEN_PREFIX_TERMS,
    collect_final_token_prefix_terms,
};
#[cfg(test)]
use crate::analyzer::{Token, TokenKind};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::atomic::Ordering as AtomicOrdering;

// === Layout constants ===

const ENTITY_ID_LEN: usize = 16;

/// Sum of `field_id_u16_be + tf_u32_le`.
const FIELD_TF_LEN: usize = 6;

/// `doc_count_u32_le + total_length_u64_le`.
const FIELD_STATS_LEN: usize = 12;

/// `field_id_u16_be + length_u32_le`.
const FIELD_LENGTH_LEN: usize = 6;

const DOC_META_LEN: usize = 8;

const TOTAL_DOCS_KEY: [u8; 16] = [0x00; 16];

/// Deprecated total-length sentinel kept as a reserved key so fresh vaults
/// never collide with a legacy entry. Per-field lengths live in
/// `text_bm25_field_stats` (plan §4.1).
const TOTAL_LENGTH_KEY: [u8; 16] = [0xFF; 16];

/// Version of the binary value layout used in `text_postings`.
/// * v1 = concatenated multi-entry blob per term (pre-ONE-299).
/// * v2 = ONE-299 / storage ABI v4: `DUP_SORT` single-entry duplicate
///   items per (term, entity); `text_forward` records carry no `tf`.
pub(crate) const POSTINGS_VALUE_FORMAT_VERSION: u16 = 2;

/// Byte width of the `field_id_u16_be` trailer of a forward record.
const FORWARD_FIELD_ID_LEN: usize = 2;

const BM25_DIAGNOSTIC_COUNTER_COUNT: usize = 4;
