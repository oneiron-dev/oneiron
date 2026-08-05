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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use heed::{RoTxn, RwTxn};

use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer, Token, TokenKind};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::registry::short_id_prefix;
use crate::store::{ManifestDbs, Store};

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

static BM25_DIAGNOSTIC_COUNTERS: [AtomicU64; BM25_DIAGNOSTIC_COUNTER_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Content-free BM25 integrity diagnostic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm25DiagnosticKind {
    MalformedPostingAlignment,
    MissingScoredDocumentMetadata,
    DeindexSelfHealedMissingPostingRow,
    DeindexSelfHealedMissingPostingEntity,
}

impl Bm25DiagnosticKind {
    /// Stable, privacy-preserving label for metrics and diagnostic surfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedPostingAlignment => "malformed_posting_alignment",
            Self::MissingScoredDocumentMetadata => "missing_scored_document_metadata",
            Self::DeindexSelfHealedMissingPostingRow => "deindex_self_healed_missing_posting_row",
            Self::DeindexSelfHealedMissingPostingEntity => {
                "deindex_self_healed_missing_posting_entity"
            }
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::MalformedPostingAlignment => 0,
            Self::MissingScoredDocumentMetadata => 1,
            Self::DeindexSelfHealedMissingPostingRow => 2,
            Self::DeindexSelfHealedMissingPostingEntity => 3,
        }
    }

    const fn metric_values() -> [Self; BM25_DIAGNOSTIC_COUNTER_COUNT] {
        [
            Self::MalformedPostingAlignment,
            Self::MissingScoredDocumentMetadata,
            Self::DeindexSelfHealedMissingPostingRow,
            Self::DeindexSelfHealedMissingPostingEntity,
        ]
    }
}

/// Count for one BM25 integrity diagnostic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm25DiagnosticCounter {
    pub kind: Bm25DiagnosticKind,
    pub count: u64,
}

/// Process-local BM25 integrity diagnostics with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm25DiagnosticsSnapshot {
    pub counters: [Bm25DiagnosticCounter; BM25_DIAGNOSTIC_COUNTER_COUNT],
}

impl Bm25DiagnosticsSnapshot {
    #[must_use]
    pub fn count(&self, kind: Bm25DiagnosticKind) -> u64 {
        self.counters[kind.metric_index()].count
    }
}

/// Returns process-local BM25 integrity diagnostic counters.
#[must_use]
pub fn bm25_diagnostics_snapshot() -> Bm25DiagnosticsSnapshot {
    Bm25DiagnosticsSnapshot {
        counters: Bm25DiagnosticKind::metric_values().map(|kind| Bm25DiagnosticCounter {
            kind,
            count: BM25_DIAGNOSTIC_COUNTERS[kind.metric_index()].load(AtomicOrdering::Relaxed),
        }),
    }
}

fn record_bm25_diagnostic(kind: Bm25DiagnosticKind) {
    BM25_DIAGNOSTIC_COUNTERS[kind.metric_index()].fetch_add(1, AtomicOrdering::Relaxed);
}

fn prove_bm25_doc_counted_for_missing_posting_repair(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    expected_lengths: &HashMap<u16, u32>,
) -> Result<()> {
    let mut saw_doc = false;
    let mut recomputed_total_docs = 0_u32;
    let mut recomputed_field_stats: BTreeMap<u16, (u32, u64)> = BTreeMap::new();

    for row in store.text_doc_field_lengths().iter(txn)? {
        let (raw_id, raw_lengths) = row?;
        if raw_id.len() != ENTITY_ID_LEN {
            return Err(corrupted("field lengths key has invalid byte length"));
        }
        let lengths = decode_field_lengths(&raw_lengths)?;
        if raw_id.as_ref() == id.as_bytes() {
            if &lengths != expected_lengths {
                return Err(corrupted(
                    "field lengths changed during missing posting repair",
                ));
            }
            saw_doc = true;
        }

        recomputed_total_docs = recomputed_total_docs
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("bm25 total_docs recompute"))?;
        for (&fid, &len) in &lengths {
            let (doc_count, total_length) = recomputed_field_stats.entry(fid).or_default();
            *doc_count = doc_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("bm25 field doc_count recompute"))?;
            *total_length =
                total_length
                    .checked_add(u64::from(len))
                    .ok_or(Error::ArithmeticOverflow(
                        "bm25 field total_length recompute",
                    ))?;
        }
    }

    if !saw_doc {
        return Err(corrupted(
            "missing field lengths for missing posting repair",
        ));
    }
    if read_total_docs(store, txn)? != recomputed_total_docs {
        return Err(corrupted(
            "missing posting repair cannot prove document is counted in total_docs",
        ));
    }

    for (&fid, &expected) in &recomputed_field_stats {
        if read_field_stats(store, txn, fid)? != expected {
            return Err(corrupted(
                "missing posting repair cannot prove document is counted in field stats",
            ));
        }
    }
    for row in store.text_bm25_field_stats().iter(txn)? {
        let (raw_fid, raw_stats) = row?;
        if raw_fid.len() != 2 {
            return Err(corrupted("field stats key has invalid byte length"));
        }
        if raw_stats.len() != FIELD_STATS_LEN {
            return Err(corrupted("field stats has invalid byte length"));
        }
        let fid = u16::from_be_bytes([raw_fid[0], raw_fid[1]]);
        if !recomputed_field_stats.contains_key(&fid) {
            return Err(corrupted("field stats row has no matching doc lengths"));
        }
    }

    Ok(())
}

// === Rank profile configuration ===

/// Per-channel length normalization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldLengthPolicy {
    /// Denominator uses `(1 - b) + b * len_f / avgdl_f`, i.e. classical
    /// BM25 length norm.
    CountLengthIncrement,
    /// No length norm — denominator is `1.0`. Useful for overlay channels
    /// whose token counts are mechanical (diacritic folds, kana folds)
    /// and should not drag long docs down.
    NoNorm,
}

impl FieldLengthPolicy {
    pub(crate) fn manifest_tag(self) -> &'static str {
        match self {
            FieldLengthPolicy::CountLengthIncrement => "count_length_increment",
            FieldLengthPolicy::NoNorm => "no_norm",
        }
    }
}

/// Per-field (channel) BM25F parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FieldConfig {
    pub weight: f64,
    pub b: f64,
    pub length_policy: FieldLengthPolicy,
}

impl FieldConfig {
    const fn disabled() -> Self {
        Self {
            weight: 0.0,
            b: 0.0,
            length_policy: FieldLengthPolicy::NoNorm,
        }
    }
}

/// BM25 scoring variant (ARCH-0031 / ARCH-0019 D3).
///
/// `Okapi` is the contract default. `Plus` is the BM25+ lower-bound
/// variant per Lv & Zhai 2011: it adds `idf · delta` to every matching
/// term's contribution (the contract opt-in value is `delta: 1.0`).
/// The formula is scoring-only — switching it never requires a reindex.
/// `delta` must be finite and strictly positive; it is validated
/// fail-closed when a [`crate::Bm25RankProfile`] is used and rejected
/// with [`crate::Error::InvalidRankProfile`] otherwise.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Bm25Formula {
    /// Classical Okapi BM25 saturation (contract default).
    Okapi,
    /// BM25+ with a constant per-term lower bound (Lv & Zhai 2011).
    Plus {
        /// Constant added to the saturated TF term, scaled by `idf`.
        /// Must be finite and `> 0.0`; the contract opt-in is `1.0`.
        delta: f64,
    },
}

/// Global BM25F configuration. `fields` is indexed by channel — only
/// channels with non-zero weight contribute to scoring. Rank profile is a
/// scoring-only parameter (plan §4.2) — changing it does **not** require
/// a reindex, so this config lives outside the on-disk manifest.
#[derive(Debug, Clone)]
pub(crate) struct Bm25Config {
    pub(crate) k1: f64,
    pub(crate) formula: Bm25Formula,
    /// Per-channel config, indexed by [`AnalyzerChannel::field_id`]. The
    /// array has one slot per reserved channel, so adding a new channel
    /// in [`AnalyzerChannel`] requires extending this.
    pub(crate) fields: [FieldConfig; BM25_FIELD_COUNT],
}

/// Query-time recency blend for BM25F keyword ranking.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Bm25RecencyConfig {
    pub(crate) half_life_days: f64,
    pub(crate) boost: f64,
    pub(crate) now_secs: u64,
}

impl Bm25RecencyConfig {
    fn is_enabled(self) -> bool {
        self.half_life_days.is_finite()
            && self.half_life_days > 0.0
            && self.boost.is_finite()
            && self.boost > 0.0
    }
}

#[derive(Debug, Clone, PartialEq)]
struct QueryTerm {
    term: String,
    weight: f64,
}

pub(crate) struct Bm25SearchOptions<'a, F>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    pub(crate) recency: Option<Bm25RecencyConfig>,
    pub(crate) exact_posting_matches_scope: &'a mut F,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PrefixExpansionPostingDecision {
    pub(crate) matches_scope: bool,
    pub(crate) rejected_by_gate: bool,
}

const FINAL_TOKEN_PREFIX_WEIGHT: f64 = 0.5;
const MAX_FINAL_TOKEN_PREFIX_TERMS: usize = 64;
/// Bound term-key reads for any one prefix after the scoped expansion cap.
///
/// Out-of-scope completions do not consume the 64-term expansion budget, but
/// broad prefixes still need a hard cursor-walk ceiling.
const MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS: usize = MAX_FINAL_TOKEN_PREFIX_TERMS * 64;

/// One slot per reserved [`AnalyzerChannel`]. A new channel whose
/// `field_id()` falls outside `0..BM25_FIELD_COUNT` would silently
/// out-of-bounds index `Bm25Config::fields`; the const block below ties
/// this constant to the highest-id channel so adding a variant without
/// growing the array breaks the build.
pub(crate) const BM25_FIELD_COUNT: usize = AnalyzerChannel::ALL_RESERVED.len();

const _: () = {
    // The reserved-channel set is `Surface, Stem, NormalizedOverlay,
    // CjkNgram, Shingle, Synonym, Phonetic`. `Phonetic` carries the
    // highest `field_id` (6), so this assert fires whenever a future
    // variant pushes the highest id past `BM25_FIELD_COUNT - 1`.
    assert!(
        AnalyzerChannel::Phonetic.field_id() as usize == BM25_FIELD_COUNT - 1,
        "Bm25Config::fields must grow when AnalyzerChannel gains a higher-id variant"
    );
};

impl Bm25Config {
    pub(crate) fn field(&self, channel: AnalyzerChannel) -> FieldConfig {
        self.fields[channel.field_id() as usize]
    }
}

impl Default for Bm25Config {
    fn default() -> Self {
        // Plan §1.3 default rank profile. Weights and `b` are research-band
        // starting values; ONE-318 bench tuning will replace them with
        // empirically-derived numbers.
        let mut fields = [FieldConfig::disabled(); BM25_FIELD_COUNT];
        fields[AnalyzerChannel::Surface.field_id() as usize] = FieldConfig {
            weight: 1.00,
            b: 0.75,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        fields[AnalyzerChannel::Stem.field_id() as usize] = FieldConfig {
            weight: 0.35,
            b: 0.65,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        fields[AnalyzerChannel::NormalizedOverlay.field_id() as usize] = FieldConfig {
            weight: 0.55,
            b: 0.00,
            length_policy: FieldLengthPolicy::NoNorm,
        };
        fields[AnalyzerChannel::CjkNgram.field_id() as usize] = FieldConfig {
            weight: 0.45,
            b: 0.30,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        // Shingle / Synonym / Phonetic remain disabled; v1 analyzers do
        // not emit on these channels but the storage round-trips them.
        Self {
            k1: 1.2,
            formula: Bm25Formula::Okapi,
            fields,
        }
    }
}

// === Indexing ===

pub(crate) fn index_text(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    id: &EntityId,
    fields: &[(String, String)],
) -> Result<()> {
    validate_text_doc_id(id)?;

    match store.text_forward().get(wtxn, id.as_bytes())? {
        Some(_) => deindex_text(store, wtxn, id)?,
        None if store.text_meta().get(wtxn, id.as_bytes())?.is_some() => {
            return Err(corrupted("missing forward index for indexed document"));
        }
        None => {}
    }

    let mut tokens: Vec<Token> = Vec::new();
    let ctx = AnalyzerContext::for_index();
    for (_, value) in fields {
        analyzer.analyze(value, &ctx, &mut tokens);
    }

    if tokens.is_empty() {
        return Ok(());
    }

    // Aggregate tokens by (channel, term) → tf, and by channel → length.
    // Terms within the same channel collide on identical folded text, so
    // tf = count of matching tokens regardless of offset.
    let mut per_field: HashMap<u16, HashMap<String, u32>> = HashMap::new();
    let mut per_field_len: HashMap<u16, u32> = HashMap::new();
    let mut doc_len_total: u32 = 0;

    for tok in &tokens {
        let fid = tok.channel.field_id();
        let entry = per_field.entry(fid).or_default();
        *entry.entry(tok.term.as_ref().to_owned()).or_insert(0) += 1;
        let inc = u32::from(tok.length_increment);
        let slot = per_field_len.entry(fid).or_insert(0);
        *slot = slot
            .checked_add(inc)
            .ok_or(Error::ArithmeticOverflow("bm25 per-field length"))?;
        doc_len_total = doc_len_total
            .checked_add(inc)
            .ok_or(Error::ArithmeticOverflow("bm25 doc length"))?;
    }

    if per_field.is_empty() {
        return Ok(());
    }

    // Build the flat (term, field, tf) list, sorted lexicographically by
    // term then ascending field_id so the forward index is canonical.
    let mut per_term: BTreeMap<String, BTreeMap<u16, u32>> = BTreeMap::new();
    for (fid, terms) in per_field {
        for (term, tf) in terms {
            per_term.entry(term).or_default().insert(fid, tf);
        }
    }

    // === Postings: append ONE duplicate item per term (DUP_SORT) ===
    // The append never reads the existing posting list — that is the
    // ONE-299 contract (O(1) per term on a hot term instead of the v1
    // read-modify-rewrite of the whole blob).
    let mut entry_buf: Vec<u8> = Vec::new();
    for (term, fields_tf) in &per_term {
        entry_buf.clear();
        encode_posting_entry(id, fields_tf, &mut entry_buf)?;
        store
            .text_postings()
            .put(wtxn, term.as_bytes(), &entry_buf)?;
    }

    // === Forward index: (term_len, term, field_id) records ===
    let forward_bytes = encode_forward(&per_term)?;
    store
        .text_forward()
        .put(wtxn, id.as_bytes(), &forward_bytes)?;

    // === Per-doc field lengths ===
    let field_lengths_bytes = encode_field_lengths(&per_field_len);
    store
        .text_doc_field_lengths()
        .put(wtxn, id.as_bytes(), &field_lengths_bytes)?;

    // === Document metadata (doc_len kept for status reporting) ===
    let field_count = u32::try_from(per_field_len.len())
        .map_err(|_| Error::ArithmeticOverflow("bm25 field count"))?;
    let mut doc_meta = [0_u8; DOC_META_LEN];
    doc_meta[..4].copy_from_slice(&doc_len_total.to_le_bytes());
    doc_meta[4..].copy_from_slice(&field_count.to_le_bytes());
    store.text_meta().put(wtxn, id.as_bytes(), &doc_meta)?;

    // === Per-field corpus stats ===
    for (&fid, &len) in &per_field_len {
        let (doc_count, total_length) = read_field_stats(store, wtxn, fid)?;
        let doc_count = doc_count
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("bm25 field doc_count"))?;
        let total_length = total_length
            .checked_add(u64::from(len))
            .ok_or(Error::ArithmeticOverflow("bm25 field total_length"))?;
        write_field_stats(store, wtxn, fid, doc_count, total_length)?;
    }

    // === Collection-wide doc count (plan §4.1 keeps TOTAL_DOCS_KEY only) ===
    let total_docs = read_total_docs(store, wtxn)?;
    let total_docs = total_docs
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("bm25 total_docs"))?;
    write_total_docs(store, wtxn, total_docs)?;

    Ok(())
}

pub(crate) fn deindex_text(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    validate_text_doc_id(id)?;

    let Some(forward_raw) = store.text_forward().get(wtxn, id.as_bytes())? else {
        if store.text_meta().get(wtxn, id.as_bytes())?.is_some() {
            return Err(corrupted("missing forward index for indexed document"));
        }
        return Ok(());
    };
    let forward = decode_forward(&forward_raw)?;

    if store.text_meta().get(wtxn, id.as_bytes())?.is_none() {
        return Err(corrupted("missing text metadata for deindex"));
    }

    // Pull per-field lengths so we can decrement corpus stats correctly.
    // Without this row, `total_docs--` would fire at the end without the
    // per-field `doc_count` / `total_length` decrements, permanently
    // drifting the corpus.
    let Some(raw) = store.text_doc_field_lengths().get(wtxn, id.as_bytes())? else {
        return Err(corrupted("missing field lengths for indexed document"));
    };
    let lengths = decode_field_lengths(&raw)?;

    // Group (term, fields) so each posting is rewritten once regardless of
    // how many channels a term appears on.
    let mut per_term: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    let mut forward_fields: BTreeSet<u16> = BTreeSet::new();
    for rec in forward {
        forward_fields.insert(rec.field_id);
        per_term.entry(rec.term).or_default().push(rec.field_id);
    }

    // Forward and per-doc lengths must reference the same field set. Any
    // asymmetry drifts `text_bm25_field_stats` against `total_docs`: the
    // posting rewrite below and the length-loop decrement cover different
    // field sets, but `total_docs--` unconditionally fires once.
    for fid in &forward_fields {
        let Some(&len) = lengths.get(fid) else {
            return Err(corrupted(
                "forward field missing from per-doc field lengths",
            ));
        };
        // `total_length -= 0` would silently succeed while `doc_count--`
        // still fires, drifting `avgdl` for every subsequent score. Only
        // overlay channels legitimately carry zero-length tokens.
        if let Some(channel) = AnalyzerChannel::from_field_id(*fid)
            && !channel.permits_zero_doc_field_length()
            && len == 0
        {
            return Err(corrupted(
                "zero length for indexed field that does not emit zero-length tokens",
            ));
        }
    }
    for fid in lengths.keys() {
        if !forward_fields.contains(fid) {
            return Err(corrupted(
                "per-doc field length has no matching forward field",
            ));
        }
    }

    let mut postings_to_delete = Vec::new();
    let mut missing_posting_diagnostics = Vec::new();
    for term in per_term.keys() {
        // Forward index says this term exists for this doc. If the posting
        // row or entity duplicate is already missing, only finish deleting the
        // remaining per-doc metadata and corpus stats after proving the
        // aggregate stats still count this doc. Otherwise a previous partial
        // repair could make this call double-decrement corpus stats.
        match find_posting_dup(store, wtxn, term, id)? {
            PostingLookup::Found(entry) => postings_to_delete.push((term.as_str(), entry)),
            PostingLookup::RowMissing => {
                missing_posting_diagnostics
                    .push(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingRow);
            }
            PostingLookup::EntityMissing => {
                missing_posting_diagnostics
                    .push(Bm25DiagnosticKind::DeindexSelfHealedMissingPostingEntity);
            }
        };
    }
    if !missing_posting_diagnostics.is_empty() {
        prove_bm25_doc_counted_for_missing_posting_repair(store, wtxn, id, &lengths)?;
        for kind in missing_posting_diagnostics {
            record_bm25_diagnostic(kind);
        }
    }
    for (term, entry) in postings_to_delete {
        // Exactly one duplicate item is removed; LMDB drops the term key
        // itself once its last duplicate is deleted.
        if !store
            .text_postings()
            .delete_one_duplicate(wtxn, term.as_bytes(), &entry)?
        {
            return Err(corrupted(
                "posting entry vanished mid-transaction during deindex",
            ));
        }
    }

    // Decrement per-field stats using the per-doc lengths we recorded.
    for (&fid, &len) in &lengths {
        let (doc_count, total_length) = read_field_stats(store, wtxn, fid)?;
        let doc_count = doc_count
            .checked_sub(1)
            .ok_or_else(|| corrupted("field doc_count underflow during deindex"))?;
        let total_length = total_length
            .checked_sub(u64::from(len))
            .ok_or_else(|| corrupted("field total_length underflow during deindex"))?;
        if doc_count == 0 && total_length == 0 {
            store
                .text_bm25_field_stats()
                .delete(wtxn, &fid.to_be_bytes())?;
        } else {
            write_field_stats(store, wtxn, fid, doc_count, total_length)?;
        }
    }

    let total_docs = read_total_docs(store, wtxn)?;
    let total_docs = total_docs
        .checked_sub(1)
        .ok_or_else(|| corrupted("total_docs underflow during deindex"))?;
    write_total_docs(store, wtxn, total_docs)?;

    store.text_meta().delete(wtxn, id.as_bytes())?;
    store.text_forward().delete(wtxn, id.as_bytes())?;
    store.text_doc_field_lengths().delete(wtxn, id.as_bytes())?;

    Ok(())
}

// === Scoring ===

fn collect_query_terms(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    query: &str,
    tokens: &[Token],
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<QueryTerm>> {
    // Dedupe query terms across channels — one term per unique string
    // (scorer looks up posting list then combines field TFs from the
    // posting entries themselves). This preserves the pre-ONE-317
    // "query dedupe" semantics for exact query tokens.
    let mut terms: BTreeMap<String, f64> = BTreeMap::new();
    for token in tokens {
        insert_query_term(&mut terms, token.term.as_ref().to_owned(), 1.0);
    }

    collect_final_token_prefix_terms(
        store,
        rtxn,
        query.trim_end().len(),
        config,
        tokens,
        &mut terms,
        exact_posting_matches_scope,
    )?;

    Ok(terms
        .into_iter()
        .map(|(term, weight)| QueryTerm { term, weight })
        .collect())
}

fn collect_final_token_prefix_terms(
    store: &Store,
    rtxn: &RoTxn<'_>,
    trimmed_query_end: usize,
    config: &Bm25Config,
    tokens: &[Token],
    terms: &mut BTreeMap<String, f64>,
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<()> {
    let prefixes = final_token_prefix_terms(tokens, trimmed_query_end);

    let mut expanded_terms = 0usize;
    'prefixes: for prefix in prefixes {
        if exact_term_has_scoped_posting(store, rtxn, config, &prefix, exact_posting_matches_scope)?
        {
            continue;
        }
        if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
            break;
        }

        // The scan cap is per distinct final surface prefix. A query can
        // carry multiple final surface tokens, so total cursor reads are
        // bounded by prefix_count * MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS while
        // accepted expansions still share MAX_FINAL_TOKEN_PREFIX_TERMS.
        for (scanned_terms, row) in store
            .text_postings
            .prefix_iter(rtxn, prefix.as_bytes())?
            .move_between_keys()
            .enumerate()
        {
            if scanned_terms == MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS {
                break;
            }
            if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
                break 'prefixes;
            }
            let (term_bytes, _) = row?;
            let term = str::from_utf8(&term_bytes)
                .map_err(|_| corrupted("posting term key is not valid utf-8"))?
                .to_owned();
            if !exact_term_has_scoped_posting(
                store,
                rtxn,
                config,
                &term,
                exact_posting_matches_scope,
            )? {
                continue;
            }
            insert_query_term(terms, term, FINAL_TOKEN_PREFIX_WEIGHT);
            expanded_terms += 1;
        }
    }

    Ok(())
}

pub(crate) fn final_token_exact_posting_matches<F>(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    mut posting_matches: F,
) -> Result<bool>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    let trimmed_query_end = query.trim_end().len();
    if trimmed_query_end == 0 {
        return Ok(false);
    }

    let mut tokens = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    for term in final_token_prefix_terms(&tokens, trimmed_query_end) {
        let Some(dups) = store.text_postings.get_duplicates(rtxn, term.as_bytes())? else {
            continue;
        };
        for item in dups {
            let (_, dup) = item?;
            let entry = decode_posting_entry(&dup)?;
            let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
                continue;
            };
            if posting_has_enabled_channel(config, &entry)? && posting_matches(&scope_id)? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub(crate) fn final_token_prefix_expansion_has_scoped_and_rejected_postings<F>(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    mut classify_posting: F,
) -> Result<bool>
where
    F: FnMut(&EntityId) -> Result<PrefixExpansionPostingDecision>,
{
    let trimmed_query_end = query.trim_end().len();
    if trimmed_query_end == 0 {
        return Ok(false);
    }

    let mut tokens = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);

    let prefixes = final_token_prefix_terms(&tokens, trimmed_query_end);
    let mut expanded_terms = 0usize;
    'prefixes: for prefix in prefixes {
        let exact_status =
            term_posting_decisions(store, rtxn, config, &prefix, &mut classify_posting)?;
        if exact_status.has_scoped_posting {
            continue;
        }
        if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
            break;
        }

        for (scanned_terms, row) in store
            .text_postings
            .prefix_iter(rtxn, prefix.as_bytes())?
            .move_between_keys()
            .enumerate()
        {
            if scanned_terms == MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS {
                break;
            }
            if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
                break 'prefixes;
            }
            let (term_bytes, _) = row?;
            let term = str::from_utf8(&term_bytes)
                .map_err(|_| corrupted("posting term key is not valid utf-8"))?;
            let status = term_posting_decisions(store, rtxn, config, term, &mut classify_posting)?;
            if !status.has_scoped_posting {
                continue;
            }
            if status.has_rejected_posting {
                return Ok(true);
            }
            expanded_terms += 1;
        }
    }

    Ok(false)
}

fn final_token_prefix_terms(tokens: &[Token], trimmed_query_end: usize) -> BTreeSet<String> {
    tokens
        .iter()
        .filter(|token| final_token_prefix_candidate(token, trimmed_query_end))
        .map(|token| token.term.as_ref().to_owned())
        .collect()
}

fn final_token_prefix_candidate(token: &Token, trimmed_query_end: usize) -> bool {
    token.byte_end as usize == trimmed_query_end
        && !token.term.is_empty()
        && token.channel == AnalyzerChannel::Surface
        && matches!(token.kind, TokenKind::Word | TokenKind::Numeric)
}

fn exact_term_has_scoped_posting(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    term: &str,
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<bool> {
    let Some(dups) = store.text_postings.get_duplicates(rtxn, term.as_bytes())? else {
        return Ok(false);
    };
    for item in dups {
        let (_, dup) = item?;
        let entry = decode_posting_entry(&dup)?;
        let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
            continue;
        };
        if exact_posting_matches_scope(&scope_id)? && posting_has_enabled_channel(config, &entry)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, Default)]
struct TermPostingDecisions {
    has_scoped_posting: bool,
    has_rejected_posting: bool,
}

fn term_posting_decisions(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    term: &str,
    classify_posting: &mut impl FnMut(&EntityId) -> Result<PrefixExpansionPostingDecision>,
) -> Result<TermPostingDecisions> {
    let Some(dups) = store.text_postings.get_duplicates(rtxn, term.as_bytes())? else {
        return Ok(TermPostingDecisions::default());
    };

    let mut decisions = TermPostingDecisions::default();
    for item in dups {
        let (_, dup) = item?;
        let entry = decode_posting_entry(&dup)?;
        if !posting_has_enabled_channel(config, &entry)? {
            continue;
        }
        let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
            continue;
        };
        let decision = classify_posting(&scope_id)?;
        decisions.has_scoped_posting |= decision.matches_scope;
        decisions.has_rejected_posting |= decision.rejected_by_gate;
        if decisions.has_scoped_posting && decisions.has_rejected_posting {
            break;
        }
    }

    Ok(decisions)
}

fn posting_has_enabled_channel(config: &Bm25Config, entry: &PostingEntry) -> Result<bool> {
    for (fid, _) in &entry.fields {
        let Some(channel) = AnalyzerChannel::from_field_id(*fid) else {
            return Err(corrupted("posting field_id not in current schema"));
        };
        if config.field(channel).weight != 0.0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insert_query_term(terms: &mut BTreeMap<String, f64>, term: String, weight: f64) {
    match terms.entry(term) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if weight > *entry.get() {
                *entry.get_mut() = weight;
            }
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(weight);
        }
    }
}

fn apply_recency_blend(
    store: &Store,
    rtxn: &RoTxn<'_>,
    recency: Option<Bm25RecencyConfig>,
    scores: &mut HashMap<EntityId, f64>,
) -> Result<()> {
    let Some(recency) = recency else {
        return Ok(());
    };
    if !recency.is_enabled() {
        return Ok(());
    }

    let seconds_per_half_life = recency.half_life_days * 86_400.0;
    if seconds_per_half_life <= 0.0 {
        return Ok(());
    }
    let decay = std::f64::consts::LN_2 / seconds_per_half_life;

    for (id, score) in scores {
        let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        let age_secs = recency.now_secs.saturating_sub(header.learned_at) as f64;
        let freshness = (-decay * age_secs).exp();
        *score *= 1.0 + recency.boost * freshness;
    }

    Ok(())
}

pub(crate) fn search_text(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    search_text_with_recency(store, rtxn, analyzer, config, query, limit, None)
}

pub(crate) fn search_text_with_recency(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    recency: Option<Bm25RecencyConfig>,
) -> Result<Vec<ScoredEntity>> {
    let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
    search_text_scoped_with_recency(
        store,
        rtxn,
        analyzer,
        config,
        query,
        limit,
        Bm25SearchOptions {
            recency,
            exact_posting_matches_scope: &mut exact_posting_matches_scope,
        },
    )
}

pub(crate) fn search_text_scoped_with_recency<F>(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    options: Bm25SearchOptions<'_, F>,
) -> Result<Vec<ScoredEntity>>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut tokens: Vec<Token> = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    let query_terms = collect_query_terms(
        store,
        rtxn,
        config,
        query,
        &tokens,
        options.exact_posting_matches_scope,
    )?;

    let total_docs = read_total_docs(store, rtxn)?;
    if total_docs == 0 {
        return Ok(Vec::new());
    }
    let n = f64::from(total_docs);

    // Cache per-field avgdl and per-(doc, field) length so we don't reopen
    // the same DB entries once per query term.
    let mut avgdl_cache: HashMap<u16, f64> = HashMap::new();
    let mut field_length_cache: HashMap<EntityId, HashMap<u16, u32>> = HashMap::new();
    let mut scores: HashMap<EntityId, f64> = HashMap::new();

    for query_term in query_terms {
        let Some(dups) = store
            .text_postings
            .get_duplicates(rtxn, query_term.term.as_bytes())?
        else {
            continue;
        };

        // One duplicate item per (term, entity): df = the dup count. LMDB
        // yields duplicates bytewise sorted, so entity ids must arrive
        // strictly ascending — an equal or descending neighbour means two
        // dup items share one entity (df drift) and scoring fails closed.
        let mut entries: Vec<PostingEntry> = Vec::new();
        for item in dups {
            let (_, dup) = item?;
            let entry = decode_posting_entry(&dup)?;
            if let Some(prev) = entries.last()
                && prev.id.as_bytes() >= entry.id.as_bytes()
            {
                return Err(corrupted_with_diagnostic(
                    "duplicate posting entries for one entity",
                    Bm25DiagnosticKind::MalformedPostingAlignment,
                ));
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            continue;
        }
        let df = entries.len() as f64;
        if df > n {
            return Err(corrupted_with_diagnostic(
                "posting list length exceeds total_docs",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

        for entry in entries {
            let id = entry.id;

            // Enforce row-existence for every scored entry, not only those
            // that reach a `CountLengthIncrement` branch — otherwise a
            // NoNorm-only match silently skips the corruption guard.
            if let Entry::Vacant(v) = field_length_cache.entry(id) {
                let raw = store.text_doc_field_lengths.get(rtxn, id.as_bytes())?;
                let Some(bytes) = raw else {
                    return Err(corrupted_with_diagnostic(
                        "missing field lengths for scored doc",
                        Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                    ));
                };
                let map = decode_field_lengths(&bytes)?;
                v.insert(map);
            }

            let mut x_t_d = 0.0_f64;

            for (fid, tf) in &entry.fields {
                let Some(channel) = AnalyzerChannel::from_field_id(*fid) else {
                    return Err(corrupted("posting field_id not in current schema"));
                };
                let cfg = config.field(channel);
                if cfg.weight == 0.0 {
                    continue;
                }

                let lens = field_length_cache
                    .get(&id)
                    .expect("field-lengths row loaded above for this entry id");
                // The posting-entry-implies-row invariant applies per-field:
                // a referenced `fid` must have an entry in the length row,
                // including on NoNorm channels where the value is unused.
                // Indexing always inserts the entry (including a 0 for
                // overlay-only channels), so absence is corruption. Silently
                // defaulting would yield `norm = 1 - b = 0.25` for the
                // default `b=0.75` — a 4× artificial boost.
                let stored_len = match lens.get(fid).copied() {
                    None => {
                        return Err(corrupted_with_diagnostic(
                            "posting field missing from per-doc field lengths",
                            Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                        ));
                    }
                    Some(n) => n,
                };
                let len_f = match cfg.length_policy {
                    FieldLengthPolicy::NoNorm => 0.0,
                    FieldLengthPolicy::CountLengthIncrement => {
                        if stored_len == 0 {
                            return Err(corrupted_with_diagnostic(
                                "zero length for scored CountLengthIncrement field",
                                Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                            ));
                        }
                        f64::from(stored_len)
                    }
                };

                let avgdl = if matches!(cfg.length_policy, FieldLengthPolicy::NoNorm) {
                    0.0
                } else {
                    // Fail closed on a corrupted `text_bm25_field_stats`
                    // row — scoring without a real avgdl would silently
                    // return wrong rankings instead of the caller's
                    // `Err(CorruptedIndex)`.
                    match avgdl_cache.entry(*fid) {
                        Entry::Occupied(o) => *o.get(),
                        Entry::Vacant(v) => *v.insert(compute_avgdl(store, rtxn, *fid)?),
                    }
                };

                let norm = match cfg.length_policy {
                    FieldLengthPolicy::NoNorm => 1.0,
                    FieldLengthPolicy::CountLengthIncrement => {
                        // avgdl must be positive for any field that has
                        // postings — absence means stats corruption.
                        if avgdl <= 0.0 {
                            return Err(corrupted("field stats missing for scored field"));
                        }
                        1.0 - cfg.b + cfg.b * (len_f / avgdl)
                    }
                };

                x_t_d += cfg.weight * f64::from(*tf) / norm;
            }

            if x_t_d == 0.0 {
                continue;
            }

            let saturated = (config.k1 + 1.0) * x_t_d / (config.k1 + x_t_d);
            let mut contribution = idf * saturated;
            if let Bm25Formula::Plus { delta } = config.formula {
                contribution += idf * delta;
            }
            contribution *= query_term.weight;
            *scores.entry(id).or_insert(0.0) += contribution;
        }
    }

    collapse_lexical_query_hint_scores(store, rtxn, &mut scores)?;
    apply_recency_blend(store, rtxn, options.recency, &mut scores)?;

    let mut ranked: Vec<(EntityId, f64)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    ranked.truncate(limit);

    Ok(ranked
        .into_iter()
        .map(|(id, score)| ScoredEntity {
            id,
            score: score as f32,
        })
        .collect())
}

fn compute_avgdl(store: &Store, rtxn: &RoTxn<'_>, field_id: u16) -> Result<f64> {
    let (doc_count, total_length) = read_field_stats(store, rtxn, field_id)?;
    if doc_count == 0 {
        return Ok(0.0);
    }
    Ok(total_length as f64 / f64::from(doc_count))
}

fn collapse_lexical_query_hint_scores(
    store: &Store,
    rtxn: &RoTxn<'_>,
    scores: &mut HashMap<EntityId, f64>,
) -> Result<()> {
    let mut collapsed = HashMap::<EntityId, f64>::with_capacity(scores.len());
    for (id, score) in scores.drain() {
        let target = match resolve_lexical_query_hint_record(store, rtxn, &id)? {
            LexicalQueryHintResolution::Live { target } => {
                if !lexical_query_hint_target_is_live_claim(store, rtxn, &target)? {
                    continue;
                }
                target
            }
            LexicalQueryHintResolution::DeadHint => continue,
            LexicalQueryHintResolution::NonHint => id,
        };
        match collapsed.entry(target) {
            Entry::Occupied(mut entry) => {
                if score > *entry.get() {
                    *entry.get_mut() = score;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(score);
            }
        }
    }
    *scores = collapsed;
    Ok(())
}

enum LexicalQueryHintResolution {
    NonHint,
    Live { target: EntityId },
    DeadHint,
}

fn resolve_lexical_query_hint_record(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<LexicalQueryHintResolution> {
    if !id
        .as_bytes()
        .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(LexicalQueryHintResolution::NonHint);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(corrupted("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    if raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    let body =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
            .map_err(|_| corrupted("lexical query hint claim"))?;
    if body.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    if body.lifecycle != crate::claim::ClaimLifecycleStatus::Active {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    if !body.stale {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    let Some(target) = crate::claim::lexical_query_hint_target(&body)
        .map_err(|_| corrupted("lexical query hint claim"))?
    else {
        return Ok(LexicalQueryHintResolution::DeadHint);
    };
    Ok(LexicalQueryHintResolution::Live { target })
}

fn lexical_query_hint_target_is_live_claim(
    store: &Store,
    rtxn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities.get(rtxn, target.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(corrupted("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let Ok(body) =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
    else {
        return Ok(false);
    };
    Ok(body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
}

fn lexical_query_hint_scope_id(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    match resolve_lexical_query_hint_record(store, rtxn, id)? {
        LexicalQueryHintResolution::Live { target } => {
            if lexical_query_hint_target_is_live_claim(store, rtxn, &target)? {
                Ok(Some(target))
            } else {
                Ok(None)
            }
        }
        LexicalQueryHintResolution::NonHint => Ok(Some(*id)),
        LexicalQueryHintResolution::DeadHint => Ok(None),
    }
}

// === Encoders / decoders ===

#[derive(Debug)]
struct PostingEntry {
    id: EntityId,
    fields: Vec<(u16, u32)>,
}

/// Outcome of looking up the posting duplicate item for one (term, entity).
enum PostingLookup {
    /// The term key does not exist in `text_postings` at all.
    RowMissing,
    /// The term key exists but carries no duplicate for the entity.
    EntityMissing,
    /// The single duplicate item, returned as owned bytes so the read
    /// borrow ends before `delete_one_duplicate` mutates the transaction.
    Found(Vec<u8>),
}

/// Finds the posting duplicate item for `id` under `term` with a
/// prefix-ranged cursor walk: LMDB keeps duplicate items bytewise sorted
/// and every item starts with the 16-byte entity id, so the scan stops at
/// the first item whose prefix exceeds `id`. Fails closed when two
/// duplicate items share one entity prefix — that breaks the
/// one-dup-per-(term, entity) invariant and would drift `df`.
fn find_posting_dup(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    term: &str,
    id: &EntityId,
) -> Result<PostingLookup> {
    let Some(dups) = store.text_postings().get_duplicates(txn, term.as_bytes())? else {
        return Ok(PostingLookup::RowMissing);
    };
    let mut found: Option<Vec<u8>> = None;
    for item in dups {
        let (_, dup) = item?;
        if dup.len() < ENTITY_ID_LEN + 1 {
            return Err(corrupted_with_diagnostic(
                "posting entry truncated at header",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        match dup[..ENTITY_ID_LEN].cmp(id.as_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if found.is_some() {
                    return Err(corrupted_with_diagnostic(
                        "duplicate posting entries for one entity",
                        Bm25DiagnosticKind::MalformedPostingAlignment,
                    ));
                }
                found = Some(dup.to_vec());
                // Keep scanning one step: an adjacent item with the same
                // prefix is the duplicate-entity corruption case above.
            }
            std::cmp::Ordering::Greater => break,
        }
    }
    Ok(match found {
        Some(entry) => PostingLookup::Found(entry),
        None => PostingLookup::EntityMissing,
    })
}

/// Decodes ONE posting duplicate item. The length must match the declared
/// `field_count` exactly — trailing bytes (e.g. a concatenated v1-style
/// multi-entry blob) are corruption, not extra entries.
fn decode_posting_entry(raw: &[u8]) -> Result<PostingEntry> {
    if raw.len() < ENTITY_ID_LEN + 1 {
        return Err(corrupted_with_diagnostic(
            "posting entry truncated at header",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        ));
    }
    let id_bytes: [u8; ENTITY_ID_LEN] = raw[..ENTITY_ID_LEN].try_into().map_err(|_| {
        corrupted_with_diagnostic(
            "posting entry id slice",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        )
    })?;
    let id = EntityId::from_bytes(id_bytes).map_err(|_| {
        corrupted_with_diagnostic(
            "posting entry has invalid id",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        )
    })?;
    let field_count = raw[ENTITY_ID_LEN] as usize;
    if field_count == 0 {
        return Err(corrupted_with_diagnostic(
            "posting entry has zero field count",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        ));
    }
    let body_start = ENTITY_ID_LEN + 1;
    let Some(body_len) = field_count
        .checked_mul(FIELD_TF_LEN)
        .filter(|len| body_start + len == raw.len())
    else {
        return Err(corrupted_with_diagnostic(
            "posting entry length mismatches field count",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        ));
    };
    let (chunks, rem) = raw[body_start..body_start + body_len].as_chunks::<FIELD_TF_LEN>();
    debug_assert!(rem.is_empty());
    let mut fields = Vec::with_capacity(field_count);
    for &[b0, b1, b2, b3, b4, b5] in chunks {
        let fid = u16::from_be_bytes([b0, b1]);
        let tf = u32::from_le_bytes([b2, b3, b4, b5]);
        if tf == 0 {
            return Err(corrupted_with_diagnostic(
                "posting entry has zero term frequency",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        fields.push((fid, tf));
    }
    Ok(PostingEntry { id, fields })
}

fn encode_posting_entry(
    id: &EntityId,
    fields: &BTreeMap<u16, u32>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let count = u8::try_from(fields.len())
        .map_err(|_| Error::ArithmeticOverflow("bm25 posting field count"))?;
    if count == 0 {
        return Err(corrupted("posting entry has zero field count"));
    }
    out.extend_from_slice(id.as_bytes());
    out.push(count);
    for (fid, tf) in fields {
        out.extend_from_slice(&fid.to_be_bytes());
        out.extend_from_slice(&tf.to_le_bytes());
    }
    Ok(())
}

#[derive(Debug)]
struct ForwardRecord {
    term: String,
    field_id: u16,
}

/// Encodes the forward row as `[(term_len_u16_le | term_bytes |
/// field_id_u16_be)*]`. The per-field `tf` u32 that v1 carried was dead on
/// the read side (deindex only needs the term/field set) and was dropped
/// in storage ABI v4 (ONE-299).
fn encode_forward(per_term: &BTreeMap<String, BTreeMap<u16, u32>>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (term, fields) in per_term {
        let len = u16::try_from(term.len())
            .map_err(|_| Error::ArithmeticOverflow("bm25 forward term length"))?;
        for fid in fields.keys() {
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(term.as_bytes());
            out.extend_from_slice(&fid.to_be_bytes());
        }
    }
    Ok(out)
}

fn decode_forward(raw: &[u8]) -> Result<Vec<ForwardRecord>> {
    if raw.is_empty() {
        return Err(corrupted("empty forward row"));
    }
    let mut records = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let Some((term_len_bytes, after_len)) = rest.split_at_checked(2) else {
            return Err(corrupted("forward index truncated at term-len"));
        };
        let term_len = u16::from_le_bytes([term_len_bytes[0], term_len_bytes[1]]) as usize;
        if term_len == 0 {
            return Err(corrupted("forward index has zero-length term"));
        }
        let Some((term_bytes, after_term)) = after_len.split_at_checked(term_len) else {
            return Err(corrupted("forward index truncated at term body"));
        };
        let Some((field_id_bytes, after_field)) = after_term.split_at_checked(FORWARD_FIELD_ID_LEN)
        else {
            return Err(corrupted("forward index truncated at term body"));
        };
        let term = str::from_utf8(term_bytes)
            .map(str::to_owned)
            .map_err(|_| corrupted("forward index has non-utf8 term"))?;
        let field_id = u16::from_be_bytes([field_id_bytes[0], field_id_bytes[1]]);
        rest = after_field;
        records.push(ForwardRecord { term, field_id });
    }
    Ok(records)
}

fn encode_field_lengths(lengths: &HashMap<u16, u32>) -> Vec<u8> {
    let mut pairs: Vec<(u16, u32)> = lengths.iter().map(|(k, v)| (*k, *v)).collect();
    pairs.sort_by_key(|&(fid, _)| fid);
    let mut out = Vec::with_capacity(pairs.len() * FIELD_LENGTH_LEN);
    for (fid, len) in pairs {
        out.extend_from_slice(&fid.to_be_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    out
}

fn decode_field_lengths(raw: &[u8]) -> Result<HashMap<u16, u32>> {
    if raw.is_empty() {
        return Err(corrupted("empty field lengths row"));
    }
    if !raw.len().is_multiple_of(FIELD_LENGTH_LEN) {
        return Err(corrupted("per-doc field lengths has invalid byte length"));
    }
    let (chunks, rem) = raw.as_chunks::<FIELD_LENGTH_LEN>();
    debug_assert!(rem.is_empty());
    let mut map = HashMap::with_capacity(chunks.len());
    for &[b0, b1, b2, b3, b4, b5] in chunks {
        let fid = u16::from_be_bytes([b0, b1]);
        let len = u32::from_le_bytes([b2, b3, b4, b5]);
        map.insert(fid, len);
    }
    Ok(map)
}

fn read_field_stats(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    field_id: u16,
) -> Result<(u32, u64)> {
    let key = field_id.to_be_bytes();
    let Some(raw) = store.text_bm25_field_stats().get(txn, &key)? else {
        return Ok((0, 0));
    };
    if raw.len() != FIELD_STATS_LEN {
        return Err(corrupted("field stats has invalid byte length"));
    }
    let doc_count = u32::from_le_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| corrupted("field stats doc_count slice"))?,
    );
    let total_length = u64::from_le_bytes(
        raw[4..]
            .try_into()
            .map_err(|_| corrupted("field stats total_length slice"))?,
    );
    Ok((doc_count, total_length))
}

fn write_field_stats(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    field_id: u16,
    doc_count: u32,
    total_length: u64,
) -> Result<()> {
    let mut value = [0_u8; FIELD_STATS_LEN];
    value[..4].copy_from_slice(&doc_count.to_le_bytes());
    value[4..].copy_from_slice(&total_length.to_le_bytes());
    let key = field_id.to_be_bytes();
    store.text_bm25_field_stats().put(wtxn, &key, &value)?;
    Ok(())
}

pub(crate) fn read_total_docs(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u32> {
    match store.text_meta().get(txn, &TOTAL_DOCS_KEY)? {
        Some(raw) => {
            Ok(u32::from_le_bytes(raw.as_ref().try_into().map_err(
                |_| corrupted("total_docs sentinel has invalid length"),
            )?))
        }
        None => Ok(0),
    }
}

fn write_total_docs(store: &impl ManifestDbs, wtxn: &mut RwTxn<'_>, total_docs: u32) -> Result<()> {
    store
        .text_meta()
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    Ok(())
}

fn corrupted(message: &'static str) -> Error {
    Error::CorruptedIndex(message)
}

fn corrupted_with_diagnostic(message: &'static str, kind: Bm25DiagnosticKind) -> Error {
    record_bm25_diagnostic(kind);
    corrupted(message)
}

fn validate_text_doc_id(id: &EntityId) -> Result<()> {
    let bytes = id.as_bytes();
    if bytes == &TOTAL_DOCS_KEY
        || bytes == &TOTAL_LENGTH_KEY
        || (bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok())
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
