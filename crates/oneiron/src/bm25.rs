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

use heed::{RoTxn, RwTxn};

use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer, Token, TokenKind};
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{EntityId, ScoredEntity, short_id_prefix};

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
    pub(crate) const DEFAULT_BOOST: f64 = 0.5;

    pub(crate) fn new(half_life_days: f32, now_secs: u64) -> Self {
        Self {
            half_life_days: f64::from(half_life_days),
            boost: Self::DEFAULT_BOOST,
            now_secs,
        }
    }

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
pub(crate) const BM25_FIELD_COUNT: usize = 7;

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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    id: &EntityId,
    fields: &[(String, String)],
) -> Result<()> {
    validate_text_doc_id(id)?;

    match store.text_forward.get(wtxn, id.as_bytes())? {
        Some(_) => deindex_text(store, wtxn, id)?,
        None if store.text_meta.get(wtxn, id.as_bytes())?.is_some() => {
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
        store.text_postings.put(wtxn, term.as_bytes(), &entry_buf)?;
    }

    // === Forward index: (term_len, term, field_id) records ===
    let forward_bytes = encode_forward(&per_term)?;
    store
        .text_forward
        .put(wtxn, id.as_bytes(), &forward_bytes)?;

    // === Per-doc field lengths ===
    let field_lengths_bytes = encode_field_lengths(&per_field_len);
    store
        .text_doc_field_lengths
        .put(wtxn, id.as_bytes(), &field_lengths_bytes)?;

    // === Document metadata (doc_len kept for status reporting) ===
    let field_count = u32::try_from(per_field_len.len())
        .map_err(|_| Error::ArithmeticOverflow("bm25 field count"))?;
    let mut doc_meta = [0_u8; DOC_META_LEN];
    doc_meta[..4].copy_from_slice(&doc_len_total.to_le_bytes());
    doc_meta[4..].copy_from_slice(&field_count.to_le_bytes());
    store.text_meta.put(wtxn, id.as_bytes(), &doc_meta)?;

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

pub(crate) fn deindex_text(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    validate_text_doc_id(id)?;

    let Some(forward_raw) = store.text_forward.get(wtxn, id.as_bytes())? else {
        if store.text_meta.get(wtxn, id.as_bytes())?.is_some() {
            return Err(corrupted("missing forward index for indexed document"));
        }
        return Ok(());
    };
    let forward = decode_forward(forward_raw)?;

    if store.text_meta.get(wtxn, id.as_bytes())?.is_none() {
        return Err(corrupted("missing text metadata for deindex"));
    }

    // Pull per-field lengths so we can decrement corpus stats correctly.
    // Without this row, `total_docs--` would fire at the end without the
    // per-field `doc_count` / `total_length` decrements, permanently
    // drifting the corpus.
    let Some(raw) = store.text_doc_field_lengths.get(wtxn, id.as_bytes())? else {
        return Err(corrupted("missing field lengths for indexed document"));
    };
    let lengths = decode_field_lengths(raw)?;

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

    for term in per_term.keys() {
        // Forward index says this term exists for this doc; an absent
        // posting row (or a row without this entity's dup) is corruption,
        // not a normal "term gone" condition. Silently skipping would let
        // `total_docs--` fire below while the already-missing posting
        // bytes remain unaccounted for.
        let entry = match find_posting_dup(store, wtxn, term, id)? {
            PostingLookup::Found(entry) => entry,
            PostingLookup::RowMissing => {
                return Err(corrupted(
                    "forward term references missing posting row during deindex",
                ));
            }
            PostingLookup::EntityMissing => {
                return Err(corrupted(
                    "forward term missing entity in posting during deindex",
                ));
            }
        };
        // Exactly one duplicate item is removed; LMDB drops the term key
        // itself once its last duplicate is deleted.
        if !store
            .text_postings
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
                .text_bm25_field_stats
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

    store.text_meta.delete(wtxn, id.as_bytes())?;
    store.text_forward.delete(wtxn, id.as_bytes())?;
    store.text_doc_field_lengths.delete(wtxn, id.as_bytes())?;

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
    let prefixes: BTreeSet<String> = tokens
        .iter()
        .filter(|token| {
            token.byte_end as usize == trimmed_query_end
                && !token.term.is_empty()
                && token.channel == AnalyzerChannel::Surface
                && matches!(token.kind, TokenKind::Word | TokenKind::Numeric)
        })
        .map(|token| token.term.as_ref().to_owned())
        .collect();

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
            let term = str::from_utf8(term_bytes)
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
        let entry = decode_posting_entry(dup)?;
        if exact_posting_matches_scope(&entry.id)? && posting_has_enabled_channel(config, &entry)? {
            return Ok(true);
        }
    }
    Ok(false)
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
        let Some(header) = EntityMetadataHeader::parse(raw) else {
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
            let entry = decode_posting_entry(dup)?;
            if let Some(prev) = entries.last()
                && prev.id.as_bytes() >= entry.id.as_bytes()
            {
                return Err(corrupted("duplicate posting entries for one entity"));
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            continue;
        }
        let df = entries.len() as f64;
        if df > n {
            return Err(corrupted("posting list length exceeds total_docs"));
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
                    return Err(corrupted("missing field lengths for scored doc"));
                };
                let map = decode_field_lengths(bytes)?;
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
                        return Err(corrupted(
                            "posting field missing from per-doc field lengths",
                        ));
                    }
                    Some(n) => n,
                };
                let len_f = match cfg.length_policy {
                    FieldLengthPolicy::NoNorm => 0.0,
                    FieldLengthPolicy::CountLengthIncrement => {
                        if stored_len == 0 {
                            return Err(corrupted(
                                "zero length for scored CountLengthIncrement field",
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
    store: &Store,
    txn: &RoTxn<'_>,
    term: &str,
    id: &EntityId,
) -> Result<PostingLookup> {
    let Some(dups) = store.text_postings.get_duplicates(txn, term.as_bytes())? else {
        return Ok(PostingLookup::RowMissing);
    };
    let mut found: Option<Vec<u8>> = None;
    for item in dups {
        let (_, dup) = item?;
        if dup.len() < ENTITY_ID_LEN + 1 {
            return Err(corrupted("posting entry truncated at header"));
        }
        match dup[..ENTITY_ID_LEN].cmp(id.as_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if found.is_some() {
                    return Err(corrupted("duplicate posting entries for one entity"));
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
        return Err(corrupted("posting entry truncated at header"));
    }
    let id_bytes: [u8; ENTITY_ID_LEN] = raw[..ENTITY_ID_LEN]
        .try_into()
        .map_err(|_| corrupted("posting entry id slice"))?;
    let id =
        EntityId::from_bytes(id_bytes).map_err(|_| corrupted("posting entry has invalid id"))?;
    let field_count = raw[ENTITY_ID_LEN] as usize;
    if field_count == 0 {
        return Err(corrupted("posting entry has zero field count"));
    }
    let body_start = ENTITY_ID_LEN + 1;
    let Some(body_len) = field_count
        .checked_mul(FIELD_TF_LEN)
        .filter(|len| body_start + len == raw.len())
    else {
        return Err(corrupted("posting entry length mismatches field count"));
    };
    let (chunks, rem) = raw[body_start..body_start + body_len].as_chunks::<FIELD_TF_LEN>();
    debug_assert!(rem.is_empty());
    let mut fields = Vec::with_capacity(field_count);
    for &[b0, b1, b2, b3, b4, b5] in chunks {
        let fid = u16::from_be_bytes([b0, b1]);
        let tf = u32::from_le_bytes([b2, b3, b4, b5]);
        if tf == 0 {
            return Err(corrupted("posting entry has zero term frequency"));
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

fn read_field_stats(store: &Store, txn: &RoTxn<'_>, field_id: u16) -> Result<(u32, u64)> {
    let key = field_id.to_be_bytes();
    let Some(raw) = store.text_bm25_field_stats.get(txn, &key)? else {
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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    field_id: u16,
    doc_count: u32,
    total_length: u64,
) -> Result<()> {
    let mut value = [0_u8; FIELD_STATS_LEN];
    value[..4].copy_from_slice(&doc_count.to_le_bytes());
    value[4..].copy_from_slice(&total_length.to_le_bytes());
    let key = field_id.to_be_bytes();
    store.text_bm25_field_stats.put(wtxn, &key, &value)?;
    Ok(())
}

pub(crate) fn read_total_docs(store: &Store, txn: &RoTxn<'_>) -> Result<u32> {
    match store.text_meta.get(txn, &TOTAL_DOCS_KEY)? {
        Some(raw) => {
            Ok(u32::from_le_bytes(raw.try_into().map_err(|_| {
                corrupted("total_docs sentinel has invalid length")
            })?))
        }
        None => Ok(0),
    }
}

fn write_total_docs(store: &Store, wtxn: &mut RwTxn<'_>, total_docs: u32) -> Result<()> {
    store
        .text_meta
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    Ok(())
}

fn corrupted(message: &'static str) -> Error {
    Error::CorruptedIndex(message)
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
mod tests {
    use super::*;
    use crate::types::{HnswConfig, TimeRange, VaultConfig};
    use crate::{Error, Vault};
    use core::assert_matches;

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: None,
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
            text_analyzer: crate::types::TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn test_time_range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn contains_id(results: &[ScoredEntity], id: &EntityId) -> bool {
        results.iter().any(|r| r.id == *id)
    }

    fn put_text_doc(vault: &Vault, id: &EntityId, text: &str) -> Result<()> {
        put_text_doc_at(vault, id, text, 2)
    }

    fn put_text_doc_at(vault: &Vault, id: &EntityId, text: &str, learned_at: u64) -> Result<()> {
        vault
            .batch()
            .put(id, 1, test_time_range(1, 1), learned_at, b"text-doc")
            .text(id, &[("body", text)])
            .commit()
    }

    fn test_entity_id(n: u16) -> EntityId {
        let mut bytes = [0x42; ENTITY_ID_LEN];
        bytes[14..].copy_from_slice(&n.to_be_bytes());
        EntityId::from_bytes_unchecked(bytes)
    }

    fn final_word_token(term: &str) -> Token {
        Token::new(
            term,
            0,
            u32::try_from(term.len()).expect("test token fits in u32"),
            0,
            AnalyzerChannel::Surface,
            TokenKind::Word,
        )
    }

    fn put_raw_posting_terms(vault: &Vault, terms: &[String]) -> Result<()> {
        let postings = terms
            .iter()
            .enumerate()
            .map(|(idx, term)| {
                (
                    term.clone(),
                    test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
                )
            })
            .collect::<Vec<_>>();
        put_raw_posting_terms_with_ids(vault, &postings)
    }

    fn put_raw_posting_terms_with_ids(
        vault: &Vault,
        postings: &[(String, EntityId)],
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut fields = BTreeMap::new();
        fields.insert(AnalyzerChannel::Surface.field_id(), 1);
        for (term, id) in postings {
            let mut entry = Vec::new();
            encode_posting_entry(id, &fields, &mut entry)?;
            vault
                .store
                .text_postings
                .put(&mut wtxn, term.as_bytes(), &entry)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    fn cap_prefix_term(index: usize) -> String {
        format!("capbound{index:04}")
    }

    fn repeated(term: &str, count: usize) -> String {
        std::iter::repeat_n(term, count)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn default_config_matches_plan_defaults() {
        let c = Bm25Config::default();
        assert_eq!(c.k1, 1.2);
        assert_eq!(c.formula, Bm25Formula::Okapi);
        let surface = c.field(AnalyzerChannel::Surface);
        assert_eq!(surface.weight, 1.00);
        assert_eq!(surface.b, 0.75);
        assert_eq!(
            surface.length_policy,
            FieldLengthPolicy::CountLengthIncrement
        );
        let ngram = c.field(AnalyzerChannel::CjkNgram);
        assert_eq!(ngram.weight, 0.45);
        assert_eq!(ngram.b, 0.30);
        let overlay = c.field(AnalyzerChannel::NormalizedOverlay);
        assert_eq!(overlay.length_policy, FieldLengthPolicy::NoNorm);
        // Reserved channels disabled.
        assert_eq!(c.field(AnalyzerChannel::Shingle).weight, 0.0);
        assert_eq!(c.field(AnalyzerChannel::Synonym).weight, 0.0);
        assert_eq!(c.field(AnalyzerChannel::Phonetic).weight, 0.0);
    }

    #[test]
    fn index_and_search_basic() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id1 = EntityId::now();
        let id2 = EntityId::now();
        let id3 = EntityId::now();

        put_text_doc(&vault, &id1, "rust language and systems")?;
        put_text_doc(&vault, &id2, "bm25 ranking in search")?;
        put_text_doc(&vault, &id3, "graph traversal only")?;

        let results = vault.search_text("rust", 10)?;
        assert!(contains_id(&results, &id1));
        assert!(!contains_id(&results, &id2));
        assert!(!contains_id(&results, &id3));
        Ok(())
    }

    #[test]
    fn search_ranking_100_docs() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut batch = vault.batch();
        let best_idx = 42;
        let mut best_id = None;

        for idx in 0..100 {
            let id = EntityId::now();
            if idx == best_idx {
                best_id = Some(id);
            }
            let tf = if idx == best_idx { 20 } else { 1 };
            let text = repeated("apple", tf);
            batch = batch
                .put(
                    &id,
                    1,
                    test_time_range(idx as u64, idx as u64),
                    idx as u64,
                    b"doc",
                )
                .text(&id, &[("body", &text)]);
        }
        batch.commit()?;

        let best_id = best_id.ok_or(Error::InvalidKey)?;
        let results = vault.search_text("apple", 10)?;
        assert!(!results.is_empty());
        assert_eq!(results[0].id, best_id);
        Ok(())
    }

    #[test]
    fn deindex_removes_from_search() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "deindex me please")?;
        let before = vault.search_text("deindex", 10)?;
        assert!(contains_id(&before, &id));

        assert!(vault.delete_entity(&id)?);
        let after = vault.search_text("deindex", 10)?;
        assert!(!contains_id(&after, &id));
        Ok(())
    }

    #[test]
    fn multi_term_query() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id_both = EntityId::now();
        let id_alpha = EntityId::now();
        let id_beta = EntityId::now();

        put_text_doc(&vault, &id_both, "alpha beta")?;
        put_text_doc(&vault, &id_alpha, "alpha")?;
        put_text_doc(&vault, &id_beta, "beta")?;

        let results = vault.search_text("alpha beta", 10)?;
        assert_eq!(results[0].id, id_both);
        Ok(())
    }

    #[test]
    fn final_token_prefix_matches_only_last_query_token() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let retrieval = EntityId::now();
        let alpha_only = EntityId::now();
        let unrelated = EntityId::now();

        put_text_doc(&vault, &retrieval, "omega retrieval")?;
        put_text_doc(&vault, &alpha_only, "alpha zulu")?;
        put_text_doc(&vault, &unrelated, "garden zulu")?;

        let results = vault.search_text("alp retr", 10)?;
        assert!(contains_id(&results, &retrieval));
        assert!(
            !contains_id(&results, &alpha_only),
            "non-final query token must not be prefix-expanded",
        );
        assert!(!contains_id(&results, &unrelated));

        Ok(())
    }

    #[test]
    fn final_token_prefix_expands_matching_terms_below_cap() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        put_raw_posting_terms(
            &vault,
            &[
                "normprefixalpha".to_owned(),
                "normprefixbeta".to_owned(),
                "otherprefix".to_owned(),
            ],
        )?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            "normprefix".len(),
            &Bm25Config::default(),
            &[final_word_token("normprefix")],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        let collected = terms.keys().cloned().collect::<Vec<_>>();
        assert_eq!(
            collected,
            vec!["normprefixalpha".to_owned(), "normprefixbeta".to_owned()]
        );
        assert!(
            terms
                .values()
                .all(|weight| *weight == FINAL_TOKEN_PREFIX_WEIGHT)
        );
        Ok(())
    }

    #[test]
    fn final_token_prefix_ignores_derived_stem_prefixes() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        put_raw_posting_terms(
            &vault,
            &[
                "runner".to_owned(),
                "runningly".to_owned(),
                "runt".to_owned(),
            ],
        )?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            "running".len(),
            &Bm25Config::default(),
            &[
                final_word_token("running"),
                Token::new(
                    "run",
                    0,
                    "running".len() as u32,
                    0,
                    AnalyzerChannel::Stem,
                    TokenKind::Word,
                ),
            ],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        assert_eq!(
            terms.keys().cloned().collect::<Vec<_>>(),
            vec!["runningly".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn final_token_prefix_expansion_is_capped_in_deterministic_order() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let indexed_terms = (0..MAX_FINAL_TOKEN_PREFIX_TERMS + 2)
            .map(cap_prefix_term)
            .collect::<Vec<_>>();
        put_raw_posting_terms(&vault, &indexed_terms)?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            "capbound".len(),
            &Bm25Config::default(),
            &[final_word_token("capbound")],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        let collected = terms.keys().cloned().collect::<Vec<_>>();
        let expected = (0..MAX_FINAL_TOKEN_PREFIX_TERMS)
            .map(cap_prefix_term)
            .collect::<Vec<_>>();
        assert_eq!(collected, expected);
        assert!(!terms.contains_key(&cap_prefix_term(MAX_FINAL_TOKEN_PREFIX_TERMS)));
        Ok(())
    }

    #[test]
    fn final_token_prefix_expansion_applies_cap_after_scope_filtering() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let prefix = "scopecap";
        let in_scope_index = MAX_FINAL_TOKEN_PREFIX_TERMS + 1;
        let in_scope_id = test_entity_id(0x8000);
        let mut postings = (0..in_scope_index)
            .map(|idx| {
                (
                    format!("{prefix}{idx:04}"),
                    test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
                )
            })
            .collect::<Vec<_>>();
        postings.push((format!("{prefix}{in_scope_index:04}"), in_scope_id));
        put_raw_posting_terms_with_ids(&vault, &postings)?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut scope_checks = 0usize;
        let mut exact_posting_matches_scope = |id: &EntityId| {
            scope_checks += 1;
            Ok(*id == in_scope_id)
        };
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            prefix.len(),
            &Bm25Config::default(),
            &[final_word_token(prefix)],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        let in_scope_term = format!("{prefix}{in_scope_index:04}");
        assert_eq!(
            terms.keys().cloned().collect::<Vec<_>>(),
            vec![in_scope_term]
        );
        assert!(
            scope_checks > MAX_FINAL_TOKEN_PREFIX_TERMS,
            "scope filtering must happen before the 64-term expansion cap"
        );
        assert!(scope_checks <= MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
        Ok(())
    }

    #[test]
    fn final_token_prefix_scan_budget_ignores_out_of_scope_completions() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let prefix = "scopeaware";
        let old_prescope_cap = MAX_FINAL_TOKEN_PREFIX_TERMS * 16;
        let in_scope_index = old_prescope_cap + 1;
        assert!(in_scope_index < MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);

        let in_scope_id = test_entity_id(0x9000);
        let mut postings = (0..in_scope_index)
            .map(|idx| {
                (
                    format!("{prefix}{idx:04}"),
                    test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
                )
            })
            .collect::<Vec<_>>();
        postings.push((format!("{prefix}{in_scope_index:04}"), in_scope_id));
        put_raw_posting_terms_with_ids(&vault, &postings)?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut scope_checks = 0usize;
        let mut exact_posting_matches_scope = |id: &EntityId| {
            scope_checks += 1;
            Ok(*id == in_scope_id)
        };
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            prefix.len(),
            &Bm25Config::default(),
            &[final_word_token(prefix)],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        assert_eq!(
            terms.keys().cloned().collect::<Vec<_>>(),
            vec![format!("{prefix}{in_scope_index:04}")]
        );
        assert!(
            scope_checks > old_prescope_cap,
            "out-of-scope completions must not consume the scoped expansion budget"
        );
        assert!(scope_checks <= MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
        Ok(())
    }

    #[test]
    fn final_token_prefix_scope_filtering_keeps_global_scan_bounded() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let prefix = "scopebound";
        let postings = (0..MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS + 2)
            .map(|idx| {
                (
                    format!("{prefix}{idx:04}"),
                    test_entity_id(u16::try_from(idx).expect("test id fits in u16")),
                )
            })
            .collect::<Vec<_>>();
        put_raw_posting_terms_with_ids(&vault, &postings)?;

        let rtxn = vault.store.env.read_txn()?;
        let mut terms = BTreeMap::new();
        let mut scope_checks = 0usize;
        let mut exact_posting_matches_scope = |_id: &EntityId| {
            scope_checks += 1;
            Ok(false)
        };
        collect_final_token_prefix_terms(
            &vault.store,
            &rtxn,
            prefix.len(),
            &Bm25Config::default(),
            &[final_word_token(prefix)],
            &mut terms,
            &mut exact_posting_matches_scope,
        )?;

        assert!(terms.is_empty());
        assert_eq!(scope_checks, MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS);
        Ok(())
    }

    #[test]
    fn final_token_prefix_does_not_expand_before_dropped_punctuation() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let widened = EntityId::now();

        put_text_doc(&vault, &widened, "foobarbaz")?;

        let results = vault.search_text("foo.", 10)?;
        assert!(
            !contains_id(&results, &widened),
            "token before trailing punctuation must not be treated as a final prefix"
        );
        Ok(())
    }

    #[test]
    fn bm25_recency_blend_is_configurable_and_deterministic() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let old = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
        let fresh = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

        put_text_doc_at(&vault, &old, "needle", 0)?;
        put_text_doc_at(&vault, &fresh, "needle", 86_400)?;

        let rtxn = vault.store.env.read_txn()?;
        let config = Bm25Config::default();
        let baseline = search_text_with_recency(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &config,
            "needle",
            10,
            None,
        )?;
        assert_eq!(baseline[0].id, old, "baseline tie breaks by entity id");

        let recency = Some(Bm25RecencyConfig {
            half_life_days: 0.01,
            boost: 4.0,
            now_secs: 86_400,
        });
        let boosted = search_text_with_recency(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &config,
            "needle",
            10,
            recency,
        )?;
        let repeated = search_text_with_recency(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &config,
            "needle",
            10,
            recency,
        )?;
        assert_eq!(boosted[0].id, fresh);
        assert_eq!(boosted.len(), repeated.len());
        for (left, right) in boosted.iter().zip(repeated.iter()) {
            assert_eq!(left.id, right.id);
            assert_eq!(left.score, right.score);
        }
        Ok(())
    }

    #[test]
    fn empty_query_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let results = vault.search_text("", 10)?;
        assert!(results.is_empty());
        Ok(())
    }

    #[test]
    fn zero_limit_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let results = vault.search_text("hello", 0)?;
        assert!(results.is_empty());
        Ok(())
    }

    #[test]
    fn empty_vault_query_returns_empty() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let results = vault.search_text("hello", 10)?;
        assert!(results.is_empty());
        Ok(())
    }

    #[test]
    fn empty_document() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 2, b"empty")
            .text(&id, &[("title", ""), ("body", "")])
            .commit()?;

        let results = vault.search_text("anything", 10)?;
        assert!(!contains_id(&results, &id));
        Ok(())
    }

    #[test]
    fn reindex_overwrites_cleanly() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "foo bar")?;
        vault.batch().text(&id, &[("body", "baz qux")]).commit()?;

        let foo_results = vault.search_text("foo", 10)?;
        let baz_results = vault.search_text("baz", 10)?;

        assert!(!contains_id(&foo_results, &id));
        assert!(contains_id(&baz_results, &id));
        Ok(())
    }

    #[test]
    fn fullwidth_ascii_document_matches_ascii_query() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "ＡＢＣ fullwidth mixed with regular ABC")?;

        let lower = vault.search_text("abc", 10)?;
        assert!(contains_id(&lower, &id));
        let upper = vault.search_text("ABC", 10)?;
        assert!(contains_id(&upper, &id));
        let fullwidth = vault.search_text("ＡＢＣ", 10)?;
        assert!(contains_id(&fullwidth, &id));
        Ok(())
    }

    #[test]
    fn stem_channel_enables_cross_inflection_recall() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id_runs = EntityId::now();
        let id_ran = EntityId::now();
        put_text_doc(&vault, &id_runs, "she runs every morning before work")?;
        // `runs`, `running`, `runnings` all Snowball-stem to `run`, so a
        // `running` query must reach a doc that only carries a sibling
        // inflection. Regression guard for symmetric stem emission.
        put_text_doc(&vault, &id_ran, "he runnings the marathon next spring")?;

        let hits = vault.search_text("running", 10)?;
        assert!(contains_id(&hits, &id_runs));
        assert!(contains_id(&hits, &id_ran));
        Ok(())
    }

    /// Katakana query must retrieve a hiragana-only doc via the kana-fold
    /// overlay. Runs only with `ONEIRON_TEST_SUDACHI_DICT` pointing at
    /// `system.dic`: the portable/cjk_ngram path doesn't apply kana-fold,
    /// so this regression guard requires the morphological analyzer.
    #[test]
    fn katakana_query_matches_hiragana_document() -> Result<()> {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
            return Ok(());
        };
        let dict_dir = match std::path::Path::new(&dict_path).parent() {
            Some(p) => p.to_path_buf(),
            None => return Ok(()),
        };

        let temp_dir = tempfile::tempdir()?;
        let mut config = test_config();
        config.dict_search_paths = vec![dict_dir];
        let vault = Vault::open(temp_dir.path(), config)?;

        let id = EntityId::now();
        put_text_doc(&vault, &id, "とうきょう")?;
        let hits = vault.search_text("トウキョウ", 10)?;
        assert!(
            contains_id(&hits, &id),
            "katakana query must retrieve hiragana doc via kana-fold overlay",
        );
        // Inverse direction (regression guard for index-side overlay).
        let id2 = EntityId::now();
        put_text_doc(&vault, &id2, "トウキョウ")?;
        let hits2 = vault.search_text("とうきょう", 10)?;
        assert!(contains_id(&hits2, &id2));
        Ok(())
    }

    /// End-to-end check on the analyzer contract: kana-fold emissions on
    /// `NormalizedOverlay` must persist a zero field length (Surface
    /// still records its own length), and deindex must tolerate that
    /// zero given the matching forward-index entry.
    #[test]
    fn normalized_overlay_persists_zero_field_length() -> Result<()> {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
            return Ok(());
        };
        let dict_dir = match std::path::Path::new(&dict_path).parent() {
            Some(p) => p.to_path_buf(),
            None => return Ok(()),
        };

        let temp_dir = tempfile::tempdir()?;
        let mut config = test_config();
        config.dict_search_paths = vec![dict_dir];
        let vault = Vault::open(temp_dir.path(), config)?;

        let id = EntityId::now();
        put_text_doc(&vault, &id, "トウキョウ")?;

        let overlay_fid = AnalyzerChannel::NormalizedOverlay.field_id();
        {
            let rtxn = vault.store.env.read_txn()?;
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(&rtxn, id.as_bytes())?
                .expect("lengths row written");
            let lens = decode_field_lengths(raw)?;
            assert_eq!(
                lens.get(&overlay_fid).copied(),
                Some(0),
                "NormalizedOverlay field length must be 0 under zero-length-token contract",
            );
            let (doc_count, total_length) = read_field_stats(&vault.store, &rtxn, overlay_fid)?;
            assert_eq!(doc_count, 1);
            assert_eq!(total_length, 0);
        }

        assert!(vault.delete_entity(&id)?);
        Ok(())
    }

    #[test]
    fn cjk_query_matches_bigram_channel() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "東京塔")?;
        // "東京" matches the `東京` bigram on the CjkNgram channel.
        let results = vault.search_text("東京", 10)?;
        assert!(contains_id(&results, &id));
        Ok(())
    }

    #[test]
    fn single_character_cjk_document_is_searchable() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();

        put_text_doc(&vault, &id, "東")?;
        let results = vault.search_text("東", 10)?;
        assert!(contains_id(&results, &id));
        Ok(())
    }

    #[test]
    fn reserved_bm25_doc_ids_are_rejected() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let mut short_id_sentinel = [0xFF; 16];
        short_id_sentinel[0] = 1;

        for raw_id in [TOTAL_DOCS_KEY, TOTAL_LENGTH_KEY, short_id_sentinel] {
            let id = EntityId::from_bytes_unchecked(raw_id);
            let err = vault
                .batch()
                .text(&id, &[("body", "reserved")])
                .commit()
                .unwrap_err();
            assert_matches!(err, Error::InvalidKey);
        }

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_total_docs(&vault.store, &rtxn)?, 0);
        Ok(())
    }

    #[test]
    fn bm25_plus_formula_does_not_require_reindex() -> Result<()> {
        // Changing the rank profile is scoring-only — same index, same
        // postings, different score. Plan §4.2.
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let okapi = vault.search_text("hello", 10)?;
        assert!(contains_id(&okapi, &id));

        let rtxn = vault.store.env.read_txn()?;
        let plus_cfg = Bm25Config {
            formula: Bm25Formula::Plus { delta: 1.0 },
            ..Bm25Config::default()
        };
        let plus = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &plus_cfg,
            "hello",
            10,
        )?;
        assert!(contains_id(&plus, &id));
        // BM25+ adds a positive delta·idf term per query term, so the
        // scored value must be strictly greater than Okapi's.
        let okapi_score = okapi.iter().find(|r| r.id == id).unwrap().score;
        let plus_score = plus.iter().find(|r| r.id == id).unwrap().score;
        assert!(plus_score > okapi_score);

        // Release the read txn — LMDB allows one read txn per thread and
        // the public path below opens its own.
        drop(rtxn);

        // Public path: the same formula switch through the
        // `Bm25RankProfile` knob must produce the identical BM25+ score
        // against the same index — no reindex happened in between.
        let plus_profile =
            crate::types::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });
        let public_plus = vault.search_text_with_profile("hello", 10, &plus_profile)?;
        let public_plus_score = public_plus.iter().find(|r| r.id == id).unwrap().score;
        assert_eq!(public_plus_score, plus_score);
        assert!(public_plus_score > okapi_score);
        Ok(())
    }

    #[test]
    fn okapi_surface_score_matches_formula_fixture() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        let other_alpha = EntityId::now();
        let other_beta = EntityId::now();
        put_text_doc(&vault, &id, "alpha alpha alpha")?;
        put_text_doc(&vault, &other_alpha, "alpha")?;
        put_text_doc(&vault, &other_beta, "beta")?;

        let mut config = Bm25Config {
            fields: [FieldConfig::disabled(); BM25_FIELD_COUNT],
            ..Bm25Config::default()
        };
        config.fields[AnalyzerChannel::Surface.field_id() as usize] = FieldConfig {
            weight: 1.0,
            b: 0.75,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?,
            (3, 5),
            "fixture must be three Surface documents with five total tokens"
        );
        let results = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &config,
            "alpha",
            10,
        )?;
        let score = results
            .iter()
            .find(|result| result.id == id)
            .expect("document must score")
            .score as f64;

        let n = 3.0_f64;
        let df = 2.0_f64;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
        let avgdl = 5.0_f64 / 3.0_f64;
        let norm = 1.0 - 0.75 + 0.75 * (3.0 / avgdl);
        let x_t_d = 3.0_f64 / norm;
        let expected = idf * ((config.k1 + 1.0) * x_t_d / (config.k1 + x_t_d));
        assert!(
            (score - expected).abs() < 1e-6,
            "score {score} did not match expected {expected}"
        );
        Ok(())
    }

    /// The public default profile must lower to the literal ARCH-0031
    /// channel table (weights / `b` / length policy), the pinned global
    /// `k1 = 1.2`, and the Okapi default formula. Reserved channels stay
    /// disabled. The profile deliberately exposes no `k1` knob.
    #[test]
    fn rank_profile_default_lowers_to_contract_literals() -> Result<()> {
        let c = crate::types::Bm25RankProfile::default().to_bm25_config()?;
        assert_eq!(c.k1, 1.2);
        assert_eq!(c.formula, Bm25Formula::Okapi);

        let surface = c.field(AnalyzerChannel::Surface);
        assert_eq!(surface.weight, 1.00);
        assert_eq!(surface.b, 0.75);
        assert_eq!(
            surface.length_policy,
            FieldLengthPolicy::CountLengthIncrement
        );
        let stem = c.field(AnalyzerChannel::Stem);
        assert_eq!(stem.weight, 0.35);
        assert_eq!(stem.b, 0.65);
        assert_eq!(stem.length_policy, FieldLengthPolicy::CountLengthIncrement);
        let overlay = c.field(AnalyzerChannel::NormalizedOverlay);
        assert_eq!(overlay.weight, 0.55);
        assert_eq!(overlay.b, 0.00);
        assert_eq!(overlay.length_policy, FieldLengthPolicy::NoNorm);
        let ngram = c.field(AnalyzerChannel::CjkNgram);
        assert_eq!(ngram.weight, 0.45);
        assert_eq!(ngram.b, 0.30);
        assert_eq!(ngram.length_policy, FieldLengthPolicy::CountLengthIncrement);

        for reserved in [
            AnalyzerChannel::Shingle,
            AnalyzerChannel::Synonym,
            AnalyzerChannel::Phonetic,
        ] {
            assert_eq!(c.field(reserved).weight, 0.0);
        }
        Ok(())
    }

    /// AC3: a `weight == 0.0` channel override excludes that channel from
    /// scoring through both public paths (`search_text_with_profile` and
    /// the pipeline's `rank_profile`). The query `running` reaches the
    /// doc only via the Stem channel (`runs` and `running` both stem to
    /// `run`), so zeroing Stem must drop the doc entirely.
    #[test]
    fn zero_weight_channel_excluded_through_public_path() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "she runs every morning before work")?;

        // Default profile: stem channel carries the match.
        let default_profile = crate::types::Bm25RankProfile::default();
        let stem_only_query = "running.";
        let hits = vault.search_text_with_profile(stem_only_query, 10, &default_profile)?;
        assert!(contains_id(&hits, &id));

        // Stem weight zeroed: the only matching channel is excluded. The
        // punctuation keeps this assertion isolated from final-token prefix
        // widening, which may legitimately match `runs` through Surface.
        let stem_zero = crate::types::Bm25RankProfile::default()
            .with_channel_weight(AnalyzerChannel::Stem, 0.0);
        let hits = vault.search_text_with_profile(stem_only_query, 10, &stem_zero)?;
        assert!(
            !contains_id(&hits, &id),
            "zero-weight Stem channel must be excluded from scoring",
        );

        // Same exclusion through the pipeline path.
        let hits = vault
            .query()
            .search_text(stem_only_query, 10)
            .rank_profile(stem_zero)
            .run()?;
        assert!(!contains_id(&hits, &id));
        let hits = vault.query().search_text(stem_only_query, 10).run()?;
        assert!(contains_id(&hits, &id), "default pipeline still matches");

        // All four v1 channels zeroed: even a direct surface match is
        // excluded and the result set is empty.
        let all_zero = crate::types::Bm25RankProfile::default()
            .with_channel_weight(AnalyzerChannel::Surface, 0.0)
            .with_channel_weight(AnalyzerChannel::Stem, 0.0)
            .with_channel_weight(AnalyzerChannel::NormalizedOverlay, 0.0)
            .with_channel_weight(AnalyzerChannel::CjkNgram, 0.0);
        let hits = vault.search_text_with_profile("runs", 10, &all_zero)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn stem_exact_hit_does_not_suppress_surface_prefix_expansion() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let stem_exact = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
        let surface_prefix = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

        put_text_doc(&vault, &stem_exact, "she runs daily")?;
        put_text_doc(&vault, &surface_prefix, "runningly specific surface")?;

        let hits = vault.search_text("running", 10)?;

        assert!(contains_id(&hits, &stem_exact));
        assert!(contains_id(&hits, &surface_prefix));
        Ok(())
    }

    #[test]
    fn disabled_channel_exact_hit_does_not_suppress_enabled_prefix() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let disabled_exact = EntityId::from_bytes_unchecked([0x10; ENTITY_ID_LEN]);
        let enabled_prefix = EntityId::from_bytes_unchecked([0x20; ENTITY_ID_LEN]);

        put_text_doc(&vault, &disabled_exact, "she runs daily")?;
        put_text_doc(&vault, &enabled_prefix, "runningly specific surface")?;

        let stem_zero = crate::types::Bm25RankProfile::default()
            .with_channel_weight(AnalyzerChannel::Stem, 0.0);
        let hits = vault.search_text_with_profile("running", 10, &stem_zero)?;

        assert!(contains_id(&hits, &enabled_prefix));
        Ok(())
    }

    /// AC6: invalid rank-profile inputs are rejected fail-closed with the
    /// typed `Error::InvalidRankProfile` through both public paths —
    /// never clamped, skipped, or silently defaulted. Boundary-legal
    /// values stay accepted.
    #[test]
    fn rank_profile_validation_fails_closed() -> Result<()> {
        use crate::types::Bm25RankProfile;

        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "hello world")?;

        let cases: Vec<(&str, Bm25RankProfile, &'static str)> = vec![
            (
                "weight_nan",
                Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Surface, f64::NAN),
                "channel.weight",
            ),
            (
                "weight_negative",
                Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Surface, -0.1),
                "channel.weight",
            ),
            (
                "weight_infinite",
                Bm25RankProfile::default()
                    .with_channel_weight(AnalyzerChannel::Surface, f64::INFINITY),
                "channel.weight",
            ),
            (
                "b_nan",
                Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, f64::NAN),
                "channel.b",
            ),
            (
                "b_negative",
                Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, -0.01),
                "channel.b",
            ),
            (
                "b_above_one",
                Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Surface, 1.01),
                "channel.b",
            ),
            (
                "delta_nan",
                Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: f64::NAN }),
                "formula.delta",
            ),
            (
                "delta_zero",
                Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 0.0 }),
                "formula.delta",
            ),
            (
                "delta_negative",
                Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: -1.0 }),
                "formula.delta",
            ),
            (
                "delta_infinite",
                Bm25RankProfile::default().with_formula(Bm25Formula::Plus {
                    delta: f64::INFINITY,
                }),
                "formula.delta",
            ),
            (
                "weight_on_reserved_channel",
                Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Shingle, 0.5),
                "weight.reserved_channel",
            ),
            (
                "b_on_reserved_channel",
                Bm25RankProfile::default().with_channel_b(AnalyzerChannel::Phonetic, 0.5),
                "b.reserved_channel",
            ),
        ];

        for (case_name, profile, expected_parameter) in cases {
            let err = vault
                .search_text_with_profile("hello", 10, &profile)
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::InvalidRankProfile { parameter, .. } if parameter == expected_parameter
                ),
                "case {case_name}: expected InvalidRankProfile({expected_parameter}), got {err:?}",
            );

            // The pipeline fails closed too — even with no text search
            // attached, an invalid profile is a caller bug.
            let err = vault.query().rank_profile(profile).run().unwrap_err();
            assert!(
                matches!(err, Error::InvalidRankProfile { .. }),
                "case {case_name} (pipeline): expected InvalidRankProfile, got {err:?}",
            );
            assert_eq!(err.kind(), crate::error::ErrorKind::InvalidRankProfile);
        }

        // Boundary-legal values stay accepted: weight 0.0, b 0.0 / 1.0,
        // small positive delta; the last override per channel wins.
        let legal = crate::types::Bm25RankProfile::default()
            .with_formula(Bm25Formula::Plus { delta: 1e-6 })
            .with_channel_weight(AnalyzerChannel::Surface, 0.0)
            .with_channel_weight(AnalyzerChannel::Surface, 2.5)
            .with_channel_b(AnalyzerChannel::Stem, 0.0)
            .with_channel_b(AnalyzerChannel::CjkNgram, 1.0);
        let config = legal.to_bm25_config()?;
        assert_eq!(config.field(AnalyzerChannel::Surface).weight, 2.5);
        assert_eq!(config.field(AnalyzerChannel::Stem).b, 0.0);
        assert_eq!(config.field(AnalyzerChannel::CjkNgram).b, 1.0);
        assert_eq!(config.formula, Bm25Formula::Plus { delta: 1e-6 });
        assert!(vault.search_text_with_profile("hello", 10, &legal).is_ok());
        Ok(())
    }

    #[test]
    fn field_stats_track_per_field_lengths() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta gamma")?;

        let rtxn = vault.store.env.read_txn()?;
        let (doc_count, total_length) =
            read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?;
        assert_eq!(doc_count, 1);
        assert_eq!(total_length, 3);
        Ok(())
    }

    #[test]
    fn deindex_decrements_per_field_stats() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;
        assert!(vault.delete_entity(&id)?);

        let rtxn = vault.store.env.read_txn()?;
        let (doc_count, total_length) =
            read_field_stats(&vault.store, &rtxn, AnalyzerChannel::Surface.field_id())?;
        assert_eq!(doc_count, 0);
        assert_eq!(total_length, 0);
        Ok(())
    }

    #[test]
    fn cjk_ngram_field_length_reflects_bigram_count() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let short_id = EntityId::now();
        let long_id = EntityId::now();
        put_text_doc(&vault, &short_id, "東京")?;
        put_text_doc(&vault, &long_id, "東京大学研究所")?;

        let rtxn = vault.store.env.read_txn()?;
        let ngram_fid = AnalyzerChannel::CjkNgram.field_id();

        let read_len = |id: &EntityId| -> Result<u32> {
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(&rtxn, id.as_bytes())?
                .expect("doc must have field lengths");
            let map = decode_field_lengths(raw)?;
            Ok(map.get(&ngram_fid).copied().unwrap_or(0))
        };

        let short_len = read_len(&short_id)?;
        let long_len = read_len(&long_id)?;
        // "東京" → 1 bigram; "東京大学研究所" → 6 bigrams.
        assert_eq!(short_len, 1);
        assert_eq!(long_len, 6);

        let (doc_count, total_length) = read_field_stats(&vault.store, &rtxn, ngram_fid)?;
        assert_eq!(doc_count, 2);
        assert_eq!(total_length, u64::from(short_len) + u64::from(long_len));
        Ok(())
    }

    #[test]
    fn long_cjk_document_loses_to_short_one_on_shared_bigram() -> Result<()> {
        // Isolate CjkNgram by zeroing every other field so the assertion
        // doesn't ride on Surface/Stem length norm.
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let short_id = EntityId::now();
        let long_id = EntityId::now();
        put_text_doc(&vault, &short_id, "東京")?;
        put_text_doc(&vault, &long_id, "東京研究所大学図書館")?;

        let mut fields = [FieldConfig::disabled(); BM25_FIELD_COUNT];
        fields[AnalyzerChannel::CjkNgram.field_id() as usize] = FieldConfig {
            weight: 1.0,
            b: 0.30,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        let cjk_only = Bm25Config {
            k1: 1.2,
            formula: Bm25Formula::Okapi,
            fields,
        };

        let rtxn = vault.store.env.read_txn()?;
        let results = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &cjk_only,
            "東京",
            10,
        )?;
        let short_score = results
            .iter()
            .find(|r| r.id == short_id)
            .expect("short doc in results")
            .score;
        let long_score = results
            .iter()
            .find(|r| r.id == long_id)
            .expect("long doc in results")
            .score;
        assert!(
            short_score > long_score,
            "expected short doc to outrank long doc on CjkNgram channel once length norm fires: short={short_score} long={long_score}",
        );
        Ok(())
    }

    /// Each search-side variant corrupts BM25 state in a different way, then
    /// asserts `search_text` propagates `CorruptedIndex` rather than silently
    /// returning wrong rankings.
    ///
    /// Variants:
    /// - `corrupted_field_stats`: a `text_bm25_field_stats` row with the
    ///   wrong byte length (4 vs FIELD_STATS_LEN=12) — `read_field_stats`'s
    ///   length check must fire instead of swallowing as `avgdl = 0`.
    /// - `missing_field_lengths`: full `text_doc_field_lengths` row deleted.
    /// - `missing_field_stats_for_used_field`: stats row deleted for the
    ///   Surface fid that the corpus actually references.
    /// - `unknown_field_id`: posting entry rewritten to a fid that no
    ///   field schema covers (9999).
    /// - `df_exceeds_total_docs`: posting entry appends a phantom doc id,
    ///   driving DF above the corpus size.
    /// - `partial_field_lengths`: length row present but missing the
    ///   Surface fid — must not default `len_f = 0` (would give
    ///   `norm = 1 - b`, a 4× boost under default b=0.75).
    /// - `missing_lengths_for_nonorm_only_match`: the row-existence check
    ///   must fire even when no `CountLengthIncrement` field has non-zero
    ///   weight in the rank profile (pre-fix this was nested inside that
    ///   branch and NoNorm-only matches slipped past).
    #[test]
    #[allow(clippy::type_complexity)]
    fn search_fails_closed_on_all_corruption_variants() -> Result<()> {
        type Setup = fn(&Vault, &EntityId) -> Result<()>;
        fn setup_corrupted_field_stats(vault: &Vault, _id: &EntityId) -> Result<()> {
            let surface_fid = AnalyzerChannel::Surface.field_id();
            let mut wtxn = vault.store.env.write_txn()?;
            let short = [0_u8; 4];
            vault
                .store
                .text_bm25_field_stats
                .put(&mut wtxn, &surface_fid.to_be_bytes(), &short)?;
            wtxn.commit()?;
            Ok(())
        }
        fn setup_missing_field_lengths(vault: &Vault, id: &EntityId) -> Result<()> {
            let mut wtxn = vault.store.env.write_txn()?;
            assert!(
                vault
                    .store
                    .text_doc_field_lengths
                    .delete(&mut wtxn, id.as_bytes())?
            );
            wtxn.commit()?;
            Ok(())
        }
        fn setup_missing_field_stats_for_used_field(vault: &Vault, _id: &EntityId) -> Result<()> {
            let surface_fid = AnalyzerChannel::Surface.field_id();
            let mut wtxn = vault.store.env.write_txn()?;
            assert!(
                vault
                    .store
                    .text_bm25_field_stats
                    .delete(&mut wtxn, &surface_fid.to_be_bytes())?
            );
            wtxn.commit()?;
            Ok(())
        }
        fn setup_unknown_field_id(vault: &Vault, _id: &EntityId) -> Result<()> {
            let mut wtxn = vault.store.env.write_txn()?;
            // DUP_SORT: `get` returns the first duplicate item, which is
            // the doc's single posting entry here. Swap it for a copy
            // whose field id no schema covers.
            let original = vault
                .store
                .text_postings
                .get(&wtxn, b"alpha")?
                .expect("alpha posting written")
                .to_vec();
            let mut patched = original.clone();
            let fid_offset = ENTITY_ID_LEN + 1;
            patched[fid_offset..fid_offset + 2].copy_from_slice(&9999_u16.to_be_bytes());
            assert!(
                vault
                    .store
                    .text_postings
                    .delete_one_duplicate(&mut wtxn, b"alpha", &original)?
            );
            vault
                .store
                .text_postings
                .put(&mut wtxn, b"alpha", &patched)?;
            wtxn.commit()?;
            Ok(())
        }
        fn setup_df_exceeds_total_docs(vault: &Vault, _id: &EntityId) -> Result<()> {
            let mut wtxn = vault.store.env.write_txn()?;
            // Appending a phantom entity as a second duplicate drives the
            // dup count (df) above total_docs.
            let phantom = EntityId::now();
            let mut fields = std::collections::BTreeMap::new();
            fields.insert(AnalyzerChannel::Surface.field_id(), 1);
            let mut entry = Vec::new();
            encode_posting_entry(&phantom, &fields, &mut entry)?;
            vault.store.text_postings.put(&mut wtxn, b"alpha", &entry)?;
            wtxn.commit()?;
            Ok(())
        }
        fn setup_partial_field_lengths(vault: &Vault, id: &EntityId) -> Result<()> {
            let surface_fid = AnalyzerChannel::Surface.field_id();
            let mut wtxn = vault.store.env.write_txn()?;
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(&wtxn, id.as_bytes())?
                .expect("length row written on index")
                .to_vec();
            let mut lens = decode_field_lengths(&raw)?;
            assert!(lens.remove(&surface_fid).is_some());
            let patched = encode_field_lengths(&lens);
            vault
                .store
                .text_doc_field_lengths
                .put(&mut wtxn, id.as_bytes(), &patched)?;
            wtxn.commit()?;
            Ok(())
        }
        fn setup_missing_lengths_for_nonorm_only_match(vault: &Vault, id: &EntityId) -> Result<()> {
            let mut wtxn = vault.store.env.write_txn()?;
            assert!(
                vault
                    .store
                    .text_doc_field_lengths
                    .delete(&mut wtxn, id.as_bytes())?
            );
            wtxn.commit()?;
            Ok(())
        }

        // Default config + custom config for the NoNorm-only variant.
        let default_cfg = || Bm25Config::default();
        let nonorm_only_cfg = || {
            let mut config = Bm25Config::default();
            config.fields[AnalyzerChannel::Surface.field_id() as usize].weight = 0.0;
            config.fields[AnalyzerChannel::Stem.field_id() as usize].weight = 0.0;
            config.fields[AnalyzerChannel::CjkNgram.field_id() as usize].weight = 0.0;
            config
        };

        // (case_name, setup_fn, config_builder, doc_text)
        let cases: Vec<(&str, Setup, fn() -> Bm25Config, &str)> = vec![
            (
                "corrupted_field_stats",
                setup_corrupted_field_stats,
                default_cfg,
                "alpha beta",
            ),
            (
                "missing_field_lengths",
                setup_missing_field_lengths,
                default_cfg,
                "alpha beta",
            ),
            (
                "missing_field_stats_for_used_field",
                setup_missing_field_stats_for_used_field,
                default_cfg,
                "alpha beta",
            ),
            (
                "unknown_field_id",
                setup_unknown_field_id,
                default_cfg,
                "alpha beta",
            ),
            (
                "df_exceeds_total_docs",
                setup_df_exceeds_total_docs,
                default_cfg,
                "alpha beta",
            ),
            (
                "partial_field_lengths",
                setup_partial_field_lengths,
                default_cfg,
                "alpha beta",
            ),
            (
                "missing_lengths_for_nonorm_only_match",
                setup_missing_lengths_for_nonorm_only_match,
                nonorm_only_cfg,
                "alpha",
            ),
        ];

        for (case_name, setup, build_cfg, doc_text) in cases {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            put_text_doc(&vault, &id, doc_text)?;

            setup(&vault, &id)?;

            let cfg = build_cfg();
            let rtxn = vault.store.env.read_txn()?;
            let err = search_text(
                &vault.store,
                &rtxn,
                &MultilingualAnalyzer::portable(),
                &cfg,
                "alpha",
                10,
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::CorruptedIndex(_)),
                "case {case_name}: expected CorruptedIndex, got {err:?}"
            );
        }
        Ok(())
    }

    /// Each deindex-side variant corrupts the BM25 state then asserts
    /// `deindex_text` propagates `CorruptedIndex` rather than drifting the
    /// corpus stats.
    ///
    /// Variants:
    /// - `missing_field_lengths`: full lengths row deleted.
    /// - `forward_posting_membership_mismatch`: forward record lists the doc
    ///   for "alpha" but posting list has been rewritten without it.
    /// - `partial_field_lengths`: lengths row present but missing the
    ///   Surface fid — per-field stats decrement would silently skip while
    ///   total_docs-- still fires.
    /// - `orphan_length_entry`: lengths row carries a fid (9999) that no
    ///   forward record references — same drift class, inverse direction.
    /// - `zero_length_count_field`: zero length on the Surface channel
    ///   (which never emits zero-length tokens) would underflow
    ///   `total_length` decrement.
    #[test]
    fn deindex_fails_closed_on_all_corruption_variants() -> Result<()> {
        type Setup = fn(&Vault, &EntityId, &mut heed::RwTxn<'_>) -> Result<()>;
        fn setup_missing_field_lengths(
            vault: &Vault,
            id: &EntityId,
            wtxn: &mut heed::RwTxn<'_>,
        ) -> Result<()> {
            assert!(
                vault
                    .store
                    .text_doc_field_lengths
                    .delete(wtxn, id.as_bytes())?
            );
            Ok(())
        }
        fn setup_forward_posting_membership_mismatch(
            vault: &Vault,
            id: &EntityId,
            wtxn: &mut heed::RwTxn<'_>,
        ) -> Result<()> {
            // Caller pre-inserted a second doc "other" so the posting key
            // survives after this doc's duplicate item is removed.
            let entry = match find_posting_dup(&vault.store, wtxn, "alpha", id)? {
                PostingLookup::Found(entry) => entry,
                _ => panic!("alpha posting dup for doc must exist"),
            };
            assert!(
                vault
                    .store
                    .text_postings
                    .delete_one_duplicate(wtxn, b"alpha", &entry)?
            );
            Ok(())
        }
        fn setup_partial_field_lengths(
            vault: &Vault,
            id: &EntityId,
            wtxn: &mut heed::RwTxn<'_>,
        ) -> Result<()> {
            let surface_fid = AnalyzerChannel::Surface.field_id();
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(wtxn, id.as_bytes())?
                .expect("length row written on index")
                .to_vec();
            let mut lens = decode_field_lengths(&raw)?;
            assert!(lens.remove(&surface_fid).is_some());
            let patched = encode_field_lengths(&lens);
            vault
                .store
                .text_doc_field_lengths
                .put(wtxn, id.as_bytes(), &patched)?;
            Ok(())
        }
        fn setup_orphan_length_entry(
            vault: &Vault,
            id: &EntityId,
            wtxn: &mut heed::RwTxn<'_>,
        ) -> Result<()> {
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(wtxn, id.as_bytes())?
                .expect("length row written on index")
                .to_vec();
            let mut lens = decode_field_lengths(&raw)?;
            lens.insert(9999, 7);
            let patched = encode_field_lengths(&lens);
            vault
                .store
                .text_doc_field_lengths
                .put(wtxn, id.as_bytes(), &patched)?;
            Ok(())
        }
        fn setup_zero_length_count_field(
            vault: &Vault,
            id: &EntityId,
            wtxn: &mut heed::RwTxn<'_>,
        ) -> Result<()> {
            let surface_fid = AnalyzerChannel::Surface.field_id();
            let raw = vault
                .store
                .text_doc_field_lengths
                .get(wtxn, id.as_bytes())?
                .expect("length row written on index")
                .to_vec();
            let mut lens = decode_field_lengths(&raw)?;
            lens.insert(surface_fid, 0);
            let patched = encode_field_lengths(&lens);
            vault
                .store
                .text_doc_field_lengths
                .put(wtxn, id.as_bytes(), &patched)?;
            Ok(())
        }

        // (case_name, setup_fn, needs_second_doc)
        let cases: Vec<(&str, Setup, bool)> = vec![
            ("missing_field_lengths", setup_missing_field_lengths, false),
            (
                "forward_posting_membership_mismatch",
                setup_forward_posting_membership_mismatch,
                true,
            ),
            ("partial_field_lengths", setup_partial_field_lengths, false),
            ("orphan_length_entry", setup_orphan_length_entry, false),
            (
                "zero_length_count_field",
                setup_zero_length_count_field,
                false,
            ),
        ];

        for (case_name, setup, needs_second_doc) in cases {
            let temp_dir = tempfile::tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            if needs_second_doc {
                // Membership-mismatch variant needs a second doc on "alpha".
                let other = EntityId::now();
                put_text_doc(&vault, &id, "alpha")?;
                put_text_doc(&vault, &other, "alpha")?;
            } else {
                put_text_doc(&vault, &id, "alpha beta")?;
            }

            let mut wtxn = vault.store.env.write_txn()?;
            setup(&vault, &id, &mut wtxn)?;
            let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
            assert!(
                matches!(err, Error::CorruptedIndex(_)),
                "case {case_name}: expected CorruptedIndex, got {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn posting_decode_rejects_zero_tf() {
        let mut posting = Vec::new();
        let id = EntityId::now();
        posting.extend_from_slice(id.as_bytes());
        posting.push(1);
        posting.extend_from_slice(&AnalyzerChannel::Surface.field_id().to_be_bytes());
        posting.extend_from_slice(&0_u32.to_le_bytes());
        let err = decode_posting_entry(&posting).unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
    }

    #[test]
    fn posting_decode_rejects_truncated_entry() {
        let id = EntityId::now();
        let mut posting = id.as_bytes().to_vec();
        posting.push(1); // claim one field but supply no bytes
        let err = decode_posting_entry(&posting).unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
    }

    /// A v1-style concatenated multi-entry blob must NOT decode as a
    /// single duplicate item — exactly one entry per dup is the ONE-299
    /// invariant, so trailing bytes are corruption.
    #[test]
    fn posting_decode_rejects_concatenated_entries() -> Result<()> {
        let mut fields = BTreeMap::new();
        fields.insert(AnalyzerChannel::Surface.field_id(), 1_u32);
        let mut blob = Vec::new();
        encode_posting_entry(&EntityId::now(), &fields, &mut blob)?;
        encode_posting_entry(&EntityId::now(), &fields, &mut blob)?;
        let err = decode_posting_entry(&blob).unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
        Ok(())
    }

    #[test]
    fn decode_rejects_empty_rows() {
        assert!(decode_posting_entry(&[]).is_err());
        assert!(decode_forward(&[]).is_err());
        assert!(decode_field_lengths(&[]).is_err());
    }

    #[test]
    fn forward_roundtrips_utf8_terms() -> Result<()> {
        let mut m: BTreeMap<String, BTreeMap<u16, u32>> = BTreeMap::new();
        m.entry("東京".into()).or_default().insert(0, 1);
        m.entry("hello".into()).or_default().insert(0, 2);
        m.get_mut("hello").unwrap().insert(1, 1);
        let bytes = encode_forward(&m)?;
        let back = decode_forward(&bytes)?;
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].term, "hello");
        assert_eq!(back[2].term, "東京");
        Ok(())
    }

    /// ABI v4 forward record layout, literal bytes: `term_len_u16_le |
    /// term_bytes | field_id_u16_be` — and nothing else. An
    /// implementation still writing the dead v1 `tf` u32 FAILS here.
    #[test]
    fn forward_record_layout_drops_tf() -> Result<()> {
        let mut m: BTreeMap<String, BTreeMap<u16, u32>> = BTreeMap::new();
        m.entry("ab".into()).or_default().insert(3, 7);
        let bytes = encode_forward(&m)?;
        assert_eq!(bytes, vec![2, 0, b'a', b'b', 0, 3]);

        let back = decode_forward(&bytes)?;
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].term, "ab");
        assert_eq!(back[0].field_id, 3);
        Ok(())
    }

    /// A v1-shaped forward row (with the trailing `tf` u32 per record)
    /// must fail decoding, not silently misparse.
    #[test]
    fn forward_decode_rejects_v1_records_with_tf() {
        let v1_record = [2, 0, b'a', b'b', 0, 3, 7, 0, 0, 0];
        let err = decode_forward(&v1_record).unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
    }

    #[test]
    fn field_lengths_roundtrip() -> Result<()> {
        let mut m = HashMap::new();
        m.insert(0, 5);
        m.insert(2, 1);
        m.insert(3, 8);
        let bytes = encode_field_lengths(&m);
        let back = decode_field_lengths(&bytes)?;
        assert_eq!(back, m);
        Ok(())
    }

    fn collect_posting_dups(vault: &Vault, term: &[u8]) -> Result<Vec<Vec<u8>>> {
        let rtxn = vault.store.env.read_txn()?;
        let Some(dups) = vault.store.text_postings.get_duplicates(&rtxn, term)? else {
            return Ok(Vec::new());
        };
        let mut items = Vec::new();
        for item in dups {
            let (_, dup) = item?;
            items.push(dup.to_vec());
        }
        Ok(items)
    }

    /// ONE-299 AC1: `text_postings` holds one DUP_SORT duplicate item per
    /// (term, entity), bytewise-sorted so items order by entity-id
    /// prefix, and each item decodes standalone. A v1-style
    /// implementation that concatenates all entries under one value
    /// would yield a single dup here and FAIL the count assertion.
    #[test]
    fn postings_store_one_sorted_dup_item_per_entity() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
        for id in &ids {
            put_text_doc(&vault, id, "shared")?;
        }
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let items = collect_posting_dups(&vault, b"shared")?;
        assert_eq!(items.len(), 3, "one dup item per (term, entity)");
        for (item, id) in items.iter().zip(&ids) {
            assert_eq!(
                &item[..ENTITY_ID_LEN],
                id.as_bytes(),
                "dup items must sort by entity-id prefix",
            );
            let entry = decode_posting_entry(item)?;
            assert_eq!(entry.id, *id);
        }
        Ok(())
    }

    /// ONE-299 AC1 literal bytes: one dup item is exactly
    /// `entity_id(16) | field_count(u8) | field_id_u16_be | tf_u32_le`.
    /// "apple" stems to "appl", so the `apple` posting carries only the
    /// Surface channel (field id 0) with tf 2.
    #[test]
    fn posting_dup_item_literal_layout() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "apple apple")?;

        let items = collect_posting_dups(&vault, b"apple")?;
        assert_eq!(items.len(), 1);
        let mut expected = id.as_bytes().to_vec();
        expected.push(1); // field_count
        expected.extend_from_slice(&AnalyzerChannel::Surface.field_id().to_be_bytes());
        expected.extend_from_slice(&2_u32.to_le_bytes()); // tf, little-endian
        assert_eq!(items[0], expected);
        Ok(())
    }

    /// ONE-299 AC2: deindex deletes exactly ONE duplicate item — sibling
    /// entities' items survive byte-identical — and deleting the last
    /// duplicate removes the term key itself.
    #[test]
    fn deindex_deletes_exactly_one_dup_item() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
        for id in &ids {
            put_text_doc(&vault, id, "shared")?;
        }
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let before = collect_posting_dups(&vault, b"shared")?;
        assert_eq!(before.len(), 3);

        assert!(vault.delete_entity(&ids[1])?);
        let after = collect_posting_dups(&vault, b"shared")?;
        assert_eq!(after.len(), 2);
        assert_eq!(
            after[0], before[0],
            "untouched dup must stay byte-identical"
        );
        assert_eq!(
            after[1], before[2],
            "untouched dup must stay byte-identical"
        );

        assert!(vault.delete_entity(&ids[0])?);
        assert!(vault.delete_entity(&ids[2])?);
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.text_postings.get(&rtxn, b"shared")?.is_none(),
            "term key must disappear with its last duplicate",
        );
        Ok(())
    }

    /// Two duplicate items sharing one entity prefix violate the
    /// one-dup-per-(term, entity) invariant (df would drift). Both the
    /// search path and the deindex prefix scan must fail closed.
    #[test]
    fn duplicate_entity_dup_items_fail_closed() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha")?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            let mut fields = BTreeMap::new();
            fields.insert(AnalyzerChannel::Surface.field_id(), 9_u32);
            let mut second = Vec::new();
            encode_posting_entry(&id, &fields, &mut second)?;
            vault
                .store
                .text_postings
                .put(&mut wtxn, b"alpha", &second)?;
            wtxn.commit()?;
        }

        let rtxn = vault.store.env.read_txn()?;
        let err = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &Bm25Config::default(),
            "alpha",
            10,
        )
        .unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
        drop(rtxn);

        let mut wtxn = vault.store.env.write_txn()?;
        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_));
        Ok(())
    }
}
