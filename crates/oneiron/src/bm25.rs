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
//! Storage (plan §4.1):
//! * `text_postings` value: `[(entity_id(16) | field_count(u8) |
//!   (field_id_u16_be | tf_u32_le)*)]×N`
//! * `text_forward` value: `[(term_len_u16_le | term_bytes |
//!   field_id_u16_be | tf_u32_le)*]`
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

use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer, Token};
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

/// BM25 scoring variant. `Okapi` is the default; `Plus` adds a constant
/// offset to the TF term per Lv & Zhai 2011.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Bm25Formula {
    Okapi,
    #[allow(dead_code)] // exposed through Bm25Config once types.rs plumbs user config
    Plus {
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

    // === Postings: append one (entity_id, field_tfs) entry per term ===
    for (term, fields_tf) in &per_term {
        let mut posting = read_posting(store, wtxn, term)?;
        encode_posting_entry(id, fields_tf, &mut posting)?;
        store.text_postings.put(wtxn, term.as_bytes(), &posting)?;
    }

    // === Forward index: (term_len, term, field_id, tf) records ===
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
    let lengths = match store.text_doc_field_lengths.get(wtxn, id.as_bytes())? {
        Some(raw) => decode_field_lengths(raw)?,
        None => return Err(corrupted("missing field lengths for indexed document")),
    };

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
        // posting row is corruption, not a normal "term gone" condition.
        // Silently skipping would let `total_docs--` fire below while the
        // already-missing posting bytes remain unaccounted for.
        let Some(posting) = store.text_postings.get(wtxn, term.as_bytes())? else {
            return Err(corrupted(
                "forward term references missing posting row during deindex",
            ));
        };
        let (retained, removed) = strip_entity_from_posting(posting, id)?;
        if !removed {
            continue;
        }
        if retained.is_empty() {
            store.text_postings.delete(wtxn, term.as_bytes())?;
        } else {
            store.text_postings.put(wtxn, term.as_bytes(), &retained)?;
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

pub(crate) fn search_text(
    store: &Store,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut tokens: Vec<Token> = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    // Dedupe query terms across channels — one term per unique string
    // (scorer looks up posting list then combines field TFs from the
    // posting entries themselves). This preserves the pre-ONE-317
    // "query dedupe" semantics.
    let mut unique_terms: Vec<String> = tokens
        .into_iter()
        .map(|t| t.term.as_ref().to_owned())
        .collect();
    unique_terms.sort();
    unique_terms.dedup();

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

    for term in unique_terms {
        let Some(posting) = store.text_postings.get(rtxn, term.as_bytes())? else {
            continue;
        };

        let entries = decode_posting(posting)?;
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
                let map = match raw {
                    Some(bytes) => decode_field_lengths(bytes)?,
                    None => return Err(corrupted("missing field lengths for scored doc")),
                };
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
            *scores.entry(id).or_insert(0.0) += contribution;
        }
    }

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

fn decode_posting(raw: &[u8]) -> Result<Vec<PostingEntry>> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if i + ENTITY_ID_LEN + 1 > raw.len() {
            return Err(corrupted("posting truncated at entry header"));
        }
        let id_bytes: [u8; ENTITY_ID_LEN] = raw[i..i + ENTITY_ID_LEN]
            .try_into()
            .map_err(|_| corrupted("posting entry id slice"))?;
        let id = EntityId::from_bytes(id_bytes)
            .map_err(|_| corrupted("posting entry has invalid id"))?;
        let field_count = raw[i + ENTITY_ID_LEN] as usize;
        if field_count == 0 {
            return Err(corrupted("posting entry has zero field count"));
        }
        let body_start = i + ENTITY_ID_LEN + 1;
        let body_end = body_start + field_count * FIELD_TF_LEN;
        if body_end > raw.len() {
            return Err(corrupted("posting truncated at field-tf body"));
        }
        let mut fields = Vec::with_capacity(field_count);
        for chunk in raw[body_start..body_end].chunks_exact(FIELD_TF_LEN) {
            let fid = u16::from_be_bytes([chunk[0], chunk[1]]);
            let tf = u32::from_le_bytes(
                chunk[2..6]
                    .try_into()
                    .map_err(|_| corrupted("posting tf slice"))?,
            );
            if tf == 0 {
                return Err(corrupted("posting entry has zero term frequency"));
            }
            fields.push((fid, tf));
        }
        entries.push(PostingEntry { id, fields });
        i = body_end;
    }
    Ok(entries)
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

struct ForwardRecord {
    term: String,
    field_id: u16,
    #[allow(dead_code)] // read only when we need to regenerate postings
    tf: u32,
}

fn encode_forward(per_term: &BTreeMap<String, BTreeMap<u16, u32>>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (term, fields) in per_term {
        let len = u16::try_from(term.len())
            .map_err(|_| Error::ArithmeticOverflow("bm25 forward term length"))?;
        for (fid, tf) in fields {
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(term.as_bytes());
            out.extend_from_slice(&fid.to_be_bytes());
            out.extend_from_slice(&tf.to_le_bytes());
        }
    }
    Ok(out)
}

fn decode_forward(raw: &[u8]) -> Result<Vec<ForwardRecord>> {
    let mut records = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if i + 2 > raw.len() {
            return Err(corrupted("forward index truncated at term-len"));
        }
        let term_len = u16::from_le_bytes([raw[i], raw[i + 1]]) as usize;
        i += 2;
        if term_len == 0 {
            return Err(corrupted("forward index has zero-length term"));
        }
        let term_end = i + term_len;
        if term_end + FIELD_TF_LEN > raw.len() {
            return Err(corrupted("forward index truncated at term body"));
        }
        let term = str::from_utf8(&raw[i..term_end])
            .map(str::to_owned)
            .map_err(|_| corrupted("forward index has non-utf8 term"))?;
        i = term_end;
        let field_id = u16::from_be_bytes([raw[i], raw[i + 1]]);
        let tf = u32::from_le_bytes(
            raw[i + 2..i + 6]
                .try_into()
                .map_err(|_| corrupted("forward index tf slice"))?,
        );
        if tf == 0 {
            return Err(corrupted("forward index has zero tf"));
        }
        i += FIELD_TF_LEN;
        records.push(ForwardRecord { term, field_id, tf });
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
    if !raw.len().is_multiple_of(FIELD_LENGTH_LEN) {
        return Err(corrupted("per-doc field lengths has invalid byte length"));
    }
    let mut map = HashMap::with_capacity(raw.len() / FIELD_LENGTH_LEN);
    for chunk in raw.chunks_exact(FIELD_LENGTH_LEN) {
        let fid = u16::from_be_bytes([chunk[0], chunk[1]]);
        let len = u32::from_le_bytes(
            chunk[2..6]
                .try_into()
                .map_err(|_| corrupted("field length slice"))?,
        );
        map.insert(fid, len);
    }
    Ok(map)
}

fn read_field_stats(store: &Store, txn: &RoTxn<'_>, field_id: u16) -> Result<(u32, u64)> {
    let key = field_id.to_be_bytes();
    match store.text_bm25_field_stats.get(txn, &key)? {
        Some(raw) => {
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
        None => Ok((0, 0)),
    }
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

fn read_posting(store: &Store, txn: &RoTxn<'_>, term: &str) -> Result<Vec<u8>> {
    Ok(store
        .text_postings
        .get(txn, term.as_bytes())?
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default())
}

fn strip_entity_from_posting(posting: &[u8], id: &EntityId) -> Result<(Vec<u8>, bool)> {
    let entries = decode_posting(posting)?;
    let mut out = Vec::with_capacity(posting.len());
    let mut removed = false;
    for entry in entries {
        if &entry.id == id {
            removed = true;
            continue;
        }
        let mut fields = BTreeMap::new();
        for (fid, tf) in entry.fields {
            fields.insert(fid, tf);
        }
        encode_posting_entry(&entry.id, &fields, &mut out)?;
    }
    Ok((out, removed))
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
        vault
            .batch()
            .put(id, 0, test_time_range(1, 1), 2, b"text-doc")
            .text(id, &[("body", text)])
            .commit()
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
                    0,
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
            .put(&id, 0, test_time_range(1, 1), 2, b"empty")
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
            assert!(matches!(err, Error::InvalidKey));
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

    #[test]
    fn search_fails_closed_on_corrupted_field_stats() -> Result<()> {
        // A `text_bm25_field_stats` row with the wrong byte length must
        // propagate `CorruptedIndex` through the scorer rather than being
        // silently swallowed as `avgdl = 0` (which would return wrong
        // rankings instead of failing closed).
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        // Valid row is FIELD_STATS_LEN (12) bytes; a 4-byte row trips
        // `read_field_stats`'s length check.
        let short = [0_u8; 4];
        vault
            .store
            .text_bm25_field_stats
            .put(&mut wtxn, &surface_fid.to_be_bytes(), &short)?;
        wtxn.commit()?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn search_fails_closed_on_missing_field_lengths() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(&mut wtxn, id.as_bytes())?
        );
        wtxn.commit()?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn search_fails_closed_on_missing_field_stats_for_used_field() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_bm25_field_stats
                .delete(&mut wtxn, &surface_fid.to_be_bytes())?
        );
        wtxn.commit()?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn search_fails_closed_on_unknown_field_id() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        let mut posting = vault
            .store
            .text_postings
            .get(&wtxn, b"alpha")?
            .expect("alpha posting written")
            .to_vec();
        let fid_offset = ENTITY_ID_LEN + 1;
        posting[fid_offset..fid_offset + 2].copy_from_slice(&9999_u16.to_be_bytes());
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        wtxn.commit()?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn search_fails_closed_on_df_exceeds_total_docs() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        let mut posting = vault
            .store
            .text_postings
            .get(&wtxn, b"alpha")?
            .expect("alpha posting written")
            .to_vec();
        let phantom = EntityId::now();
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(AnalyzerChannel::Surface.field_id(), 1);
        encode_posting_entry(&phantom, &fields, &mut posting)?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"alpha", &posting)?;
        wtxn.commit()?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn deindex_fails_closed_on_missing_field_lengths() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(&mut wtxn, id.as_bytes())?
        );
        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    /// Row present but missing the `Surface` fid. Scorer must not silently
    /// default `len_f = 0`, which would yield `norm = 1 - b` (a 4× boost
    /// under default b=0.75) for the corrupted document.
    #[test]
    fn search_fails_closed_on_partial_field_lengths() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

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
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    /// Row present but missing a forward-referenced fid. Deindex must refuse
    /// to run: the per-field `text_bm25_field_stats` decrement at the
    /// length-loop site would silently skip while `total_docs--` still
    /// fires, drifting the corpus.
    #[test]
    fn deindex_fails_closed_on_partial_field_lengths() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

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

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    /// Inverse: length row lists a fid with no matching forward entry.
    /// Same drift class — forward-loop decrements fire for a subset of
    /// fields that doesn't cover the lengths map.
    #[test]
    fn deindex_fails_closed_on_orphan_length_entry() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let mut wtxn = vault.store.env.write_txn()?;
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(&wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        // Inject an orphan fid that no forward record will reference.
        lens.insert(9999, 7);
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(&mut wtxn, id.as_bytes(), &patched)?;

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    /// A zero length on Surface (a channel that never emits zero-length
    /// tokens) means the lengths row was corrupted — deindex must refuse
    /// rather than silently underflow `total_length` decrement.
    #[test]
    fn deindex_fails_closed_on_zero_length_count_field() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha beta")?;

        let surface_fid = AnalyzerChannel::Surface.field_id();
        let mut wtxn = vault.store.env.write_txn()?;
        let raw = vault
            .store
            .text_doc_field_lengths
            .get(&wtxn, id.as_bytes())?
            .expect("length row written on index")
            .to_vec();
        let mut lens = decode_field_lengths(&raw)?;
        lens.insert(surface_fid, 0);
        let patched = encode_field_lengths(&lens);
        vault
            .store
            .text_doc_field_lengths
            .put(&mut wtxn, id.as_bytes(), &patched)?;

        let err = deindex_text(&vault.store, &mut wtxn, &id).unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
        Ok(())
    }

    /// Row-existence must fire even when no `CountLengthIncrement` field
    /// has non-zero weight in the rank profile — pre-fix the lookup was
    /// nested inside that branch and a NoNorm-only match slipped past.
    #[test]
    fn search_fails_closed_on_missing_lengths_for_nonorm_only_match() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = EntityId::now();
        put_text_doc(&vault, &id, "alpha")?;

        let mut wtxn = vault.store.env.write_txn()?;
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .delete(&mut wtxn, id.as_bytes())?
        );
        wtxn.commit()?;

        let mut config = Bm25Config::default();
        config.fields[AnalyzerChannel::Surface.field_id() as usize].weight = 0.0;
        config.fields[AnalyzerChannel::Stem.field_id() as usize].weight = 0.0;
        config.fields[AnalyzerChannel::CjkNgram.field_id() as usize].weight = 0.0;

        let rtxn = vault.store.env.read_txn()?;
        let err = search_text(
            &vault.store,
            &rtxn,
            &MultilingualAnalyzer::portable(),
            &config,
            "alpha",
            10,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}"
        );
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
        let err = decode_posting(&posting).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));
    }

    #[test]
    fn posting_decode_rejects_truncated_entry() {
        let id = EntityId::now();
        let mut posting = id.as_bytes().to_vec();
        posting.push(1); // claim one field but supply no bytes
        let err = decode_posting(&posting).unwrap_err();
        assert!(matches!(err, Error::CorruptedIndex(_)));
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
}
