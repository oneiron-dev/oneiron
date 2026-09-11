//! Index/deindex mutation paths plus the missing-posting repair proof.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use heed::{RoTxn, RwTxn};

use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer, Token};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

use super::codec::{
    PostingLookup, corrupted, decode_field_lengths, decode_forward, encode_field_lengths,
    encode_forward, encode_posting_entry, find_posting_dup, read_field_stats, read_total_docs,
    validate_text_doc_id, write_field_stats, write_total_docs,
};
use super::diagnostics::Bm25DiagnosticKind;
use super::{DOC_META_LEN, ENTITY_ID_LEN, FIELD_STATS_LEN};

// === Indexing ===

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
            store.diagnostics().bm25.record(kind);
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
