//! Binary codecs, stat/total-docs accessors, corruption constructors, key validation.
use std::collections::{BTreeMap, HashMap};

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::short_id_prefix;
use crate::store::ManifestDbs;

use super::diagnostics::{Bm25DiagnosticKind, Bm25Diagnostics};
use super::{
    ENTITY_ID_LEN, FIELD_LENGTH_LEN, FIELD_STATS_LEN, FIELD_TF_LEN, FORWARD_FIELD_ID_LEN,
    TOTAL_DOCS_KEY, TOTAL_LENGTH_KEY,
};

// === Encoders / decoders ===

#[derive(Debug)]
pub(super) struct PostingEntry {
    pub(super) id: EntityId,
    pub(super) fields: Vec<(u16, u32)>,
}

/// Outcome of looking up the posting duplicate item for one (term, entity).
pub(super) enum PostingLookup {
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
pub(super) fn find_posting_dup(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    term: &str,
    id: &EntityId,
) -> Result<PostingLookup> {
    let diagnostics = &store.diagnostics().bm25;
    let Some(dups) = store.text_postings().get_duplicates(txn, term.as_bytes())? else {
        return Ok(PostingLookup::RowMissing);
    };
    let mut found: Option<Vec<u8>> = None;
    for item in dups {
        let (_, dup) = item?;
        if dup.len() < ENTITY_ID_LEN + 1 {
            return Err(corrupted_with_diagnostic(
                diagnostics,
                "posting entry truncated at header",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        match dup[..ENTITY_ID_LEN].cmp(id.as_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if found.is_some() {
                    return Err(corrupted_with_diagnostic(
                        diagnostics,
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
pub(super) fn decode_posting_entry(
    diagnostics: &Bm25Diagnostics,
    raw: &[u8],
) -> Result<PostingEntry> {
    if raw.len() < ENTITY_ID_LEN + 1 {
        return Err(corrupted_with_diagnostic(
            diagnostics,
            "posting entry truncated at header",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        ));
    }
    let id_bytes: [u8; ENTITY_ID_LEN] = raw[..ENTITY_ID_LEN].try_into().map_err(|_| {
        corrupted_with_diagnostic(
            diagnostics,
            "posting entry id slice",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        )
    })?;
    let id = EntityId::from_bytes(id_bytes).map_err(|_| {
        corrupted_with_diagnostic(
            diagnostics,
            "posting entry has invalid id",
            Bm25DiagnosticKind::MalformedPostingAlignment,
        )
    })?;
    let field_count = raw[ENTITY_ID_LEN] as usize;
    if field_count == 0 {
        return Err(corrupted_with_diagnostic(
            diagnostics,
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
            diagnostics,
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
                diagnostics,
                "posting entry has zero term frequency",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        fields.push((fid, tf));
    }
    Ok(PostingEntry { id, fields })
}

pub(super) fn encode_posting_entry(
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
pub(super) struct ForwardRecord {
    pub(super) term: String,
    pub(super) field_id: u16,
}

/// Encodes the forward row as `[(term_len_u16_le | term_bytes |
/// field_id_u16_be)*]`. The per-field `tf` u32 that v1 carried was dead on
/// the read side (deindex only needs the term/field set) and was dropped
/// in storage ABI v4 (ONE-299).
pub(super) fn encode_forward(per_term: &BTreeMap<String, BTreeMap<u16, u32>>) -> Result<Vec<u8>> {
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

pub(super) fn decode_forward(raw: &[u8]) -> Result<Vec<ForwardRecord>> {
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

pub(super) fn encode_field_lengths(lengths: &HashMap<u16, u32>) -> Vec<u8> {
    let mut pairs: Vec<(u16, u32)> = lengths.iter().map(|(k, v)| (*k, *v)).collect();
    pairs.sort_by_key(|&(fid, _)| fid);
    let mut out = Vec::with_capacity(pairs.len() * FIELD_LENGTH_LEN);
    for (fid, len) in pairs {
        out.extend_from_slice(&fid.to_be_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    out
}

pub(super) fn decode_field_lengths(raw: &[u8]) -> Result<HashMap<u16, u32>> {
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

pub(super) fn read_field_stats(
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

pub(super) fn write_field_stats(
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

pub(super) fn write_total_docs(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    total_docs: u32,
) -> Result<()> {
    store
        .text_meta()
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    Ok(())
}

pub(super) fn corrupted(message: &'static str) -> Error {
    Error::CorruptedIndex(message)
}

pub(super) fn corrupted_with_diagnostic(
    diagnostics: &Bm25Diagnostics,
    message: &'static str,
    kind: Bm25DiagnosticKind,
) -> Error {
    diagnostics.record(kind);
    corrupted(message)
}

pub(super) fn validate_text_doc_id(id: &EntityId) -> Result<()> {
    let bytes = id.as_bytes();
    if bytes == &TOTAL_DOCS_KEY
        || bytes == &TOTAL_LENGTH_KEY
        || (bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok())
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}
