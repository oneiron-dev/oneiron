//! Binary codecs, stat/total-docs accessors, corruption constructors, key validation.
use std::collections::{BTreeMap, HashMap};

use heed::{RoTxn, RwTxn};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::short_id_prefix;
use oneiron_contracts::entity_id::EntityId;

use crate::text_index::ENTITY_ID_LEN;
use crate::text_index::FIELD_LENGTH_LEN;
use crate::text_index::FIELD_STATS_LEN;
use crate::text_index::FIELD_TF_LEN;
use crate::text_index::FORWARD_FIELD_ID_LEN;
use crate::text_index::FORWARD_TERM_LEN_LEN;
use crate::text_index::TOTAL_DOCS_KEY;
use crate::text_index::TOTAL_LENGTH_KEY;
use crate::text_index::diagnostics::Bm25DiagnosticKind;
use crate::text_index::diagnostics::Bm25Diagnostics;

// === Posting keys ===

/// LMDB refuses a key over 511 bytes (`MDB_MAXKEYSIZE`), so a term is its own
/// `text_postings` key only up to that length. Every term that fits keeps its
/// raw bytes, exactly as before.
pub const MAX_RAW_POSTING_KEY_BYTES: usize = 511;
/// How much of an over-long term its digest key keeps, so prefix expansion
/// still reaches it from a short query prefix.
const LONG_TERM_HEAD_BYTES: usize = 256;

/// The `text_postings` key for one term. A term over the LMDB key limit (a
/// pasted base64 blob is one word) keys as its head, a U+0001 separator, and
/// 128 bits of its BLAKE3 digest: stable across index, query and deindex, and
/// itself under the limit, so applying this to a stored key is the identity.
pub fn posting_key(term: &str) -> std::borrow::Cow<'_, str> {
    if term.len() <= MAX_RAW_POSTING_KEY_BYTES {
        return std::borrow::Cow::Borrowed(term);
    }
    let mut head = LONG_TERM_HEAD_BYTES;
    while !term.is_char_boundary(head) {
        head -= 1;
    }
    let digest = blake3::Hasher::new_derive_key("oneiron/bm25/long-term-posting-key/v1")
        .update(term.as_bytes())
        .finalize();
    std::borrow::Cow::Owned(format!("{}\u{1}{}", &term[..head], &digest.to_hex()[..32]))
}

// === Encoders / decoders ===

#[derive(Debug)]
pub struct PostingEntry {
    pub id: EntityId,
    pub fields: Vec<(u16, u32)>,
}

/// Outcome of looking up the posting duplicate item for one (term, entity).
pub enum PostingLookup {
    /// The term key does not exist in `text_postings` at all.
    RowMissing,
    /// The term key exists but carries no duplicate for the entity.
    EntityMissing,
    /// The single duplicate item, returned as owned bytes so the read
    /// borrow ends before `delete_one_duplicate` mutates the transaction.
    Found(Vec<u8>),
}

/// Decodes ONE posting duplicate item. The length must match the declared
/// `field_count` exactly — trailing bytes (e.g. a concatenated v1-style
/// multi-entry blob) are corruption, not extra entries.
pub fn decode_posting_entry(diagnostics: &Bm25Diagnostics, raw: &[u8]) -> Result<PostingEntry> {
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

pub fn encode_posting_entry(
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
pub struct ForwardRecord {
    pub term: String,
    pub field_id: u16,
}

/// Encodes the forward row as `[(term_len_u64_le | term_bytes |
/// field_id_u16_be)*]`, each term's full UTF-8 bytes whatever its length.
/// The per-field `tf` u32 that v1 carried was dead on the read side (deindex
/// only needs the term/field set) and was dropped in storage ABI v4 (ONE-299).
pub fn encode_forward(per_term: &BTreeMap<String, BTreeMap<u16, u32>>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (term, fields) in per_term {
        let len = u64::try_from(term.len())
            .map_err(|_| Error::ArithmeticOverflow("bm25 forward term length"))?;
        for fid in fields.keys() {
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(term.as_bytes());
            out.extend_from_slice(&fid.to_be_bytes());
        }
    }
    Ok(out)
}

pub fn decode_forward(raw: &[u8]) -> Result<Vec<ForwardRecord>> {
    if raw.is_empty() {
        return Err(corrupted("empty forward row"));
    }
    let mut records = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let Some((term_len_bytes, after_len)) = rest.split_first_chunk::<FORWARD_TERM_LEN_LEN>()
        else {
            return Err(corrupted("forward index truncated at term-len"));
        };
        let term_len = usize::try_from(u64::from_le_bytes(*term_len_bytes))
            .map_err(|_| corrupted("forward index truncated at term body"))?;
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

pub fn encode_field_lengths(lengths: &HashMap<u16, u32>) -> Vec<u8> {
    let mut pairs: Vec<(u16, u32)> = lengths.iter().map(|(k, v)| (*k, *v)).collect();
    pairs.sort_by_key(|&(fid, _)| fid);
    let mut out = Vec::with_capacity(pairs.len() * FIELD_LENGTH_LEN);
    for (fid, len) in pairs {
        out.extend_from_slice(&fid.to_be_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    out
}

pub fn decode_field_lengths(raw: &[u8]) -> Result<HashMap<u16, u32>> {
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

pub fn corrupted(message: &'static str) -> Error {
    Error::CorruptedIndex(message)
}

pub fn corrupted_with_diagnostic(
    diagnostics: &Bm25Diagnostics,
    message: &'static str,
    kind: Bm25DiagnosticKind,
) -> Error {
    diagnostics.record(kind);
    corrupted(message)
}

pub fn validate_text_doc_id(id: &EntityId) -> Result<()> {
    let bytes = id.as_bytes();
    if bytes == &TOTAL_DOCS_KEY
        || bytes == &TOTAL_LENGTH_KEY
        || (bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok())
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}
