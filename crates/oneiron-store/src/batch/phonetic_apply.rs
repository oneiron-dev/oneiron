use std::collections::HashSet;
use std::str;

use heed::RwTxn;

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::StoreError;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;
pub mod checkpoint;

pub fn log_phonetic_forward_fallback(id: &EntityId, reason: &'static str) {
    tracing::warn!(
        entity = %id.to_hex(),
        reason,
        "phonetic_forward unavailable during delete; falling back to full scan"
    );
}

/// The length of every physical `phonetic_index` key ([`phonetic_posting_key`]).
pub const PHONETIC_POSTING_KEY_LEN: usize = blake3::OUT_LEN;

/// The physical `phonetic_index` key of `code` (FIX 5340): a BLAKE3 digest
/// of the whole code. Every put, get and delete of a code's posting keys by
/// it, so a code of any length fits LMDB's key bound and still matches only
/// itself; the forward and source rows keep the code itself, uncut.
pub fn phonetic_posting_key(code: &str) -> [u8; PHONETIC_POSTING_KEY_LEN] {
    *blake3::hash(code.as_bytes()).as_bytes()
}

pub fn validate_phonetic_code(code: &str) -> Result<()> {
    if code.is_empty() || code.as_bytes().contains(&0) {
        return Err(Error::InvalidKey);
    }

    Ok(())
}

pub fn posting_without_entity(posting: &[u8], id: &EntityId) -> Result<Option<Vec<u8>>> {
    if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
        return Err(Error::CorruptedIndex("phonetic posting"));
    }

    let retained: Vec<u8> = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk != id.as_bytes())
        .flat_map(|chunk| chunk.iter().copied())
        .collect();

    Ok((retained.len() != posting.len()).then_some(retained))
}

pub fn decode_phonetic_forward_codes(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Err(Error::CorruptedIndex("phonetic forward row"));
    }

    let mut codes: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(Error::CorruptedIndex("phonetic forward row"));
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| Error::CorruptedIndex("phonetic forward row"))
        })
        .collect::<Result<_>>()?;
    codes.sort();
    codes.dedup();
    Ok(codes)
}

pub fn encode_phonetic_forward_codes(codes: &[String]) -> Vec<u8> {
    codes.join("\0").into_bytes()
}
