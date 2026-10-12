//! A TURN's words as the sieve reads them: one chunk per source row, each
//! with the digest that versions it.

use crate::dreamer_consolidation::decode_turn_body;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// One source's text: a MESSAGE of the turn, or the TURN itself when its
/// body carries the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chunk {
    pub(crate) source: EntityId,
    pub(crate) text: String,
    /// BLAKE3 of the text: the version a span's offsets index.
    pub(crate) digest: [u8; 32],
}

impl Chunk {
    fn new(source: EntityId, text: String) -> Self {
        let digest = *blake3::Hasher::new()
            .update(b"oneiron:dreamer-sieve:chunk:v1")
            .update(text.as_bytes())
            .finalize()
            .as_bytes();
        Self {
            source,
            text,
            digest,
        }
    }
}

/// The chunks of a live TURN, `None` when it is absent, deleted, archived or
/// not a TURN. A TURN whose logical body carries `txt|text` (a document's
/// text when the field lives in one) reads as that one chunk, as a
/// consolidation branch reads it. A witnessed TURN reads its visible MESSAGE
/// rows in message order, the words its saved tags index.
pub(crate) fn turn_chunks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<Chunk>>> {
    let Some(members) = crate::tagging::turn_members_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    let LiveEntityRow::Live { entity_type, .. } = live_entity_row_in_txn(&vault.store, txn, turn)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_TURN {
        return Ok(None);
    }
    let Some(body) = crate::ports::safe_read_text(vault, txn, turn)? else {
        return Ok(None);
    };
    if let Some(text) = decode_turn_body(&body).text {
        return Ok(Some(vec![Chunk::new(*turn, text)]));
    }
    Ok(Some(
        members
            .into_iter()
            .filter_map(|(message, text)| Some(Chunk::new(message, text?)))
            .collect(),
    ))
}

/// The version of a whole reading: every chunk's source and digest, in order.
pub(super) fn reading_digest(chunks: &[Chunk]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-sieve:reading:v1");
    hash.update(&(chunks.len() as u64).to_be_bytes());
    for chunk in chunks {
        hash.update(chunk.source.as_bytes());
        hash.update(&chunk.digest);
    }
    *hash.finalize().as_bytes()
}
