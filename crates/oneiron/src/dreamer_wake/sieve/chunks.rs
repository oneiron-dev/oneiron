//! A TURN's words as the sieve reads them: one chunk per source row, each
//! with the digest that versions it, read through the Dreamer's own gate.

use crate::dreamer_consolidation::{decode_turn_body, dreamer_may_read_messages_in};
use crate::error::{Error, Result};
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

/// What the sieve may read of one TURN.
pub(crate) struct TurnChunks {
    pub(crate) chunks: Vec<Chunk>,
    /// A MESSAGE with words the Dreamer may not read (a private row, or a
    /// relationship row without its live grant) gave no chunk.
    pub(crate) withheld: bool,
}

/// The chunks of a live TURN, `None` when it is absent, deleted, archived or
/// not a TURN. A TURN whose logical body carries `txt|text` (a document's
/// text when the field lives in one) reads as that one chunk, as a
/// consolidation branch reads it. A witnessed TURN reads its visible MESSAGE
/// rows in message order, the words its saved tags index, each only if the
/// Dreamer may read it.
pub(crate) fn turn_chunks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnChunks>> {
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
        return Ok(Some(TurnChunks {
            chunks: vec![Chunk::new(*turn, text)],
            withheld: false,
        }));
    }
    let ids: Vec<EntityId> = members.iter().map(|(message, _)| *message).collect();
    let readable = match dreamer_may_read_messages_in(vault, txn, &ids) {
        Ok(readable) => readable,
        // A read the gate refuses as a whole reads none of them.
        Err(Error::InvalidClaimBody(_)) => vec![false; ids.len()],
        Err(error) => return Err(error),
    };
    let mut withheld = false;
    let mut chunks = Vec::with_capacity(members.len());
    for ((message, text), readable) in members.into_iter().zip(readable) {
        let Some(text) = text else {
            continue;
        };
        if readable {
            chunks.push(Chunk::new(message, text));
        } else {
            withheld = true;
        }
    }
    Ok(Some(TurnChunks { chunks, withheld }))
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
