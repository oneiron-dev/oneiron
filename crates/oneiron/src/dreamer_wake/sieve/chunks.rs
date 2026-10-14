//! A TURN's words as the sieve reads them: one chunk per source row, each
//! with the digest that versions it, read through the Dreamer's own gate.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::dreamer_consolidation::{
    decode_turn_body, dreamer_may_read_messages_in, dreamer_may_read_turns_in,
};
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
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

/// A chunk as a read that stopped in it holds it: its source, its digest
/// and its length, so the read goes on without hashing it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChunkRef {
    pub(crate) source: EntityId,
    pub(crate) digest: [u8; 32],
    pub(crate) len: u64,
}

impl Chunk {
    pub(crate) fn held(&self) -> ChunkRef {
        ChunkRef {
            source: self.source,
            digest: self.digest,
            len: self.text.len() as u64,
        }
    }

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
/// not a TURN. A TURN the Dreamer may not read gives no chunk and waits, as
/// a branch refuses it. A TURN whose logical body carries `txt|text` (a
/// document's text when the field lives in one) reads as that one chunk, as
/// a consolidation branch reads it. A witnessed TURN reads its visible
/// MESSAGE rows in message order, the words its saved tags index, each only
/// if the Dreamer may read it.
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
    if turns_readable_in(vault, txn, &[*turn])? != [true] {
        return Ok(Some(TurnChunks {
            chunks: Vec::new(),
            withheld: true,
        }));
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
    let readable = readable_in(vault, txn, &ids)?;
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

/// Whether the Dreamer may read a source as a chunk of its turn now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Readable,
    /// The Dreamer's gate refuses the TURN, or the MESSAGE: a private row,
    /// or a relationship row whose grant is revoked, expired or never
    /// written.
    Unreadable,
    /// The turn is gone or archived, or the source is no longer part of it
    /// or is archived.
    Detached,
}

/// Whether the Dreamer may read each `(turn, source)` as a chunk of the turn
/// now, as [`turn_chunks_in_txn`] admits a chunk, without reading any text:
/// the rows first, then the Dreamer's gate over the turns left standing and
/// over their MESSAGEs, one call each, as a branch reads them (the TURN, and
/// each MESSAGE under the Dreamer's relationship grants).
pub(crate) fn admissions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pairs: &[(EntityId, EntityId)],
) -> Result<Vec<Admission>> {
    let mut live = BTreeMap::new();
    let mut attached = Vec::with_capacity(pairs.len());
    for (turn, source) in pairs {
        let turn_live = match live.get(turn) {
            Some(turn_live) => *turn_live,
            None => {
                let turn_live = turn_live_in(vault, txn, turn)?;
                live.insert(*turn, turn_live);
                turn_live
            }
        };
        attached.push(turn_live && (source == turn || part_of_in(vault, txn, turn, source)?));
    }
    let turns: Vec<EntityId> = live
        .into_iter()
        .filter_map(|(turn, turn_live)| turn_live.then_some(turn))
        .collect();
    let readable_turns: BTreeMap<EntityId, bool> = turns
        .iter()
        .copied()
        .zip(turns_readable_in(vault, txn, &turns)?)
        .collect();
    let turn_readable = |turn: &EntityId| readable_turns.get(turn) == Some(&true);
    let messages: Vec<EntityId> = pairs
        .iter()
        .zip(&attached)
        .filter(|((turn, source), attached)| **attached && source != turn && turn_readable(turn))
        .map(|((_, source), _)| *source)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let readable_messages: BTreeMap<EntityId, bool> = messages
        .iter()
        .copied()
        .zip(readable_in(vault, txn, &messages)?)
        .collect();
    Ok(pairs
        .iter()
        .zip(attached)
        .map(|((turn, source), attached)| {
            if !attached {
                Admission::Detached
            } else if turn_readable(turn)
                && (source == turn || readable_messages.get(source) == Some(&true))
            {
                Admission::Readable
            } else {
                Admission::Unreadable
            }
        })
        .collect())
}

/// Whether `turn` is a live TURN, not archived.
fn turn_live_in(vault: &Vault, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<bool> {
    let live = match live_entity_row_in_txn(&vault.store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } => entity_type == ENTITY_TYPE_TURN,
        _ => false,
    };
    Ok(live && vault.archive_tombstone_in_txn(txn, turn)?.is_none())
}

/// Whether `message` is still part of `turn`, and not archived.
fn part_of_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    message: &EntityId,
) -> Result<bool> {
    Ok(vault
        .store
        .port_edge_get(txn, message, crate::edge::EdgeKind::PartOf, turn)?
        .is_some()
        && vault.archive_tombstone_in_txn(txn, message)?.is_none())
}

/// The text of one chunk of `turn`, read as [`turn_chunks_in_txn`] reads it,
/// for a read that goes on in it: `None` when the turn or the source no
/// longer reads, the source is no longer part of the turn, or the Dreamer
/// may no longer read it.
pub(crate) fn chunk_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    source: &EntityId,
) -> Result<Option<String>> {
    if admissions_in_txn(vault, txn, &[(*turn, *source)])? != [Admission::Readable] {
        return Ok(None);
    }
    let body = crate::ports::safe_read_text(vault, txn, source)?;
    Ok(if source == turn {
        body.and_then(|body| decode_turn_body(&body).text)
    } else {
        body.and_then(|body| crate::tagging::shown_message_text(&body))
    })
}

/// Whether `turn` still holds each of `sources`, chunks a read of it has
/// passed, where the Dreamer may still read it, as [`chunk_text_in_txn`]
/// checks a chunk, without reading its text.
pub(crate) fn still_held_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    sources: &[EntityId],
) -> Result<bool> {
    let pairs: Vec<(EntityId, EntityId)> = sources.iter().map(|source| (*turn, *source)).collect();
    Ok(admissions_in_txn(vault, txn, &pairs)?
        .into_iter()
        .all(|admission| admission == Admission::Readable))
}

/// Which of `messages` the Dreamer may read.
fn readable_in(vault: &Vault, txn: &heed::RoTxn<'_>, messages: &[EntityId]) -> Result<Vec<bool>> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }
    refused_as_none(dreamer_may_read_messages_in(vault, txn, messages), messages)
}

/// Which of `turns` the Dreamer may read.
fn turns_readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turns: &[EntityId],
) -> Result<Vec<bool>> {
    if turns.is_empty() {
        return Ok(Vec::new());
    }
    refused_as_none(dreamer_may_read_turns_in(vault, txn, turns), turns)
}

/// A read the gate refuses as a whole reads none of `ids`.
fn refused_as_none(readable: Result<Vec<bool>>, ids: &[EntityId]) -> Result<Vec<bool>> {
    match readable {
        Err(Error::InvalidClaimBody(_)) => Ok(vec![false; ids.len()]),
        readable => readable,
    }
}

/// The version of a whole reading: every chunk's source and digest, in order.
pub(super) fn reading_digest(chunks: &[ChunkRef]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-sieve:reading:v1");
    hash.update(&(chunks.len() as u64).to_be_bytes());
    for chunk in chunks {
        hash.update(chunk.source.as_bytes());
        hash.update(&chunk.digest);
    }
    *hash.finalize().as_bytes()
}
