//! The follower's log (FIX 7510): the ordered feed of newly admitted source
//! observations, read forward from the session's own change cursor. Each
//! TURN a change names is read once, as the sieve reads it, and its chunks
//! not yet framed append as one frame, rendered once and kept as its exact
//! bytes. A re-tag or a correction appends a new frame; no frame is ever
//! rewritten. A span the router sends here gets its chunk framed too, from
//! the words the sieve read at the span's digest, so no span waits on a
//! frame that never comes. A chunk the Dreamer may not read stays a hole
//! until a grant lets the sieve read it, and frames then.

use std::collections::{BTreeMap, BTreeSet};

use crate::dreamer_wake::SieveSpan;
use crate::dreamer_wake::sieve::follower::{CapturedChunk, capture_turn_in_txn, pins_in_txn};
use crate::error::Result;
use crate::ports::ChangeLogStoreRead;
use crate::store::Store;
use crate::{EntityId, Vault};

use super::state::{
    self, FollowerFrame, FrameChunk, Pin, Session, frame_texts, frames_in_txn, render_frame,
};

/// One frame as a prepare holds it: its row and, once read, its chunk texts.
pub(super) struct Held {
    pub(super) ordinal: u64,
    pub(super) frame: FollowerFrame,
    texts: Option<Vec<String>>,
}

impl Held {
    /// The frame's chunk texts, read from its bytes once.
    pub(super) fn texts(&mut self) -> Result<&[String]> {
        if self.texts.is_none() {
            self.texts = Some(frame_texts(&self.frame)?);
        }
        Ok(self.texts.as_deref().unwrap_or_default())
    }
}

/// The frames a session's prompt can still hold (those after its keyframe's
/// coverage), in order, and where each chunk they hold sits.
pub(super) struct Log {
    pub(super) frames: Vec<Held>,
    index: BTreeMap<(EntityId, EntityId, [u8; 32]), (u64, u32)>,
}

impl Log {
    pub(super) fn load_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        session: &Session,
    ) -> Result<Self> {
        let mut log = Self {
            frames: Vec::new(),
            index: BTreeMap::new(),
        };
        for (ordinal, frame) in
            frames_in_txn(store, txn, &session.key, session.state.covered_through)?
        {
            log.push(ordinal, frame, None);
        }
        Ok(log)
    }

    fn push(&mut self, ordinal: u64, frame: FollowerFrame, texts: Option<Vec<String>>) {
        for (chunk, held) in frame.chunks.iter().enumerate() {
            self.index
                .entry((frame.turn, held.source, held.digest))
                .or_insert((ordinal, chunk as u32));
        }
        self.frames.push(Held {
            ordinal,
            frame,
            texts,
        });
    }

    /// The frame and chunk holding `span`'s words at its digest, if framed.
    pub(super) fn find(&self, span: &SieveSpan) -> Option<(u64, u32)> {
        self.index
            .get(&(span.turn, span.source, span.source_digest))
            .copied()
    }

    pub(super) fn held_mut(&mut self, ordinal: u64) -> Option<&mut Held> {
        self.frames.iter_mut().find(|held| held.ordinal == ordinal)
    }
}

/// One observation a frame records.
struct Observation {
    turn: EntityId,
    chunks: Vec<CapturedChunk>,
    pins: Vec<(EntityId, String)>,
    change: Option<[u8; 16]>,
}

/// Renders and appends `observation` as the session's next frame.
fn append_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    session: &mut Session,
    log: &mut Log,
    observation: Observation,
) -> Result<u64> {
    let ordinal = session.state.next_frame;
    let mut chunks = Vec::with_capacity(observation.chunks.len());
    let mut texts = Vec::with_capacity(observation.chunks.len());
    for chunk in observation.chunks {
        chunks.push(FrameChunk {
            source: chunk.source,
            digest: chunk.digest,
        });
        texts.push(chunk.text);
    }
    let frame = FollowerFrame {
        turn: observation.turn,
        chunks,
        pins: observation
            .pins
            .into_iter()
            .map(|(document, version)| Pin { document, version })
            .collect(),
        change: observation.change,
        bytes: render_frame(ordinal, &texts)?,
    };
    let ordinal = state::append_frame_in_txn(store, txn, session, &frame)?;
    log.push(ordinal, frame, Some(texts));
    Ok(ordinal)
}

/// Reads the changes after the session's cursor, in order, and appends each
/// named TURN's readable chunks not yet framed, frozen as this transaction
/// reads them. The cursor moves past every change read, in the same commit.
pub(super) fn materialize_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    session: &mut Session,
    log: &mut Log,
) -> Result<()> {
    let mut last = session.state.materialized_after;
    let mut changed = Vec::new();
    {
        let read: &heed::RoTxn<'_> = txn;
        for entry in vault.store.port_changelog_after(read, last)? {
            let (id, change) = entry?;
            last = Some(id);
            changed.push((change.entity, id));
        }
    }
    let mut seen = BTreeSet::new();
    let mut turns = Vec::new();
    for (entity, change) in changed {
        for turn in super::super::text_turns_in_txn(&vault.store, txn, &entity)? {
            if seen.insert(turn) {
                turns.push((turn, change));
            }
        }
    }
    for (turn, change) in turns {
        let Some(captured) = capture_turn_in_txn(vault, txn, &turn)? else {
            continue;
        };
        let chunks: Vec<CapturedChunk> = captured
            .into_iter()
            .filter(|chunk| !log.index.contains_key(&(turn, chunk.source, chunk.digest)))
            .collect();
        if chunks.is_empty() {
            continue;
        }
        let ids: Vec<EntityId> = std::iter::once(turn)
            .chain(chunks.iter().map(|chunk| chunk.source))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        // A source the Dreamer cannot pin now is a hole: a span of it is
        // framed when it is routed, once the sieve reads it.
        let Some(pins) = pins_in_txn(vault, txn, &ids)? else {
            continue;
        };
        append_in_txn(
            &vault.store,
            txn,
            session,
            log,
            Observation {
                turn,
                chunks,
                pins,
                change: Some(change),
            },
        )?;
    }
    session.state.materialized_after = last;
    Ok(())
}

/// The frame and chunk `span`'s words are in: one the log holds, or a new
/// frame of the chunk as the sieve read it at the span's digest. `None`
/// when the chunk no longer reads at that digest, or its turn or source
/// cannot be pinned now: the span stays on its own rung.
pub(super) fn frame_span_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    session: &mut Session,
    log: &mut Log,
    span: &SieveSpan,
) -> Result<Option<(u64, u32)>> {
    if let Some(at) = log.find(span) {
        return Ok(Some(at));
    }
    let Some(text) = crate::dreamer_wake::sieve::follower::span_chunk_in_txn(vault, txn, span)?
    else {
        return Ok(None);
    };
    let ids: Vec<EntityId> = BTreeSet::from([span.turn, span.source])
        .into_iter()
        .collect();
    let Some(pins) = pins_in_txn(vault, txn, &ids)? else {
        return Ok(None);
    };
    let ordinal = append_in_txn(
        &vault.store,
        txn,
        session,
        log,
        Observation {
            turn: span.turn,
            chunks: vec![CapturedChunk {
                source: span.source,
                digest: span.source_digest,
                text,
            }],
            pins,
            change: None,
        },
    )?;
    Ok(Some((ordinal, 0)))
}

/// The words `span`'s offsets index in chunk `chunk` of frame `frame`.
pub(super) fn quote_in(
    log: &mut Log,
    frame: u64,
    chunk: u32,
    span: &SieveSpan,
) -> Result<Option<String>> {
    let Some(held) = log.held_mut(frame) else {
        return Ok(None);
    };
    let texts = held.texts()?;
    let Some(text) = usize::try_from(chunk)
        .ok()
        .and_then(|chunk| texts.get(chunk))
    else {
        return Ok(None);
    };
    let (Ok(start), Ok(end)) = (usize::try_from(span.start), usize::try_from(span.end)) else {
        return Ok(None);
    };
    Ok(text.get(start..end).map(str::to_owned))
}
