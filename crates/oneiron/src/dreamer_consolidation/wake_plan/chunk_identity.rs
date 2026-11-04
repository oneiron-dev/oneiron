//! A sibling chunk's identity (FIX 7488): the parent its source attempt is
//! queued under, its branch, and the exact version of every TURN it owes,
//! read at the wake's one pin. That key is the queue's advisory dedupe, so
//! the same work owed by two attempts under one parent is queued once
//! (FIX 9351), and the sibling names the first to owe it. Whether a chunk
//! already completed also reads the attempt that first owed its work: a
//! retry prepared again re-queues none that already completed at those
//! same versions for that same origin; a chunk whose TURNs changed, or new
//! work, has a key of its own and stays owed. A completed chunk the queue
//! no longer lists is owed again: duplicate work, nothing lost.

use std::collections::{BTreeMap, BTreeSet};

use super::retry::Lineage;
use crate::EntityId;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::dreamer_consolidation::branch::QueuedBranch;

/// The domain of a chunk's key.
const KEY_DOMAIN: &[u8] = b"oneiron:dreamer:retry-chunk:v3";

/// Every chunk key's prefix: the dedupe key its sibling is queued under.
const KEY_PREFIX: &str = "retry-chunk:";

/// What a chunk's identity reads at the wake's pin: the frozen source pool
/// and every sibling chunk of the lane that completed, each as
/// [`completed_key`] names it.
#[derive(Clone, Copy)]
pub(super) struct ChunkPin<'p> {
    pub(super) sources: &'p BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    pub(super) completed: &'p BTreeSet<String>,
}

impl ChunkPin<'_> {
    /// `chunk`'s key under `lineage`: its branch's identity, the lineage's
    /// parent, and each TURN it owes with the learned-at and body digest the
    /// pin holds for it (a TURN the pin does not hold is marked absent). The
    /// origin is no part of it (FIX 9351): it is the pending dedupe.
    pub(super) fn key(&self, chunk: &QueuedBranch, lineage: &Lineage) -> String {
        let turns = chunk.turn_ids();
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(&chunk.identity());
        match lineage.parent {
            Some(parent) => {
                hasher.update(&[1]);
                hasher.update(parent.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&(turns.len() as u64).to_be_bytes());
        for turn in &turns {
            hasher.update(turn.as_bytes());
            match self.sources.get(turn) {
                Some((_, learned_at, body)) => {
                    hasher.update(&[1]);
                    hasher.update(&learned_at.to_be_bytes());
                    hasher.update(blake3::hash(body).as_bytes());
                }
                None => {
                    hasher.update(&[0]);
                }
            }
        }
        format!("{KEY_PREFIX}{}", hasher.finalize().to_hex())
    }

    /// Whether a sibling queued under `key` for the work `origin` first owed
    /// already completed.
    pub(super) fn completed(&self, key: &str, origin: AttemptId) -> bool {
        self.completed.contains(&completed_key(key, origin))
    }
}

/// A completed sibling as the completed check reads it: its key and the
/// attempt that first owed its work.
fn completed_key(key: &str, origin: AttemptId) -> String {
    format!(
        "{key}:{}",
        crate::entity_id::bytes_to_hex_lower(origin.as_bytes())
    )
}

/// Every sibling chunk of lane `kind` that completed, among `records`, as
/// [`completed_key`] names it. One whose payload names no origin is left
/// out: it is owed again, duplicate work, nothing lost.
pub(super) fn completed_chunks(records: &[AttemptRecord], kind: &str) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.kind == kind && record.state == AttemptState::Completed)
        .filter_map(|record| {
            let key = record.dedupe_key.as_deref()?;
            if !key.starts_with(KEY_PREFIX) {
                return None;
            }
            let payload =
                crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
            let origin = super::super::partition::decode_branch_origin(&payload.input)?;
            Some(completed_key(key, origin))
        })
        .collect()
}
