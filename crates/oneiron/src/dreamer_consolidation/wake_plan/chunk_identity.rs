//! A sibling chunk's identity (FIX 7488): the exact lineage it is owed
//! under (its source attempt's parent and the attempt that first owed its
//! work), its branch, and the exact version of every TURN it owes, read at
//! the wake's one pin. A retry prepared again re-queues no chunk that is
//! still pending (the queue's advisory dedupe on this key) and none that
//! already completed at those same versions; a chunk whose TURNs changed,
//! or new work, has a key of its own and stays owed. A completed chunk the
//! queue no longer lists is owed again: duplicate work, nothing lost.

use std::collections::{BTreeMap, BTreeSet};

use super::retry::Lineage;
use crate::EntityId;
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::dreamer_consolidation::branch::QueuedBranch;

/// The domain of a chunk's key.
const KEY_DOMAIN: &[u8] = b"oneiron:dreamer:retry-chunk:v2";

/// Every chunk key's prefix: the dedupe key its sibling is queued under.
const KEY_PREFIX: &str = "retry-chunk:";

/// What a chunk's identity reads at the wake's pin: the frozen source pool
/// and the key of every sibling chunk of the lane that completed.
#[derive(Clone, Copy)]
pub(super) struct ChunkPin<'p> {
    pub(super) sources: &'p BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    pub(super) completed: &'p BTreeSet<String>,
}

impl ChunkPin<'_> {
    /// `chunk`'s key under `lineage`: its branch's identity, the lineage's
    /// parent and origin, and each TURN it owes with the learned-at and
    /// body digest the pin holds for it (a TURN the pin does not hold is
    /// marked absent).
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
        hasher.update(lineage.origin.as_bytes());
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

    /// Whether a sibling queued under `key` already completed.
    pub(super) fn completed(&self, key: &str) -> bool {
        self.completed.contains(key)
    }
}

/// The key of every sibling chunk of lane `kind` that completed, among
/// `records`.
pub(super) fn completed_chunks(records: &[AttemptRecord], kind: &str) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.kind == kind && record.state == AttemptState::Completed)
        .filter_map(|record| record.dedupe_key.as_deref())
        .filter(|key| key.starts_with(KEY_PREFIX))
        .map(str::to_owned)
        .collect()
}
