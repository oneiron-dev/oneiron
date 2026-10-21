//! Rule 5 for a selection retry's source budget (L02-38): `max_sources` is a
//! work size, never a total. A retry runs every original with the oldest
//! other sources that fit; the newer rest is split into sibling chunks of
//! that same size, each an ordinary consolidation attempt of its own, queued
//! once the wake's read transaction has closed.
//!
//! A sibling owes exactly its turns. Each passed the retry's own admission at
//! the wake's snapshot (readable by the Dreamer, an admissible role, the
//! part's world and facet); the sibling carries no branch scope of its own,
//! sits under the retry's own parent, and reads its turns again through the
//! same scoped read at its own wake. A source that fails there refuses or
//! defers that chunk alone, never the retry.
//!
//! A multi-part branch's part that cannot be read whole at the snapshot is
//! owed the same way (FIX 7524, Engine ruling B): a one-part sibling of the
//! same thing and watermark, so the other parts run. Every sibling names the
//! attempt that first owed its work (`origin`), which the nightly merge fans
//! it in beside.

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::ConversationPart;
use crate::dreamer_consolidation::branch::QueuedBranch;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, Result, Vault};

use super::retry::Lineage;

/// The widening floor a sibling chunk is queued with. No TURN is learned at
/// or after it, so a retry of the chunk itself reads its own turns only: a
/// deferred chunk never splits its conversation again.
const CHUNK_WIDENS_NOTHING: u64 = u64::MAX;

/// The work one prepared attempt owes as siblings.
#[derive(Debug, Clone)]
pub(super) struct WakePreparationChunks {
    /// The attempt whose preparation owed them.
    source: [u8; 16],
    origin: AttemptId,
    parent: Option<AttemptId>,
    run_id: Option<String>,
    chunks: Vec<QueuedBranch>,
}

impl WakePreparationChunks {
    /// `chunks` owed by `source` under its `lineage`; `None` when there are
    /// none.
    pub(super) fn new(
        source: [u8; 16],
        lineage: &Lineage,
        chunks: Vec<QueuedBranch>,
    ) -> Option<Self> {
        if chunks.is_empty() {
            return None;
        }
        Some(Self {
            source,
            origin: lineage.origin,
            parent: lineage.parent,
            run_id: lineage.run_id.clone(),
            chunks,
        })
    }

    /// Queues every chunk in the caller's commit; returns how many were new.
    /// Each chunk's sibling, new or standing, carries the sieve receipts the
    /// source carried for its TURNs from this commit on (FIX 7498).
    fn enqueue_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        scope: DreamerConsolidationScope,
    ) -> Result<usize> {
        let store = DreamerRunnerStore::new(vault);
        let now = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        let source = AttemptId::from_bytes(&self.source)?;
        let mut queued = 0_usize;
        for chunk in &self.chunks {
            let outcome = store.enqueue_consolidation_in_txn(
                txn,
                EnqueueDreamerConsolidationAttempt {
                    scope,
                    input: super::super::partition::encode_branch_payload(chunk, Some(self.origin)),
                    parent_attempt: self.parent,
                    dedupe_key: Some(self.chunk_key(chunk)),
                    run_id: self.run_id.clone(),
                    now,
                },
            )?;
            let sibling = match &outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
            };
            let moved = crate::dreamer_wake::sieve::retarget_consumed_in_txn(
                &vault.store,
                txn,
                source,
                sibling,
                &chunk.turn_ids(),
            )?;
            if moved > 0 {
                tracing::debug!(
                    retry = %bytes_to_hex_lower(&self.source),
                    sibling = %bytes_to_hex_lower(sibling.as_bytes()),
                    moved,
                    "sieve receipts follow their TURNs to the split-off sibling"
                );
            }
            if matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_)) {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// One chunk's advisory dedupe key, by the exact turns it owes under its
    /// parent and branch: a retry prepared again re-queues no chunk that is
    /// still pending. A one-part chunk's branch identity is its partition's
    /// hash, the key it had.
    fn chunk_key(&self, chunk: &QueuedBranch) -> String {
        let turns = chunk.turn_ids();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:dreamer:retry-chunk:v1");
        hasher.update(&chunk.identity());
        match self.parent {
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
        }
        format!("retry-chunk:{}", hasher.finalize().to_hex())
    }
}

/// The parts of `branch` at `indexes`, each a one-part sibling of the same
/// thing that owes exactly its queued turns from its own watermark.
pub(super) fn split_parts(branch: &QueuedBranch, indexes: &[usize]) -> Vec<QueuedBranch> {
    indexes
        .iter()
        .filter_map(|index| branch.parts.get(*index))
        .map(|part| QueuedBranch {
            world_ref: branch.world_ref,
            facet_ref: branch.facet_ref,
            thing: branch.thing,
            parts: vec![part.clone()],
        })
        .collect()
}

/// A retry's `overflow` (each TURN by its part index, in selection order),
/// split per conversation into chunks of the resolved source budget `size`.
/// A chunk names no thing: what widening found may be another thing's, and
/// it stays in its own conversation's structural grain.
pub(super) fn overflow_chunks(
    branch: &QueuedBranch,
    overflow: Vec<(usize, EntityId)>,
    size: usize,
) -> Vec<QueuedBranch> {
    let mut by_part: Vec<(usize, Vec<EntityId>)> = Vec::new();
    for (index, turn) in overflow {
        match by_part.iter_mut().find(|(part, _)| *part == index) {
            Some((_, turns)) => turns.push(turn),
            None => by_part.push((index, vec![turn])),
        }
    }
    let mut chunks = Vec::new();
    for (index, turns) in by_part {
        let Some(part) = branch.parts.get(index) else {
            continue;
        };
        chunks.extend(turns.chunks(size.max(1)).map(|chunk| QueuedBranch {
            world_ref: branch.world_ref,
            facet_ref: branch.facet_ref,
            thing: None,
            parts: vec![ConversationPart {
                conversation_ref: part.conversation_ref,
                turns: chunk.to_vec(),
                watermark_last_learned_at: CHUNK_WIDENS_NOTHING,
            }],
        }));
    }
    chunks
}

/// Queues each attempt's owed chunks, one commit per attempt. A commit that
/// fails is logged and leaves that attempt as it ran before chunks: what it
/// kept still runs.
pub(super) fn owe(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    owed: Vec<WakePreparationChunks>,
) {
    let mut queued_any = false;
    for set in owed {
        match vault.with_write_txn_grouped(|txn| set.enqueue_in_txn(vault, txn, scope)) {
            Ok(queued) => {
                queued_any |= queued > 0;
                tracing::debug!(
                    retry = %bytes_to_hex_lower(&set.source),
                    chunks = set.chunks.len(),
                    queued,
                    "selection retry overflow owed as sibling chunks"
                );
            }
            Err(error) => tracing::warn!(
                retry = %bytes_to_hex_lower(&set.source),
                chunks = set.chunks.len(),
                kind = ?error.kind(),
                "selection retry overflow chunks were not queued"
            ),
        }
    }
    if queued_any {
        vault.store.notify_attempt_observers();
    }
}
