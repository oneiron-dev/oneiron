//! Rule 5 for a selection retry's source budget (L02-38): `max_sources` is a
//! work size, never a total. A retry runs every original with the oldest
//! other sources that fit; the newer rest is split into sibling chunks of
//! that same size, each an ordinary consolidation attempt of its own, queued
//! once the wake's read transaction has closed.
//!
//! A sibling owes exactly its turns. Each passed the retry's own admission at
//! the wake's snapshot (readable by the Dreamer, an admissible role, the
//! partition's world and facet); the sibling carries no branch scope of its
//! own, sits under the retry's own parent, and reads its turns again through
//! the same scoped read at its own wake. A source that fails there refuses or
//! defers that chunk alone, never the retry.

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{
    ConsolidationPartitionKey, ConsolidationPartitionPlan, WorkingSetTurn,
};
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::{Result, Vault};

/// The widening floor a sibling chunk is queued with. No TURN is learned at
/// or after it, so a retry of the chunk itself reads its own turns only: a
/// deferred chunk never splits its conversation again.
const CHUNK_WIDENS_NOTHING: u64 = u64::MAX;

/// The overflow of one selection retry, split into owed sibling chunks.
#[derive(Debug, Clone)]
pub(super) struct WakePreparationChunks {
    retry: [u8; 16],
    partition: ConsolidationPartitionKey,
    parent: Option<AttemptId>,
    run_id: Option<String>,
    chunks: Vec<Vec<WorkingSetTurn>>,
}

impl WakePreparationChunks {
    /// `overflow`, in the retry's selection order, split into chunks of the
    /// resolved source budget `size`; `None` when nothing overflowed.
    pub(super) fn split(
        retry: [u8; 16],
        partition: ConsolidationPartitionKey,
        parent: Option<AttemptId>,
        run_id: Option<String>,
        overflow: &[WorkingSetTurn],
        size: usize,
    ) -> Option<Self> {
        if overflow.is_empty() {
            return None;
        }
        Some(Self {
            retry,
            partition,
            parent,
            run_id,
            chunks: overflow
                .chunks(size.max(1))
                .map(<[WorkingSetTurn]>::to_vec)
                .collect(),
        })
    }

    /// Queues every chunk in the caller's commit; returns how many were new.
    fn enqueue_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        scope: DreamerConsolidationScope,
    ) -> Result<usize> {
        let store = DreamerRunnerStore::new(vault);
        let now = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        let mut queued = 0_usize;
        for turns in &self.chunks {
            let plan = ConsolidationPartitionPlan {
                key: self.partition,
                turns: turns.clone(),
                watermark_last_learned_at: CHUNK_WIDENS_NOTHING,
            };
            let outcome = store.enqueue_consolidation_in_txn(
                txn,
                EnqueueDreamerConsolidationAttempt {
                    scope,
                    input: super::super::partition::encode_partition_payload(&plan),
                    parent_attempt: self.parent,
                    dedupe_key: Some(self.chunk_key(turns)),
                    run_id: self.run_id.clone(),
                    now,
                },
            )?;
            if matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_)) {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// One chunk's advisory dedupe key, by the exact turns it owes under its
    /// parent and partition: a retry prepared again re-queues no chunk that
    /// is still pending.
    fn chunk_key(&self, turns: &[WorkingSetTurn]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:dreamer:retry-chunk:v1");
        hasher.update(&self.partition.partition_hash());
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
        for turn in turns {
            hasher.update(turn.turn_id.as_bytes());
        }
        format!("retry-chunk:{}", hasher.finalize().to_hex())
    }
}

/// Queues each retry's owed chunks, one commit per retry. A commit that
/// fails is logged and leaves that retry as it ran before chunks: its
/// originals and the sources that fit still run.
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
                    retry = %bytes_to_hex_lower(&set.retry),
                    chunks = set.chunks.len(),
                    queued,
                    "selection retry overflow owed as sibling chunks"
                );
            }
            Err(error) => tracing::warn!(
                retry = %bytes_to_hex_lower(&set.retry),
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
