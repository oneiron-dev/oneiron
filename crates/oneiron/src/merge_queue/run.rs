//! Core half of `merge_queue::run`: its store-layer items live in `oneiron_store::merge_queue::run` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::run::*;

use super::batch_index::BatchIndexKind;
use super::{BatchState, MergeBatch, MergeProposal, MergeQueue};
use crate::EntityId;
use crate::error::Result;
use crate::store::contract_oracle::invalid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

impl MergeQueue<'_> {
    /// Queues a run's exact stored proposals as one batch through the one
    /// batch formation. `admit` is the batch writer's first act: it judges
    /// the run, its proposals and its declaration again and answers the
    /// entry's order, or a refusal, which writes nothing. A proposal another
    /// live batch of this queue already holds is refused: an accepted
    /// candidate is the queue's, and no worker submits it twice.
    ///
    /// # Errors
    /// Every error of the batch formation, or an already queued proposal.
    pub(crate) fn enqueue_for_run<R>(
        &self,
        proposals: Vec<MergeProposal>,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<RepoQueueOrder, R>>,
    ) -> Result<std::result::Result<MergeBatch, R>> {
        self.enqueue_checked(proposals, |txn| {
            let order = match admit(txn)? {
                Ok(order) => order,
                Err(refused) => return Ok(Err(refused)),
            };
            // Each accepted proposal's own batches, by index (FIX 7067).
            for accepted in order.proposals.iter().map(EntityId::to_hex) {
                for batch in
                    self.indexed_batches_in_txn(txn, BatchIndexKind::Proposal, &accepted)?
                {
                    if holds_candidates(&batch)
                        && batch
                            .proposals
                            .iter()
                            .any(|proposal| proposal.id == accepted)
                    {
                        return Err(invalid("a proposal of this entry is already queued"));
                    }
                }
            }
            Ok(Ok(Some(order)))
        })
    }

    /// Whether `batch` may stage now: an owner or trusted batch always may;
    /// a run's entry once none of its predecessors holds it.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn run_batch_ready(&self, batch: &MergeBatch) -> Result<bool> {
        Ok(self
            .run_batch_blockers(batch, self.vault.now_recorded_at())?
            .is_empty())
    }

    /// The TASKs whose predecessor declarations still hold the run entry
    /// `batch` at `now`, in acceptance order; empty for an owner or trusted
    /// batch.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn run_batch_blockers(&self, batch: &MergeBatch, now: u64) -> Result<Vec<EntityId>> {
        let Some(order) = &batch.run_order else {
            return Ok(Vec::new());
        };
        let txn = self.vault.store.env.read_txn()?;
        let mut blocked = Vec::new();
        for predecessor in &order.predecessors {
            // The batches accepted under this declaration, by index (FIX 7067).
            let batches = self.indexed_batches_in_txn(
                &txn,
                BatchIndexKind::Declaration,
                &predecessor.declaration.to_hex(),
            )?;
            let accepted: Vec<(BatchState, u64)> = batches
                .iter()
                .filter_map(|other| {
                    let other_order = other.run_order.as_ref()?;
                    (other_order.declaration == Some(predecessor.declaration))
                        .then_some((other.state, other_order.sequence))
                })
                .collect();
            let landed = accepted.iter().any(|(state, _)| {
                matches!(state, BatchState::HeadAdvanced | BatchState::GreenAdvanced)
            });
            let behind = !accepted.is_empty()
                && accepted
                    .iter()
                    .all(|(_, sequence)| *sequence > order.sequence);
            if !landed
                && !behind
                && crate::task_verb::declaration_holds_in_txn(
                    self.vault,
                    &txn,
                    predecessor.task,
                    predecessor.declaration,
                    now,
                )?
            {
                blocked.push(predecessor.task);
            }
        }
        Ok(blocked)
    }

    /// The run entries of this queue accepted from `work`, in key order,
    /// read by index (FIX 7067).
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn run_batches_of(&self, work: EntityId) -> Result<Vec<MergeBatch>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .indexed_batches_in_txn(&txn, BatchIndexKind::Work, &work.to_hex())?
            .into_iter()
            .filter(|batch| {
                batch
                    .run_order
                    .as_ref()
                    .is_some_and(|order| order.work == work)
            })
            .collect())
    }
}

/// Whether `batch` still holds its candidates: every state but a
/// cancelled, rolled-back or quarantined one.
fn holds_candidates(batch: &MergeBatch) -> bool {
    !matches!(
        batch.state,
        BatchState::Cancelled | BatchState::RolledBack | BatchState::Quarantined
    )
}
