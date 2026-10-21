//! A leased run's entries in the merge queue (FIX 6867, G1 PR2b): the
//! queue's one batch formation takes the run's exact stored proposals under
//! the admission its final writer judges, and keeps beside the batch the
//! declarations of other TASKs that overlapped it then. Symbol leases order
//! work and veto none: an entry whose predecessors still hold waits Queued
//! and is never refused. A predecessor stops holding it once its
//! declaration is released, expires or is replaced, or once a run batch
//! accepted under that declaration reaches the queue's head; one accepted
//! after this entry never holds it. Acceptance hands the exact candidate to
//! the queue: staging and landing never ask whether the worker that
//! submitted it still runs, and every existing check, review and recovery
//! still applies.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{BatchState, MergeBatch, MergeProposal, MergeQueue};
use crate::EntityId;
use crate::contract_oracle::invalid;
use crate::error::Result;

/// A run's accepted queue entry: whose it is, the exact proposals accepted,
/// the declaration it was accepted under and the predecessors it waits
/// behind, as its batch writer read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoQueueOrder {
    /// The run's work the proposals were made in.
    pub work: EntityId,
    /// The TASK the run realized.
    pub task: EntityId,
    /// The actor that submitted them.
    pub holder: EntityId,
    /// The exact stored proposals accepted, in batch order.
    pub proposals: Vec<EntityId>,
    /// The run's own declaration the entry was accepted under, if it had one.
    pub declaration: Option<EntityId>,
    /// The symbols the entry touches (CALL "FIX 6867 run-only overlap
    /// granularity").
    pub symbols: BTreeSet<String>,
    /// The live declarations of other TASKs that overlapped it when it was
    /// accepted.
    pub predecessors: Vec<RepoQueuePredecessor>,
    /// The queue sequence that accepted it: an entry accepted later never
    /// holds this one.
    pub sequence: u64,
}

/// One declaration a run's entry waits behind: the TASK and the id of the
/// declaration that held it at acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoQueuePredecessor {
    pub task: EntityId,
    pub declaration: EntityId,
}

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
            let accepted: BTreeSet<String> = order.proposals.iter().map(EntityId::to_hex).collect();
            for batch in self.repo_batches_in_txn(txn)? {
                if holds_candidates(&batch)
                    && batch
                        .proposals
                        .iter()
                        .any(|proposal| accepted.contains(&proposal.id))
                {
                    return Err(invalid("a proposal of this entry is already queued"));
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
        let batches = self.repo_batches_in_txn(&txn)?;
        let mut blocked = Vec::new();
        for predecessor in &order.predecessors {
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

    /// The run entries of this queue accepted from `work`, in key order.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn run_batches_of(&self, work: EntityId) -> Result<Vec<MergeBatch>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .repo_batches_in_txn(&txn)?
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
