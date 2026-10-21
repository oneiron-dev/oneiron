use std::collections::BTreeSet;

use super::*;
use crate::contract_oracle::{ContractOracle, ContractVerdict};
use crate::error::Error;

impl Memory<'_> {
    /// `vault.code.merge_queue.observe`: the queue pointers, then each named
    /// batch through the unchanged `MergeQueue::batch`, then the stored
    /// contract verdicts those batches name. A read only: it never recovers
    /// or settles, so a queue that needs recovery refuses here as the engine
    /// refuses it.
    pub fn merge_queue_observe_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueObserveRequest,
    ) -> MemoryResult<MergeQueueObservation> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        let pointers = pointers_view(repo.repo, queue.pointers()?);
        let batches = input
            .batches
            .iter()
            .map(|id| queue.batch(id))
            .collect::<crate::error::Result<Vec<_>>>()?;
        let verdicts = self.merge_queue_verdicts(&batches)?;
        let drive = batches
            .iter()
            .map(|batch| queue.queue_driver_observation(batch))
            .collect();
        Ok(MergeQueueObservation {
            repo: pointers.repo,
            head_commit: pointers.head_commit,
            green_commit: pointers.green_commit,
            pending_slow_batch_refs: pointers.pending_slow_batch_refs,
            batches: batches.into_iter().map(batch_view).collect(),
            verdicts,
            drive,
        })
    }

    /// The CALL behind observation grain: only the verdicts the named batches
    /// hold (each fast path, the slow check and the quarantine), each once,
    /// in first-named order. No verdict id is taken from the request.
    fn merge_queue_verdicts(&self, batches: &[MergeBatch]) -> MemoryResult<Vec<ContractVerdict>> {
        let oracle = ContractOracle::new(self.vault);
        let mut seen = BTreeSet::new();
        let mut verdicts = Vec::new();
        let named = batches.iter().flat_map(|batch| {
            batch
                .paths
                .iter()
                .filter_map(|path| path.verdict.as_deref())
                .chain(batch.slow_verdict.as_deref())
                .chain(batch.quarantine.as_ref().map(|q| q.verdict.as_str()))
        });
        for id in named {
            if seen.insert(id) {
                let verdict = oracle
                    .verdict(id)?
                    .ok_or(Error::CorruptedIndex("merge batch verdict missing"))?;
                verdicts.push(verdict);
            }
        }
        Ok(verdicts)
    }
}
