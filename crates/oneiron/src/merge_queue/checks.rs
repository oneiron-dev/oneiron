//! Out-of-order check completion, all-path agreement and red-batch diagnosis.
use super::check_inputs::QueueCheckReceipt;
use super::{BatchState, CheckInvocation, CheckPhase, CheckReport, MergeQueue, Quarantine};
use crate::{
    contract_oracle::{ContractOracle, ContractVerdict, invalid},
    error::{Error, Result},
    git_wire::lock_repository,
};

impl MergeQueue<'_> {
    /// Run one check on its actual materialized worktree. The host owns sandbox,
    /// toolchain and process limits; this method owns tree binding and persistence.
    /// Different paths may complete in any order. The live repo lock is not held
    /// while the host runs tests, so queued writers are not blocked by a slow leg.
    pub fn check<F>(
        &self,
        id: &str,
        mask: u64,
        phase: CheckPhase,
        runner: &mut F,
    ) -> Result<ContractVerdict>
    where
        F: FnMut(&CheckInvocation) -> Result<CheckReport>,
    {
        let batch = self.batch(id)?;
        let (path, prior) = self.check_path(&batch, mask, phase, false)?;
        let oracle = ContractOracle::new(self.vault);
        if let Some(id) = prior {
            return oracle
                .verdict(&id)?
                .ok_or(Error::CorruptedIndex("merge verdict is missing"));
        }
        self.verify_worktree(&path)?;
        let baseline = oracle
            .baseline(&batch.baseline_id)?
            .ok_or(Error::CorruptedIndex("merge baseline is missing"))?;
        let report = runner(&CheckInvocation {
            worktree: path.worktree.clone(),
            commit: path.commit.clone(),
            tree: path.tree.clone(),
            phase,
            selected_tests: batch.selected_tests.clone(),
        })?;
        self.verify_worktree(&path)?;
        let snapshot = ContractOracle::capture(&baseline.spec, &path.worktree, report.outputs)?;
        self.verify_worktree(&path)?;
        let candidate = match phase {
            CheckPhase::Fast => format!("{}:{mask}:Fast:{}", batch.id, path.tree),
            CheckPhase::Slow => format!("{}:{mask}:Slow:{}:{}", batch.id, path.tree, path.commit),
        };
        let verdict = oracle.compare_and_record(
            &batch.baseline_id,
            &candidate,
            &snapshot,
            report.tests_passed,
        )?;
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        let mut current = self.batch(id)?;
        self.settle_slot(&mut current, mask, phase, &path.commit, &verdict.id, None)?;
        self.save(&queue, &[&current])?;
        Ok(verdict)
    }

    pub(super) fn all_paths_green(&self, batch: &super::MergeBatch) -> Result<bool> {
        self.all_paths_green_with(batch, None)
    }

    /// [`Self::all_paths_green`], with `pending` a bound receipt whose
    /// verdict is not stored with its work yet (FIX 6868).
    pub(super) fn all_paths_green_with(
        &self,
        batch: &super::MergeBatch,
        pending: Option<&QueueCheckReceipt>,
    ) -> Result<bool> {
        if batch.paths.len() != super::staging::speculative_masks(batch.proposals.len()).len() {
            return Ok(false);
        }
        let oracle = ContractOracle::new(self.vault);
        for path in &batch.paths {
            let Some(id) = &path.verdict else {
                return Ok(false);
            };
            let verdict = oracle
                .verdict(id)?
                .ok_or(Error::CorruptedIndex("merge verdict is missing"))?;
            if !self.require_check_binding(
                batch,
                path.mask,
                &path.tree,
                &path.commit,
                CheckPhase::Fast,
                &verdict,
                pending,
            )? {
                return Err(Error::CorruptedIndex("merge verdict scope differs"));
            }
            if !verdict.passes() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Bisect the full red stack, retaining interacting groups when both halves
    /// pass. A deletion pass then minimizes that group without assuming failures
    /// are monotonic. Existing content-bound verdicts are reused, not rerun.
    /// Past one speculation window, the first red path in staged order is
    /// diagnosed: its earlier windows passed whole, so its own window is
    /// bisected over them, and every checked mask is a staged path.
    pub fn diagnose_red<F>(&self, id: &str, runner: &mut F) -> Result<Quarantine>
    where
        F: FnMut(&CheckInvocation) -> Result<CheckReport>,
    {
        let batch = self.batch(id)?;
        if let Some(quarantine) = batch.quarantine {
            return Ok(quarantine);
        }
        let count = batch.proposals.len();
        let mut mask = (1_u64 << count) - 1;
        let full = self.check(id, mask, CheckPhase::Fast, runner)?;
        if full.passes() || count > super::staging::SPECULATION_WIDTH {
            // A stack can pass while an exclusion path fails. That also blocks
            // all-path agreement, so diagnose the first red path if one exists.
            let mut red = None;
            for path in &batch.paths {
                if !self
                    .check(id, path.mask, CheckPhase::Fast, runner)?
                    .passes()
                {
                    red = Some(path.mask);
                    break;
                }
            }
            mask = red.ok_or_else(|| invalid("batch has no red path"))?;
        }
        // The red mask's window starts here; every earlier window stays whole.
        let top = 63 - mask.leading_zeros() as usize;
        let start = top / super::staging::SPECULATION_WIDTH * super::staging::SPECULATION_WIDTH;
        let prefix = (1_u64 << start) - 1;
        mask &= !prefix;
        while mask.count_ones() > 1 {
            let bits: Vec<_> = (start..count).filter(|i| mask & (1 << i) != 0).collect();
            let left = bits[..bits.len() / 2]
                .iter()
                .fold(0_u64, |acc, bit| acc | (1 << bit));
            let right = mask ^ left;
            if !self
                .check(id, prefix | left, CheckPhase::Fast, runner)?
                .passes()
            {
                mask = left;
            } else if !self
                .check(id, prefix | right, CheckPhase::Fast, runner)?
                .passes()
            {
                mask = right;
            } else {
                break;
            }
        }
        // Repeat after each reduction: removal can change which interaction fails.
        loop {
            let mut reduced = false;
            for index in start..count {
                let without = mask & !(1 << index);
                if without != mask
                    && without != 0
                    && !self
                        .check(id, prefix | without, CheckPhase::Fast, runner)?
                        .passes()
                {
                    mask = without;
                    reduced = true;
                    break;
                }
            }
            if !reduced {
                break;
            }
        }
        let verdict = self.check(id, prefix | mask, CheckPhase::Fast, runner)?;
        let quarantine = Quarantine {
            proposal_ids: batch
                .proposals
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, p)| p.id.clone())
                .collect(),
            failing_mask: prefix | mask,
            verdict: verdict.id,
        };
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        let mut current = self.batch(id)?;
        if !matches!(current.state, BatchState::Staged | BatchState::Ready) {
            return Err(Error::ConcurrentWrite("batch changed during diagnosis"));
        }
        current.state = BatchState::Quarantined;
        current.quarantine = Some(quarantine.clone());
        self.save(&queue, &[&current])?;
        Ok(quarantine)
    }
}
