//! Out-of-order check completion and all-path agreement. Red-batch
//! diagnosis is in `diagnosis` (FIX 4362).
use super::check_inputs::QueueCheckReceipt;
use super::contract_review::contract_review_evidence;
use super::{CheckInvocation, CheckPhase, CheckReport, MergeQueue};
use crate::{
    error::{Error, Result},
    git_wire::lock_repository,
    store::contract_oracle::{ContractOracle, ContractVerdict},
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
        // A removed public name routes to a person review in the writer that
        // saves the settled slot (FIX 4365). The verdict stays red.
        let review = contract_review_evidence(&current, mask, phase, &path.tree, &verdict);
        self.save_with_review(&queue, &[&current], review.as_ref())?;
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
}
