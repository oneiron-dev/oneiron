//! Red-batch diagnosis (FIX 4362): bisection over a red batch's staged
//! paths and a deletion pass that minimizes its failing group. Every mask
//! decision it evaluates is kept in order and saved with its quarantine.
use super::driver_types::QueueDiagnosisDecision;
use super::{
    BatchState, CheckInvocation, CheckPhase, CheckReport, MergeBatch, MergeQueue, Quarantine,
    QueueBatchDrive,
};
use crate::{
    error::{Error, Result},
    git_wire::lock_repository,
    store::contract_oracle::invalid,
};

impl MergeQueue<'_> {
    /// Bisect the full red stack, retaining interacting groups when both halves
    /// pass. A deletion pass then minimizes that group without assuming failures
    /// are monotonic. Existing content-bound verdicts are reused, not rerun.
    /// Past one speculation window, the first red path in staged order is
    /// diagnosed: its earlier windows passed whole, so its own window is
    /// bisected over them, and every checked mask is a staged path.
    /// Each mask decision it evaluates is kept on the batch's drive record
    /// with the final quarantine, in the same writer (FIX 4362). A crash
    /// before that save loses no check: a retry evaluates the same
    /// decisions again over the verdict slots already saved.
    pub fn diagnose_red<F>(&self, id: &str, runner: &mut F) -> Result<Quarantine>
    where
        F: FnMut(&CheckInvocation) -> Result<CheckReport>,
    {
        let batch = self.batch(id)?;
        if let Some(quarantine) = batch.quarantine {
            return Ok(quarantine);
        }
        let count = batch.proposals.len();
        let full = (1_u64 << count) - 1;
        let mut mask = full;
        let mut trace = Vec::new();
        let full_red = self.diagnosis_decision(&batch, full, full, runner, &mut trace)?;
        if !full_red || count > super::staging::SPECULATION_WIDTH {
            // A stack can pass while an exclusion path fails. That also blocks
            // all-path agreement, so diagnose the first red path if one exists.
            let mut red = None;
            for path in &batch.paths {
                if self.diagnosis_decision(&batch, full, path.mask, runner, &mut trace)? {
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
            let parent = prefix | mask;
            if self.diagnosis_decision(&batch, parent, prefix | left, runner, &mut trace)? {
                mask = left;
            } else if self.diagnosis_decision(&batch, parent, prefix | right, runner, &mut trace)? {
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
                    && self.diagnosis_decision(
                        &batch,
                        prefix | mask,
                        prefix | without,
                        runner,
                        &mut trace,
                    )?
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
        current
            .drive
            .get_or_insert_with(QueueBatchDrive::default)
            .diagnosis_trace = trace;
        self.save(&queue, &[&current])?;
        Ok(quarantine)
    }

    /// One mask decision of [`Self::diagnose_red`] (FIX 4362): checks the
    /// staged path `checked` through [`Self::check`], so a verdict its slot
    /// holds is reused, not rerun. Keeps the decision in `trace` with
    /// `parent`, the path's exact staged tree and that verdict. Answers
    /// whether the path is red.
    fn diagnosis_decision<F>(
        &self,
        batch: &MergeBatch,
        parent: u64,
        checked: u64,
        runner: &mut F,
        trace: &mut Vec<QueueDiagnosisDecision>,
    ) -> Result<bool>
    where
        F: FnMut(&CheckInvocation) -> Result<CheckReport>,
    {
        let verdict = self.check(&batch.id, checked, CheckPhase::Fast, runner)?;
        let tree = batch
            .paths
            .iter()
            .find(|path| path.mask == checked)
            .ok_or_else(|| invalid("speculative path not staged"))?
            .tree
            .clone();
        let red = !verdict.passes();
        trace.push(QueueDiagnosisDecision {
            parent_mask: parent,
            checked_mask: checked,
            tree,
            verdict: verdict.id,
        });
        Ok(red)
    }
}
