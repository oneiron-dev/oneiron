//! Red-batch diagnosis (FIX 4362): bisection over a red batch's staged
//! paths and a deletion pass that minimizes its failing group.
use super::{BatchState, CheckInvocation, CheckPhase, CheckReport, MergeQueue, Quarantine};
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
