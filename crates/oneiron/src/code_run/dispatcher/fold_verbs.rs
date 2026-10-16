//! The fold verbs (ARCH-0067 §2.2): `self.fold`, `self.compact`,
//! `self.unfold`, `self.folds` and `describe({fold})` reach this run's own
//! log only, through its fold ledger where the run's rows are.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::SelfDispatchOutcome;
use crate::compaction::SelfFoldCall;
use crate::{Error, Result};

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_fold(
        &self,
        call: &SelfFoldCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let Some(site) = site else {
            return Err(Error::InvalidConfig(
                "the fold verbs act on an executor run's own log".into(),
            ));
        };
        let run_id = site.run_id;
        // The step this call runs in: the steps the run has made durable.
        let step = match self.storage.get_code_run_replay_record(&run_id)? {
            Some(record) => u64::try_from(record.step_checkpoints.len())
                .map_err(|_| Error::ArithmeticOverflow("executor step count"))?,
            None => 0,
        };
        // The steps the run's epochs already compacted.
        let prefix_end = self
            .storage
            .code_run_compaction_coverage(run_id)?
            .iter()
            .map(|row| row.last())
            .max();
        let answer = if call.writes() {
            self.storage
                .update_code_run_folds(run_id, |ledger| ledger.answer(call, step, prefix_end))?
        } else {
            self.storage
                .code_run_folds(run_id)?
                .answer(call, step, prefix_end)
        };
        Ok(SelfDispatchOutcome::Fold(answer.to_string()))
    }
}
