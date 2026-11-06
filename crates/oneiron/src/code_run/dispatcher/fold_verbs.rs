//! The fold verbs (ARCH-0067 §2.2): `self.fold`, `self.compact`,
//! `self.unfold`, `self.folds` and `describe({fold})` reach this run's own
//! log only, through its fold ledger where the run's rows are. A host action
//! for a live run (OF-181) reaches that run's log, never its own replay.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::{FoldAnswer, FoldWordRef, SelfDispatchOutcome};
use crate::compaction::{FoldLedger, SelfFoldCall};
use crate::{EntityId, Error, Result};

/// Whose log a dispatcher's fold verbs reach: its executor call's own run,
/// the live run a host action acts for (OF-181), or none, for an action
/// whose host names no executor run. An action's own replay is no log.
#[derive(Clone, Copy)]
pub(super) enum FoldLog {
    Site,
    Run(EntityId),
    Unbound,
}

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_fold(
        &self,
        call: &SelfFoldCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let run_id = match (self.fold_log, site) {
            (FoldLog::Run(run_id), _) => run_id,
            (FoldLog::Site, Some(site)) => site.run_id,
            (FoldLog::Site, None) => {
                return Err(Error::InvalidConfig(
                    "the fold verbs act on an executor run's own log".into(),
                ));
            }
            (FoldLog::Unbound, _) => {
                return Err(Error::InvalidConfig(
                    "the fold verbs act on a live run's log, and this action's host names none"
                        .into(),
                ));
            }
        };
        self.dispatch_fold_for_run(call, run_id)
    }

    /// The fold verbs on executor run `run_id`'s log, at its durable step
    /// boundary: the steps it checkpointed and the ones its epochs compacted.
    /// A live run's action reads it between entries, under the run's guard.
    fn dispatch_fold_for_run(
        &self,
        call: &SelfFoldCall,
        run_id: EntityId,
    ) -> Result<SelfDispatchOutcome> {
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
        // The words the answer copies are named from the same fenced ledger
        // that answers it, under the run whose log it reads (FIX 18924).
        let (answer, words) = if call.writes() {
            self.storage.update_code_run_folds(run_id, |ledger| {
                let answer = ledger.answer(call, step, prefix_end);
                (answer, answer_words(ledger, run_id, call))
            })?
        } else {
            let mut ledger = self.storage.code_run_folds(run_id)?;
            let answer = ledger.answer(call, step, prefix_end);
            (answer, answer_words(&ledger, run_id, call))
        };
        Ok(SelfDispatchOutcome::Fold(FoldAnswer::new(
            answer.to_string(),
            words,
        )))
    }
}

/// The folds of run `run_id`'s `ledger` whose accepted summary the answer to
/// `call` copies (FIX 18924): `describe({fold})` of a fold that still keeps
/// its words. No other answer copies a summary.
fn answer_words(ledger: &FoldLedger, run_id: EntityId, call: &SelfFoldCall) -> Vec<FoldWordRef> {
    let SelfFoldCall::Describe { fold } = call else {
        return Vec::new();
    };
    ledger
        .fold(*fold)
        .filter(|record| record.summary.is_some())
        .map(|record| FoldWordRef {
            source_run: run_id,
            fold: record.fold,
            sources: record.sources.clone(),
        })
        .into_iter()
        .collect()
}
