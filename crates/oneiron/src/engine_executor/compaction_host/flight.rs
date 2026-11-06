//! The token feed of the executor's compaction host: each step's assembled
//! request reaches the run's driver, and a breakpoint seals one flight.
//! Moved whole from `compaction_host.rs` (FIX 4933); the body is as it was.

use super::*;

impl EngineNativeExecutor<'_> {
    /// The token feed: the assembled request's size reaches the run's
    /// driver. A crossing, or the agent's `self.compact` ask, seals the steps
    /// up to the watermark and every fold mark that applies, in one flight.
    pub(in crate::engine_executor) fn feed_compaction(
        &mut self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        request: &LlmRequest,
    ) -> EngineExecutorResult<
        std::result::Result<Option<super::compaction::WindowFullReason>, VerbHookStop>,
    > {
        let completed = completed_step_count(record)?;
        if self.compaction.is_none() {
            return Ok(Ok(None));
        }
        let run_id = config.run_id;
        let ledger = self.storage.code_run_folds(run_id)?;
        let asked = ledger.compact.as_ref().map(|ask| ask.note.clone());
        let marks = if ledger.marks.is_empty() {
            Vec::new()
        } else {
            let prefix_end = self
                .storage
                .code_run_compaction_coverage(run_id)?
                .iter()
                .map(|row| row.last())
                .max();
            ledger.applicable(completed, prefix_end, asked.is_some())
        };
        // A mark by kind needs no backend pass: the batch writes it here.
        let (kind_marks, marks): (Vec<FoldMark>, Vec<FoldMark>) =
            marks.into_iter().partition(|mark| mark.kind.is_some());
        let Some(seat) = self.compaction.take() else {
            return Ok(Ok(None));
        };
        let byline = seat.swap_seat().map(|(_, byline, _)| byline);
        // A run whose compaction is off folds nothing: its asks end with why,
        // which `self.folds()` shows.
        if !seat.is_live()
            && (asked.is_some() || !marks.is_empty() || !kind_marks.is_empty())
            && let Err(error) = self.storage.update_code_run_folds(run_id, |ledger| {
                ledger.refuse_pending("compaction is off for this run")
            })
        {
            self.compaction = Some(seat);
            return Err(error.into());
        }
        let used = super::compaction::request_tokens(request);
        let mut refused = None;
        let reason = seat.feed(
            used,
            completed,
            asked.is_some(),
            !marks.is_empty() || !kind_marks.is_empty(),
            |driver, watermark| {
                if let Err(refusal) = self.admit_compaction_read() {
                    refused = Some(refusal);
                    return Ok(super::compaction::Flight::default());
                }
                let note = asked.clone().flatten();
                // FIX 4465 C: the live request as its rung sends it sizes and rides the flight.
                let (live, room) = super::compaction::live_fork::capture(driver, request);
                let (epoch, hooks) = match watermark {
                    Some(at) => match self.seal_compaction_window(
                        driver,
                        config,
                        record,
                        at,
                        note.clone(),
                        room,
                    )? {
                        Ok(Some((request, hooks))) => (Some(request), hooks),
                        Ok(None) => (None, CompactHooks::default()),
                        Err(stop) => {
                            return Ok(super::compaction::Flight {
                                pending: Some(stop),
                                ..super::compaction::Flight::default()
                            });
                        }
                    },
                    None => (None, CompactHooks::default()),
                };
                let folds =
                    self.seal_folds(driver, config, record, &marks, note.as_deref(), room)?;
                let mut kind_folds = match byline {
                    Some(byline) => self.seal_kind_folds(record, run_id, &kind_marks, byline)?,
                    None => None,
                };
                // A batch of folds by kind alone sends nothing to the
                // backend: it lands now, in one ledger write. Otherwise it
                // rides the flight and lands with its passes.
                if epoch.is_none()
                    && folds.is_empty()
                    && let Some(batch) = kind_folds.take()
                    && self
                        .storage
                        .land_code_run_folds(batch.run_id, batch.records, &[])
                        .is_err()
                {
                    tracing::warn!("a fold batch did not land");
                }
                if asked.is_some() {
                    self.storage
                        .update_code_run_folds(run_id, |ledger| ledger.compact = None)?;
                }
                Ok(super::compaction::Flight {
                    epoch,
                    folds,
                    kind_folds,
                    hooks,
                    live,
                    pending: None,
                })
            },
        );
        self.compaction = Some(seat);
        match refused {
            Some(refusal) => Err(refusal),
            None => Ok(reason),
        }
    }
}
