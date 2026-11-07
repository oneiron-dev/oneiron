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
        // FIX 4933: the step's call goes out next; a writer that forks the
        // live context holds the slot the rung that answers it fills.
        if let Some((driver, _, _)) = seat.swap_seat() {
            driver.backend().hold_answering_rungs(request);
        }
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
        // A batch of folds by kind landed here, after `request` was built.
        let mut kind_landed: Option<FoldBoundary> = None;
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
                // FIX 4933: the fork's prefix is the run's latest completed
                // call; the flight seals only the steps it holds, and every
                // later step and fold mark waits raw for a later breakpoint.
                let held = super::compaction::live_fork::held_steps(live.as_ref(), request);
                let watermark =
                    watermark.and_then(|at| super::compaction::live_fork::within_prefix(at, held));
                let deferred = marks
                    .iter()
                    .any(|mark| held.is_some_and(|steps| mark.through >= steps));
                let marks: Vec<FoldMark> = marks
                    .iter()
                    .filter(|mark| held.is_none_or(|steps| mark.through < steps))
                    .cloned()
                    .collect();
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
                {
                    let run = batch.run_id;
                    match self.storage.land_code_run_folds(run, batch.records, &[]) {
                        Ok(committed) => kind_landed = FoldBoundary::landed(run, committed),
                        Err(_) => tracing::warn!("a fold batch did not land"),
                    }
                }
                if asked.is_some() && !deferred {
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
        // FIX 17594 (Engine call B): the batch is a brief boundary; the run
        // builds this turn's request again past it before sending it.
        if let Some(landed) = kind_landed {
            self.brief_fold_committed(landed);
        }
        match refused {
            Some(refusal) => Err(refusal),
            None => Ok(reason),
        }
    }
}
