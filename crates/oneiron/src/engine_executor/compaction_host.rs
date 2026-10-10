//! The executor's side of the compaction host: landing a finished pass,
//! the token feed, and sealing a window from the durable replay.

use super::driver::EngineNativeExecutor;
use super::record::completed_step_count;
use super::store::{load_utf8_output, observation_output_path, script_output_path};
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::LlmRequest;
use crate::code_run::CodeRunReplayRecord;

impl EngineNativeExecutor<'_> {
    /// Lands a finished background pass: an accepted summary swaps in as
    /// this run's next epoch; anything else holds for the turn and leaves
    /// the window whole.
    pub(super) fn land_finished_compaction(&mut self) -> EngineExecutorResult<()> {
        let Some(seat) = self.compaction.take() else {
            return Ok(());
        };
        let landed = match seat.take_finished() {
            None => Ok(()),
            Some(Err(suppression)) => {
                seat.hold(suppression);
                Ok(())
            }
            Some(Ok(gated)) => {
                let first = gated.request().turn_start;
                let last = gated
                    .request()
                    .window
                    .last()
                    .map_or(first, |message| message.turn);
                match seat.driver_and_byline() {
                    None => Ok(()),
                    // The tail is re-derived from typed coverage at the next
                    // assembly, so no host-side splice is carried here.
                    Some((driver, byline)) => {
                        match self.integrate_compaction(driver, byline, gated, &[]) {
                            Ok(plan) => {
                                seat.swapped(plan.epoch, first, last);
                                Ok(())
                            }
                            Err(error) => {
                                tracing::warn!(%error, "a gated compaction did not land");
                                seat.hold(crate::compaction::CompactionSuppression::TurnScoped {
                                    check: None,
                                });
                                Ok(())
                            }
                        }
                    }
                }
            }
        };
        self.compaction = Some(seat);
        landed
    }

    /// The token feed: the assembled request's size reaches the run's
    /// driver, and a crossing seals the steps up to the watermark.
    pub(super) fn feed_compaction(
        &mut self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        request: &LlmRequest,
    ) -> EngineExecutorResult<Option<super::compaction::WindowFullReason>> {
        let completed = completed_step_count(record)?;
        let Some(seat) = self.compaction.take() else {
            return Ok(None);
        };
        let used = super::compaction::request_tokens(request);
        let reason = seat.feed(used, completed, |driver, watermark| {
            self.seal_compaction_window(driver, config, record, watermark)
        });
        self.compaction = Some(seat);
        Ok(reason)
    }

    /// Steps from the first uncovered one through `watermark`, with their
    /// failure pins and every record the run was served.
    fn seal_compaction_window(
        &self,
        driver: &mut crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        watermark: u64,
    ) -> EngineExecutorResult<Option<crate::compaction::CompactionRequest>> {
        let crate::code_run::ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(None);
        };
        let run_id = config.run_id;
        let run_ref = self.gated_write.run_ref();
        // The run's position is its coverage rows, withdrawn summaries
        // included: erasing a summary never moves where the next one starts.
        let prior = vault
            .code_run_compaction_coverage(run_id)?
            .iter()
            .map(|row| (row.epoch(), row.last()))
            .max();
        let start = prior.map_or(0, |(_, last)| last.saturating_add(1));
        if start > watermark {
            return Ok(None);
        }
        let session = crate::code_run::executor_compaction_session_id(run_ref, run_id)?;
        let turn_id = crate::code_run::executor_speech_turn_id_for_run(run_ref, run_id)?;
        let mut window = Vec::new();
        let mut pins = Vec::new();
        for seq in start..=watermark {
            let message = super::compaction::window_message(
                super::compaction::step_message_id(run_id, seq),
                turn_id,
                seq,
                load_utf8_output(&self.storage, record, &script_output_path(seq))?,
                load_utf8_output(&self.storage, record, &observation_output_path(seq))?,
            );
            pins.extend(super::compaction::failure_pin(&message.content));
            window.push(message);
        }
        let mut sources = super::compaction::served_sources(vault, record)?;
        if vault.entity_exists(&turn_id)? {
            sources.push(turn_id);
        }
        let prior = prior.map(|(epoch, last)| crate::compaction::PriorEpoch::new(epoch, last));
        Ok(Some(driver.request_for_log(
            vault, &session, window, pins, sources, prior,
        )?))
    }

    /// This run's swapped epochs with their summaries' prose.
    pub(super) fn compaction_epochs(
        &self,
        run_id: crate::EntityId,
    ) -> EngineExecutorResult<Vec<(crate::code_run::CodeRunCompactionCoverage, Option<String>)>>
    {
        Ok(match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => {
                vault.code_run_compaction_epochs(run_id)?
            }
            crate::code_run::ExecutorStorage::Session(_) => Vec::new(),
        })
    }

    /// One call's outcome, with the run's seat receipt.
    pub(super) fn outcome(
        &self,
        status: super::types::EngineExecutorStatus,
        steps_run: u32,
        replay_record: CodeRunReplayRecord,
    ) -> super::types::EngineExecutorOutcome {
        super::types::EngineExecutorOutcome {
            status,
            steps_run,
            replay_record,
            seat_receipt: self.seat.map(|seat| seat.receipt().clone()),
            compaction: self.compaction.as_ref().map(|seat| seat.report().clone()),
        }
    }
}
