//! The executor's side of the compaction host: landing a finished pass,
//! the token feed, and sealing a window from the durable replay.

use super::driver::EngineNativeExecutor;
use super::record::completed_step_count;
use super::store::{
    COMPACTION_OBSERVATION_WINDOW_BYTES, load_context_output, load_observation_window,
    observation_output_path, script_output_path,
};
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::LlmRequest;
use crate::code_run::CodeRunReplayRecord;
use crate::tokenizer::count_context_pack_tokens;

impl EngineNativeExecutor<'_> {
    /// Lands a finished background pass: an accepted summary swaps in as
    /// this run's next epoch; anything else holds for the turn and leaves
    /// the window whole.
    pub(super) fn land_finished_compaction(&mut self) -> EngineExecutorResult<()> {
        if self
            .compaction
            .as_ref()
            .is_some_and(|seat| seat.report().in_flight)
        {
            self.admit_compaction_read()?;
        }
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
                match seat.swap_seat() {
                    None => Ok(()),
                    // The tail is re-derived from typed coverage at the next
                    // assembly, so no host-side splice is carried here.
                    Some((driver, byline, placement)) => {
                        match self.integrate_placed(driver, byline, placement, gated) {
                            Ok(plan) => {
                                seat.swapped(plan.epoch, first, last);
                                Ok(())
                            }
                            Err(error) => {
                                tracing::warn!(
                                    variant = error.variant(),
                                    kind = ?error.engine_kind(),
                                    "a gated compaction did not land"
                                );
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
        let mut refused = None;
        let reason = seat.feed(used, completed, |driver, watermark| {
            if let Err(refusal) = self.admit_compaction_read() {
                refused = Some(refusal);
                return Ok(None);
            }
            self.seal_compaction_window(driver, config, record, watermark)
        });
        self.compaction = Some(seat);
        match refused {
            Some(refusal) => Err(refusal),
            None => Ok(reason),
        }
    }

    /// The run's host door rules on what the compaction host reads of the run
    /// as on a read of its recorded output (#1405): a pass sends the run's
    /// scripts and outputs to a model, a swap mints a summary of them, and a
    /// request renders that summary. A refusal stops the run before any of
    /// them; a finished pass stays in the seat for an admitted re-entry.
    pub(super) fn admit_compaction_read(&self) -> EngineExecutorResult<()> {
        self.storage
            .answered(|| {
                self.gated_write
                    .admit_run_call(crate::code_run::RunCall::RecordedOutput)
            })?
            .map_err(|refusal| super::types::EngineExecutorError::HostRefused {
                code: refusal.code,
            })?;
        Ok(())
    }

    /// Steps from the first uncovered one through `watermark`, with their
    /// failure pins and every record whose words reached them. A window
    /// longer than the backend takes whole, or whose pins the summary could
    /// not hold, stops at the last step that fits; the next crossing seals
    /// the rest. A run in an off-record room reads all of it through its
    /// room's overlay over base.
    fn seal_compaction_window(
        &self,
        driver: &mut crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        watermark: u64,
    ) -> EngineExecutorResult<Option<crate::compaction::CompactionRequest>> {
        let run_id = config.run_id;
        let run_ref = self.gated_write.run_ref();
        // The run's position is its coverage rows, withdrawn summaries
        // included: erasing a summary never moves where the next one starts.
        let coverage = self.storage.code_run_compaction_coverage(run_id)?;
        let newest = coverage
            .iter()
            .max_by_key(|row| row.epoch())
            .copied();
        let prior = newest.map(|row| (row.epoch(), row.last()));
        let start = prior.map_or(0, |(_, last)| last.saturating_add(1));
        if start > watermark {
            return Ok(None);
        }
        let session = crate::code_run::executor_compaction_session_id(run_ref, run_id)?;
        let turn_id = crate::code_run::executor_speech_turn_id_for_run(run_ref, run_id)?;
        let budget = driver.summary_token_budget();
        // The backend reads the rendered input: each step's JSON frame,
        // escapes included, beside the pins. That, not the steps' raw text,
        // sizes the window.
        let room = driver.backend().input_token_limit(budget);
        let oversized = || {
            crate::Error::InvalidConfig(
                "the compaction backend cannot take the next step's output whole".into(),
            )
        };
        let mut window = Vec::new();
        let mut pins: Vec<String> = Vec::new();
        // Two counts kept by parts, each part counted once: the pins as the
        // summary holds them, a line each, and the rendered input. Parts run
        // a token or so over their joined whole, so a count past its bound is
        // counted whole before it turns a step away, and goes on from there.
        let mut pin_lines = 0_u64;
        let mut input = None;
        for seq in start..=watermark {
            let message = super::compaction::window_message(
                super::compaction::step_message_id(run_id, seq),
                turn_id,
                seq,
                load_context_output(&self.storage, record, &script_output_path(seq))?,
                load_observation_window(
                    &self.storage,
                    record,
                    &observation_output_path(seq),
                    COMPACTION_OBSERVATION_WINDOW_BYTES,
                )?,
            );
            // A line several steps fail with is one pin, kept once.
            let pin =
                super::compaction::failure_pin(&message.content).filter(|pin| !pins.contains(pin));
            let mut added = crate::compaction::compaction_step_input_tokens(&message);
            if let Some(pin) = &pin {
                pin_lines = pin_lines.saturating_add(count_context_pack_tokens(pin) as u64 + 1);
                added = added.saturating_add(crate::compaction::compaction_pin_input_tokens(pin));
            }
            let pinned = pin.is_some();
            pins.extend(pin);
            window.push(message);
            // The summary holds every pin whole, inside its budget.
            if pinned && pin_lines > budget {
                pin_lines = count_context_pack_tokens(&pins.join("\n")) as u64;
            }
            let unpinnable = pinned && pin_lines > budget;
            let mut fits = !unpinnable;
            if fits && let Some(room) = room {
                let whole =
                    || crate::compaction::compaction_input_tokens(start, &window, &pins, budget);
                let counted = match input.map(|counted: u64| counted.saturating_add(added)) {
                    Some(counted) if counted <= room => counted,
                    _ => whole(),
                };
                fits = counted <= room;
                input = Some(counted);
            }
            if !fits {
                window.pop();
                if pinned {
                    pins.pop();
                }
                if window.is_empty() {
                    return Err(if unpinnable {
                        crate::Error::InvalidConfig(
                            "the next step's failure line does not fit a summary".into(),
                        )
                    } else {
                        oversized()
                    }
                    .into());
                }
                break;
            }
        }
        // The backend takes the joined input whole or not at all: it is
        // counted whole once more, and a step it does not hold waits for the
        // next pass.
        while let Some(room) = room
            && crate::compaction::compaction_input_tokens(start, &window, &pins, budget) > room
        {
            window.pop();
            if window.is_empty() {
                return Err(oversized().into());
            }
            pins = super::compaction::window_pins(&window);
        }
        // Nested provenance: the newest epoch stands for every id the calls
        // before its count served, and for the epochs before it, since those
        // are its own sources. Only the calls since then are read here, so a
        // long run never outgrows one summary's sources, and a record served
        // before the epoch and purged since withdrew that epoch instead.
        let captured = newest.map_or(0, |row| row.calls());
        let calls = usize::try_from(captured)
            .ok()
            .and_then(|from| record.bridge_calls.get(from..))
            .ok_or(crate::Error::CorruptedIndex(
                "compaction coverage names calls the run never made",
            ))?;
        // The host's own words: the run's speech since the newest epoch, and
        // that epoch, which its requests rendered.
        let mut host = vec![turn_id];
        for order in super::compaction::speech_orders(calls) {
            host.push(crate::code_run::executor_speech_message_id_in_run(
                run_ref, run_id, order,
            )?);
        }
        host.extend(newest.map(|row| row.summary_id()));
        let (sources, request_id) = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
                (
                    super::compaction::served_sources(&vault.store, &rtxn, calls, host)?,
                    vault.store.clock.entity_id()?,
                )
            }
            crate::code_run::ExecutorStorage::Session(binding) => binding.answered(|| {
                let view = binding.session.read_view()?;
                let rtxn = view.read().base().env.read_txn()?;
                Ok((
                    super::compaction::served_sources(&view, &rtxn, calls, host)?,
                    crate::store::ManifestDbs::clock(&view).entity_id()?,
                ))
            })?,
        };
        let prior = prior.map(|(epoch, last)| crate::compaction::PriorEpoch::new(epoch, last));
        let calls = u64::try_from(record.bridge_calls.len())
            .map_err(|_| crate::Error::ArithmeticOverflow("executor call count"))?;
        Ok(Some(driver.request_for_log(
            request_id, &session, window, pins, sources, prior, calls,
        )?))
    }

    /// This run's swapped epochs with their summaries' prose, where the run's
    /// rows are: base, or its room's overlay over base.
    pub(super) fn compaction_epochs(
        &self,
        run_id: crate::EntityId,
    ) -> EngineExecutorResult<Vec<(crate::code_run::CodeRunCompactionCoverage, Option<String>)>>
    {
        Ok(self.storage.code_run_compaction_epochs(run_id)?)
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
