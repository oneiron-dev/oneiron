//! The executor's side of the compaction host: landing a finished pass,
//! the token feed, and sealing a window from the durable replay.

use super::compaction::{FoldJob, RunFrames};
use super::driver::EngineNativeExecutor;
use super::record::completed_step_count;
use super::store::{
    COMPACTION_OBSERVATION_WINDOW_BYTES, RECOVERABLE_OUTPUT_CHUNK_BYTES, load_context_output,
    load_observation_window, observation_output_path, recoverable_chunk_path, script_output_path,
};
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::{CodeRunHistoryTurn, CodeRunReplayRecord};
use crate::compaction::{CompactHooks, FoldMark, FoldRecord, GatedCompaction, fold_handle};
use crate::tokenizer::count_context_pack_tokens;
use crate::{ContentPart, LlmMessage, LlmMessageRole, LlmRequest};

impl EngineNativeExecutor<'_> {
    /// Lands a finished background flight: an accepted summary swaps in as
    /// this run's next epoch, and anything else holds for the turn and leaves
    /// the window whole; its fold batch lands at once, in one ledger write.
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
        let Some(finished) = seat.take_finished() else {
            self.compaction = Some(seat);
            return Ok(());
        };
        if let Some((_, byline, _)) = seat.swap_seat() {
            self.land_folds(byline, finished.folds);
        }
        let hooks = finished.hooks;
        let landed = match finished.epoch {
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
                                if let crate::code_run::ExecutorStorage::Canonical(vault) =
                                    &self.storage
                                {
                                    vault.post_compact_hooks(hooks, &plan, first, last);
                                }
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
    /// driver. A crossing, or the agent's `self.compact` ask, seals the steps
    /// up to the watermark and every fold mark that applies, in one flight.
    pub(super) fn feed_compaction(
        &mut self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        request: &LlmRequest,
    ) -> EngineExecutorResult<Option<super::compaction::WindowFullReason>> {
        let completed = completed_step_count(record)?;
        if self.compaction.is_none() {
            return Ok(None);
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
        let Some(seat) = self.compaction.take() else {
            return Ok(None);
        };
        // A run whose compaction is off folds nothing: its asks end with why,
        // which `self.folds()` shows.
        if !seat.is_live()
            && (asked.is_some() || !marks.is_empty())
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
            !marks.is_empty(),
            |driver, watermark| {
                if let Err(refusal) = self.admit_compaction_read() {
                    refused = Some(refusal);
                    return Ok(super::compaction::Flight::default());
                }
                let note = asked.clone().flatten();
                let (epoch, hooks) = match watermark {
                    Some(watermark) => self
                        .seal_compaction_window(driver, config, record, watermark, note.clone())?
                        .map_or((None, CompactHooks::default()), |(request, hooks)| {
                            (Some(request), hooks)
                        }),
                    None => (None, CompactHooks::default()),
                };
                let folds = self.seal_folds(driver, config, record, &marks, note.as_deref())?;
                if asked.is_some() {
                    self.storage
                        .update_code_run_folds(run_id, |ledger| ledger.compact = None)?;
                }
                Ok(super::compaction::Flight {
                    epoch,
                    folds,
                    hooks,
                })
            },
        );
        self.compaction = Some(seat);
        match refused {
            Some(refusal) => Err(refusal),
            None => Ok(reason),
        }
    }

    /// One fold job per mark (ARCH-0067 §2.2): the span's own retained
    /// turns, its failure pins, the agent's notes, and what its stub lists
    /// beside the summary. A mark one pass cannot hold keeps why, in one
    /// ledger write.
    fn seal_folds(
        &self,
        driver: &crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        marks: &[FoldMark],
        asked: Option<&str>,
    ) -> EngineExecutorResult<Vec<FoldJob>> {
        let mut jobs = Vec::new();
        let mut failed = Vec::new();
        for mark in marks {
            let note = match (mark.note.as_deref(), asked) {
                (Some(mark), Some(asked)) => Some(format!("{mark}\n{asked}")),
                (mark, asked) => mark.or(asked).map(str::to_owned),
            };
            match self.seal_fold(driver, config, record, mark, note)? {
                Ok(job) => jobs.push(job),
                Err(why) => failed.push((mark.fold, why)),
            }
        }
        if !failed.is_empty() {
            self.storage
                .update_code_run_folds(config.run_id, |ledger| ledger.land(Vec::new(), &failed))?;
        }
        Ok(jobs)
    }

    fn seal_fold(
        &self,
        driver: &crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        mark: &FoldMark,
        note: Option<String>,
    ) -> EngineExecutorResult<Result<FoldJob, String>> {
        let run_id = config.run_id;
        let run_ref = self.gated_write.run_ref();
        let session = crate::code_run::executor_compaction_session_id(run_ref, run_id)?;
        let turn_id = crate::code_run::executor_speech_turn_id_for_run(run_ref, run_id)?;
        let budget = driver.summary_token_budget();
        let mut window = Vec::new();
        let mut handles = Vec::new();
        let mut reads = std::collections::BTreeSet::new();
        for seq in mark.from..=mark.through {
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
            let path = observation_output_path(seq);
            if let Some(output) = record.outputs.iter().find(|output| output.path == path) {
                handles.push(serde_json::to_string(&serde_json::json!({
                    "step": seq,
                    "sandbox.fs.read_file": recoverable_chunk_path(seq, output.output_ref(), 0),
                    "byte_len": output.raw_len,
                    "max_chunk_bytes": RECOVERABLE_OUTPUT_CHUNK_BYTES,
                }))?);
            }
            super::compaction::result_reads(&message.content, &mut reads);
            window.push(message);
        }
        // Docs Q22 (ARCH-0067 #fold-result-handles): a stub names every stored
        // result, printed or not. The bounded window scan above finds only the
        // ones the console showed; the run's stored manifests are the whole
        // set, so a never-printed result stays reachable by its handle. It may
        // name a same-run result from outside the span: a superset, never a
        // loss.
        for output in &record.outputs {
            if super::store::is_result_output_path(&output.path) {
                reads.insert(super::store::result_read_path(output.output_ref()));
            }
        }
        for read in reads {
            handles.push(serde_json::to_string(
                &serde_json::json!({ "sandbox.fs.read_file": read }),
            )?);
        }
        let mut pins = super::compaction::window_pins(&window);
        if count_context_pack_tokens(&pins.join("\n")) as u64 > budget {
            return Ok(Err(
                "its failure lines do not fit one summary; fold a shorter span".to_owned(),
            ));
        }
        let room = driver.backend().input_token_limit(budget);
        super::compaction::add_profile_pins(
            &mut pins,
            &window,
            &driver.memory_profile().verbatim_pins,
            |pins| {
                count_context_pack_tokens(&pins.join("\n")) as u64 <= budget
                    && room.is_none_or(|room| {
                        crate::compaction::compaction_input_tokens(
                            mark.from,
                            &window,
                            pins,
                            note.as_deref(),
                            budget,
                        ) <= room
                    })
            },
        );
        if let Some(room) = driver.backend().input_token_limit(budget)
            && crate::compaction::compaction_input_tokens(
                mark.from,
                &window,
                &pins,
                note.as_deref(),
                budget,
            ) > room
        {
            return Ok(Err(
                "the span is longer than the compaction backend takes whole; fold a shorter span"
                    .to_owned(),
            ));
        }
        let ids = super::compaction::span_ids(&window);
        // What the summary derives from (Docs Q24): every record whose words
        // could reach the span. No step boundary is stored with the run's
        // calls, so that is everything the run was served and the host's own
        // words to it, a superset that withdraws the summary with any of
        // them, and never a summary before it: the span is raw turns.
        let mut host = vec![turn_id];
        for order in super::compaction::speech_orders(&record.bridge_calls) {
            host.push(crate::code_run::executor_speech_message_id_in_run(
                run_ref, run_id, order,
            )?);
        }
        let sources = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
                super::compaction::served_sources(&vault.store, &rtxn, &record.bridge_calls, host)?
            }
            crate::code_run::ExecutorStorage::Session(binding) => binding.answered(|| {
                let view = binding.session.read_view()?;
                let rtxn = view.read().base().env.read_txn()?;
                super::compaction::served_sources(&view, &rtxn, &record.bridge_calls, host)
            })?,
        };
        let calls = u64::try_from(record.bridge_calls.len())
            .map_err(|_| crate::Error::ArithmeticOverflow("executor call count"))?;
        let request = driver.fold_request(
            super::compaction::fold_request_id(run_id, mark.fold),
            &session,
            window,
            pins,
            sources,
            note,
            calls,
        )?;
        Ok(Ok(FoldJob {
            run_id,
            fold: mark.fold,
            from: mark.from,
            through: mark.through,
            request,
            ids,
            handles,
        }))
    }

    /// One landed fold batch: every accepted fold becomes visible at once,
    /// in one ledger write, and each failed mark keeps why. Each summary is
    /// stamped Generated under the host's `byline`, with the sources its
    /// request was sealed with (Docs Q24). A batch that cannot be written
    /// leaves its marks pending for the next pass.
    fn land_folds(
        &self,
        byline: crate::WriteActor,
        folds: Vec<(FoldJob, Result<GatedCompaction, String>)>,
    ) {
        let Some(run_id) = folds.first().map(|(job, _)| job.run_id) else {
            return;
        };
        let mut landed = Vec::new();
        let mut failed = Vec::new();
        for (job, answer) in folds {
            match answer {
                Ok(gated) => landed.push(FoldRecord {
                    fold: job.fold,
                    from: job.from,
                    through: job.through,
                    summary: Some(gated.summary_text().to_owned()),
                    source: crate::claim::ClaimSource::Generated,
                    actor: byline.entity_ref(),
                    sources: gated.request().sources.clone(),
                    ids: job.ids,
                    handles: job.handles,
                }),
                Err(why) => failed.push((job.fold, why)),
            }
        }
        if self
            .storage
            .land_code_run_folds(run_id, landed, &failed)
            .is_err()
        {
            tracing::warn!("a fold batch did not land");
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
    /// room's overlay over base. A canonical run's window, keep list and
    /// ceiling then pass `host.compact`'s pre-hooks, which may pin more.
    fn seal_compaction_window(
        &self,
        driver: &mut crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        watermark: u64,
        note: Option<String>,
    ) -> EngineExecutorResult<Option<(crate::compaction::CompactionRequest, CompactHooks)>> {
        let run_id = config.run_id;
        let run_ref = self.gated_write.run_ref();
        // The run's position is its coverage rows, withdrawn summaries
        // included: erasing a summary never moves where the next one starts.
        let coverage = self.storage.code_run_compaction_coverage(run_id)?;
        let newest = coverage.iter().max_by_key(|row| row.epoch()).copied();
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
                let whole = || {
                    crate::compaction::compaction_input_tokens(
                        start,
                        &window,
                        &pins,
                        note.as_deref(),
                        budget,
                    )
                };
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
            && crate::compaction::compaction_input_tokens(
                start,
                &window,
                &pins,
                note.as_deref(),
                budget,
            ) > room
        {
            window.pop();
            if window.is_empty() {
                return Err(oversized().into());
            }
            pins = super::compaction::window_pins(&window);
        }
        let fits = |pins: &[String]| {
            count_context_pack_tokens(&pins.join("\n")) as u64 <= budget
                && room.is_none_or(|room| {
                    crate::compaction::compaction_input_tokens(
                        start,
                        &window,
                        pins,
                        note.as_deref(),
                        budget,
                    ) <= room
                })
        };
        super::compaction::add_profile_pins(
            &mut pins,
            &window,
            &driver.memory_profile().verbatim_pins,
            &fits,
        );
        // A run bound to a room runs no hooks: their receipts would land on
        // record.
        let hooks = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => vault.pre_compact_hooks(
                crate::compaction::compact_invocation(run_id.as_bytes(), watermark),
                self.gated_write.actor().entity_ref(),
                &window,
                &mut pins,
                budget,
                &fits,
            ),
            crate::code_run::ExecutorStorage::Session(_) => CompactHooks::default(),
        };
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
        let request = driver.request_for_log(
            request_id, &session, window, pins, sources, prior, calls, note,
        )?;
        Ok(Some((request, hooks)))
    }

    /// This run's swapped epochs with their summaries' prose, and its fold
    /// ledger, where the run's rows are: base, or its room's overlay over
    /// base.
    pub(super) fn compaction_epochs(
        &self,
        run_id: crate::EntityId,
    ) -> EngineExecutorResult<RunFrames> {
        Ok(RunFrames {
            epochs: self.storage.code_run_compaction_epochs(run_id)?,
            folds: self.storage.code_run_folds(run_id)?,
        })
    }

    /// The log at the place just before step `seq` (ARCH-0067 §2.2): each
    /// fold the agent unfolded there, its raw turns whole and labelled with
    /// their span. They stay where the end of the log was when it unfolded
    /// them and never go back in place, so the cached log holds. At the end
    /// of the log comes the dynamic folds line: handles, spans and pending
    /// marks only.
    pub(super) fn fold_tail(
        &self,
        frames: &RunFrames,
        record: &CodeRunReplayRecord,
        seq: usize,
    ) -> EngineExecutorResult<Vec<LlmMessage>> {
        let seq = u64::try_from(seq)
            .map_err(|_| crate::Error::ArithmeticOverflow("executor step count"))?;
        let completed = completed_step_count(record)?;
        let text = |text: String| LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        };
        let mut messages = Vec::new();
        if !frames.hides(record.run_id, seq) {
            for append in frames
                .folds
                .unfolds
                .iter()
                .filter(|append| append.at == seq)
            {
                let Some(fold) = frames.folds.fold(append.fold) else {
                    continue;
                };
                let mut unfolded = format!(
                    "unfolded from t{}–t{} ({}):",
                    fold.from,
                    fold.through,
                    fold_handle(fold.fold)
                );
                // A withdrawn record's words reached this span (Docs Q23):
                // its turns stay folded, so an unfold cannot bring them back.
                if fold.summary.is_none() {
                    unfolded.push_str(" withdrawn; its turns stay folded");
                    messages.push(text(unfolded));
                    continue;
                }
                for step in fold.from..=fold.through.min(completed.saturating_sub(1)) {
                    let turn = CodeRunHistoryTurn {
                        code: load_context_output(
                            &self.storage,
                            record,
                            &script_output_path(step),
                        )?,
                        console: load_context_output(
                            &self.storage,
                            record,
                            &observation_output_path(step),
                        )?,
                    };
                    unfolded.push('\n');
                    unfolded.push_str(&turn.assistant_exec());
                    unfolded.push('\n');
                    unfolded.push_str(&turn.user_console(step));
                }
                messages.push(text(unfolded));
            }
        }
        if seq >= completed
            && let Some(line) = frames.folds.board_line()
        {
            messages.push(text(line));
        }
        Ok(messages)
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
