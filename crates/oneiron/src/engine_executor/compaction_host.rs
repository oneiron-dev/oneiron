//! The executor's side of the compaction host: landing a finished pass,
//! the token feed, and sealing a window from the durable replay.

mod check_evidence;
mod pending;
mod self_steps;

use super::compaction::{FoldJob, KindFolds, RunFrames};
use super::driver::EngineNativeExecutor;
use super::record::completed_step_count;
use super::self_brief::FoldBoundary;
use super::store::{
    COMPACTION_OBSERVATION_WINDOW_BYTES, RECOVERABLE_OUTPUT_CHUNK_BYTES, load_context_output,
    load_observation_window, load_script_context, observation_output_path, recoverable_chunk_path,
    scan_output_windows, script_output_path,
};
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::{CodeRunHistoryTurn, CodeRunReplayRecord};
use crate::compaction::{
    CompactHooks, FoldKind, FoldMark, FoldRecord, FoldedOutput, GatedCompaction, fold_handle,
};
use crate::runtime_hooks::VerbHookStop;
use crate::tokenizer::count_context_pack_tokens;
use crate::{ContentPart, LlmMessage, LlmMessageRole, LlmRequest};

impl EngineNativeExecutor<'_> {
    /// Keeps an unlanded pass's `host.compact` pre-chain records in its room
    /// (REVIEW-4357 P1-2): a backend refusal or a pre-swap-gate rejection
    /// ends the pass without landing, so its hooks never reach a post chain.
    /// No post hooks run here. A canonical pass keeps its own.
    fn keep_unlanded_compact_hooks(&self, hooks: CompactHooks) {
        let crate::code_run::ExecutorStorage::Session(binding) = &self.storage else {
            return;
        };
        crate::compaction::keep_compact_hooks_in_room(&binding.session, &binding.route, hooks);
    }

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
        let Some(mut finished) = seat.take_finished() else {
            self.compaction = Some(seat);
            return Ok(());
        };
        // FIX 4465 B: every paid call of a self-written pass is filed before
        // anything lands, so a landing that is refused keeps its steps too.
        self.file_self_passes(&mut finished);
        // FIX 17594 (Engine call B): a fold batch that committed is a brief
        // boundary, before the epoch the flight may swap in after it.
        if let Some((_, byline, _)) = seat.swap_seat()
            && let Some(landed) = self.land_folds(byline, finished.folds, finished.kind_folds)
        {
            self.brief_fold_committed(landed);
        }
        let hooks = finished.hooks;
        let epoch_execution = finished.epoch_execution;
        let landed = match finished.epoch {
            None => {
                self.keep_unlanded_compact_hooks(hooks);
                Ok(())
            }
            Some(Err(suppression)) => {
                seat.hold(suppression);
                self.keep_unlanded_compact_hooks(hooks);
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
                        match self.integrate_placed(
                            driver,
                            byline,
                            placement,
                            gated,
                            epoch_execution,
                        ) {
                            Ok(plan) => {
                                seat.swapped(plan.epoch, first, last);
                                // The post chain runs where its pre chain
                                // did: the vault, or the run's room (FIX
                                // 1594).
                                match &self.storage {
                                    crate::code_run::ExecutorStorage::Canonical(vault) => {
                                        vault.post_compact_hooks(hooks, &plan, first, last);
                                    }
                                    crate::code_run::ExecutorStorage::Session(binding) => {
                                        crate::compaction::post_compact_hooks_in_room(
                                            &binding.session,
                                            &binding.route,
                                            hooks,
                                            &plan,
                                            first,
                                            last,
                                        );
                                    }
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
                                self.keep_unlanded_compact_hooks(hooks);
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
                // A fold-sealing or ledger error after the pre-chain keeps
                // the unlanded pre-chain records in the room (REVIEW-4357
                // P1): the flight never lands, so the hooks never reach a
                // post chain, and no post hooks run here.
                let folds =
                    match self.seal_folds(driver, config, record, &marks, note.as_deref(), room) {
                        Ok(folds) => folds,
                        Err(error) => {
                            self.keep_unlanded_compact_hooks(hooks);
                            return Err(error);
                        }
                    };
                let mut kind_folds = match byline {
                    Some(byline) => {
                        match self.seal_kind_folds(record, run_id, &kind_marks, byline) {
                            Ok(folds) => folds,
                            Err(error) => {
                                self.keep_unlanded_compact_hooks(hooks);
                                return Err(error);
                            }
                        }
                    }
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
                if asked.is_some() {
                    match self
                        .storage
                        .update_code_run_folds(run_id, |ledger| ledger.compact = None)
                    {
                        Ok(()) => {}
                        Err(error) => {
                            self.keep_unlanded_compact_hooks(hooks);
                            return Err(error.into());
                        }
                    }
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
        room: Option<u64>,
    ) -> EngineExecutorResult<Vec<FoldJob>> {
        let mut jobs = Vec::new();
        let mut failed = Vec::new();
        for mark in marks {
            let note = match (mark.note.as_deref(), asked) {
                (Some(mark), Some(asked)) => Some(format!("{mark}\n{asked}")),
                (mark, asked) => mark.or(asked).map(str::to_owned),
            };
            match self.seal_fold(driver, config, record, mark, note, room)? {
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

    /// One batch's folds by kind (ARCH-0067 §2.2, fold by kind): for a
    /// `repl_output` mark, each step of its span keeps in its stub its
    /// output's handle, every stored result the output names and every id
    /// it names. The engine writes them from the steps' typed outputs, with
    /// no model call; the program text and its say() messages stay.
    fn seal_kind_folds(
        &self,
        record: &CodeRunReplayRecord,
        run_id: crate::EntityId,
        marks: &[FoldMark],
        byline: crate::WriteActor,
    ) -> EngineExecutorResult<Option<KindFolds>> {
        let mut records = Vec::new();
        for mark in marks {
            let Some(kind) = mark.kind else {
                continue;
            };
            let mut outputs = Vec::new();
            for seq in mark.from..=mark.through {
                match kind {
                    FoldKind::ReplOutput => {
                        let path = observation_output_path(seq);
                        let Some(output) = record.outputs.iter().find(|output| output.path == path)
                        else {
                            continue;
                        };
                        let mut handles = vec![serde_json::to_string(&serde_json::json!({
                            "step": seq,
                            "sandbox.fs.read_file": recoverable_chunk_path(seq, output.output_ref(), 0),
                            "byte_len": output.raw_len,
                            "max_chunk_bytes": RECOVERABLE_OUTPUT_CHUNK_BYTES,
                        }))?];
                        // The whole output, by range: a ref past the first
                        // window stays in the stub too.
                        let mut reads = std::collections::BTreeSet::new();
                        let mut ids = std::collections::BTreeSet::new();
                        scan_output_windows(&self.storage, record, output, |window| {
                            super::compaction::result_reads(window, &mut reads);
                            ids.extend(super::compaction::text_ids(window));
                        })?;
                        for read in reads {
                            handles.push(super::compaction::result_read_affordance(&read)?);
                        }
                        outputs.push(FoldedOutput {
                            step: seq,
                            handles,
                            ids: ids.into_iter().collect(),
                            said: Vec::new(),
                        });
                    }
                    FoldKind::Program => {
                        let path = script_output_path(seq);
                        if !record.outputs.iter().any(|output| output.path == path) {
                            continue;
                        }
                        let program = load_script_context(&self.storage, record, &path, None)?;
                        outputs.push(FoldedOutput {
                            step: seq,
                            handles: Vec::new(),
                            ids: super::compaction::text_ids(&program),
                            said: step_speech(record, seq),
                        });
                    }
                }
            }
            records.push(FoldRecord::of_kind(
                mark,
                kind,
                byline.entity_ref(),
                outputs,
            ));
        }
        Ok((!records.is_empty()).then_some(KindFolds { run_id, records }))
    }

    fn seal_fold(
        &self,
        driver: &crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        mark: &FoldMark,
        note: Option<String>,
        room: Option<u64>,
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
                super::compaction::step_message_id(run_id, seq)?,
                turn_id,
                seq,
                // A step's program, as its observation, is carried up to the
                // window's bytes, read by range (FIX 311).
                load_script_context(
                    &self.storage,
                    record,
                    &script_output_path(seq),
                    Some(COMPACTION_OBSERVATION_WINDOW_BYTES),
                )?,
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
            handles.push(super::compaction::result_read_affordance(&read)?);
        }
        // The span's failure lines and the agent's own profile pins it holds
        // are mandatory alike (FIX 9837): a span whose pins do not fit one
        // summary, or the backend's input, is refused, never kept without them.
        let pins = super::compaction::window_pins(&window, &driver.memory_profile().verbatim_pins);
        if count_context_pack_tokens(&pins.join("\n")) as u64 > budget {
            return Ok(Err(
                "its pinned lines do not fit one summary; fold a shorter span".to_owned(),
            ));
        }
        if let Some(room) = room
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
            super::compaction::fold_request_id(run_id, mark.fold)?,
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
            execution: None,
            marked_at: mark.marked_at,
        }))
    }

    /// One landed fold batch: every accepted fold becomes visible at once,
    /// in one ledger write, and each failed mark keeps why. Each summary is
    /// stamped Generated under the host's `byline`, with the sources its
    /// request was sealed with (Docs Q24), and a self-written one with each
    /// home part it wore too (FIX 4465 B). A batch that cannot be written
    /// leaves its marks pending for the next pass. Returns what the batch
    /// committed, as its brief boundary (FIX 17594): `None` when it wrote no
    /// fold, or was not written.
    fn land_folds(
        &self,
        byline: crate::WriteActor,
        folds: Vec<(FoldJob, Result<GatedCompaction, String>)>,
        kind_folds: Option<KindFolds>,
    ) -> Option<FoldBoundary> {
        let run_id = folds
            .first()
            .map(|(job, _)| job.run_id)
            .or(kind_folds.as_ref().map(|batch| batch.run_id))?;
        // The batch's folds by kind land in the same write as its passes.
        let mut landed = kind_folds.map_or_else(Vec::new, |batch| batch.records);
        let mut failed = Vec::new();
        for (job, answer) in folds {
            match answer {
                Ok(gated) => match self.self_fold_receipt(byline, &job, &gated) {
                    Ok(execution) => landed.push(FoldRecord {
                        fold: job.fold,
                        from: job.from,
                        through: job.through,
                        summary: Some(gated.summary_text().to_owned()),
                        source: crate::claim::ClaimSource::Generated,
                        actor: byline.entity_ref(),
                        sources: fold_sources(&gated, execution.as_ref()),
                        ids: job.ids,
                        handles: job.handles,
                        execution,
                        kind: None,
                        note: None,
                        outputs: Vec::new(),
                        marked_at: job.marked_at,
                    }),
                    Err(why) => failed.push((job.fold, why)),
                },
                Err(why) => failed.push((job.fold, why)),
            }
        }
        landed.sort_by_key(|record| record.fold);
        match self.storage.land_code_run_folds(run_id, landed, &failed) {
            Ok(committed) => FoldBoundary::landed(run_id, committed),
            Err(_) => {
                tracing::warn!("a fold batch did not land");
                None
            }
        }
    }

    /// A self-written fold (FIX 4465) lands only on its packet: a turn digest
    /// of its gated window, admitted on the run's log for the fold's span and
    /// checked against its gated request. Its receipt rides the fold record.
    /// Any other fold carries none. A room's run admits it against its replay
    /// as its captured route reads it (FIX 4465 B).
    fn self_fold_receipt(
        &self,
        byline: crate::WriteActor,
        job: &FoldJob,
        gated: &GatedCompaction,
    ) -> Result<Option<crate::compaction::CompactionExecution>, String> {
        let Some(execution) = job.execution.clone() else {
            return Ok(None);
        };
        let log = crate::compaction::CompactionHostLog {
            run_ref: self.gated_write.run_ref(),
            run_id: job.run_id,
            first: job.from,
            last: job.through,
        };
        let admitted = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => {
                crate::compaction::admit_self_landing(vault, log, gated, execution)
            }
            crate::code_run::ExecutorStorage::Session(_) => self
                .storage
                .get_code_run_replay_record(&job.run_id)
                .and_then(|record| {
                    record.ok_or(crate::Error::CorruptedIndex(
                        "missing executor replay record",
                    ))
                })
                .and_then(|record| {
                    crate::compaction::admit_self_landing_on(&record, log, gated, execution)
                }),
        };
        admitted
            .and_then(|landing| {
                crate::compaction::CompactionDriver::check_self_landing(
                    gated, job.run_id, byline, &landing,
                )?;
                Ok(Some(landing.execution))
            })
            .map_err(|_| "its self-written summary's packet was not admitted".to_owned())
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
                // A fold by kind brings back only the content it folded,
                // each step's labelled with its step; the programs never left.
                if let Some(kind) = fold.kind {
                    let mut unfolded = format!(
                        "unfolded {} from t{}–t{} ({}):",
                        kind.as_str(),
                        fold.from,
                        fold.through,
                        fold_handle(fold.fold)
                    );
                    for output in &fold.outputs {
                        match kind {
                            FoldKind::Program => {
                                let turn = CodeRunHistoryTurn {
                                    code: load_script_context(
                                        &self.storage,
                                        record,
                                        &script_output_path(output.step),
                                        None,
                                    )?,
                                    console: String::new(),
                                };
                                unfolded.push_str(&format!("\nt{}:\n", output.step));
                                unfolded.push_str(&turn.assistant_exec());
                            }
                            FoldKind::ReplOutput => {
                                let turn = CodeRunHistoryTurn {
                                    code: String::new(),
                                    console: load_context_output(
                                        &self.storage,
                                        record,
                                        &observation_output_path(output.step),
                                    )?,
                                };
                                unfolded.push('\n');
                                unfolded.push_str(&turn.user_console(output.step));
                            }
                        }
                    }
                    messages.push(text(unfolded));
                    continue;
                }
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
                        code: load_script_context(
                            &self.storage,
                            record,
                            &script_output_path(step),
                            None,
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
            program_steps: self.program_steps(replay_record.run_id),
            status,
            steps_run,
            replay_record,
            seat_receipt: self.seat.map(|seat| seat.receipt().clone()),
            compaction: self.compaction_report(),
        }
    }
}

/// Each speech call step `seq` made, in order, by its bridge call: read from
/// the step's own bridge calls, as its checkpoint records them. No text is
/// kept; the stub reads it, masked, when it renders. A step whose checkpoint
/// keeps no range, or a call that did not emit, gives none.
fn step_speech(record: &CodeRunReplayRecord, seq: u64) -> Vec<crate::compaction::FoldedSpeech> {
    let Some(range) = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == seq)
        .and_then(crate::code_run::CodeRunStepCheckpoint::bridge_range)
    else {
        return Vec::new();
    };
    record
        .bridge_calls
        .get(range)
        .unwrap_or_default()
        .iter()
        .filter(|call| call.emitted_speech() && super::compaction::speech_call_text(call).is_some())
        .map(|call| crate::compaction::FoldedSpeech {
            verb: call.effect.as_str().to_owned(),
            call: call.seq,
        })
        .collect()
}

/// What a fold's summary is derived from: every record its request was
/// sealed with, and for a self-written one each home part its call wore
/// whole (FIX 4465 B, Engine 10-19), so withdrawing one withdraws the words.
fn fold_sources(
    gated: &GatedCompaction,
    execution: Option<&crate::compaction::CompactionExecution>,
) -> Vec<crate::EntityId> {
    let mut sources = gated.request().sources.clone();
    for row in execution
        .into_iter()
        .flat_map(crate::compaction::CompactionExecution::home_dependencies)
    {
        if !sources.contains(&row) {
            sources.push(row);
        }
    }
    sources
}
