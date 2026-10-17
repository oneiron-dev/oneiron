//! Durable REPL loop: run(), persistence helpers, and LLM request building.

use super::code_check::ShadowStep;
use super::driver::EngineNativeExecutor;
use super::host::{
    RecordingJsHost, executor_boundary_contract, executor_system_prompt, executor_turn_instruction,
};
use super::record::{
    LoadedReplayRecord, PromptBinding, REPLAY_METADATA_SCHEMA_VERSION, StepResultDigests,
    completed_step_count, load_terminal_status, parked_wait_at, previous_state_hash,
    record_config_marker, record_terminal_output, step_state_hash, validate_executor_config_marker,
    wait_key,
};
use super::store::{
    COMPACTION_OBSERVATION_WINDOW_BYTES, ObservationRef, RECOVERABLE_OUTPUT_CHUNK_BYTES,
    RESULT_REPLY_INLINE_BYTES, checkpoint_label, clean_for_context, fallback_speech_marker,
    implicit_speak_output_path, load_context_output, load_observation_window, load_utf8_output,
    observation_output_path, observation_ref, publish_output, record_reply_evidence,
    record_script_output, record_text_output, recoverable_chunk_path, resumed_output_path,
    resumed_output_wait, script_output_path, validate_runtime_outputs, write_json,
};
use super::types::{
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorConfig,
    EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus, JsCodeModeStep,
};
use super::wire::{HealedExecutorReply, heal_executor_reply};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunBridgeCall, CodeRunHistoryTurn, CodeRunRawOutput,
    CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunResultBinding, CodeRunStepCheckpoint,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, WaitKey,
};
use crate::compaction::output::{OutputAffordance, OutputRef, OutputTier, OutputWorkingContext};
use crate::off_record::ExecutorUtterance;
use crate::prompt::resolve_engine_executor_wire_prompt;
use crate::runtime_hooks::VerbHookStop;
use crate::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, EntityId, Error,
    LlmMessage, LlmMessageRole, LlmRequest, ResponseFormat, TierPrecedence,
};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

impl EngineNativeExecutor<'_> {
    pub async fn run(
        &mut self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        self.verify_storage_dispatcher_binding()?;
        config.validate()?;
        if let Some(seat) = self.seat {
            if &config.model != seat.model()
                || config.model_locality != seat.locality()
                || config.seat_effort != Some(seat.effort())
            {
                return Err(
                    Error::InvalidConfig("executor seat and run config disagree".into()).into(),
                );
            }
            if let crate::code_run::ExecutorStorage::Canonical(vault) = &self.storage {
                let recorded = vault.model_seat_receipt(config.run_id)?;
                if !recorded.is_some_and(|receipt| {
                    receipt.model == *seat.model()
                        && receipt.effort == seat.effort()
                        && receipt.why == seat.receipt().why
                }) {
                    return Err(Error::InvalidConfig(
                        "executor seat is not durably bound to run".into(),
                    )
                    .into());
                }
            }
        } else {
            if config.seat_effort.is_some() {
                return Err(Error::InvalidConfig("executor seat pin missing".into()).into());
            }
            if let crate::code_run::ExecutorStorage::Canonical(vault) = &self.storage
                && vault.model_manifest()?.is_some()
            {
                return Err(Error::InvalidConfig(
                    "manifest-backed executor requires a seat".into(),
                )
                .into());
            }
        }
        // Resolve exactly once per run attempt. Both teaching sites use these
        // bytes, and the fingerprint joins the durable replay identity below.
        let wire_prompt = resolve_engine_executor_wire_prompt(&config.prompt_package_root)
            .map_err(Error::from)?;
        let boundary = executor_boundary_contract()?;
        let loaded = self.load_or_create_record(config, &wire_prompt.stamp.resolved_fingerprint)?;
        // A terminal replay still owes typed restore even when no new model
        // request is assembled during this attempt.
        if self.output_run != Some(config.run_id) {
            self.output_context = OutputWorkingContext::default();
            self.output_run = Some(config.run_id);
        }
        if let Some(seat) = self.compaction.as_deref_mut() {
            seat.begin_turn(matches!(
                self.storage,
                crate::code_run::ExecutorStorage::Canonical(_)
            ));
        }
        let LoadedReplayRecord {
            mut record,
            generation: mut expected_generation,
            terminal_status,
            prompt,
        } = loaded;
        if let Some(status) = terminal_status {
            // A run parked on a wait goes on, at the step after the parked
            // one, once the wait's reply is delivered.
            let resumed = match &status {
                EngineExecutorStatus::Waiting(wait) => match self.park(&record, wait)? {
                    Some(key) => {
                        // The resumed run asks the model again, so it does so
                        // under the teaching it committed to.
                        if prompt == PromptBinding::Drifted {
                            return Err(Error::InvalidConfig(
                                "engine executor config changed for existing run".to_owned(),
                            )
                            .into());
                        }
                        self.resume_delivered_wait(&mut record, wait, &key, expected_generation)?
                    }
                    None => None,
                },
                _ => None,
            };
            let Some(generation) = resumed else {
                self.recover_checkpointed_implicit_speak(&record, &status, config)?;
                return Ok(self.outcome(status, 0, record));
            };
            expected_generation = Some(generation);
        }
        let mut steps_run = 0_u32;

        loop {
            let completed_steps = completed_step_count(&record)?;
            if completed_steps >= u64::from(config.limits.hard_steps) {
                return Ok(self.outcome(
                    EngineExecutorStatus::HardStepLimitReached,
                    steps_run,
                    record,
                ));
            }
            if steps_run >= config.limits.soft_steps {
                return Ok(self.outcome(
                    EngineExecutorStatus::Yielded {
                        next_step_seq: completed_steps,
                    },
                    steps_run,
                    record,
                ));
            }

            self.land_finished_compaction()?;
            // A turn hook's ask parks the run before the turn, as a call's
            // ask parks the call; a skip or a hidden result ends the entry.
            let turn = match self.pre_turn_hooks(config, completed_steps)? {
                Ok(turn) => turn,
                Err(stop) => {
                    let Some(wait) = turn_hook_wait(&stop) else {
                        return Err(Error::from(stop).into());
                    };
                    let key = wait_key(&record, &wait);
                    if !self.storage.park_wait(&key)? {
                        return Ok(self.outcome(
                            EngineExecutorStatus::Waiting(wait),
                            steps_run,
                            record,
                        ));
                    }
                    // The ask settled before the park: the turn's hooks take
                    // its answer now, and any stop then ends the entry.
                    self.storage.clear_wait(&key)?;
                    self.pre_turn_hooks(config, completed_steps)?
                        .map_err(Error::from)?
                }
            };
            let request = self.build_llm_request(config, &record, &wire_prompt.text)?;
            if let Some(reason) = self.feed_compaction(config, &record, &request)? {
                return Ok(self.outcome(
                    EngineExecutorStatus::WindowFull {
                        next_step_seq: completed_steps,
                        reason,
                    },
                    steps_run,
                    record,
                ));
            }
            let request_hash = request.canonical_hash()?;
            let response = self.backend.generate(request, self.lease).await?;
            self.post_turn_hooks(turn, &response)?;
            // The provider that answered is the one this turn's program
            // speaks for: each verb call it makes carries the name (OF-560).
            self.gated_write
                .observe_model_provider(response.usage.served_provider());
            // The reply as the provider gave it, kept apart from the program
            // healed out of it: evidence, never executed.
            record_reply_evidence(
                &self.storage,
                &mut record,
                completed_steps,
                &response.message,
            )?;
            // ONE-1929: the ONE normalization seam. Only `code` is executed,
            // staged, hashed, or replayed; the reply's own console bytes are
            // already gone, and `trailing_speak` belongs to ONE-1686.
            let HealedExecutorReply {
                code: script,
                trailing_speak,
                repairs,
            } = heal_executor_reply(&response)?;
            record_script_output(
                &self.storage,
                &mut record,
                script_output_path(completed_steps),
                &script,
            )?;
            // Shadow mode type-checks the program before it runs and acts on
            // nothing it finds. The report is appended once the step's own
            // state is durable.
            let mut shadow = self
                .code_check
                .map(|shadow| ShadowStep::check(shadow, config.run_id, completed_steps, &script));

            let bridge_start = record.bridge_calls.len();
            // ONE-1314: the DURABLE history is the load-bearing half of the
            // lineage seam. An outbound effect parks its step, so a run that
            // reached outside and then writes always spans a resume, and the
            // resuming step's only record of that hop is the replay record
            // being read here. Observed before any write of this step can
            // dispatch; the dispatcher owns the history-to-lineage mapping.
            self.gated_write
                .observe_bridge_history(&record.bridge_calls);
            let recoverable = self.observation_refs(&record)?;
            let mut host = RecordingJsHost::new(
                self.gated_write,
                config.run_id,
                bridge_start as u64,
                config.determinism,
                self.legibility,
            )
            .with_recoverable_outputs(&self.storage, &record, recoverable)?
            .with_skill_executor(&config.model);
            let step = JsCodeModeStep {
                run_id: config.run_id,
                seq: completed_steps,
                script: &script,
                boundary,
                determinism: config.determinism,
            };
            let step_outcome = match self.runtime.run_step(step, &mut host) {
                Ok(outcome) => outcome,
                Err(err) => {
                    let durable_wait = host.durable_wait;
                    let bridge_calls = host.bridge_calls;
                    let captured = host.captured;
                    if !bridge_calls.is_empty()
                        && let Some(status) = self.persist_failed_step_after_bridge_calls(
                            &mut record,
                            expected_generation,
                            completed_steps,
                            &request_hash,
                            &script,
                            bridge_start,
                            bridge_calls,
                            captured,
                            durable_wait,
                            format!("Runtime error after host bridge calls: {err}"),
                            repairs.healed(),
                            config,
                        )?
                    {
                        if let Some(shadow) = &mut shadow {
                            shadow.ended(Some(&status));
                        }
                        return Ok(self.outcome(status, steps_run + 1, record));
                    }
                    return Err(err.into());
                }
            };
            if let Some(failure) = host.hard_failure.take() {
                // The guest saw a typed Denied/Failed response (budget
                // attached) at the chokepoint; the STEP still fails with
                // the original error after persisting the bridge rows.
                let durable_wait = host.durable_wait;
                let bridge_calls = host.bridge_calls;
                let captured = host.captured;
                if let Some(status) = self.persist_failed_step_after_bridge_calls(
                    &mut record,
                    expected_generation,
                    completed_steps,
                    &request_hash,
                    &script,
                    bridge_start,
                    bridge_calls,
                    captured,
                    durable_wait,
                    format!("Host bridge call failed: {failure}"),
                    repairs.healed(),
                    config,
                )? {
                    if let Some(shadow) = &mut shadow {
                        shadow.ended(Some(&status));
                    }
                    return Ok(self.outcome(status, steps_run + 1, record));
                }
                return Err(failure.into());
            }
            // The step's bodies, streamed by the guest or returned whole by a
            // runtime that does not stream, each in a sink of the run's body
            // store; none is held whole here.
            let step_bodies = host
                .take_streamed()
                .into_step_bodies(&self.storage, &step_outcome)
                .map_err(Into::into)
                .and_then(|bodies| {
                    validate_runtime_outputs(&record, completed_steps, &bodies.files)
                        .map(|paths| (bodies, paths))
                });
            let (bodies, runtime_output_paths) = match step_bodies {
                Ok(found) => found,
                Err(err) => {
                    let durable_wait = host.durable_wait;
                    let bridge_calls = host.bridge_calls;
                    let captured = host.captured;
                    if !bridge_calls.is_empty()
                        && let Some(status) = self.persist_failed_step_after_bridge_calls(
                            &mut record,
                            expected_generation,
                            completed_steps,
                            &request_hash,
                            &script,
                            bridge_start,
                            bridge_calls,
                            captured,
                            durable_wait,
                            format!(
                                "Runtime output recording failed after host bridge calls: {err}"
                            ),
                            repairs.healed(),
                            config,
                        )?
                    {
                        if let Some(shadow) = &mut shadow {
                            shadow.ended(Some(&status));
                        }
                        return Ok(self.outcome(status, steps_run + 1, record));
                    }
                    return Err(err);
                }
            };
            self.gated_write.refuse_a_step_that_dropped_a_write(
                config.run_id,
                bridge_start as u64,
                &host.bridge_calls,
            )?;
            record.bridge_calls.extend(host.bridge_calls);
            // Bridge results too large for one reply and stored values, as
            // bodies; the calls' rows and the step's bindings carry their
            // handles.
            record.outputs.extend(host.captured);
            // The names the step bound join the record in this same
            // checkpointed append; a rebound name keeps its place.
            let bindings: Vec<_> = host
                .bound
                .iter()
                .map(|binding| (binding.name.clone(), binding.handle.clone()))
                .collect();
            for binding in host.bound {
                match record
                    .bindings
                    .iter_mut()
                    .find(|held| held.name == binding.name)
                {
                    Some(held) => *held = binding,
                    None => record.bindings.push(binding),
                }
            }
            let observation = publish_output(
                &self.storage,
                &mut record,
                observation_output_path(completed_steps),
                bodies.observation,
            )?;
            let mut outputs = Vec::with_capacity(bodies.files.len());
            for ((path, sink), stored_path) in bodies.files.into_iter().zip(runtime_output_paths) {
                let output = publish_output(&self.storage, &mut record, stored_path, sink)?;
                outputs.push((path, output.raw_blake3));
            }
            let step_result = StepResultDigests {
                observation: observation.raw_blake3,
                done: step_outcome.done,
                outputs,
                bindings,
            };
            // The agent's own refusal declined her TASK (OF-533): the run
            // ends here, complete, and says nothing more on her behalf.
            let declined = host.declined.is_some();
            let terminal_status = host
                .durable_wait
                .clone()
                .map(EngineExecutorStatus::Waiting)
                .or({
                    if step_outcome.done || declined {
                        Some(EngineExecutorStatus::Complete)
                    } else {
                        None
                    }
                });
            let implicit_speak = (!declined
                && matches!(terminal_status, Some(EngineExecutorStatus::Complete)))
            .then(|| {
                self.prepare_trailing_speak_fallback(
                    &record,
                    &observation,
                    trailing_speak.as_deref(),
                )
            })
            .transpose()?
            .flatten();
            if let Some(text) = implicit_speak.as_deref() {
                // The exact side-effect payload is part of the replay append,
                // not ephemeral provider state. It is content-addressed like
                // every other executor output and hashed into the checkpoint.
                record_text_output(
                    &self.storage,
                    &mut record,
                    implicit_speak_output_path(completed_steps),
                    text,
                )?;
            }
            if let Some(status) = &terminal_status {
                record_terminal_output(&self.storage, &mut record, completed_steps, status)?;
            }

            let checkpoint = CodeRunStepCheckpoint::new(
                completed_steps,
                checkpoint_label(completed_steps),
                step_state_hash(
                    previous_state_hash(&record),
                    completed_steps,
                    &request_hash,
                    &script,
                    &step_result,
                    implicit_speak.as_deref(),
                    &record.bridge_calls[bridge_start..],
                )?,
                config
                    .determinism
                    .frozen_unix_ms
                    .saturating_add(completed_steps),
            )?;
            record.step_checkpoints.push(checkpoint);
            // Replay persistence and its one-per-healed-turn signal are one
            // transaction. A generation conflict, tally error, or failed
            // commit advances neither; a durable append has already counted.
            // The fold receipts the step's stores computed land in it too,
            // beside the bindings they describe.
            let mut next_generation = self
                .storage
                .put_code_run_replay_record_with_receipts_if_generation(
                    &record,
                    expected_generation,
                    repairs.healed().then_some(&config.model),
                    &host.receipts,
                )?;
            // The implicit bubble is downstream of its checkpoint commit. A
            // compare-and-put failure emits nothing. A terminal retry replays
            // this delivery under stable witness ids, so it can recover a
            // missed emit without minting a duplicate bubble.
            if let Some(text) = implicit_speak.as_deref() {
                self.emit_trailing_speak_fallback(&record, completed_steps, text, config)?;
            }
            steps_run += 1;
            if let Some(shadow) = &mut shadow {
                shadow.ended(terminal_status.as_ref());
                if let Some(generation) =
                    shadow.append_report(&self.storage, &mut record, next_generation)
                {
                    next_generation = generation;
                }
            }

            if let Some(status) = terminal_status {
                // A reply that landed while the step ran resumes the run
                // here, with no round trip through its host.
                if let EngineExecutorStatus::Waiting(wait) = &status
                    && let Some(key) = self.park(&record, wait)?
                    && let Some(generation) =
                        self.resume_delivered_wait(&mut record, wait, &key, Some(next_generation))?
                {
                    expected_generation = Some(generation);
                    continue;
                }
                return Ok(self.outcome(status, steps_run, record));
            }
            expected_generation = Some(next_generation);
        }
    }

    /// Registers the run as parked on `wait`, the wait its last step
    /// committed, and answers the wait's key once its reply is delivered.
    /// Every entry of a Waiting run parks again, idempotently, so a park that
    /// a crash after the commit skipped is not lost.
    fn park(
        &self,
        record: &CodeRunReplayRecord,
        wait: &SelfDurableWait,
    ) -> EngineExecutorResult<Option<WaitKey>> {
        let key = wait_key(record, wait);
        Ok(self.storage.park_wait(&key)?.then_some(key))
    }

    /// Publishes the reply delivered to `key` as the result the parked
    /// step's call came back with, bound as `wait<s>`, and commits it. The
    /// parked step's bridge rows stay as recorded and nothing is dispatched
    /// again: the run goes on at the next step, whose context carries the
    /// reply. `None` when no reply is delivered.
    fn resume_delivered_wait(
        &mut self,
        record: &mut CodeRunReplayRecord,
        wait: &SelfDurableWait,
        key: &WaitKey,
        expected: Option<CodeRunReplayGeneration>,
    ) -> EngineExecutorResult<Option<CodeRunReplayGeneration>> {
        let Some(delivery) = self.storage.wait_delivery(key)? else {
            return Ok(None);
        };
        let seq = completed_step_count(record)?
            .checked_sub(1)
            .ok_or(Error::CorruptedIndex("executor replay wait without a step"))?;
        let mut reply: serde_json::Value = serde_json::from_str(&delivery.reply)
            .map_err(|_| Error::CorruptedIndex("code-run wait delivery"))?;
        if wait.effect == SelfEffect::Summarize {
            reply = self.storage.delivered_summary_reply(reply)?;
        }
        let mut sink = self.storage.code_run_output_sink()?;
        write_json(
            &mut sink,
            &json!({
                "schema_version": REPLAY_METADATA_SCHEMA_VERSION,
                "wait_id": wait.wait_id.to_hex(),
                "effect": wait.effect.as_str(),
                "generation": key.generation,
                "reply": reply,
            }),
        )?;
        let output = publish_output(
            &self.storage,
            record,
            resumed_output_path(seq, wait.wait_id),
            sink,
        )?;
        let name = format!("wait{seq}");
        match record.bindings.iter_mut().find(|held| held.name == name) {
            Some(held) => held.handle = output.handle,
            None => record
                .bindings
                .push(CodeRunResultBinding::new(name, output.handle)),
        }
        let generation = self
            .storage
            .put_code_run_wait_resume_record(record, expected, key)?;
        self.storage.clear_wait(key)?;
        Ok(Some(generation))
    }

    /// Selects the IMPLICIT speak payload BEFORE the terminal checkpoint
    /// (ONE-1686 policy, ONE-1929 checkpointing).
    ///
    /// # What is said
    ///
    /// A completed run's trailing plaintext becomes its last word. With
    /// bare-wire healing (ONE-1929) that plaintext is the HEALED trailing
    /// prose when the reply carried one, and the raw observation otherwise, so
    /// a model that wrapped its answer in a fence or forged a `<console>`
    /// block still speaks the words it actually meant.
    ///
    /// # What suppresses it
    ///
    /// Explicit speech is CANONICAL, and "canonical" is about the TEXT, not
    /// about whether the run happened to speak at all. A run that spoke and
    /// then finished with the SAME words has already said them, so a trailing
    /// bubble would be a duplicate; a run that spoke and then finished with
    /// DIFFERENT words has a last word nobody has heard, and dropping it loses
    /// the answer. So the suppression is per-text: the fallback is skipped only
    /// when an emitted speech row in the durable record carries exactly this
    /// trailing text. The check is over the DURABLE record, not a per-step
    /// flag, so a run that spoke in step 0 and completed in step 3 is still
    /// judged against everything it said.
    ///
    /// A speech row that did NOT emit — a barrier-parked wait, a denied or
    /// failed trap — never suppresses anything: no bubble exists for it, so
    /// its text was not said.
    ///
    /// It fires on `Complete` only: a run parked on a durable wait has not
    /// finished speaking, and a yielded or step-limited run has not finished
    /// at all. Both storage arms answer here, because ONE-1686 gave a
    /// canonical run a derived shell and turn of its own; the arm choice lives
    /// at the witness door, not in this policy.
    ///
    /// # How much is said
    ///
    /// An answer has no size limit, and a bubble is no place for a large one:
    /// it says the answer whole up to a compaction window, read by range
    /// from its stored body, and past that its head and the stored reference
    /// to the rest.
    fn prepare_trailing_speak_fallback(
        &self,
        record: &CodeRunReplayRecord,
        observation: &CodeRunRawOutput,
        trailing_speak: Option<&str>,
    ) -> EngineExecutorResult<Option<String>> {
        let answer;
        let text = match trailing_speak {
            Some(text) => text,
            None => {
                answer = load_observation_window(
                    &self.storage,
                    record,
                    &observation.path,
                    COMPACTION_OBSERVATION_WINDOW_BYTES,
                )?;
                &answer
            }
        }
        .trim();
        if text.is_empty() {
            return Ok(None);
        }
        if record
            .bridge_calls
            .iter()
            .filter_map(CodeRunBridgeCall::emitted_visible_speech_text)
            .any(|spoken| spoken.trim() == text)
        {
            return Ok(None);
        }
        Ok(Some(text.to_owned()))
    }

    /// Recovers a terminal checkpoint's implicit speech intent (ONE-1929).
    ///
    /// The payload is content-addressed into the replay record BEFORE the
    /// terminal commit, so a retry that resumes a committed-but-unspoken run
    /// replays the exact words from durable storage and never needs provider
    /// bytes: a fresh session, a restarted process, or a prompt
    /// deployment/fingerprint drift recovers the same bubble. The bubble's
    /// identity is derived from the durable run identity and its order, and
    /// the durable marker below makes the delivery at-most-once, so recovery
    /// converges on the row that already exists instead of minting a second.
    fn recover_checkpointed_implicit_speak(
        &mut self,
        record: &CodeRunReplayRecord,
        status: &EngineExecutorStatus,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        if !matches!(status, EngineExecutorStatus::Complete) {
            return Ok(());
        }
        let Some(seq) = completed_step_count(record)?.checked_sub(1) else {
            return Ok(());
        };
        let path = implicit_speak_output_path(seq);
        if !record.outputs.iter().any(|output| output.path == path) {
            return Ok(());
        }
        let text = load_utf8_output(&self.storage, record, &path)?;
        self.emit_trailing_speak_fallback(record, seq, &text, config)
    }

    /// Materializes ONE already-checkpointed implicit bubble, at most once.
    ///
    /// # Crash and retry
    ///
    /// The bubble is downstream of its checkpoint commit, so the window
    /// between them is real: a crash, or a post-commit witness failure, sends
    /// the caller back through terminal recovery. Two things close it, and
    /// both are needed. The DURABLE MARKER below is written straight after the
    /// bubble, keyed by content into the same routed raw-output store the run
    /// already uses, so a recovery that runs after a successful emit says
    /// nothing a second time. And the bubble's own IDENTITY is derived from
    /// the durable run identity and this order (`code_run::storage`), so even
    /// a crash landing between the witness and the marker re-puts THAT row
    /// rather than adding a second one: the witness door verifies the existing
    /// materialization exactly and refuses a divergent one typed. There is no
    /// window in which the transcript grows twice.
    fn emit_trailing_speak_fallback(
        &mut self,
        record: &CodeRunReplayRecord,
        step_seq: u64,
        text: &str,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        let order = u32::try_from(record.bridge_calls.len()).unwrap_or(u32::MAX);
        let (marker, marker_bytes) = fallback_speech_marker(config.run_id, step_seq, order)?;
        if self.storage.get_code_run_raw_output(&marker)?.is_some() {
            return Ok(());
        }
        // The bubble is the run's own `self.speak`: a bound door rules on it
        // as on any other, answered as a call is. A refused bubble stays a
        // checkpointed intent that a later admitted retry delivers.
        self.storage
            .answered(|| {
                self.gated_write
                    .admit_run_call(crate::code_run::RunCall::Bridge(
                        crate::code_run::SelfEffect::Speak,
                    ))
            })?
            .map_err(|refusal| super::types::EngineExecutorError::HostRefused {
                code: refusal.code,
            })?;
        let occurred_at = config
            .determinism
            .frozen_unix_ms
            .saturating_add(u64::from(order))
            / 1000;
        #[cfg(test)]
        if self.fail_before_implicit_speak_once {
            self.fail_before_implicit_speak_once = false;
            return Err(Error::InvariantViolation(
                "injected failure before implicit speech materialization",
            )
            .into());
        }
        self.witness_turn_for_run_at(
            Some(config.run_id),
            ExecutorUtterance::Speak,
            text,
            occurred_at,
            order,
        )?;
        // Written AFTER the bubble, deliberately: a marker written first and
        // then orphaned by a crash would silence a run that never spoke, which
        // is the failure the fallback exists to prevent. Written second, the
        // worst case is a re-emission that lands on the same derived MESSAGE
        // id.
        self.storage
            .put_code_run_raw_output(config.run_id, &marker, &marker_bytes)?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "failed REPL step persistence is atomic"
    )]
    fn persist_failed_step_after_bridge_calls(
        &self,
        record: &mut CodeRunReplayRecord,
        expected_generation: Option<CodeRunReplayGeneration>,
        completed_steps: u64,
        request_hash: &[u8; 32],
        script: &str,
        bridge_start: usize,
        bridge_calls: Vec<CodeRunBridgeCall>,
        captured: Vec<CodeRunRawOutput>,
        durable_wait: Option<SelfDurableWait>,
        observation: String,
        healed: bool,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
        self.gated_write.refuse_a_step_that_dropped_a_write(
            config.run_id,
            bridge_start as u64,
            &bridge_calls,
        )?;
        record.bridge_calls.extend(bridge_calls);
        record.outputs.extend(captured);
        record_text_output(
            &self.storage,
            record,
            observation_output_path(completed_steps),
            &observation,
        )?;
        let terminal_status = durable_wait.map(EngineExecutorStatus::Waiting);
        if let Some(status) = &terminal_status {
            record_terminal_output(&self.storage, record, completed_steps, status)?;
        }
        let checkpoint = CodeRunStepCheckpoint::new(
            completed_steps,
            checkpoint_label(completed_steps),
            step_state_hash(
                previous_state_hash(record),
                completed_steps,
                request_hash,
                script,
                &StepResultDigests::of(&observation, false),
                None,
                &record.bridge_calls[bridge_start..],
            )?,
            config
                .determinism
                .frozen_unix_ms
                .saturating_add(completed_steps),
        )?;
        record.step_checkpoints.push(checkpoint);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(
                record,
                expected_generation,
                healed.then_some(&config.model),
            )?;
        // The run parks on the step's wait; a reply already delivered
        // resumes it at its next entry.
        if let Some(EngineExecutorStatus::Waiting(wait)) = &terminal_status {
            self.park(record, wait)?;
        }
        Ok(terminal_status)
    }

    /// Loads the run's replay record, or starts and saves one.
    ///
    /// Run IDENTITY is strict on every resume. Resolved-prompt drift is judged
    /// against what the resume would DO: a record that is not terminal still
    /// owes provider requests and replay appends, and those must be produced
    /// under the teaching this run committed to, so drift refuses with the same
    /// typed config error as before, before another provider call. A TERMINAL
    /// record owes neither — its last checkpoint is committed, and the only
    /// work left is materializing an implicit bubble whose exact payload is
    /// already in the record — so drift is allowed through and the run returns
    /// its stored terminal status. Refusing there would strand a checkpointed
    /// bubble permanently the first time a prompt block was re-deployed.
    fn load_or_create_record(
        &self,
        config: &EngineExecutorConfig,
        prompt_fingerprint: &str,
    ) -> EngineExecutorResult<LoadedReplayRecord> {
        if let Some(record) = self.storage.get_code_run_replay_record(&config.run_id)? {
            if record.determinism != config.determinism {
                return Err(Error::InvalidConfig(
                    "engine executor determinism changed for existing run".to_owned(),
                )
                .into());
            }
            let prompt_binding = validate_executor_config_marker(
                &self.storage,
                &record,
                config,
                prompt_fingerprint,
            )?;
            let generation = Some(record.generation()?);
            let terminal_status = load_terminal_status(&self.storage, &record)?;
            if prompt_binding == PromptBinding::Drifted && terminal_status.is_none() {
                return Err(Error::InvalidConfig(
                    "engine executor config changed for existing run".to_owned(),
                )
                .into());
            }
            return Ok(LoadedReplayRecord {
                record,
                generation,
                terminal_status,
                prompt: prompt_binding,
            });
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(&self.storage, &mut record, config, prompt_fingerprint)?;
        // The run's clock and config are durable from its start: a process
        // that stops after the first step's writes and before its checkpoint
        // resumes under them, never under a fresh clock or another task.
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&record, None, None)?;
        Ok(LoadedReplayRecord {
            record,
            generation: Some(generation),
            terminal_status: None,
            prompt: PromptBinding::Unchanged,
        })
    }

    /// Resolve a typed model-facing re-expand action through the same routed
    /// replay store as the original observation, including off-record overlays.
    pub fn reexpand_observation(
        &self,
        record: &CodeRunReplayRecord,
        action: OutputAffordance,
    ) -> EngineExecutorResult<Vec<u8>> {
        self.verify_storage_dispatcher_binding()?;
        if self.output_run != Some(record.run_id) {
            return Err(Error::InvalidConfig("executor output run mismatch".into()).into());
        }
        let OutputAffordance::Reexpand(source) = action else {
            return Err(Error::InvalidConfig("expected reexpand action".into()).into());
        };
        // The manifest names the body: no other observation is read.
        for seq in 0..completed_step_count(record)? {
            let path = observation_output_path(seq);
            let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
                continue;
            };
            if output.output_ref() == source {
                // A body that is not clean reaches the model as the mark.
                if !clean_for_context(&self.storage, Some(record.run_id), output)? {
                    return Ok(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.as_bytes().to_vec());
                }
                return Ok(self
                    .storage
                    .get_code_run_raw_output(output)?
                    .ok_or(Error::CorruptedIndex("executor replay output bytes"))?);
            }
        }
        Err(Error::CorruptedIndex("missing recoverable executor observation").into())
    }

    /// Sync every durably completed observation before either a model request
    /// or a compaction mint. No uncommitted runtime output enters context.
    /// Returns the step that holds each source, for the views that expand it.
    pub(super) fn sync_output_context(
        &mut self,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<HashMap<OutputRef, u64>> {
        // Reconstruct references from the routed durable replay record. No
        // observation is copied into the base vault for off-record sessions.
        // Working flags are projections of committed typed coverage. Rebuild
        // rather than trusting a cached flag or any raw-output existence.
        self.output_context = OutputWorkingContext::default();
        self.output_run = Some(record.run_id);
        let coverage = self.storage.code_run_compaction_coverage(record.run_id)?;
        let mut steps = HashMap::new();
        for (seq, _, observation) in self.observation_refs(record)? {
            self.output_context
                .record_referenced(seq, observation.source, observation.overview)?;
            if coverage.iter().any(|row| row.covers(record.run_id, seq)) {
                self.output_context.compact_span(seq, seq);
            }
            steps.insert(observation.source, seq);
        }
        Ok(steps)
    }

    /// Every completed step's observation reference, from its manifest: no
    /// past body is read to build a turn's context.
    pub(super) fn observation_refs(
        &self,
        record: &CodeRunReplayRecord,
    ) -> EngineExecutorResult<Vec<(u64, CodeRunRawOutput, ObservationRef)>> {
        let mut refs = Vec::new();
        for seq in 0..completed_step_count(record)? {
            let path = observation_output_path(seq);
            let output = record
                .outputs
                .iter()
                .find(|output| output.path == path)
                .ok_or(Error::CorruptedIndex("executor replay output path"))?;
            refs.push((seq, output.clone(), observation_ref(output)));
        }
        Ok(refs)
    }

    fn build_llm_request(
        &mut self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        wire_prompt: &str,
    ) -> EngineExecutorResult<LlmRequest> {
        let completed_steps = completed_step_count(record)?;
        let mut messages = Vec::new();
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: executor_system_prompt(wire_prompt),
            }],
        });
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: format!(
                    "Run id: {}\nHard step limit: {}\nTask:\n{}",
                    config.run_id.to_hex(),
                    config.limits.hard_steps,
                    config.task
                ),
            }],
        });

        let steps = self.sync_output_context(record)?;
        // Only a Full view expands its body; older steps cost their reference.
        // A Full body is held against the run's share of the result-memory
        // pool first: one that does not fit stays in its file, and its view
        // falls back to the reference the run reads it by.
        self.context_holds.clear();
        let mut holds = Vec::new();
        let mut left = Vec::new();
        let views = {
            let share = &self.result_share;
            let watch = self.storage.limit_watch();
            self.output_context
                .assemble_with(completed_steps, self.output_decay, |source| {
                    let seq = steps
                        .get(&source)
                        .ok_or(Error::CorruptedIndex("missing executor observation"))?;
                    let Some(hold) = share.hold(source.byte_len, watch) else {
                        left.push((*seq, source));
                        return Ok(None);
                    };
                    holds.push((source, hold));
                    load_context_output(&self.storage, record, &observation_output_path(*seq))
                        .map(|text| Some(text.into_bytes()))
                })?
        };
        let memory_note = result_memory_note(&self.result_share, &holds, &left);
        self.context_holds = holds.into_iter().map(|(_, hold)| hold).collect();
        let epochs = self.compaction_epochs(record.run_id)?;
        if !epochs.is_empty() {
            self.admit_compaction_read()?;
        }
        // The replies parked calls resumed with, by the step that parked.
        let resumed: BTreeMap<u64, &CodeRunRawOutput> = record
            .outputs
            .iter()
            .filter_map(|output| resumed_output_wait(&output.path).map(|(seq, _)| (seq, output)))
            .collect();
        let mut swapped = false;
        for (seq, view) in views.iter().enumerate() {
            messages.extend(self.fold_tail(&epochs, record, seq)?);
            match super::compaction::epoch_frame(&epochs, record.run_id, seq, &views)? {
                Some(Some(frame)) => {
                    messages.push(frame);
                    swapped = true;
                    continue;
                }
                Some(None) => continue,
                None => {}
            }
            let view = view.clone();
            // ONE-1929 framing remains engine-authored. The stored program and
            // observation never change; only this model-facing projection does.
            let console = match view.tier {
                OutputTier::Full | OutputTier::Overview => String::from_utf8(view.bytes)
                    .map_err(|_| Error::CorruptedIndex("executor observation encoding"))?,
                OutputTier::Stub => serde_json::to_string(&json!({
                    "sandbox.fs.read_file": recoverable_chunk_path(seq as u64, view.source, 0),
                    "byte_len": view.source.byte_len,
                    "max_chunk_bytes": RECOVERABLE_OUTPUT_CHUNK_BYTES,
                }))?,
            };
            let turn = CodeRunHistoryTurn {
                code: load_context_output(&self.storage, record, &script_output_path(seq as u64))?,
                console,
            };
            messages.push(LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: turn.assistant_exec(),
                }],
            });
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: turn.user_console(seq as u64),
                }],
            });
            if let Some(output) = resumed.get(&(seq as u64)) {
                messages.push(self.resumed_reply_message(record, seq as u64, output)?);
            }
        }
        messages.extend(self.fold_tail(&epochs, record, views.len())?);

        // Past a swap, the run's results are named once more beside the
        // frame that replaced the turns that bound them.
        if swapped && let Some(brief) = self.bindings_brief(record)? {
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: brief }],
            });
        }
        if let Some(note) = memory_note {
            messages.push(LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: note }],
            });
        }
        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: executor_turn_instruction(completed_steps, wire_prompt),
            }],
        });

        let mut request = LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: crate::llm::Scope::default(),
                purpose: CallPurpose::Other {
                    name: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
                },
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: ENGINE_EXECUTOR_FALLBACK_NAME.to_owned(),
                        config: Some(json!({
                            "run_id": config.run_id.to_hex(),
                            "step_seq": completed_steps,
                        })),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Other {
                        name: ENGINE_EXECUTOR_PURPOSE_NAME.into(),
                    },
                    config.global_tier.clone(),
                ),
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        if let Some(seat) = self.seat {
            seat.bind(&mut request);
        }
        Ok(request)
    }
}

impl EngineNativeExecutor<'_> {
    /// What follows a parked step's turn once its wait was answered: the
    /// reply inline within one reply's bound, else its card under `wait<s>`.
    /// A body that is not clean reaches the model as its card, which withholds
    /// it.
    fn resumed_reply_message(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
        output: &CodeRunRawOutput,
    ) -> EngineExecutorResult<LlmMessage> {
        let wait = parked_wait_at(&self.storage, record, seq)?.ok_or(Error::CorruptedIndex(
            "executor resumed reply without a wait",
        ))?;
        let head = format!(
            "The call parked at step {seq} ({}, wait {}) answered",
            wait.effect.as_str(),
            wait.wait_id.to_hex()
        );
        let text = if output.raw_len <= RESULT_REPLY_INLINE_BYTES as u64
            && clean_for_context(&self.storage, Some(record.run_id), output)?
        {
            let body: serde_json::Value =
                serde_json::from_str(&load_utf8_output(&self.storage, record, &output.path)?)
                    .map_err(|_| Error::CorruptedIndex("executor resumed reply"))?;
            format!("{head}:\n{}", serde_json::to_string(&body["reply"])?)
        } else {
            let name = format!("wait{seq}");
            let card = crate::code_run::result_card(
                &self.storage,
                record.run_id,
                output,
                Some(name.as_str()),
            )?;
            format!(
                "{head}; the reply is the result {name}:\n{}",
                serde_json::to_string(&card)?
            )
        };
        Ok(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        })
    }
}

/// Bound results a post-swap brief lists, newest first.
const BRIEF_BINDINGS: usize = 64;

/// Characters of a result's preview a brief line carries.
const BRIEF_PREVIEW_CHARS: usize = 120;

impl EngineNativeExecutor<'_> {
    /// The run's live result names, newest first, a line each from its
    /// manifest and taint sidecars alone: no body is read.
    fn bindings_brief(&self, record: &CodeRunReplayRecord) -> EngineExecutorResult<Option<String>> {
        if record.bindings.is_empty() {
            return Ok(None);
        }
        let mut lines = vec![
            "Results bound in this run (describe(name) gives a card; a card's `read` path reads \
             it a chunk at a time):"
                .to_owned(),
        ];
        for binding in record.bindings.iter().rev().take(BRIEF_BINDINGS) {
            let Some(output) = record
                .outputs
                .iter()
                .find(|output| output.handle == binding.handle)
            else {
                return Err(Error::CorruptedIndex("executor result binding").into());
            };
            let preview: String = if clean_for_context(&self.storage, Some(record.run_id), output)?
            {
                output
                    .preview
                    .text
                    .chars()
                    .take(BRIEF_PREVIEW_CHARS)
                    .map(|c| if c == '\n' { '\u{23ce}' } else { c })
                    .collect()
            } else {
                "withheld".to_owned()
            };
            lines.push(format!(
                "{} \u{2014} {}, {} bytes, {} lines, {} \u{2014} preview: {preview}",
                binding.name,
                match output.kind {
                    crate::code_run::CodeRunOutputKind::Text => "text",
                    crate::code_run::CodeRunOutputKind::Binary => "binary",
                },
                grouped(output.raw_len),
                grouped(output.lines),
                if output.complete {
                    "complete"
                } else {
                    "incomplete"
                },
            ));
        }
        if record.bindings.len() > BRIEF_BINDINGS {
            lines.push(format!(
                "\u{2026}and {} more",
                record.bindings.len() - BRIEF_BINDINGS
            ));
        }
        Ok(Some(lines.join("\n")))
    }
}

/// The wait a turn hook's ask parks the run on, as a call's ask parks the
/// call (`code_run::dispatcher::verb_hooks`): the ask's group, its prompt
/// naming the turn's invocation, whose next try takes the answer. `None` for
/// a skip, a hidden result, or an ask with no group: the turn ends there.
fn turn_hook_wait(stop: &VerbHookStop) -> Option<SelfDurableWait> {
    let VerbHookStop::Pending { invocation, ask } = stop else {
        return None;
    };
    Some(SelfDurableWait {
        wait_id: EntityId::from_hex(ask).ok()?,
        effect: SelfEffect::TasksWait,
        reason: SelfDurableWaitReason::PeerResult,
        prompt: Some(format!("verb_hook:{invocation}")),
    })
}

/// `n` with its thousands grouped: `2,104,331`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Past 60% of the run's result-memory share, a line naming the biggest
/// bodies held; and one line for every body that stayed in its file because
/// it did not fit, naming why and how to read it.
fn result_memory_note(
    share: &crate::result_memory::ResultShare,
    held: &[(OutputRef, crate::result_memory::ResultHold)],
    left: &[(u64, OutputRef)],
) -> Option<String> {
    let mut lines = Vec::new();
    let share_bytes = share.bytes();
    let held_bytes = share.held();
    if held_bytes.saturating_mul(10) > share_bytes.saturating_mul(6) {
        let mut biggest: Vec<_> = held.iter().map(|(source, _)| *source).collect();
        biggest.sort_by_key(|source| std::cmp::Reverse(source.byte_len));
        let names: Vec<_> = biggest
            .iter()
            .take(3)
            .map(|source| {
                format!(
                    "output:blake3:{}:{}",
                    crate::entity_id::bytes_to_hex_lower(&source.hash),
                    source.byte_len
                )
            })
            .collect();
        lines.push(format!(
            "Result memory: {held_bytes} of this run's {share_bytes} bytes held \
             (limits.code_result_session_memory_bytes); biggest: {}.",
            names.join(", ")
        ));
    }
    for (seq, source) in left {
        lines.push(format!(
            "Result of step {seq} ({} bytes) left context memory: it would pass \
             limits.code_result_session_memory_bytes or limits.code_result_memory_bytes. \
             It is stored whole; read it with sandbox.fs.read_file(\"{}\").",
            source.byte_len,
            recoverable_chunk_path(*seq, *source, 0)
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}
