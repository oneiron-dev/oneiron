//! The durable code-mode REPL orchestrator.
//! Entry: `EngineNativeExecutor::run`.
//! `EngineNativeExecutor` is defined by `driver`; children own persistence, speech and requests.

mod persistence;
mod request;
mod speech;

use super::continuation::{ContinuationNote, continuation_note, turn_note};
use super::driver::EngineNativeExecutor;
use super::host::{
    RecordingJsHost, executor_boundary_contract, executor_system_prompt, executor_turn_instruction,
};
use super::record::{
    LoadedReplayRecord, PromptBinding, REPLAY_METADATA_SCHEMA_VERSION, StepResultDigests,
    code_consent_evidence, completed_step_count, load_terminal_status, parked_wait, parked_wait_at,
    prepared_step_state_hash, previous_state_hash, record_config_marker, record_terminal_output,
    validate_executor_config_marker, verify_code_consent_park, wait_key,
};
use super::store::{
    COMPACTION_OBSERVATION_WINDOW_BYTES, IMPLICIT_SPEECH_TEXT_BYTES, ImplicitSpeechIntent,
    ObservationRef, RECOVERABLE_OUTPUT_CHUNK_BYTES, RESULT_REPLY_INLINE_BYTES, checkpoint_label,
    clean_for_context, console_output_path, fallback_speech_marker, implicit_speak_output_path,
    load_context_output, load_observation_window, load_utf8_output, message_result_attachment,
    observation_output_path, observation_ref, publish_output, record_prepared_source,
    record_reply_evidence, record_script_output, record_text_output, recoverable_chunk_path,
    resumed_output_path, resumed_output_wait, script_output_path, validate_runtime_outputs,
    write_json,
};
use super::types::{
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorConfig,
    EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus, JsCodeModeStep,
};
use super::wire::{HealedExecutorReply, heal_executor_reply};
use super::{compaction, types};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunBridgeCall, CodeRunHistoryTurn, CodeRunRawOutput,
    CodeRunReplayGeneration, CodeRunReplayRecord, CodeRunResultBinding, CodeRunStepCheckpoint,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, WaitKey,
};
use crate::code_sandbox::source::{PreparedSource, TranspiledSource, prepare_source};
use crate::compaction::output::{OutputAffordance, OutputRef, OutputTier, OutputWorkingContext};
use crate::limit_ask::EngineLimit;
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
        // The entry's capture epoch of the run's read-world ledger (FIX 6130).
        let gated = self.gated_write;
        let _read_worlds = gated.enter_read_worlds(config.run_id);
        self.validate_run_seat(config)?;
        // Resolve exactly once per run attempt. Both teaching sites use these
        // bytes, and the fingerprint joins the durable replay identity below.
        let wire_prompt = resolve_engine_executor_wire_prompt(&config.prompt_package_root)
            .map_err(Error::from)?;
        let boundary = executor_boundary_contract()?;
        // A run forked from a failed one carries its approved note (FIX 3694).
        let continuation = continuation_note(&self.storage, config.run_id)?;
        let loaded = self.load_or_create_record(
            config,
            &wire_prompt.stamp.resolved_fingerprint,
            continuation.as_ref(),
        )?;
        // A terminal replay still owes typed restore even when no new model
        // request is assembled during this attempt.
        self.prepare_run_context(config);
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
        // The loop's root (FIX 600): a hard queue control that committed for
        // this run's attempt stops the step it is running, and the next.
        let root = self.attempt_root();
        let cancel = root.token();

        loop {
            cancel.check()?;
            let completed_steps = completed_step_count(&record)?;
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
            let request =
                self.build_llm_request(config, &record, &wire_prompt.text, continuation.as_ref())?;
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
            // Rule 5 (FIX 4197): the first step past the `[limits]
            // executor_run_steps` row asks whether everything is okay, once
            // per run however often it re-enters, and the run keeps going.
            let steps = self.storage.limit_watch();
            if completed_steps == steps.bound(EngineLimit::ExecutorRunSteps) {
                steps.measure(EngineLimit::ExecutorRunSteps, completed_steps + 1);
            }
            let request_hash = request.canonical_hash()?;
            self.capture_step_start(
                config,
                completed_steps,
                &request,
                &record,
                &wire_prompt.stamp.resolved_fingerprint,
            );
            let response = {
                let _generating = self.gated_write.activity_generating();
                self.backend.generate(request, self.lease).await
            }?;
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
            // One preparation per program (FIX 8276): a TypeScript program
            // runs as the JavaScript Oxc prints for it, kept beside the
            // program with its map and Oxc pin; JavaScript runs as written.
            let prepared = prepare_source(&script);
            record_prepared_source(&self.storage, &mut record, completed_steps, &prepared)?;
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
            .with_skill_executor(&config.model)
            .with_result_share(&self.result_share);
            let step = JsCodeModeStep {
                run_id: config.run_id,
                seq: completed_steps,
                script: &script,
                boundary,
                determinism: config.determinism,
            };
            // Feedback mode checks the program as its author wrote it, on
            // its own thread, while the program runs: nothing waits on the
            // check or is refused for it (FIX 8277). Every way out of the
            // step leaves its feedback, its preparation note included.
            let mut checking = self.start_step_check(&record, completed_steps, &prepared);
            let step_outcome = self
                .runtime
                .run_prepared_step_cancellable(step, &prepared, &mut host, cancel);
            self.keep_step_feedback(&checking);
            let step_outcome = match step_outcome {
                Ok(outcome) => outcome,
                Err(err) => {
                    // A cancelled root fails the step: the bridge rows it
                    // left stay recorded, and no wait it reached hides that.
                    let durable_wait = host.durable_wait.filter(|_| !cancel.is_cancelled());
                    let bridge_calls = host.bridge_calls;
                    let captured = host.captured;
                    if !bridge_calls.is_empty()
                        && let Some(status) = self.persist_failed_step_after_bridge_calls(
                            &mut record,
                            expected_generation,
                            completed_steps,
                            &request_hash,
                            &prepared,
                            bridge_start,
                            bridge_calls,
                            captured,
                            durable_wait,
                            format!("Runtime error after host bridge calls: {err}"),
                            repairs.healed(),
                            config,
                        )?
                    {
                        checking.ended(Some(&status));
                        return Ok(self.outcome(status, steps_run + 1, record));
                    }
                    // A step a provider outage ended stops on that outage,
                    // which parks its run, however its guest took the
                    // failure (FIX 3194).
                    if let Some(outage) = host
                        .hard_failure
                        .take()
                        .filter(|failure| matches!(failure, Error::ProviderUnavailable { .. }))
                    {
                        return Err(outage.into());
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
                    &prepared,
                    bridge_start,
                    bridge_calls,
                    captured,
                    durable_wait,
                    format!("Host bridge call failed: {failure}"),
                    repairs.healed(),
                    config,
                )? {
                    checking.ended(Some(&status));
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
                            &prepared,
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
                        checking.ended(Some(&status));
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
            // The board frames its answers carried, for the model's view of
            // the step (FIX 2135).
            super::board_frames::record_step_board_frames(
                &self.storage,
                &mut record,
                completed_steps,
                bridge_start,
            );
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
            // A finished step's console lines are evidence, not its result,
            // so they stay out of the step's result digests.
            if let Some(console) = bodies.console {
                publish_output(
                    &self.storage,
                    &mut record,
                    console_output_path(completed_steps),
                    console,
                )?;
            }
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
            let implicit_speak_bytes = implicit_speak
                .as_ref()
                .map(ImplicitSpeechIntent::encode)
                .transpose()?;
            if let Some(stored) = implicit_speak_bytes.as_deref() {
                // The exact side-effect payload is part of the replay append,
                // not ephemeral provider state. It is content-addressed like
                // every other executor output and hashed into the checkpoint.
                record_text_output(
                    &self.storage,
                    &mut record,
                    implicit_speak_output_path(completed_steps),
                    stored,
                )?;
            }
            if let Some(status) = &terminal_status {
                record_terminal_output(&self.storage, &mut record, completed_steps, status)?;
            }

            let checkpoint = CodeRunStepCheckpoint::new(
                completed_steps,
                checkpoint_label(completed_steps),
                prepared_step_state_hash(
                    previous_state_hash(&record),
                    completed_steps,
                    &request_hash,
                    &script,
                    prepared
                        .transpiled()
                        .map(TranspiledSource::identity)
                        .as_ref(),
                    &step_result,
                    implicit_speak_bytes.as_deref(),
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
            // beside the bindings they describe, and so does the seal of the
            // code consent wait the step parks on (DOOR-079 1b).
            let parked = parked_wait(&record, terminal_status.as_ref(), bridge_start);
            let next_generation = self
                .storage
                .put_code_run_replay_record_with_receipts_if_generation(
                    &record,
                    expected_generation,
                    repairs.healed().then_some(&config.model),
                    &host.receipts,
                    parked.as_ref(),
                )?;
            // The implicit bubble is downstream of its checkpoint commit. A
            // compare-and-put failure emits nothing. A terminal retry replays
            // this delivery under stable witness ids, so it can recover a
            // missed emit without minting a duplicate bubble.
            if let Some(intent) = &implicit_speak {
                self.emit_trailing_speak_fallback(&record, completed_steps, intent, config)?;
            }
            steps_run += 1;
            checking.ended(terminal_status.as_ref());

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

    /// A seat run: its config and its durable seat receipt agree with the
    /// seat. A run with no seat: no seat pin, and no model manifest.
    fn validate_run_seat(&self, config: &EngineExecutorConfig) -> EngineExecutorResult<()> {
        if let Some(seat) = self.seat {
            if &config.model != seat.model()
                || config.model_locality != seat.locality()
                || config.seat_effort != Some(seat.effort())
            {
                return Err(
                    Error::InvalidConfig("executor seat and run config disagree".into()).into(),
                );
            }
            // The seat's receipt is read where the run's rows are: base for a
            // canonical run, its room's route for a session-bound one.
            let recorded = self.storage.model_seat_receipt(config.run_id)?;
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
        Ok(())
    }

    /// The output context of a new run, and the compaction seat turn begun.
    fn prepare_run_context(&mut self, config: &EngineExecutorConfig) {
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
