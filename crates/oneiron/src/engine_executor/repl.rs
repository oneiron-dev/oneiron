//! Durable REPL loop: run(), persistence helpers, and LLM request building.

use super::driver::EngineNativeExecutor;
use super::host::{
    RecordingJsHost, executor_boundary_contract, executor_system_prompt, executor_turn_instruction,
};
use super::record::{
    LoadedReplayRecord, PromptBinding, completed_step_count, load_terminal_status,
    previous_state_hash, record_config_marker, record_terminal_output, step_state_hash,
    validate_executor_config_marker,
};
use super::store::{
    checkpoint_label, fallback_speech_marker, implicit_speak_output_path, load_utf8_output,
    observation_output_path, record_output, record_text_output, script_output_path,
    validate_runtime_outputs,
};
use super::types::{
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorConfig,
    EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus, JsCodeModeStep,
    JsCodeModeStepOutcome,
};
use super::wire::{HealedExecutorReply, heal_executor_reply};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunHistoryTurn, CodeRunReplayGeneration, CodeRunReplayRecord,
    CodeRunStepCheckpoint, SelfDurableWait,
};
use crate::off_record::ExecutorUtterance;
use crate::prompt::resolve_engine_executor_wire_prompt;
use crate::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, Error, LlmMessage,
    LlmMessageRole, LlmRequest, ResponseFormat, TierPrecedence,
};
use serde_json::json;
use std::collections::BTreeMap;

impl EngineNativeExecutor<'_> {
    pub async fn run(
        &mut self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        self.verify_storage_dispatcher_binding()?;
        config.validate()?;
        // Resolve exactly once per run attempt. Both teaching sites use these
        // bytes, and the fingerprint joins the durable replay identity below.
        let wire_prompt = resolve_engine_executor_wire_prompt(&config.prompt_package_root)
            .map_err(Error::from)?;
        let boundary = executor_boundary_contract()?;
        let loaded = self.load_or_create_record(config, &wire_prompt.stamp.resolved_fingerprint)?;
        if let Some(status) = loaded.terminal_status {
            self.recover_checkpointed_implicit_speak(&loaded.record, &status, config)?;
            return Ok(EngineExecutorOutcome {
                status,
                steps_run: 0,
                replay_record: loaded.record,
            });
        }
        let mut record = loaded.record;
        let mut expected_generation = loaded.generation;
        let mut steps_run = 0_u32;

        loop {
            let completed_steps = completed_step_count(&record)?;
            if completed_steps >= u64::from(config.limits.hard_steps) {
                return Ok(EngineExecutorOutcome {
                    status: EngineExecutorStatus::HardStepLimitReached,
                    steps_run,
                    replay_record: record,
                });
            }
            if steps_run >= config.limits.soft_steps {
                return Ok(EngineExecutorOutcome {
                    status: EngineExecutorStatus::Yielded {
                        next_step_seq: completed_steps,
                    },
                    steps_run,
                    replay_record: record,
                });
            }

            let request = self.build_llm_request(config, &record, &wire_prompt.text)?;
            let request_hash = request.canonical_hash()?;
            let response = self.backend.generate(request, self.lease).await?;
            // ONE-1929: the ONE normalization seam. Only `code` is executed,
            // staged, hashed, or replayed; the reply's own console bytes are
            // already gone, and `trailing_speak` belongs to ONE-1686.
            let HealedExecutorReply {
                code: script,
                trailing_speak,
                repairs,
            } = heal_executor_reply(&response)?;
            record_text_output(
                &self.storage,
                &mut record,
                script_output_path(completed_steps),
                &script,
            )?;

            let bridge_start = record.bridge_calls.len();
            // ONE-1314: the DURABLE history is the load-bearing half of the
            // lineage seam. An outbound effect parks its step, so a run that
            // reached outside and then writes always spans a resume, and the
            // resuming step's only record of that hop is the replay record
            // being read here. Observed before any write of this step can
            // dispatch; the dispatcher owns the history-to-lineage mapping.
            self.gated_write
                .observe_bridge_history(&record.bridge_calls);
            let mut host = RecordingJsHost::new(
                self.gated_write,
                config.run_id,
                bridge_start as u64,
                config.determinism,
                self.legibility,
            );
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
                    if !bridge_calls.is_empty()
                        && let Some(status) = self.persist_failed_step_after_bridge_calls(
                            &mut record,
                            expected_generation,
                            completed_steps,
                            &request_hash,
                            &script,
                            bridge_start,
                            bridge_calls,
                            durable_wait,
                            format!("Runtime error after host bridge calls: {err}"),
                            repairs.healed(),
                            config,
                        )?
                    {
                        return Ok(EngineExecutorOutcome {
                            status,
                            steps_run: steps_run + 1,
                            replay_record: record,
                        });
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
                if let Some(status) = self.persist_failed_step_after_bridge_calls(
                    &mut record,
                    expected_generation,
                    completed_steps,
                    &request_hash,
                    &script,
                    bridge_start,
                    bridge_calls,
                    durable_wait,
                    format!("Host bridge call failed: {failure}"),
                    repairs.healed(),
                    config,
                )? {
                    return Ok(EngineExecutorOutcome {
                        status,
                        steps_run: steps_run + 1,
                        replay_record: record,
                    });
                }
                return Err(failure.into());
            }
            let runtime_output_paths =
                match validate_runtime_outputs(&record, completed_steps, &step_outcome) {
                    Ok(paths) => paths,
                    Err(err) => {
                        let durable_wait = host.durable_wait;
                        let bridge_calls = host.bridge_calls;
                        if !bridge_calls.is_empty()
                            && let Some(status) = self.persist_failed_step_after_bridge_calls(
                                &mut record,
                                expected_generation,
                                completed_steps,
                                &request_hash,
                                &script,
                                bridge_start,
                                bridge_calls,
                                durable_wait,
                                format!(
                                    "Runtime output recording failed after host bridge calls: {err}"
                                ),
                                repairs.healed(),
                                config,
                            )?
                        {
                            return Ok(EngineExecutorOutcome {
                                status,
                                steps_run: steps_run + 1,
                                replay_record: record,
                            });
                        }
                        return Err(err);
                    }
                };
            record.bridge_calls.extend(host.bridge_calls);
            record_text_output(
                &self.storage,
                &mut record,
                observation_output_path(completed_steps),
                &step_outcome.observation,
            )?;
            for (path, output) in runtime_output_paths
                .into_iter()
                .zip(step_outcome.outputs.iter())
            {
                record_output(&self.storage, &mut record, path, &output.bytes)?;
            }
            let terminal_status = host
                .durable_wait
                .clone()
                .map(EngineExecutorStatus::Waiting)
                .or({
                    if step_outcome.done {
                        Some(EngineExecutorStatus::Complete)
                    } else {
                        None
                    }
                });
            let implicit_speak = matches!(terminal_status, Some(EngineExecutorStatus::Complete))
                .then(|| {
                    self.prepare_trailing_speak_fallback(
                        &record,
                        &step_outcome,
                        trailing_speak.as_deref(),
                    )
                })
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
                    &step_outcome,
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
            let next_generation = self
                .storage
                .put_code_run_replay_record_if_generation_with_heal(
                    &record,
                    expected_generation,
                    repairs.healed().then_some(&config.model),
                )?;
            // The implicit bubble is downstream of its checkpoint commit. A
            // compare-and-put failure emits nothing. A terminal retry replays
            // this delivery under stable witness ids, so it can recover a
            // missed emit without minting a duplicate bubble.
            if let Some(text) = implicit_speak.as_deref() {
                self.emit_trailing_speak_fallback(&record, completed_steps, text, config)?;
            }
            steps_run += 1;

            if let Some(status) = terminal_status {
                return Ok(EngineExecutorOutcome {
                    status,
                    steps_run,
                    replay_record: record,
                });
            }
            expected_generation = Some(next_generation);
        }
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
    fn prepare_trailing_speak_fallback(
        &self,
        record: &CodeRunReplayRecord,
        step_outcome: &JsCodeModeStepOutcome,
        trailing_speak: Option<&str>,
    ) -> Option<String> {
        let text = trailing_speak.unwrap_or(&step_outcome.observation).trim();
        if text.is_empty() {
            return None;
        }
        if record
            .bridge_calls
            .iter()
            .filter_map(CodeRunBridgeCall::emitted_visible_speech_text)
            .any(|spoken| spoken.trim() == text)
        {
            return None;
        }
        Some(text.to_owned())
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
            .put_code_run_raw_output(&marker, &marker_bytes)?;
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
        durable_wait: Option<SelfDurableWait>,
        observation: String,
        healed: bool,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
        record.bridge_calls.extend(bridge_calls);
        let failed_outcome = JsCodeModeStepOutcome::pending(observation);
        record_text_output(
            &self.storage,
            record,
            observation_output_path(completed_steps),
            &failed_outcome.observation,
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
                &failed_outcome,
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
        Ok(terminal_status)
    }

    /// Loads the run's replay record, or starts one.
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
            });
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(&self.storage, &mut record, config, prompt_fingerprint)?;
        Ok(LoadedReplayRecord {
            record,
            generation: None,
            terminal_status: None,
        })
    }

    fn build_llm_request(
        &self,
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

        for seq in 0..completed_steps {
            // ONE-1929: history is rendered CANONICALLY from the two trusted
            // sources — the healed bare program and the runtime's own
            // observation. A malformed provider reply is never taught back,
            // and neither payload can forge the engine's framing.
            let turn = CodeRunHistoryTurn {
                code: load_utf8_output(&self.storage, record, &script_output_path(seq))?,
                console: load_utf8_output(&self.storage, record, &observation_output_path(seq))?,
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
                    text: turn.user_console(seq),
                }],
            });
        }

        messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: executor_turn_instruction(completed_steps, wire_prompt),
            }],
        });

        Ok(LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
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
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: config.global_tier.clone(),
                },
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}
