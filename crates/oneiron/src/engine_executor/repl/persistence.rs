//! Durable REPL record loading, failed-step appends, refused-reply
//! correction records and wait resumption.
//! Entry: `EngineNativeExecutor::load_or_create_record`.
//! Executor definitions belong to `engine_executor::driver` and replay rows to `code_run`.

use super::super::types::EngineExecutorError;
use super::super::wire::heal_executor_text_tracking_repairs;
use super::*;
use crate::code_run::ExecutorWireRepairs;

impl EngineNativeExecutor<'_> {
    /// Registers the run as parked on `wait`, the wait its last step
    /// committed, and answers the wait's key once its reply is delivered.
    /// Every entry of a Waiting run parks again, idempotently, so a park that
    /// a crash after the commit skipped is not lost. A bound code consent
    /// wait parks only as its step sealed it (DOOR-079 1b).
    pub(in crate::engine_executor) fn park(
        &self,
        record: &CodeRunReplayRecord,
        wait: &SelfDurableWait,
    ) -> EngineExecutorResult<Option<WaitKey>> {
        let key = wait_key(record, wait);
        verify_code_consent_park(&self.storage, record, &key)?;
        Ok(self.storage.park_wait(&key)?.then_some(key))
    }

    /// Publishes the reply delivered to `key` as the result the parked
    /// step's call came back with, bound as `wait<s>`, and commits it. The
    /// parked step's bridge rows stay as recorded and nothing is dispatched
    /// again: the run goes on at the next step, whose context carries the
    /// reply. `None` when no reply is delivered.
    ///
    /// A bound code consent wait's reply is verified as its settlement's own
    /// before it is read, the result carries the consent evidence by
    /// reference, and the commit consumes the settlement once beside it
    /// (DOOR-079 1b). The cleanup after it is never the consumer.
    ///
    /// The run's ledger notes the origins its settler froze with the reply it
    /// is served, at the bridge position of the call parked on the wait (FIX
    /// 7083). Unknown origins, or no such call, mark the ledger `WaitReply`.
    pub(in crate::engine_executor) fn resume_delivered_wait(
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
        let consent = code_consent_evidence(&self.storage, record, key, seq, &delivery.reply)?;
        let mut reply: serde_json::Value = serde_json::from_str(&delivery.reply)
            .map_err(|_| Error::CorruptedIndex("code-run wait delivery"))?;
        let mut origins = delivery.origins;
        if wait.effect == SelfEffect::Summarize {
            (reply, origins) = self.storage.delivered_summary_reply(reply, origins)?;
        }
        // The reply reaches the run (FIX 6130) at the position of the call
        // parked on its wait, with the origins its settler froze (FIX 7083).
        let parked_at = record
            .bridge_calls
            .iter()
            .rev()
            .find(|call| crate::code_run::parks_on(&call.outcome, wait.wait_id))
            .map(|call| call.seq);
        match parked_at {
            Some(at) => {
                self.gated_write
                    .read_worlds_wait_reply(record.run_id, at, origins.as_ref());
            }
            None => {
                let cause = crate::code_run::ReadWorldUnknown::WaitReply;
                self.gated_write.read_worlds_unknown(record.run_id, cause);
            }
        }
        // The rows the reply was derived from, as its settler listed them,
        // join the parked call's own (FIX 5455).
        if let Some(rows) = &delivery.source_rows
            && let Some(call) = record
                .bridge_calls
                .iter_mut()
                .rev()
                .find(|call| crate::code_run::parks_on(&call.outcome, wait.wait_id))
        {
            crate::code_run::keep_wait_rows(&mut call.outcome, rows);
            record.invalidate_verb_rows();
        }
        let mut resumed = json!({
            "schema_version": REPLAY_METADATA_SCHEMA_VERSION,
            "wait_id": wait.wait_id.to_hex(),
            "effect": wait.effect.as_str(),
            "generation": key.generation,
            "reply": reply,
        });
        if let Some(consent) = consent {
            resumed["consent"] = consent;
        }
        let mut sink = self.storage.code_run_output_sink()?;
        write_json(&mut sink, &resumed)?;
        let path = resumed_output_path(seq, wait.wait_id);
        let output = publish_output(&self.storage, record, path.clone(), sink)?;
        let name = format!("wait{seq}");
        match record.bindings.iter_mut().find(|held| held.name == name) {
            Some(held) => {
                held.handle = output.handle.clone();
                held.path = output.path.clone();
            }
            None => record.bindings.push(CodeRunResultBinding::new(
                name,
                output.handle.clone(),
                output.path.clone(),
            )),
        }
        let generation = self
            .storage
            .put_code_run_wait_resume_record(record, expected, key, seq, &path)?;
        if let crate::code_run::ExecutorStorage::Session(_) = &self.storage {
            self.storage.clear_wait(key)?;
        }
        Ok(Some(generation))
    }

    /// The ONE-1929 normalization of one reply's post-hook text. A reply it
    /// refuses, and one that did not finish cleanly, keeps its correction
    /// record on the run's route, with the repairs made before the refusal
    /// and the refusal's reason, before the error returns (FIX 4412). No
    /// program runs and the step commits nothing: the caller's re-entry asks
    /// the model again, and that reply records as the step's next attempt.
    pub(super) fn heal_reply_or_record_rejection(
        &self,
        config: &EngineExecutorConfig,
        step: u64,
        response: &crate::LlmResponse,
        execution_text: &str,
    ) -> EngineExecutorResult<HealedExecutorReply> {
        let mut tracked_repairs = ExecutorWireRepairs::default();
        let healed = if response.finish_reason == crate::FinishReason::Stop {
            heal_executor_text_tracking_repairs(execution_text, &mut tracked_repairs)
        } else {
            Err(Error::InvalidClaimBody("executor LLM response did not finish cleanly").into())
        };
        let error = match healed {
            Ok(healed) => return Ok(healed),
            Err(error) => error,
        };
        let rejected = CodeRunCorrectionDraft::rejected(
            config.run_id,
            step,
            &config.model,
            tracked_repairs,
            rejection_reason(&error),
        );
        self.storage.put_rejected_code_run_correction(&rejected)?;
        Err(error)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "failed REPL step persistence is atomic"
    )]
    pub(super) fn persist_failed_step_after_bridge_calls(
        &self,
        record: &mut CodeRunReplayRecord,
        expected_generation: Option<CodeRunReplayGeneration>,
        completed_steps: u64,
        request_hash: &[u8; 32],
        prepared: &PreparedSource<'_>,
        bridge_start: usize,
        bridge_calls: Vec<CodeRunBridgeCall>,
        captured: Vec<CodeRunRawOutput>,
        bound: Vec<CodeRunResultBinding>,
        receipts: Vec<ReaderFoldReceipt>,
        context_capture: StepContextCapture,
        callable_rows: Option<Vec<EntityId>>,
        durable_wait: Option<SelfDurableWait>,
        observation: String,
        correction: &CodeRunCorrectionDraft<'_>,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
        self.gated_write.refuse_a_step_that_dropped_a_write(
            config.run_id,
            bridge_start as u64,
            &bridge_calls,
        )?;
        record.record_callable_rows(callable_rows);
        record.bridge_calls.extend(bridge_calls);
        record.outputs.extend(captured);
        super::super::board_frames::record_step_board_frames(
            &self.storage,
            record,
            completed_steps,
            bridge_start,
        );
        // The names the failed step bound join the record with their
        // bodies, as on the success path (FIX 833), and are hashed into
        // its checkpoint below; the fold receipts its stores computed land
        // in the same commit, beside the bindings they describe.
        let mut bindings: Vec<_> = bound
            .iter()
            .map(|binding| (binding.name.clone(), binding.handle.clone()))
            .collect();
        for binding in bound {
            match record
                .bindings
                .iter_mut()
                .find(|held| held.name == binding.name)
            {
                Some(held) => *held = binding,
                None => record.bindings.push(binding),
            }
        }
        record_text_output(
            &self.storage,
            record,
            observation_output_path(completed_steps),
            &observation,
        )?;
        // The failed step's observation is a result by path (FIX 828), so it
        // takes its fresh `r<n>` here like the success path's, or no card
        // would name it.
        {
            let path = observation_output_path(completed_steps);
            if let Some(output) = record
                .outputs
                .iter()
                .find(|output| output.path == path)
                .cloned()
            {
                bind_published_output(record, &mut bindings, &output);
                // FIX 18924: its console may print the run's fold answers.
                self.record_step_fold_dependents(record, &[&output])?;
            }
        }
        let terminal_status = durable_wait.map(EngineExecutorStatus::Waiting);
        if let Some(status) = &terminal_status {
            record_terminal_output(&self.storage, record, completed_steps, status)?;
        }
        let mut digests = StepResultDigests::of(&observation, false);
        digests.bindings = bindings;
        // Where the failed step's calls end, and what its guest read before
        // it failed (FIX 6354, FIX 6351, FIX 6352).
        let (end, context) = self.step_context(config, record, bridge_start, context_capture)?;
        let checkpoint = CodeRunStepCheckpoint::new(
            completed_steps,
            checkpoint_label(completed_steps),
            prepared_step_state_hash(
                previous_state_hash(record),
                completed_steps,
                request_hash,
                prepared.original(),
                prepared
                    .transpiled()
                    .map(TranspiledSource::identity)
                    .as_ref(),
                &digests,
                None,
                &record.bridge_calls[bridge_start..],
                end,
            )?,
            config
                .determinism
                .frozen_unix_ms
                .saturating_add(completed_steps),
        )?
        .ending_at(end.bridge_end);
        let bridge_end = record.bridge_calls.len();
        record
            .step_checkpoints
            .push(checkpoint.with_bridge_calls(bridge_start, bridge_end));
        // A wait seen on a failed step is sealed with it too (DOOR-079 1b).
        let parked = parked_wait(record, terminal_status.as_ref(), bridge_start);
        // The reply's correction record commits with this checkpoint (FIX
        // 4411). A flaky commit converts to success on one identical retry
        // (FIX 1443); a first commit that actually landed fails the retry
        // closed on its generation mismatch instead.
        let _ = match self
            .storage
            .put_code_run_replay_record_with_receipts_if_generation(
                record,
                expected_generation,
                correction,
                &receipts,
                parked.as_ref(),
                &context,
            ) {
            Err(error) if matches!(error, Error::Storage(_) | Error::MapFull) => {
                tracing::warn!(
                    "{error:?}: step checkpoint commit hit a storage error; retrying once"
                );
                self.storage
                    .put_code_run_replay_record_with_receipts_if_generation(
                        record,
                        expected_generation,
                        correction,
                        &receipts,
                        parked.as_ref(),
                        &context,
                    )?
            }
            result => result?,
        };
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
    ///
    /// A run that carries a continuation binds its digest in the marker, and
    /// is only ever seeded by its fork: it never starts at step 0 here.
    pub(super) fn load_or_create_record(
        &self,
        config: &EngineExecutorConfig,
        prompt_fingerprint: &str,
        continuation: Option<&ContinuationNote>,
    ) -> EngineExecutorResult<LoadedReplayRecord> {
        let continuation_digest = continuation.map(|note| &note.digest);
        if let Some(record) = self.storage.get_code_run_replay_record(&config.run_id)? {
            let determinism = record.determinism.ok_or_else(|| {
                Error::InvalidConfig("engine executor code run has unknown determinism".to_owned())
            })?;
            if determinism != config.determinism {
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
                continuation_digest,
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
        if continuation_digest.is_some() {
            return Err(Error::InvalidConfig(
                "continuation_unforked: a continued run starts from its fork".to_owned(),
            )
            .into());
        }
        let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        record_config_marker(&self.storage, &mut record, config, prompt_fingerprint, None)?;
        // The run's clock and config are durable from its start: a process
        // that stops after the first step's writes and before its checkpoint
        // resumes under them, never under a fresh clock or another task. Its
        // replies are its actor's from the start too (FIX 5718).
        let actor = self.gated_write.actor().entity_ref();
        let generation =
            self.storage
                .put_owned_code_run_replay_record(&record, None, config.run_id, actor)?;
        Ok(LoadedReplayRecord {
            record,
            generation: Some(generation),
            terminal_status: None,
            prompt: PromptBinding::Unchanged,
        })
    }
}

/// The stable text a refused reply's correction record keeps (FIX 4412):
/// the normalization's own static reason, never text from the reply.
fn rejection_reason(error: &EngineExecutorError) -> String {
    match error {
        EngineExecutorError::Engine(
            Error::InvalidClaimBody(reason) | Error::ArithmeticOverflow(reason),
        ) => (*reason).to_owned(),
        other => other.variant().to_owned(),
    }
}
