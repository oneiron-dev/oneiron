//! Model-free entry and replay of the caller's own source (FIX EXECUTE-CALLER-CODE).

use std::collections::{HashMap, VecDeque};

use oneiron_contracts::fingerprint::{ContentHash, ContentHasher};
use serde::{Deserialize, Serialize};

use super::driver::EngineNativeExecutor;
use super::host::{CallableChecks, RecordingJsHost, executor_boundary_contract};
use super::program_entry::{
    ProgramInjection, ProgramLogEntry, SettledCall, read_delivered_reply, row_at,
};
use super::record::{
    LoadedReplayRecord, StepResultDigests, completed_step_count, parked_wait,
    prepared_step_state_hash, previous_state_hash, record_terminal_output, self_effect_from_str,
};
use super::repl::deadline::guest_abi_digest;
use super::repl::persistence::WaitResume;
use super::store::{
    SCRIPT_OUTPUT_DIR, StepBodies, bind_published_output, checkpoint_label, clean_for_context,
    console_output_path, executed_output_path, load_utf8_output, observation_output_path,
    publish_output, record_prepared_source, record_script_output, resumed_output_path,
    source_map_output_path, validate_runtime_outputs,
};
use super::types::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus,
    JsCodeModeStep,
};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunRawOutput, CodeRunReplayRecord, CodeRunResultBinding,
    CodeRunStepCheckpoint, ExecutorStorage, PendingCodeStep, ProgramResumeCall, ProgramResumeKind,
    ReaderFoldReceipt, RecordedProducer, SelfDurableWait, StepContextCapture, program_resume_call,
};
use crate::code_sandbox::source::{PreparedSource, TranspiledSource, prepare_source};
use crate::store::result_manifest::invalid_code_run_replay;
use crate::{EntityId, Error, Result};

const ENTRY_DOMAIN: &[u8] = b"oneiron:engine-executor:caller-source-entry:v1";
const NO_PROMPT: &str = "";

/// The replay prefix is kept beside the record that holds its rows. The head
/// names the calls in source order; it never duplicates their replies.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerSourceHead {
    frontier: u64,
    guest_abi: [u8; 32],
    preparation: Option<[u8; 32]>,
    calls: Vec<ProgramResumeCall>,
    wait_row: Option<u64>,
}

/// One pass through the caller source, before its durable append.
struct CallerSourceSlice {
    deadline: bool,
    wait: Option<SelfDurableWait>,
    steps_run: u32,
    bodies: Option<StepBodies>,
    done: bool,
    error: Option<Error>,
    calls: Vec<ProgramResumeCall>,
    wait_row: Option<u64>,
    callable_rows: Option<Vec<EntityId>>,
    bridge_calls: Vec<CodeRunBridgeCall>,
    captured: Vec<CodeRunRawOutput>,
    bound: Vec<CodeRunResultBinding>,
    receipts: Vec<ReaderFoldReceipt>,
    context_capture: StepContextCapture,
}

impl EngineNativeExecutor<'_> {
    /// Runs the caller's exact source on the bound host door, without a model
    /// turn. A later entry replays settled calls before issuing any new ones.
    /// A completed run returns its stored record without running again.
    ///
    /// # Errors
    ///
    /// The run identity, stored source or replay prefix does not match, or
    /// the storage, runtime or bridge refuses the entry.
    pub fn run_caller_source(
        &mut self,
        config: &EngineExecutorConfig,
        code: &str,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        config.validate()?;
        self.verify_storage_dispatcher_binding()?;
        let digest = config.caller_source_digest.ok_or_else(|| {
            Error::InvalidConfig("caller source requires a source config".to_owned())
        })?;
        let gated = self.gated_write;
        let LoadedReplayRecord {
            mut record,
            mut generation,
            terminal_status,
            ..
        } = self.load_or_create_record(config, NO_PROMPT, None, Some(code))?;
        if terminal_status == Some(EngineExecutorStatus::Complete) {
            return Ok(self.caller_source_outcome(EngineExecutorStatus::Complete, 0, record));
        }
        if self.storage.code_run_response_erased(config.run_id)? {
            return Err(crate::code_run::response_erased_error("caller source replay").into());
        }

        let seq = completed_step_count(&record)?;
        let boundary = executor_boundary_contract()?;
        let guest_abi = guest_abi_digest(&boundary);
        let request_hash = caller_source_entry_digest(config.run_id, digest);
        let head = self.load_caller_source_head(&record, seq, guest_abi, request_hash, digest)?;
        let mut settled = self.caller_source_settled(&record, head.as_ref())?;
        let mut delivery = None;
        if let Some(EngineExecutorStatus::Waiting(wait)) = terminal_status {
            let wait_row = head
                .as_ref()
                .and_then(|head| head.wait_row)
                .ok_or_else(|| invalid_code_run_replay("caller source wait has no resume row"))?;
            let row = source_wait_row(&record, wait_row, &wait)?;
            let status = EngineExecutorStatus::Waiting(wait.clone());
            let key = self.park(&record, &wait)?;
            if let Some(paused) = self.pause_at_wait(&record, &status)? {
                return Ok(self.caller_source_outcome(paused, 0, record));
            }
            let resume = match key {
                Some(key) => self.prepare_wait_resume(&record, &wait, &key)?,
                None => None,
            };
            let Some(resume) = resume else {
                return Ok(self.caller_source_outcome(status, 0, record));
            };
            let producer = RecordedProducer::of_row(&row, false);
            settled.push_back(SettledCall {
                listed: program_resume_call(&row, Some(wait.wait_id))?,
                row,
                // The host replaces the parked answer only after consuming its reply.
                reply: None,
            });
            delivery = Some((wait_row, wait, resume, producer));
        } else if let Some(wait_row) = head.as_ref().and_then(|head| head.wait_row) {
            // A prior entry consumed its wait after matching the prefix, but
            // stopped before it could commit another checkpoint.
            let row = row_at(&record, wait_row).ok_or_else(missing_row)?.clone();
            let wait = row.program_durable_wait()?.ok_or_else(missing_row)?;
            let listed = program_resume_call(&row, Some(wait.wait_id))?;
            let reply = caller_source_reply(&self.storage, &record, &listed)?;
            settled.push_back(SettledCall { row, listed, reply });
        }

        let prepared = self
            .prepare_caller_source(&record, head.as_ref(), code)?
            .with_return_capture();
        let preparation = prepared.transpiled().map(TranspiledSource::identity);
        let root = self.attempt_root();
        let cancel = root.token();
        cancel.check()?;
        let mut read_worlds = None;
        let live_start = record.bridge_calls.len();
        gated.observe_bridge_history(&record.bridge_calls);
        gated.observe_consumed_code_replies(&record)?;
        gated.observe_model_provider(None);
        let storage = &self.storage;
        let slice = {
            let mut advance;
            let mut host = RecordingJsHost::new(
                gated,
                config.run_id,
                live_start as u64,
                config.determinism,
                self.legibility,
            )
            .with_recoverable_outputs(storage, &record, self.observation_refs(&record)?)?
            .with_file_output_step(seq)
            .with_result_share(&self.result_share)
            .with_callable_checks(CallableChecks::new(self.code_check, seq));
            host.injection = Some(ProgramInjection::for_caller_source(settled));
            advance = |at| -> Result<Option<serde_json::Value>> {
                let Some(at) = at else {
                    read_worlds.get_or_insert_with(|| {
                        gated.enter_read_worlds(config.run_id, &config.task)
                    });
                    return Ok(None);
                };
                let Some((row, _, _, _)) = delivery.as_ref() else {
                    return Ok(None);
                };
                if *row != at {
                    return Ok(None);
                }
                let (_, wait, resume, producer): (_, _, WaitResume, _) = delivery.take().ok_or(
                    Error::InvariantViolation("caller source lost its wait reply"),
                )?;
                if !gated.releases_recorded_answer(resume.source_rows(), producer) {
                    return Err(Error::InvalidConfig(
                        "the bound door no longer releases the caller source wait reply".to_owned(),
                    ));
                }
                read_worlds
                    .get_or_insert_with(|| gated.enter_read_worlds(config.run_id, &config.task));
                generation = Some(resume.commit(storage, gated, &mut record, &wait, generation)?);
                gated.observe_consumed_code_replies(&record)?;
                read_caller_source_reply(storage, &record, seq - 1, wait.wait_id).map(Some)
            };
            host.advance_caller_source = Some(&mut advance);
            let step = JsCodeModeStep {
                run_id: config.run_id,
                // It is the same guest entry each time, even after a wait checkpoint.
                seq: 0,
                script: code,
                boundary,
                determinism: config.determinism,
            };
            let ran = self
                .runtime
                .run_prepared_step_cancellable(step, &prepared, &mut host, cancel);
            let hit_deadline = ran.is_ok() && host.parks_at_deadline();
            let replay = host.injection.take().ok_or(Error::InvariantViolation(
                "caller source lost its replay prefix",
            ))?;
            // A shorter deadline may stop a replay before its old frontier.
            // The old frontier still names the same source.
            if hit_deadline && replay.awaiting_caller_source_prefix() {
                None
            } else {
                let log = replay.settle().map_err(invalid_code_run_replay)?;
                let wait = host.durable_wait.take();
                let steps_run = if ran.is_ok() { 1 } else { 0 };
                let hard_failure = host.hard_failure.take();
                // A step that failed after it parked returns its wait, as a
                // task step does: its failure is its observation
                // (`persist_failed_step_after_bridge_calls`). A cancelled
                // entry still fails.
                let parks = wait.is_some() && !cancel.is_cancelled();
                let (bodies, done, error) = match ran {
                    Ok(outcome) if !hit_deadline && hard_failure.is_none() => {
                        match host.take_streamed().into_step_bodies(
                            storage,
                            config.run_id,
                            &outcome,
                        ) {
                            Ok(bodies) => (Some(bodies), outcome.done, None),
                            Err(error) if parks => (
                                Some(failure_observation(
                                    storage,
                                    "Runtime output recording failed after host bridge calls",
                                    &error,
                                )?),
                                false,
                                None,
                            ),
                            Err(error) => (None, false, Some(error)),
                        }
                    }
                    _ if parks => match hard_failure {
                        Some(failure) => (
                            Some(failure_observation(
                                storage,
                                "Host bridge call failed",
                                &failure,
                            )?),
                            false,
                            None,
                        ),
                        None => (None, false, None),
                    },
                    Ok(_) => (None, false, hard_failure),
                    Err(error) => (None, false, Some(hard_failure.unwrap_or(error))),
                };
                let (calls, wait_row) = caller_source_calls(&host, log, wait.as_ref())?;
                let callable_rows = host.result_rows();
                Some(CallerSourceSlice {
                    deadline: hit_deadline,
                    wait,
                    steps_run,
                    bodies,
                    done,
                    error,
                    calls,
                    wait_row,
                    callable_rows,
                    bridge_calls: host.bridge_calls,
                    captured: host.captured,
                    bound: host.bound,
                    receipts: host.receipts,
                    context_capture: host.context_capture,
                })
            }
        };
        let Some(CallerSourceSlice {
            deadline,
            wait,
            steps_run,
            bodies,
            done,
            error,
            calls,
            wait_row,
            callable_rows,
            bridge_calls,
            captured,
            bound,
            receipts,
            context_capture,
        }) = slice
        else {
            return Ok(self.caller_source_outcome(
                EngineExecutorStatus::Yielded { next_step_seq: seq },
                0,
                record,
            ));
        };
        gated.refuse_a_step_that_dropped_a_write(
            config.run_id,
            live_start as u64,
            &bridge_calls,
        )?;
        if wait.is_none()
            && bridge_calls.is_empty()
            && captured.is_empty()
            && let Some(error) = error
        {
            return Err(error.into());
        }
        record.record_callable_rows(callable_rows);
        record.bridge_calls.extend(bridge_calls);
        record.outputs.extend(captured);
        let mut bindings = Vec::new();
        for binding in bound {
            bindings.push((binding.name.clone(), binding.handle.clone()));
            if let Some(held) = record
                .bindings
                .iter_mut()
                .find(|held| held.name == binding.name)
            {
                *held = binding;
            } else {
                record.bindings.push(binding);
            }
        }
        if head.is_none() {
            record_prepared_source(&self.storage, &mut record, 0, &prepared)?;
        }
        let prior = record.pending_step.take();
        let bridge_start = prior
            .as_ref()
            .map_or(live_start, |prior| prior.bridge_start as usize);
        let head = CallerSourceHead {
            frontier: record.bridge_calls.len() as u64,
            guest_abi,
            preparation,
            calls,
            wait_row,
        };
        if wait.is_none() && (deadline || error.is_some()) {
            let park_generation = prior
                .as_ref()
                .map_or(0, |prior| prior.park_generation.saturating_add(1));
            keep_head(
                &self.storage,
                &mut record,
                seq,
                Some(park_generation),
                &head,
            )?;
            let guest_calls = head
                .calls
                .iter()
                .map(|call| call.row)
                .filter(|row| *row >= bridge_start as u64)
                .collect();
            record.pending_step = Some(PendingCodeStep {
                step_seq: seq,
                bridge_start: bridge_start as u64,
                guest_calls,
                bridge_frontier: head.frontier,
                output_frontier: record.outputs.len() as u64,
                script_blake3: digest.into_bytes(),
                prepared_identity: preparation,
                guest_abi,
                request_hash,
                // PendingCodeStep has a required model field. Source mode
                // uses the config's fixed value but writes no model receipt.
                model: config.model.clone(),
                answered_by: None,
                repairs: Default::default(),
                determinism: config.determinism,
                trailing_speech: false,
                park_generation,
            });
            // A flaky commit converts to success on one identical retry (FIX
            // 1443); a first commit that actually landed fails the retry
            // closed on its generation mismatch instead.
            match self
                .storage
                .put_code_run_replay_record_if_generation(&record, generation)
            {
                Err(error) if matches!(error, Error::Storage(_) | Error::MapFull) => {
                    tracing::warn!(
                        "{error:?}: caller source pending commit hit a storage error; retrying once"
                    );
                    self.storage
                        .put_code_run_replay_record_if_generation(&record, generation)?;
                }
                result => {
                    result?;
                }
            }
            if let Some(error) = error {
                return Err(error.into());
            }
            return Ok(self.caller_source_outcome(
                EngineExecutorStatus::Yielded { next_step_seq: seq },
                0,
                record,
            ));
        }
        let status = if let Some(wait) = wait {
            self_effect_from_str(wait.effect.as_str())?;
            keep_head(&self.storage, &mut record, seq, None, &head)?;
            EngineExecutorStatus::Waiting(wait)
        } else {
            EngineExecutorStatus::Complete
        };
        let mut result = self.publish_caller_source_result(&mut record, seq, bodies, bindings)?;
        result.done = done;
        record_terminal_output(&self.storage, &mut record, seq, &status)?;
        let (end, context) = self.step_context(config, &record, bridge_start, context_capture)?;
        let state_hash = prepared_step_state_hash(
            previous_state_hash(&record),
            seq,
            &request_hash,
            code,
            preparation.as_ref(),
            &result,
            None,
            &record.bridge_calls[bridge_start..],
            end,
        )?;
        record.step_checkpoints.push(
            CodeRunStepCheckpoint::new(
                seq,
                checkpoint_label(seq),
                state_hash,
                config.determinism.frozen_unix_ms.saturating_add(seq),
            )?
            .ending_at(end.bridge_end)
            .with_bridge_calls(bridge_start, record.bridge_calls.len()),
        );
        // A wait is bound to the live slice that issued it, even if the
        // checkpoint covers rows kept by earlier deadline slices.
        let parked = parked_wait(&record, Some(&status), live_start);
        // One identical retry on a flaky commit, as above (FIX 1443).
        let _ = match self.storage.put_caller_source_replay_record(
            &record,
            generation,
            &receipts,
            parked.as_ref(),
            &context,
        ) {
            Err(error) if matches!(error, Error::Storage(_) | Error::MapFull) => {
                tracing::warn!(
                    "{error:?}: caller source step commit hit a storage error; retrying once"
                );
                self.storage.put_caller_source_replay_record(
                    &record,
                    generation,
                    &receipts,
                    parked.as_ref(),
                    &context,
                )?
            }
            result => result?,
        };
        if let EngineExecutorStatus::Waiting(wait) = &status {
            self.park(&record, wait)?;
        }
        cancel.check()?;
        if let Some(error) = error {
            return Err(error.into());
        }
        let status = if matches!(status, EngineExecutorStatus::Waiting(_)) {
            self.pause_at_wait(&record, &status)?.unwrap_or(status)
        } else {
            status
        };
        Ok(self.caller_source_outcome(status, steps_run, record))
    }

    fn caller_source_outcome(
        &self,
        status: EngineExecutorStatus,
        steps_run: u32,
        replay_record: CodeRunReplayRecord,
    ) -> EngineExecutorOutcome {
        EngineExecutorOutcome {
            status,
            steps_run,
            replay_record,
            seat_receipt: None,
            compaction: None,
            program_steps: Vec::new(),
            resume_preflight: None,
            cache_horizon: None,
        }
    }

    fn load_caller_source_head(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
        guest_abi: [u8; 32],
        request_hash: [u8; 32],
        digest: ContentHash,
    ) -> EngineExecutorResult<Option<CallerSourceHead>> {
        let path = match &record.pending_step {
            Some(pending) => {
                if pending.step_seq != seq
                    || pending.request_hash != request_hash
                    || &pending.script_blake3 != digest.as_bytes()
                    || pending.guest_abi != guest_abi
                    || pending.determinism != record.determinism.ok_or_else(missing_row)?
                    || pending.bridge_frontier != record.bridge_calls.len() as u64
                    || pending.output_frontier != record.outputs.len() as u64
                {
                    return Err(
                        invalid_code_run_replay("caller source pending frontier changed").into(),
                    );
                }
                head_path(seq, Some(pending.park_generation))
            }
            None if seq > 0 => head_path(seq - 1, None),
            None if record.bridge_calls.is_empty() => return Ok(None),
            None => return Err(missing_row().into()),
        };
        let text = load_utf8_output(&self.storage, record, &path)?;
        let head: CallerSourceHead = serde_json::from_str(&text)
            .map_err(|_| Error::CorruptedIndex("caller source replay head"))?;
        if head.frontier != record.bridge_calls.len() as u64
            || head.guest_abi != guest_abi
            || record.pending_step.as_ref().is_some_and(|pending| {
                head.preparation != pending.prepared_identity || head.wait_row.is_some()
            })
        {
            return Err(invalid_code_run_replay(
                "caller source replay frontier or boundary changed",
            )
            .into());
        }
        Ok(Some(head))
    }

    fn prepare_caller_source<'s>(
        &self,
        record: &CodeRunReplayRecord,
        head: Option<&CallerSourceHead>,
        code: &'s str,
    ) -> EngineExecutorResult<PreparedSource<'s>> {
        let prepared = prepare_source(code);
        let Some(head) = head else {
            return Ok(prepared);
        };
        if let Some(identity) = head.preparation {
            let executed = load_utf8_output(&self.storage, record, &executed_output_path(0))?;
            let map = load_utf8_output(&self.storage, record, &source_map_output_path(0))?;
            let (original, kept) = TranspiledSource::from_record(executed, map.as_bytes())?;
            if kept.identity() == identity
                && let Some(prepared) = prepared.reusing(&original, &kept)
            {
                return Ok(prepared);
            }
        } else if prepared.transpiled().is_none() {
            return Ok(prepared);
        }
        Err(invalid_code_run_replay("caller source preparation changed").into())
    }

    fn caller_source_settled(
        &self,
        record: &CodeRunReplayRecord,
        head: Option<&CallerSourceHead>,
    ) -> EngineExecutorResult<VecDeque<SettledCall>> {
        head.into_iter()
            .flat_map(|head| &head.calls)
            .map(|listed| {
                let row = row_at(record, listed.row).ok_or_else(missing_row)?.clone();
                let reply = caller_source_reply(&self.storage, record, listed)?;
                Ok(SettledCall {
                    row,
                    listed: *listed,
                    reply,
                })
            })
            .collect()
    }

    fn publish_caller_source_result(
        &self,
        record: &mut CodeRunReplayRecord,
        seq: u64,
        bodies: Option<StepBodies>,
        mut bindings: Vec<(String, String)>,
    ) -> EngineExecutorResult<StepResultDigests> {
        let bodies = match bodies {
            Some(bodies) => bodies,
            None => StepBodies {
                observation: self.storage.code_run_output_sink()?,
                console: None,
                files: Vec::new(),
            },
        };
        let paths = validate_runtime_outputs(record, seq, &bodies.files)?;
        let observation = publish_output(
            &self.storage,
            record,
            observation_output_path(seq),
            bodies.observation,
        )?;
        bind_published_output(record, &mut bindings, &observation);
        let mut printed = vec![observation];
        if let Some(console) = bodies.console {
            printed.push(publish_output(
                &self.storage,
                record,
                console_output_path(seq),
                console,
            )?);
        }
        let mut outputs = Vec::new();
        for ((file, sink), path) in bodies.files.into_iter().zip(paths) {
            let output = publish_output(&self.storage, record, path, sink)?;
            outputs.push((file, output.raw_blake3));
            bind_published_output(record, &mut bindings, &output);
            printed.push(output);
        }
        self.record_step_fold_dependents(record, &printed.iter().collect::<Vec<_>>())?;
        Ok(StepResultDigests {
            observation: printed[0].raw_blake3,
            done: false,
            outputs,
            bindings,
        })
    }
}

/// The observation of a step that failed after it parked, in the words the
/// task path keeps for one (`persist_failed_step_after_bridge_calls`).
fn failure_observation(
    storage: &ExecutorStorage<'_>,
    what: &str,
    failure: &Error,
) -> Result<StepBodies> {
    let mut observation = storage.code_run_output_sink()?;
    observation.write(format!("{what}: {failure}").as_bytes())?;
    Ok(StepBodies {
        observation,
        console: None,
        files: Vec::new(),
    })
}

fn caller_source_calls(
    host: &RecordingJsHost<'_, '_>,
    log: Vec<ProgramLogEntry>,
    wait: Option<&SelfDurableWait>,
) -> Result<(Vec<ProgramResumeCall>, Option<u64>)> {
    let rows: HashMap<_, _> = host.bridge_calls.iter().map(|row| (row.seq, row)).collect();
    let mut calls = Vec::new();
    let mut inside_settled = 0;
    for (index, entry) in log.into_iter().enumerate() {
        if index < inside_settled {
            continue;
        }
        let seq = match entry {
            ProgramLogEntry::Answered(listed) => {
                calls.push(listed);
                continue;
            }
            ProgramLogEntry::Issued(seq) => seq,
        };
        let row = rows.get(&seq).ok_or_else(missing_row)?;
        if wait.is_some_and(|wait| crate::code_run::parks_on(&row.outcome, wait.wait_id)) {
            return Ok((calls, Some(seq)));
        }
        let mut listed = program_resume_call(row, None)?;
        if let Some(span) = host.program_callables.iter().find(|span| span.seq == seq) {
            listed.kind = span.kind;
            if span.kind == ProgramResumeKind::Settled {
                inside_settled = span.log_end;
            }
        }
        calls.push(listed);
    }
    if wait.is_some() {
        return Err(missing_row());
    }
    Ok((calls, None))
}

fn source_wait_row(
    record: &CodeRunReplayRecord,
    row: u64,
    wait: &SelfDurableWait,
) -> Result<crate::code_run::CodeRunBridgeCall> {
    let row = row_at(record, row).ok_or_else(missing_row)?;
    if !crate::code_run::parks_on(&row.outcome, wait.wait_id) {
        return Err(missing_row());
    }
    Ok(row.clone())
}

fn caller_source_reply(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    listed: &ProgramResumeCall,
) -> Result<Option<serde_json::Value>> {
    let Some(wait) = listed.reply else {
        return Ok(None);
    };
    let step = record
        .step_checkpoints
        .iter()
        .find(|step| {
            step.bridge_calls
                .is_some_and(|(start, end)| (start..end).contains(&listed.row))
        })
        .ok_or_else(missing_row)?;
    read_caller_source_reply(storage, record, step.seq, wait).map(Some)
}

fn read_caller_source_reply(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    seq: u64,
    wait: EntityId,
) -> Result<serde_json::Value> {
    let path = resumed_output_path(seq, wait);
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("caller source wait reply"))?;
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Err(Error::InvalidConfig(
            "caller source wait reply is withheld".to_owned(),
        ));
    }
    read_delivered_reply(storage, record, &path)?
        .ok_or(Error::CorruptedIndex("caller source wait reply"))
}

fn keep_head(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    seq: u64,
    park: Option<u64>,
    head: &CallerSourceHead,
) -> EngineExecutorResult<()> {
    let head = serde_json::to_string(head)?;
    record_script_output(storage, record, head_path(seq, park), &head)
}

fn head_path(seq: u64, park: Option<u64>) -> String {
    match park {
        Some(park) => format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.{park:06}.caller-source.pending.json"),
        None => format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.caller-source.wait.json"),
    }
}

fn missing_row() -> Error {
    invalid_code_run_replay("caller source replay row missing")
}

fn caller_source_entry_digest(run: EntityId, digest: ContentHash) -> [u8; 32] {
    let mut hash = ContentHasher::new();
    hash.update(ENTRY_DOMAIN)
        .update(run.as_bytes())
        .update(digest.as_bytes());
    hash.finish().into_bytes()
}
