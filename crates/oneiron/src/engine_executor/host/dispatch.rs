//! Recording dispatch and callable-skill answers for one JS host.
//! Entry: `RecordingJsHost::dispatch_call`.
//! `RecordingJsHost` state is defined by `engine_executor::host`.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// A verb's or a callable skill's answer too large for one reply, stored
    /// whole as a body of the run as it is encoded. The guest and the replay
    /// row get its handle (`result_handle_json`), never the answer; nothing is
    /// refused for size.
    pub(super) fn store_large_answer(
        &mut self,
        seq: u64,
        mut outcome: SelfDispatchOutcome,
    ) -> Result<SelfDispatchOutcome> {
        let answer = match &mut outcome {
            SelfDispatchOutcome::AgentVerb(answer) => &mut answer.output,
            SelfDispatchOutcome::SkillCall(result) => &mut result.output,
            _ => return Ok(outcome),
        };
        let mut size = ByteCount::default();
        serde_json::to_writer(&mut size, &*answer).map_err(|error| {
            Error::InvalidConfig(format!("verb answer encoding failed: {error}"))
        })?;
        if size.0 <= RESULT_REPLY_INLINE_BYTES {
            return Ok(outcome);
        }
        *answer = self.store_answer(seq, |sink| write_json(sink, &*answer))?;
        Ok(outcome)
    }

    /// Stores what `write` puts in a sink as a body of the run, bound to the
    /// next auto name: the card the guest and the replay row get for it. The
    /// body is masked at write (FIX 5718 part 3): one holding a secret no
    /// handle can stand for is not stored, and the guest gets typed
    /// unavailable content in its place; the call it answers ran.
    pub(super) fn store_answer(
        &mut self,
        seq: u64,
        write: impl FnOnce(&mut BodySink) -> Result<()>,
    ) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let mut sink = storage.code_run_reply_spool()?;
        write(&mut sink)?;
        let path = bridge_result_output_path(seq);
        let output = match storage.publish_code_run_reply(path, sink, self.run_id)? {
            Ok(output) => output,
            Err(unavailable) => return Ok(unavailable),
        };
        let name = self.next_auto_name();
        self.bind(name.clone(), output.handle.clone());
        let mut card = result_handle_json(&output);
        card["name"] = json!(name);
        self.captured.push(output);
        Ok(card)
    }

    /// A callable skill's checked answer as the guest gets it: its JSON up
    /// to the inline reply size, else its card, the answer copied whole from
    /// the call's spool into a body of the run, never read into one value.
    pub(super) fn skill_answer(
        &mut self,
        seq: u64,
        mut answer: crate::skill::CallableSkillAnswer,
    ) -> Result<serde_json::Value> {
        if answer.byte_len() <= RESULT_REPLY_INLINE_BYTES as u64 {
            return serde_json::from_reader(std::io::BufReader::new(answer.reader()?)).map_err(
                |_| Error::InvalidConfig("callable skill returned non-JSON output".to_owned()),
            );
        }
        self.store_answer(seq, |sink| {
            let reader = answer.reader()?;
            let mut frame = vec![0; 64 * 1024];
            loop {
                let read = std::io::Read::read(reader, &mut frame)?;
                if read == 0 {
                    return Ok(());
                }
                sink.write(&frame[..read])?;
            }
        })
    }

    /// `self.skills.call` (OF-353): an agent-callable skill run as a step of
    /// its own, on the sibling runtime the caller's step lent, under the
    /// running attempt's lease, with this host as its bridge. The skill's own
    /// calls are gated and recorded as the run's, at the positions after this
    /// one's. A skill that fails answers a typed failure the program reads;
    /// a halt or a declined TASK among its calls is this call's answer too.
    /// The skill runs under a child of `parent`, the caller's step token: a
    /// stop of the caller stops it, and its owner's suspension stops it alone
    /// (FIX 600). A cancelled skill answers `code_step_cancelled`, and the
    /// caller's step goes on. A callable's own call nests inside it: past
    /// the `[limits] callable_nest_depth` row it asks, and the call runs.
    /// A call that would start below the thread's stack floor answers
    /// `skills_call_stack_floor` instead.
    pub(super) fn call_skill(
        &mut self,
        seq: u64,
        started_at_ms: u64,
        call: &SelfCall,
        skill: SelfSkillCall,
        runtime: &mut dyn JsCodeModeRuntime,
        parent: &StepCancellation,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |error: String| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::SkillsCall,
                error,
            })
        };
        // Each nested level keeps its host loop's frames on this thread.
        if below_stack_floor() {
            return Ok(failed("skills_call_stack_floor".to_owned()));
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        let lease = match self
            .gated_write
            .admit_skill_call_for_executor_run(site, call)?
        {
            Ok(lease) => lease,
            Err(refused) => return Ok(refused),
        };
        // The call's verb hooks once it is admitted (ARCH-0080 §3): a rewrite
        // names the skill and the args it runs with.
        let (skill, hooked) = if self.admitted_skill_seq == Some(seq) {
            (skill, None)
        } else {
            match self.gated_write.enter_verb_hooks(
                SelfCall::SkillsCall(skill),
                Some(site),
                lease.read_as.clone(),
            )? {
                Ok((SelfCall::SkillsCall(skill), hooked)) => (skill, Some(hooked)),
                Ok(_) => {
                    return Err(Error::InvariantViolation(
                        "a skill call's hooks rewrote it into another call",
                    ));
                }
                Err(stopped) => return Ok(stopped),
            }
        };
        let Some(executor) = self.skill_executor.clone() else {
            return Ok(failed("skills_call_no_executor".to_owned()));
        };
        let (run_id, determinism) = (self.run_id, self.determinism);
        self.callable_depth += 1;
        lease.vault.measure_limit(
            crate::limit_ask::EngineLimit::CallableNestDepth,
            u64::from(self.callable_depth),
        );
        // The skill's stored body and its own calls reach the run (FIX 6130).
        let cause = crate::code_run::ReadWorldUnknown::CallableSkill;
        self.gated_write.read_worlds_unknown(run_id, cause);
        let mut loaded = Vec::new();
        // The answer check holds its buffers on the run's own share (FIX
        // 10149); a host lent none checks unheld, as before.
        let memory = self.result_share.zip(self.storage).map(|(share, storage)| {
            crate::skill::AnswerMemory {
                share,
                watch: storage.limit_watch(),
            }
        });
        let ran = crate::skill::execute_callable_skill_cancellable(
            &lease.vault,
            &lease.leased,
            &skill.skill,
            &executor,
            &skill.args,
            runtime,
            &mut *self,
            run_id,
            seq,
            determinism,
            started_at_ms / 1000,
            parent,
            &mut loaded,
            memory,
        );
        self.callable_rows.0.extend(loaded);
        self.callable_depth -= 1;
        if self.hard_failure.is_some() || self.left_a_gap {
            return Ok(failed("host_bridge_halted".to_owned()));
        }
        if self.declined.is_some() {
            return Ok(failed("task_declined".to_owned()));
        }
        let outcome = match ran {
            Ok(answer) => SelfDispatchOutcome::SkillCall(SelfSkillCallResult {
                skill: skill.skill,
                output: self.skill_answer(seq, answer)?,
            }),
            // A cancelled skill is a failed call under its stable code, read
            // from the typed error the runtime raised, never from guest text.
            Err(Error::Code(CodeError::CodeStepCancelled)) => {
                failed(CodeError::CodeStepCancelled.to_string())
            }
            Err(error) => failed(error.to_string()),
        };
        // The post chain reads the answer as the guest gets it: a large one
        // by its handle.
        let outcome = self.store_large_answer(seq, outcome)?;
        match hooked {
            Some(hooked) => self.gated_write.leave_verb_hooks(hooked, outcome),
            None => Ok(outcome),
        }
    }

    /// One `self.*` call over the bridge. `runtime` is the sibling a call
    /// that runs a step of its own runs it on, when the caller's runtime
    /// lent one ([`JsCodeModeHost::dispatch_self_nested`]), with the
    /// caller's step token that step's own descends from.
    pub(super) fn dispatch_call(
        &mut self,
        call: SelfCall,
        runtime: Option<(&mut dyn JsCodeModeRuntime, &StepCancellation)>,
    ) -> Result<SelfDispatchResponse> {
        // A resumed turn program's settled calls answer from the rows that
        // settled them, before a position is taken or anything dispatched
        // (DOOR-141 PR3b). Only a pinned entry binds an injection.
        if let Some(injection) = self.injection.as_mut() {
            match injection.answer(&call) {
                InjectedAnswer::Live => {}
                InjectedAnswer::Settled { outcome, view } => {
                    return Ok(self.respond(*outcome, view));
                }
                InjectedAnswer::Hold => {
                    if self.hard_failure.is_none() {
                        self.hard_failure =
                            Some(Error::InvalidConfig(PROGRAM_RESUME_HELD.to_owned()));
                    }
                    let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                        effect: call.effect(),
                        error: PROGRAM_RESUME_HELD.to_owned(),
                    });
                    return Ok(self.respond(outcome, None));
                }
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        // ONE-1686: the speech family's order and timestamp are the BRIDGE's,
        // stamped here — on the one ordering path every `self.*` call takes —
        // before the row is recorded or the effect dispatched. Guest code
        // cannot forge either, and the replay row, the dispatched call and the
        // emitted bubble all carry the same number.
        let call = call.with_bridge_stamp(seq, started_at_ms);
        // Past a wait or a halt the bridge answers without dispatching, but a
        // session-bound run is still answered as its participant stands: once
        // they left the room it hears `NotInRoom`, never the wait or the halt.
        if (self.durable_wait.is_some()
            || self.hard_failure.is_some()
            || self.left_a_gap
            || self.declined.is_some())
            && let Some(storage) = self.storage
            && let Err(err) = storage.answered(|| Ok(()))
        {
            self.left_a_gap = true;
            return Err(err);
        }
        if let Some(wait) = &self.durable_wait {
            let outcome = SelfDispatchOutcome::DurableWait(wait.clone());
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome, None));
        }
        if self.hard_failure.is_some() || self.left_a_gap || self.declined.is_some() {
            // Fail-closed after the first hard failure or unrecorded call:
            // no further gate dispatches; the guest sees a typed Failed
            // response (budget attached) and the replay row records exactly
            // that. A declined TASK is closed the same way, without failing
            // the step.
            let error =
                if self.declined.is_some() && self.hard_failure.is_none() && !self.left_a_gap {
                    "task_declined"
                } else {
                    "host_bridge_halted"
                };
            let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: error.to_owned(),
            });
            let row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(outcome, None));
        }
        // OF-568: what this call reads, captured before it runs, for its
        // row's action digest. Only the vault's own storage is versioned: a
        // session overlay's reads, or a capture that failed, stay unknown.
        let inputs = match self.storage {
            Some(ExecutorStorage::Canonical(vault)) => {
                self_call_inputs(vault, &call).ok().flatten()
            }
            _ => None,
        };
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        // This call's row keeps its own position: a callable skill's calls
        // take the positions after it, and their rows land first.
        let place = self.bridge_calls.len();
        // The call, a callable skill's or a reader's included, holds the
        // attempt's tool witness open until it is answered (OF-568 L5).
        let _tool = self.gated_write.activity_tool();
        let dispatched = match (&call, runtime) {
            (SelfCall::SkillsCall(skill), Some((runtime, parent))) => {
                let skill = skill.clone();
                self.call_skill(seq, started_at_ms, &call, skill, runtime, parent)
            }
            (SelfCall::ReaderSpawn(spawn), _) => {
                let spawn = (**spawn).clone();
                self.spawn_reader(seq, spawn)
            }
            (SelfCall::ReaderReport(report), _) => {
                let report = report.clone();
                self.report_finding(seq, report)
            }
            (SelfCall::Summarize(summary), _) => {
                let summary = (**summary).clone();
                self.summarize(seq, summary)
            }
            _ => {
                let site = ExecutorCallSite {
                    run_id: self.run_id,
                    seq,
                    step_start: self.step_start,
                    earlier: &self.bridge_calls,
                };
                self.gated_write
                    .dispatch_for_executor_run(site, call.clone())
            }
        };
        // A verb hook's view of this call's result, taken whatever came of
        // the call: the guest reads it, the row keeps the outcome.
        let view = self.gated_write.take_hook_view();
        let outcome = match dispatched.and_then(|outcome| self.store_large_answer(seq, outcome)) {
            Ok(outcome) => outcome,
            Err(err) => {
                let Some(error_outcome) = dispatch_error_outcome(&call, &err) else {
                    // Infrastructure failure: no guest-visible response
                    // exists for this call at all.
                    self.left_a_gap = true;
                    return Err(err);
                };
                let row = CodeRunBridgeCall::record(
                    seq,
                    &call,
                    &error_outcome,
                    started_at_ms,
                    started_at_ms,
                )?
                .with_inputs(inputs.as_ref());
                self.bridge_calls.insert(place, row);
                self.hard_failure = Some(err);
                return Ok(self.respond(error_outcome, None));
            }
        };
        let finished_at_ms = started_at_ms;
        let row = CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, finished_at_ms)?
            .with_inputs(inputs.as_ref());
        if self.durable_wait.is_none()
            && let SelfDispatchOutcome::DurableWait(wait) = &outcome
        {
            self.durable_wait = Some(wait.clone());
        }
        if let SelfDispatchOutcome::TaskRefusal(refusal) = &outcome
            && refusal.declined()
        {
            self.declined = Some(refusal.task_ref);
        }
        self.bridge_calls.insert(place, row);
        Ok(self.respond(outcome, view))
    }
}

pub(super) fn dispatch_error_outcome(call: &SelfCall, err: &Error) -> Option<SelfDispatchOutcome> {
    match err {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => Some(SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: call.effect(),
            outcome: (*outcome).to_owned(),
            reason_codes: reason_codes
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
        })),
        // No provider answered a door's model call (FIX 3194): the guest sees
        // the typed failure, and the step ends on the outage, which parks
        // its run.
        Error::ProviderUnavailable { .. } => Some(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: err.to_string(),
        })),
        // A refusal names its bound: the guest reads what it can act on.
        Error::Refused(_) => Some(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: err.to_string(),
        })),
        _ if records_failed_effect(call.effect()) => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
            }))
        }
        _ => None,
    }
}

/// Effects whose failure is REPLAY-VISIBLE rather than infrastructural.
///
/// These cross an audited durable boundary, so a refusal is part of the run's
/// history: the guest sees a typed `Failed` response, the row lands in the
/// replay log, and the fail-closed barrier refuses everything after it.
/// ONE-1686 adds the speech family — a refused bubble (a stale route after a
/// mid-run mode flip, a door rejection) is exactly that kind of failure.
pub(super) fn records_failed_effect(effect: SelfEffect) -> bool {
    matches!(
        effect,
        SelfEffect::MemoryPutClaim
            | SelfEffect::AgentsPut
            | SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
            | SelfEffect::ReportBlocked
            | SelfEffect::InferenceDefaultsReplace
    ) || effect.is_speech()
}
