//! A turn program's pinned entry (DOOR-141 PR3b, FIX 4382).
//!
//! The executor runs the program's pinned callable itself, from its stored
//! and pinned source, on the program's own attempt and code run. No model
//! writes the call, so a resume generates nothing again: a later entry
//! replays the same source, and each call an earlier entry settled is
//! answered from the record row that settled it (or with the delivered reply
//! of the wait it parked on) instead of being issued again. Past those, the
//! source's calls run live. An entry that does not line up with its
//! checkpoint holds and commits nothing.
//!
//! The pinned call goes through the executor's own bridge, so the callable's
//! source, contract, run id, executor, tier, cancellation and return checks
//! are the ordinary callable's, its refusal of an unfinished step included:
//! a pinned entry that did not finish answers that refusal, and the program
//! reads it as unfinished.

use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::json;

use super::cancel::StepCancellation;
use super::driver::EngineNativeExecutor;
use super::host::RecordingJsHost;
use super::record::{
    StepResultDigests, completed_step_count, parked_wait, prepared_step_state_hash,
    previous_state_hash, record_terminal_output, verify_code_consent_park, wait_key,
};
use super::store::{
    checkpoint_label, load_utf8_output, observation_output_path, pinned_executed_output_path,
    pinned_source_map_output_path, record_output, record_script_output, record_text_output,
    resumed_output_wait,
};
use super::types::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use crate::code_run::{
    AgentVerbAnswer, CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord,
    CodeRunStepCheckpoint, ExecutorStorage, ProgramCheckpointTail, ProgramResumeCall,
    ProgramResumeCommit, ProgramResumeWait, SelfCall, SelfDispatchOutcome, SelfDurableWait,
    SelfSkillCall, load_program_checkpoint_tail, program_resume_call,
};
use crate::code_sandbox::ProposalSpoolFloor;
use crate::code_sandbox::source::{PreparedSource, TranspiledSource, prepare_source};
use crate::entity_id::EntityId;
use crate::{Error, Vault};

/// What the guest of a call reads once its entry holds.
pub(super) const PROGRAM_RESUME_HELD: &str = "program_resume_held";

const ENTRY_DOMAIN: &[u8] = b"oneiron:engine-executor:pinned-program-entry:v1";

const NO_CHECKPOINT: &str = "the run's record holds calls no resume checkpoint lists";
const CHECKPOINT_BEHIND: &str = "the run's resume checkpoint is not the one its record committed";
const PIN_CHANGED: &str = "the run's resume checkpoint pins another program";
const ROW_MISSING: &str = "a settled call's row is not in the run's record";
const REPLY_MISSING: &str = "a settled wait's reply is not in the run's record";
const DIVERGED: &str = "the pinned source made another call where an earlier entry settled one";
const NESTED_CALLABLE: &str = "a callable the pinned entry calls cannot resume inside it";
const UNREADABLE: &str = "a settled call's row does not decode";
const UNCONSUMED: &str = "the pinned source ended before every call an earlier entry settled";
const PREPARATION_CHANGED: &str = "the run's resume checkpoint pins another preparation";

const FINISHED: &str = "the pinned entry finished";
const WAITING: &str = "the pinned entry waits";
const UNFINISHED: &str = "the pinned entry ended without finishing";

/// One entry of a turn program's code run: the pinned callable and the
/// arguments it was armed with, the revision it is pinned at, and the try
/// that runs it.
pub(crate) struct PinnedProgramEntry {
    pub(crate) code_run: EntityId,
    pub(crate) skill: EntityId,
    pub(crate) args: serde_json::Value,
    pub(crate) content_hash: String,
    pub(crate) contract_digest: [u8; 32],
    pub(crate) executor: String,
    pub(crate) attempt: [u8; 16],
    pub(crate) at: u64,
}

/// How one pinned entry ended.
pub(crate) enum PinnedProgramRun {
    /// It ran and committed: complete (its pinned call answered, finished or
    /// not) or waiting.
    Ran(Box<EngineExecutorOutcome>),
    /// It ran nothing new and committed nothing, for this reason.
    Held(&'static str),
}

/// The calls one pinned entry answers instead of issuing them, in the order
/// the pinned source makes them.
pub(super) struct ProgramInjection {
    /// Whether the entry's own pinned call went by: it is always issued.
    entered: bool,
    calls: VecDeque<SettledCall>,
    /// The calls answered so far, as the entry's checkpoint lists them.
    answered: Vec<ProgramResumeCall>,
    /// Why the entry holds, once a call did not line up.
    held: Option<&'static str>,
}

/// One call an earlier entry settled: its row, as listed, and the delivered
/// reply that answers it when it parked on a wait.
struct SettledCall {
    row: CodeRunBridgeCall,
    listed: ProgramResumeCall,
    reply: Option<serde_json::Value>,
}

/// What the bridge does with one call of a pinned entry.
pub(super) enum InjectedAnswer {
    /// Issue it.
    Live,
    /// Answer it so: an earlier entry settled it.
    Settled {
        outcome: Box<SelfDispatchOutcome>,
        view: Option<serde_json::Value>,
    },
    /// Refuse it, as every call after it: the entry holds.
    Hold,
}

impl ProgramInjection {
    /// The answer for `call`, the next call the pinned source makes. A call
    /// that is not the settled one in its place, a settled row that does not
    /// decode, or a callable called inside the entry holds the entry.
    pub(super) fn answer(&mut self, call: &SelfCall) -> InjectedAnswer {
        if !self.entered {
            self.entered = true;
            return InjectedAnswer::Live;
        }
        if self.held.is_some() {
            return InjectedAnswer::Hold;
        }
        let Some(settled) = self.calls.pop_front() else {
            return InjectedAnswer::Live;
        };
        if matches!(call, SelfCall::SkillsCall(_)) {
            return self.hold(NESTED_CALLABLE);
        }
        let outcome = match settled.row.program_answer_for(call) {
            Ok(Some(outcome)) => outcome,
            Ok(None) => return self.hold(DIVERGED),
            Err(_) => return self.hold(UNREADABLE),
        };
        self.answered.push(settled.listed);
        let Some(reply) = settled.reply else {
            return InjectedAnswer::Settled {
                outcome: Box::new(outcome),
                view: None,
            };
        };
        // The call parked on a wait whose reply is delivered: the reply is
        // its answer, as a verb's output reads.
        InjectedAnswer::Settled {
            view: Some(json!({ "output": reply.clone() })),
            outcome: Box::new(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
                output: reply,
                rows: None,
            })),
        }
    }

    fn hold(&mut self, why: &'static str) -> InjectedAnswer {
        self.held = Some(why);
        InjectedAnswer::Hold
    }

    /// The calls the entry answered, once it ended: a held entry, or one
    /// whose source ended before every settled call, holds instead.
    fn settle(self) -> Result<Vec<ProgramResumeCall>, &'static str> {
        if let Some(held) = self.held {
            return Err(held);
        }
        if !self.calls.is_empty() {
            return Err(UNCONSUMED);
        }
        Ok(self.answered)
    }
}

impl RecordingJsHost<'_, '_> {
    fn with_program_injection(mut self, injection: ProgramInjection) -> Self {
        self.injection = Some(injection);
        self
    }
}

/// A preparation kept for a pinned call: the BLAKE3 (lower-case hex) of the
/// original it was prepared from, and what that original ran as.
type KeptPreparation = (String, TranspiledSource);

/// The runtime a pinned entry lends its pinned call (FIX 8276): the
/// program's own, keeping the call's preparation. A first entry keeps what
/// a TypeScript call ran as; a later one runs the JavaScript the first kept,
/// when the call's original is the one it was prepared from, never a new
/// preparation. A callable the call calls runs on a runtime of its own.
struct PinnedSourceRuntime<'r> {
    runtime: &'r mut dyn JsCodeModeRuntime,
    /// What an earlier entry kept.
    kept: Option<KeptPreparation>,
    /// What this entry's call ran as, when TypeScript.
    ran: Option<KeptPreparation>,
}

impl JsCodeModeRuntime for PinnedSourceRuntime<'_> {
    fn bind_foreign_egress(
        &mut self,
        relay: Arc<dyn oneiron_container::EgressRelay>,
    ) -> crate::Result<()> {
        self.runtime.bind_foreign_egress(relay)
    }

    fn bind_proposal_spool(&mut self, spool: Arc<dyn ProposalSpoolFloor>) {
        self.runtime.bind_proposal_spool(spool);
    }

    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> crate::Result<JsCodeModeStepOutcome> {
        self.run_step_cancellable(step, host, &StepCancellation::never())
    }

    fn run_step_cancellable(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
        cancel: &StepCancellation,
    ) -> crate::Result<JsCodeModeStepOutcome> {
        let prepared = prepare_source(step.script);
        self.run_prepared_step_cancellable(step, &prepared, host, cancel)
    }

    fn run_prepared_step_cancellable(
        &mut self,
        step: JsCodeModeStep<'_>,
        prepared: &PreparedSource<'_>,
        host: &mut dyn JsCodeModeHost,
        cancel: &StepCancellation,
    ) -> crate::Result<JsCodeModeStepOutcome> {
        let reused = self
            .kept
            .take()
            .and_then(|(original, kept)| prepared.reusing(&original, &kept));
        let prepared = reused.as_ref().unwrap_or(prepared);
        if self.ran.is_none()
            && let Some(transpiled) = prepared.transpiled()
        {
            let original = blake3::hash(prepared.original().as_bytes());
            self.ran = Some((original.to_hex().to_string(), transpiled.clone()));
        }
        self.runtime
            .run_prepared_step_cancellable(step, prepared, host, cancel)
    }
}

/// Where a pinned entry starts: the calls it answers, or why it runs
/// nothing new.
enum Settled {
    Calls(VecDeque<SettledCall>),
    Waiting(SelfDurableWait),
    Held(&'static str),
}

impl<'a> EngineNativeExecutor<'a> {
    /// Runs one entry of a turn program's code run (DOOR-141 PR3b): its
    /// pinned callable, from the stored source its pin names, on the
    /// program's own leased attempt and code run, beside `run`. A first
    /// entry runs it from its start. A later one replays it, each call an
    /// earlier entry settled answered from its checkpoint and never issued
    /// again; a wait it parked on resumes only once its reply is delivered.
    /// A run whose pinned call already finished answers complete at once.
    /// The entry commits its rows, its checkpoint and its resume pages in one
    /// transaction; one that does not line up with its checkpoint commits
    /// nothing and answers held.
    ///
    /// # Errors
    ///
    /// A config, seat or storage binding that does not hold; storage; a call
    /// the bridge could not record.
    pub(crate) fn run_pinned_program(
        &mut self,
        config: &EngineExecutorConfig,
        entry: &PinnedProgramEntry,
    ) -> EngineExecutorResult<PinnedProgramRun> {
        self.verify_storage_dispatcher_binding()?;
        config.validate()?;
        self.pinned_seat_holds(config)?;
        crate::skill_reliability::validate_executor(&entry.executor)?;
        if entry.code_run != config.run_id {
            return Err(Error::InvalidConfig(
                "a pinned program entry names another code run".to_owned(),
            )
            .into());
        }
        let vault = self.program_vault()?;
        let (mut record, mut expected) = self.program_record(config)?;
        // A finished pinned call skips its whole interval: its result stands.
        if self.gated_write.pinned_entry_finished(&record) {
            let outcome = self.outcome(EngineExecutorStatus::Complete, 0, record);
            return Ok(PinnedProgramRun::Ran(Box::new(outcome)));
        }
        let tail = load_program_checkpoint_tail(vault, config.run_id)?;
        let preparation = tail.as_ref().and_then(|tail| tail.head.preparation);
        let settled = match self.settled_calls(entry, &mut record, &mut expected, tail)? {
            Settled::Calls(calls) => calls,
            Settled::Waiting(wait) => {
                let outcome = self.outcome(EngineExecutorStatus::Waiting(wait), 0, record);
                return Ok(PinnedProgramRun::Ran(Box::new(outcome)));
            }
            Settled::Held(why) => return Ok(PinnedProgramRun::Held(why)),
        };
        let kept = match preparation {
            Some(identity) => match self.kept_preparation(&record, identity)? {
                Some(kept) => Some(kept),
                None => return Ok(PinnedProgramRun::Held(PREPARATION_CHANGED)),
            },
            None => None,
        };
        self.run_pinned_entry(config, entry, record, expected, settled, kept)
    }

    /// The preparation the program's first entry kept for its pinned call,
    /// when it is the one the checkpoint pins (FIX 8276).
    fn kept_preparation(
        &self,
        record: &CodeRunReplayRecord,
        identity: [u8; 32],
    ) -> EngineExecutorResult<Option<KeptPreparation>> {
        let executed = load_utf8_output(&self.storage, record, &pinned_executed_output_path())?;
        let map = load_utf8_output(&self.storage, record, &pinned_source_map_output_path())?;
        let (original, kept) = TranspiledSource::from_record(executed, map.as_bytes())?;
        Ok((kept.identity() == identity).then_some((original, kept)))
    }

    /// Keeps what a TypeScript pinned call ran as: its executed JavaScript
    /// and map in the code run's record, once, by the first entry, and their
    /// identity for the checkpoint and its resume head (FIX 8276).
    fn keep_preparation(
        &self,
        record: &mut CodeRunReplayRecord,
        ran: Option<KeptPreparation>,
    ) -> EngineExecutorResult<Option<[u8; 32]>> {
        let Some((original, transpiled)) = ran else {
            return Ok(None);
        };
        let executed = pinned_executed_output_path();
        if !record.outputs.iter().any(|output| output.path == executed) {
            record_script_output(&self.storage, record, executed, transpiled.executed_js())?;
            let map = transpiled.record_json_for_digest(&original)?;
            record_output(&self.storage, record, pinned_source_map_output_path(), &map)?;
        }
        Ok(Some(transpiled.identity()))
    }

    /// The pinned entry's seat, when it has one, is its config's.
    fn pinned_seat_holds(&self, config: &EngineExecutorConfig) -> EngineExecutorResult<()> {
        if let Some(seat) = self.seat
            && (&config.model != seat.model()
                || config.model_locality != seat.locality()
                || config.seat_effort != Some(seat.effort()))
        {
            return Err(
                Error::InvalidConfig("executor seat and run config disagree".into()).into(),
            );
        }
        Ok(())
    }

    /// A turn program runs on its vault's own storage, never a room's.
    fn program_vault(&self) -> EngineExecutorResult<&'a Vault> {
        match &self.storage {
            ExecutorStorage::Canonical(vault) => Ok(*vault),
            _ => Err(Error::InvalidConfig(
                "a turn program runs on its vault's own storage".to_owned(),
            )
            .into()),
        }
    }

    /// The program's code run record, or a new one its first entry puts.
    fn program_record(
        &self,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<(CodeRunReplayRecord, Option<CodeRunReplayGeneration>)> {
        if let Some(record) = self.storage.get_code_run_replay_record(&config.run_id)? {
            if record.determinism != config.determinism {
                return Err(Error::InvalidConfig(
                    "a turn program's code run holds another determinism".to_owned(),
                )
                .into());
            }
            let generation = record.generation()?;
            return Ok((record, Some(generation)));
        }
        let record = CodeRunReplayRecord::new(config.run_id, config.determinism);
        // The program's replies are its actor's (FIX 5718).
        let actor = self.gated_write.actor().entity_ref();
        let generation =
            self.storage
                .put_owned_code_run_replay_record(&record, None, config.run_id, actor)?;
        Ok((record, Some(generation)))
    }

    /// The calls a resumed entry answers: each one its checkpoint lists, by
    /// the row that settled it, then the call its last entry parked on once
    /// that wait's reply is delivered (resumed into the record here, its
    /// consent consumed as any resumed wait's is).
    fn settled_calls(
        &mut self,
        entry: &PinnedProgramEntry,
        record: &mut CodeRunReplayRecord,
        expected: &mut Option<CodeRunReplayGeneration>,
        tail: Option<ProgramCheckpointTail>,
    ) -> EngineExecutorResult<Settled> {
        let Some(ProgramCheckpointTail { head, calls }) = tail else {
            return Ok(if record.bridge_calls.is_empty() {
                Settled::Calls(VecDeque::new())
            } else {
                Settled::Held(NO_CHECKPOINT)
            });
        };
        if Some(head.bridge_calls) != u64::try_from(record.bridge_calls.len()).ok()
            || head.state_hash != previous_state_hash(record)
        {
            return Ok(Settled::Held(CHECKPOINT_BEHIND));
        }
        if head.skill != entry.skill
            || head.content_hash != entry.content_hash
            || head.contract_digest != entry.contract_digest
        {
            return Ok(Settled::Held(PIN_CHANGED));
        }
        let mut settled = VecDeque::with_capacity(calls.len() + 1);
        for listed in calls {
            let Some(row) = row_at(record, listed.row).cloned() else {
                return Ok(Settled::Held(ROW_MISSING));
            };
            let reply = match listed.reply {
                Some(wait_id) => match delivered_reply(&self.storage, record, wait_id)? {
                    Some(reply) => Some(reply),
                    None => return Ok(Settled::Held(REPLY_MISSING)),
                },
                None => None,
            };
            settled.push_back(SettledCall { row, listed, reply });
        }
        let Some(wait) = head.wait else {
            return Ok(Settled::Calls(settled));
        };
        let Some(row) = row_at(record, wait.row).cloned() else {
            return Ok(Settled::Held(ROW_MISSING));
        };
        let Some(parked) = row.program_durable_wait()? else {
            return Ok(Settled::Held(ROW_MISSING));
        };
        let reply = match delivered_reply(&self.storage, record, parked.wait_id)? {
            Some(reply) => reply,
            None => {
                let key = wait_key(record, &parked);
                verify_code_consent_park(&self.storage, record, &key)?;
                if !self.storage.park_wait(&key)? {
                    return Ok(Settled::Waiting(parked));
                }
                let Some(generation) =
                    self.resume_delivered_wait(record, &parked, &key, *expected)?
                else {
                    return Ok(Settled::Waiting(parked));
                };
                *expected = Some(generation);
                delivered_reply(&self.storage, record, parked.wait_id)?
                    .ok_or(Error::CorruptedIndex("a resumed wait's reply"))?
            }
        };
        // A wait of the pinned call's own (its hooks' ask) is answered by
        // making the call again; a wait inside it answers the call that
        // parked.
        if wait.row != head.entry_start {
            let listed = program_resume_call(&row, Some(parked.wait_id))?;
            settled.push_back(SettledCall {
                row,
                listed,
                reply: Some(reply),
            });
        }
        Ok(Settled::Calls(settled))
    }

    /// Runs the pinned call once, `settled` answered in its place, and
    /// commits what it did.
    fn run_pinned_entry(
        &mut self,
        config: &EngineExecutorConfig,
        entry: &PinnedProgramEntry,
        mut record: CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        settled: VecDeque<SettledCall>,
        kept: Option<KeptPreparation>,
    ) -> EngineExecutorResult<PinnedProgramRun> {
        // The entry's root (FIX 600): a hard queue control that committed for
        // the program's try stops it.
        let root = self.attempt_root();
        let cancel = root.token();
        cancel.check()?;
        let bridge_start = record.bridge_calls.len();
        let entry_start = u64::try_from(bridge_start)
            .map_err(|_| Error::ArithmeticOverflow("pinned entry position"))?;
        self.gated_write
            .observe_bridge_history(&record.bridge_calls);
        let recoverable = self.observation_refs(&record)?;
        let injection = ProgramInjection {
            entered: false,
            calls: settled,
            answered: Vec::new(),
            held: None,
        };
        let mut host = RecordingJsHost::new(
            self.gated_write,
            config.run_id,
            entry_start,
            config.determinism,
            self.legibility,
        )
        .with_recoverable_outputs(&self.storage, &record, recoverable)?
        .with_skill_executor(&config.model)
        .with_program_injection(injection);
        let pinned = SelfCall::SkillsCall(SelfSkillCall {
            skill: entry.skill,
            args: entry.args.clone(),
        });
        // A kept preparation stays pinned through an entry whose call did
        // not reach its step.
        let pinned_preparation = kept.as_ref().map(|(_, kept)| kept.identity());
        let mut lent = PinnedSourceRuntime {
            runtime: &mut *self.runtime,
            kept,
            ran: None,
        };
        let response = host.dispatch_self_nested_cancellable(pinned, &mut lent, cancel)?;
        let ran = lent.ran;
        let failure = host.hard_failure.take();
        let answered = match host.injection.take().map(ProgramInjection::settle) {
            Some(Ok(answered)) => answered,
            Some(Err(why)) => return Ok(PinnedProgramRun::Held(why)),
            None => {
                return Err(Error::InvariantViolation("a pinned entry lost its injection").into());
            }
        };
        if let Some(failure) = &failure {
            tracing::warn!(
                kind = ?failure.kind(),
                "a turn program's pinned entry stopped on a failed call; it ends unfinished"
            );
        }
        let finished = matches!(
            &response.outcome,
            SelfDispatchOutcome::SkillCall(result) if result.skill == entry.skill
        );
        // A pinned call that finished is the program's result, whatever wait
        // its source reached on the way.
        let wait = host.durable_wait.take().filter(|_| !finished);
        self.gated_write.refuse_a_step_that_dropped_a_write(
            config.run_id,
            entry_start,
            &host.bridge_calls,
        )?;
        // The settled calls in the source's order: those answered, then the
        // entry's own, up to the call that parked.
        let injected = u64::try_from(answered.len())
            .map_err(|_| Error::ArithmeticOverflow("pinned entry calls"))?;
        let mut calls = answered;
        let mut parked_row = None;
        for row in host
            .bridge_calls
            .iter()
            .filter(|row| row.seq != entry_start)
        {
            if row.program_durable_wait()?.is_some() {
                parked_row = Some(row.seq);
                break;
            }
            calls.push(program_resume_call(row, None)?);
        }
        record.bridge_calls.extend(host.bridge_calls);
        record.outputs.extend(host.captured);
        let bindings: Vec<(String, String)> = host
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
        let status = wait.clone().map_or(
            EngineExecutorStatus::Complete,
            EngineExecutorStatus::Waiting,
        );
        let observation = if finished {
            FINISHED
        } else if wait.is_some() {
            WAITING
        } else {
            UNFINISHED
        };
        let seq = completed_step_count(&record)?;
        record_text_output(
            &self.storage,
            &mut record,
            observation_output_path(seq),
            observation,
        )?;
        record_terminal_output(&self.storage, &mut record, seq, &status)?;
        let preparation = self
            .keep_preparation(&mut record, ran)?
            .or(pinned_preparation);
        let script = format!("pinned:{}@{}", entry.skill.to_hex(), entry.content_hash);
        let state_hash = prepared_step_state_hash(
            previous_state_hash(&record),
            seq,
            &entry_digest(entry)?,
            &script,
            preparation.as_ref(),
            &StepResultDigests {
                observation: *blake3::hash(observation.as_bytes()).as_bytes(),
                done: finished,
                outputs: Vec::new(),
                bindings,
            },
            None,
            &record.bridge_calls[bridge_start..],
        )?;
        record.step_checkpoints.push(CodeRunStepCheckpoint::new(
            seq,
            checkpoint_label(seq),
            state_hash,
            config.determinism.frozen_unix_ms.saturating_add(seq),
        )?);
        let parked = parked_wait(&record, Some(&status), bridge_start);
        let resume = ProgramResumeCommit {
            attempt: entry.attempt,
            skill: entry.skill,
            content_hash: entry.content_hash.clone(),
            contract_digest: entry.contract_digest,
            entry_start,
            calls,
            injected,
            wait: parked.as_ref().map(|parked| ProgramResumeWait {
                row: parked_row.unwrap_or(entry_start),
                wait_id: parked.key.wait_id,
                generation: parked.key.generation,
            }),
            at: entry.at,
            preparation,
        };
        self.storage.put_program_entry_replay_record(
            &record,
            expected,
            &host.receipts,
            parked.as_ref(),
            &resume,
        )?;
        if let Some(wait) = &wait {
            // Registered as parked, so the reply that settles the wait finds
            // the run; its resume is the program's resumer's.
            let _delivered = self.park(&record, wait)?;
        }
        Ok(PinnedProgramRun::Ran(Box::new(
            self.outcome(status, 1, record),
        )))
    }
}

/// The row of `record` at `seq`.
fn row_at(record: &CodeRunReplayRecord, seq: u64) -> Option<&CodeRunBridgeCall> {
    record
        .bridge_calls
        .get(usize::try_from(seq).ok()?)
        .filter(|row| row.seq == seq)
}

/// The reply `wait_id`'s wait was resumed with, as the record keeps it. Once
/// an erase of the run's actor took its replies, a typed unavailable, never
/// the kept bytes and never none (FIX 5718).
fn delivered_reply(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    wait_id: EntityId,
) -> EngineExecutorResult<Option<serde_json::Value>> {
    if storage.code_run_response_erased(record.run_id)? {
        return Err(crate::code_run::response_erased_error("a resumed wait's reply").into());
    }
    let wanted = wait_id.to_hex();
    let Some(output) = record
        .outputs
        .iter()
        .filter(|output| resumed_output_wait(&output.path).is_some_and(|(_, wait)| wait == wanted))
        .max_by(|left, right| left.path.cmp(&right.path))
    else {
        return Ok(None);
    };
    let text = load_utf8_output(storage, record, &output.path)?;
    let Ok(serde_json::Value::Object(mut resumed)) =
        serde_json::from_str::<serde_json::Value>(&text)
    else {
        return Err(Error::CorruptedIndex("a resumed wait's reply").into());
    };
    Ok(resumed.remove("reply"))
}

/// The digest of what one pinned entry runs: its SKILL, revision, contract
/// and arguments.
fn entry_digest(entry: &PinnedProgramEntry) -> EngineExecutorResult<[u8; 32]> {
    let args = serde_json::to_vec(&entry.args).map_err(|_| {
        Error::InvalidConfig("a pinned program's arguments do not encode".to_owned())
    })?;
    Ok(*blake3::Hasher::new()
        .update(ENTRY_DOMAIN)
        .update(entry.skill.as_bytes())
        .update(entry.content_hash.as_bytes())
        .update(&entry.contract_digest)
        .update(&args)
        .finalize()
        .as_bytes())
}
