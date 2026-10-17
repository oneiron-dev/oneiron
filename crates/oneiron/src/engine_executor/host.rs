//! JS host bridge: recording dispatcher, sandbox contract, and prompt sites.

use super::store::{
    ByteCount, ObservationRef, RECOVERABLE_OUTPUT_CHUNK_BYTES, RESULT_READ_ROOT,
    RESULT_REPLY_INLINE_BYTES, StreamedOutputs, bridge_result_output_path, is_result_output_path,
    recoverable_output_path, result_handle_json, result_read_path, store_result_output_path,
    write_json,
};
use super::types::{
    EngineExecutorResult, ExecutorLegibility, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStream,
    JsResultCall, JsResultRef, JsResultTarget, SelfDispatchResponse,
};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, DelegatedSource, ExecutorCallSite, ExecutorStorage, GatedActorWrite,
    ReaderFindingRef, ResultFacet, ResultRead, ResultReply, RunCall, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDurableWait, SelfEffect, SelfFailedResult, SelfReaderReportCall,
    SelfReaderSpawnCall, SelfSkillCall, SelfSkillCallResult, agent_verb_rows_of, result_cannot,
    result_card, result_refusal,
};
use crate::code_sandbox::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_WIT_WORLD_NAME, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier,
};
use crate::compaction::output::OutputRef;
use crate::dreamer_wake::BudgetLegibilityEnvelope;
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::store::BodySink;
use crate::{Error, Result};
use serde_json::json;

pub(super) struct RecordingJsHost<'a, 's> {
    gated_write: &'a GatedActorWrite<'a>,
    run_id: EntityId,
    step_start: u64,
    next_seq: u64,
    determinism: CodeRunDeterminism,
    legibility: Option<ExecutorLegibility<'a>>,
    storage: Option<&'s ExecutorStorage<'a>>,
    recoverable: Vec<(u64, CodeRunRawOutput, OutputRef)>,
    /// The step's result as the guest streams it, written into the run's
    /// body store frame by frame.
    streamed: StreamedOutputs,
    /// The run's earlier results stored as bodies (bridge results and
    /// stored values), which the guest may read back.
    results: Vec<CodeRunRawOutput>,
    /// This step's results stored as bodies, for the record.
    pub(super) captured: Vec<CodeRunRawOutput>,
    /// The run's result names, as its record holds them.
    bindings: Vec<CodeRunResultBinding>,
    /// The names this step bound or rebound, in order, for the record.
    pub(super) bound: Vec<CodeRunResultBinding>,
    /// The rows the run's recorded verb answers were served from, `None`
    /// when one kept no set (DEC-0005).
    recorded_rows: Option<Vec<EntityId>>,
    pub(super) bridge_calls: Vec<CodeRunBridgeCall>,
    pub(super) durable_wait: Option<SelfDurableWait>,
    /// First hard bridge failure (gate rejection or failed audited write).
    /// The guest received a typed `Denied`/`Failed` RESPONSE for it (budget
    /// attached); the executor fails the step with this error AFTER the
    /// step returns, and later calls and recorded-output reads in the step
    /// are refused fail-closed.
    pub(super) hard_failure: Option<Error>,
    /// Whether a call failed with no response the bridge could record. Its
    /// bridge position keeps no row, so no later row can checkpoint; later
    /// calls and recorded-output reads in the step are refused as after a
    /// hard failure.
    left_a_gap: bool,
    /// The TASK the agent's own refusal declined in this step (OF-533). The
    /// run does nothing more for it: later calls and recorded-output reads
    /// are refused, and the step closes the run.
    pub(super) declined: Option<EntityId>,
    /// The run's executor, `provider/name@revision`, as the callable skills
    /// its program calls are credited to (OF-353).
    skill_executor: Option<String>,
}

/// The name a reader child reads its parent's source by.
const READER_SOURCE_NAME: &str = "src";

/// A result a reference names for this run: one of its own, the source a
/// reader child reads in its parent's record, or a finding of one of the
/// run's children in that child's.
struct ResolvedResult {
    output: CodeRunRawOutput,
    name: Option<String>,
    /// The run whose occurrence of it a read's taint is read in.
    owner: EntityId,
    /// The rows a read of it is withheld by beside the run's own, when it is
    /// not the run's: `Some(None)` when they are not known.
    rows: Option<Option<Vec<EntityId>>>,
    /// The range of its body a read of it must stay inside, and reads by
    /// default, in the owner's offsets.
    within: Option<(u64, u64)>,
    /// Whether a read of it re-checks that the reader child's job is live.
    child_source: bool,
}

impl<'a, 's> RecordingJsHost<'a, 's> {
    pub(super) fn new(
        gated_write: &'a GatedActorWrite<'a>,
        run_id: EntityId,
        next_seq: u64,
        determinism: CodeRunDeterminism,
        legibility: Option<ExecutorLegibility<'a>>,
    ) -> Self {
        Self {
            gated_write,
            run_id,
            step_start: next_seq,
            next_seq,
            determinism,
            legibility,
            storage: None,
            recoverable: Vec::new(),
            streamed: StreamedOutputs::default(),
            results: Vec::new(),
            captured: Vec::new(),
            bindings: Vec::new(),
            bound: Vec::new(),
            recorded_rows: Some(Vec::new()),
            bridge_calls: Vec::new(),
            durable_wait: None,
            hard_failure: None,
            left_a_gap: false,
            declined: None,
            skill_executor: None,
        }
    }

    /// Names the run's executor, as the callable skills its program calls
    /// are credited to (OF-353).
    pub(super) fn with_skill_executor(mut self, executor: &crate::ModelId) -> Self {
        self.skill_executor = Some(executor.as_str().to_owned());
        self
    }

    /// Bind only committed observations from the current run to the linked
    /// file-read import. A guest cannot turn a hash into another run's output.
    /// Each reference is its body's manifest digest and length.
    pub(super) fn with_recoverable_outputs(
        mut self,
        storage: &'s ExecutorStorage<'a>,
        record: &CodeRunReplayRecord,
        observations: Vec<(u64, CodeRunRawOutput, ObservationRef)>,
    ) -> EngineExecutorResult<Self> {
        if record.run_id != self.run_id {
            return Err(Error::InvalidConfig("executor output run mismatch".into()).into());
        }
        self.recoverable = observations
            .into_iter()
            .map(|(seq, output, observation)| (seq, output, observation.source))
            .collect();
        self.results = record
            .outputs
            .iter()
            .filter(|output| is_result_output_path(&output.path))
            .cloned()
            .collect();
        self.bindings = record.bindings.clone();
        self.recorded_rows = record.agent_verb_rows();
        self.storage = Some(storage);
        Ok(self)
    }

    /// A verb's or a callable skill's answer too large for one reply, stored
    /// whole as a body of the run as it is encoded. The guest and the replay
    /// row get its handle (`result_handle_json`), never the answer; nothing is
    /// refused for size.
    fn store_large_answer(
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
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let mut sink = storage.code_run_output_sink()?;
        write_json(&mut sink, &*answer)?;
        let output = storage.publish_code_run_output(
            bridge_result_output_path(seq),
            sink,
            true,
            self.run_id,
        )?;
        let name = self.next_auto_name();
        self.bind(name.clone(), output.handle.clone());
        *answer = result_handle_json(&output);
        answer["name"] = json!(name);
        self.captured.push(output);
        Ok(outcome)
    }

    /// `self.skills.call` (OF-353): an agent-callable skill run as a step of
    /// its own, on the sibling runtime the caller's step lent, under the
    /// running attempt's lease, with this host as its bridge. The skill's own
    /// calls are gated and recorded as the run's, at the positions after this
    /// one's. A skill that fails answers a typed failure the program reads;
    /// a halt or a declined TASK among its calls is this call's answer too.
    fn call_skill(
        &mut self,
        seq: u64,
        started_at_ms: u64,
        call: &SelfCall,
        skill: SelfSkillCall,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |error: String| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::SkillsCall,
                error,
            })
        };
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
        let (skill, hooked) = match self.gated_write.enter_verb_hooks(
            SelfCall::SkillsCall(skill),
            Some(site),
            lease.read_as.clone(),
        )? {
            Ok((SelfCall::SkillsCall(skill), hooked)) => (skill, hooked),
            Ok(_) => {
                return Err(Error::InvariantViolation(
                    "a skill call's hooks rewrote it into another call",
                ));
            }
            Err(stopped) => return Ok(stopped),
        };
        let Some(executor) = self.skill_executor.clone() else {
            return Ok(failed("skills_call_no_executor".to_owned()));
        };
        let (run_id, determinism) = (self.run_id, self.determinism);
        let ran = crate::skill::execute_callable_skill(
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
        );
        if self.hard_failure.is_some() || self.left_a_gap {
            return Ok(failed("host_bridge_halted".to_owned()));
        }
        if self.declined.is_some() {
            return Ok(failed("task_declined".to_owned()));
        }
        let output = ran.and_then(|step| {
            serde_json::from_str::<serde_json::Value>(&step.observation).map_err(|_| {
                Error::InvalidConfig("callable skill returned non-JSON output".to_owned())
            })
        });
        let outcome = match output {
            Ok(output) => SelfDispatchOutcome::SkillCall(SelfSkillCallResult {
                skill: skill.skill,
                output,
            }),
            Err(error) => failed(error.to_string()),
        };
        // The post chain reads the answer as the guest gets it: a large one
        // by its handle.
        let outcome = self.store_large_answer(seq, outcome)?;
        self.gated_write.leave_verb_hooks(hooked, outcome)
    }

    /// One `self.*` call over the bridge. `runtime` is the sibling a call
    /// that runs a step of its own runs it on, when the caller's runtime
    /// lent one ([`JsCodeModeHost::dispatch_self_nested`]).
    fn dispatch_call(
        &mut self,
        call: SelfCall,
        runtime: Option<&mut dyn JsCodeModeRuntime>,
    ) -> Result<SelfDispatchResponse> {
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
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        // This call's row keeps its own position: a callable skill's calls
        // take the positions after it, and their rows land first.
        let place = self.bridge_calls.len();
        let dispatched = match (&call, runtime) {
            (SelfCall::SkillsCall(skill), Some(runtime)) => {
                let skill = skill.clone();
                self.call_skill(seq, started_at_ms, &call, skill, runtime)
            }
            (SelfCall::ReaderSpawn(spawn), _) => {
                let spawn = (**spawn).clone();
                self.spawn_reader(seq, spawn)
            }
            (SelfCall::ReaderReport(report), _) => {
                let report = report.clone();
                self.report_finding(seq, report)
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
                )?;
                self.bridge_calls.insert(place, row);
                self.hard_failure = Some(err);
                return Ok(self.respond(error_outcome, None));
            }
        };
        let finished_at_ms = started_at_ms;
        let row = CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, finished_at_ms)?;
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

    /// The run's live result names, oldest first: this step's binds over
    /// the record's.
    fn live_bindings(&self) -> Vec<&CodeRunResultBinding> {
        let mut live: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| !self.bound.iter().any(|held| held.name == binding.name))
            .collect();
        live.extend(&self.bound);
        live
    }

    /// The next free automatic name: `r<n>`, counting from one past the
    /// live names, past any name taken.
    fn next_auto_name(&self) -> String {
        let live = self.live_bindings();
        (live.len() + 1..)
            .map(|n| format!("r{n}"))
            .find(|name| !live.iter().any(|binding| binding.name == *name))
            .unwrap_or_default()
    }

    /// Binds `name` to the result `handle` for the record; a rebind replaces
    /// the name's entry in place.
    fn bind(&mut self, name: String, handle: String) {
        let binding = CodeRunResultBinding::new(name, handle);
        match self.bound.iter_mut().find(|held| held.name == binding.name) {
            Some(held) => *held = binding,
            None => self.bound.push(binding),
        }
    }

    /// The run's result a reference names, and the live name bound to it.
    /// Only this run's results resolve: a handle names nothing else.
    fn resolve_result(
        &self,
        reference: &JsResultRef,
    ) -> Option<(CodeRunRawOutput, Option<String>)> {
        crate::code_run::resolve_result(
            self.results.iter().chain(&self.captured),
            &self.live_bindings(),
            reference,
        )
    }

    /// The refusal for a reference to no result of this run, with the live
    /// names it could have meant.
    fn unknown_handle(&self) -> serde_json::Value {
        crate::code_run::unknown_handle(&self.live_bindings())
    }

    /// The rows the run's results were served from: the conservative union
    /// of every row its recorded and this step's verb answers were served
    /// from, or none known when one answer kept no set.
    fn result_rows(&self) -> Option<Vec<EntityId>> {
        self.recorded_rows
            .as_ref()
            .zip(agent_verb_rows_of(&self.bridge_calls))
            .map(|(recorded, step)| [recorded.as_slice(), step.as_slice()].concat())
    }

    /// Whether the run's results stay on this device for its door's caller
    /// now (DEC-0005), by [`Self::result_rows`].
    fn withholds_results(&self) -> Result<bool> {
        self.withholds_rows(self.result_rows())
    }

    /// Whether a result served from `rows` stays on this device for the
    /// door's caller now.
    fn withholds_rows(&self, rows: Option<Vec<EntityId>>) -> Result<bool> {
        self.gated_write
            .withholds_retained(rows.as_deref())
            .map_err(|refusal| {
                Error::InvalidConfig(format!("stored result read refused: {}", refusal.code))
            })
    }

    /// `store(value, name?)`: the value the program just streamed, stored as
    /// a result of the run and bound to a name. Not gated: the value is the
    /// run's own, as a file it writes is. A halted bridge, or a run whose
    /// TASK was declined, stores nothing.
    fn store_result(&mut self, name: Option<String>) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let sink = self
            .streamed
            .take_store()
            .ok_or(Error::InvalidConfig("store sent no body".into()))?;
        if self.hard_failure.is_some() || self.left_a_gap {
            return Ok(result_refusal("host_bridge_halted"));
        }
        if self.declined.is_some() {
            return Ok(result_refusal("task_declined"));
        }
        if name
            .as_deref()
            .is_some_and(|name| !CodeRunResultBinding::is_valid_name(name))
        {
            return Ok(result_refusal("invalid_result_name"));
        }
        Ok(json!({"output": self.bind_stored(storage, sink, name)?}))
    }

    /// Publishes the body `sink` wrote as a stored value of the run, named
    /// by its digest, and binds it to `name`, or to the next free `r<n>`:
    /// its card. The same bytes stored twice are one output.
    fn bind_stored(
        &mut self,
        storage: &ExecutorStorage<'_>,
        sink: BodySink,
        name: Option<String>,
    ) -> Result<serde_json::Value> {
        let path = store_result_output_path(&sink.digest()?);
        let output = storage.publish_code_run_output(path, sink, true, self.run_id)?;
        if !self
            .results
            .iter()
            .chain(&self.captured)
            .any(|held| held.path == output.path)
        {
            self.captured.push(output.clone());
        }
        let name = name.unwrap_or_else(|| self.next_auto_name());
        self.bind(name.clone(), output.handle.clone());
        result_card(storage, self.run_id, &output, Some(name.as_str()))
    }

    /// The result `target` names, read as every read of a result is:
    /// resolved for this run, admitted as a read of its recorded outputs, and
    /// its rows and its taint checked now. A refusal is the reply the guest
    /// gets in its place.
    ///
    /// A reader child also reads its parent's source, as `src` or by its
    /// handle, inside the range its parent delegated, while its job is live;
    /// a parent also reads its children's settled findings by their handles.
    /// Any other handle names nothing: a guessed handle grants nothing.
    fn checked_result(
        &mut self,
        target: &JsResultTarget,
    ) -> Result<std::result::Result<ResultRead, serde_json::Value>> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let Some(found) = self.resolve_for_read(storage, &target.reference)? else {
            return Ok(Err(self.unknown_handle()));
        };
        if let (Some((start, end)), Some((from, to))) = (found.within, target.range)
            && (from < start || to > end)
        {
            return Ok(Err(result_refusal("outside_delegated_range")));
        }
        if found.child_source && !self.gated_write.reader_job_live()? {
            return Ok(Err(result_refusal("reader_task_settled")));
        }
        self.admit_result_read(storage)?;
        let rows = match found.rows {
            None => self.result_rows(),
            Some(extra) => self
                .result_rows()
                .zip(extra)
                .map(|(run, extra)| [run, extra].concat()),
        };
        if self.withholds_rows(rows)? {
            return Ok(Err(result_refusal("result_withheld")));
        }
        let whole = found
            .within
            .is_some_and(|range| range == (0, found.output.raw_len));
        let range = target.range.or(found.within.filter(|_| !whole));
        ResultRead::new(storage, found.owner, found.output, found.name, range)
    }

    /// What `reference` names for a read by this run: its own result first,
    /// then a reader child's source, then a finding of one of its children.
    fn resolve_for_read(
        &self,
        storage: &ExecutorStorage<'_>,
        reference: &JsResultRef,
    ) -> Result<Option<ResolvedResult>> {
        if let Some((output, name)) = self.resolve_result(reference) {
            return Ok(Some(ResolvedResult {
                output,
                name,
                owner: self.run_id,
                rows: None,
                within: None,
                child_source: false,
            }));
        }
        if let Some(child) = self.gated_write.reader_child() {
            let source = &child.source;
            let names_source = match reference {
                JsResultRef::Name(name) => name == READER_SOURCE_NAME,
                JsResultRef::Handle(handle) => *handle == source.handle,
            };
            if !names_source {
                return Ok(None);
            }
            let Some(output) =
                recorded_output(storage, source.owner, &source.path, &source.handle)?
            else {
                return Ok(None);
            };
            return Ok(Some(ResolvedResult {
                output,
                name: Some(READER_SOURCE_NAME.to_owned()),
                owner: source.owner,
                rows: Some(source.rows.clone()),
                within: Some(source.range),
                child_source: true,
            }));
        }
        let JsResultRef::Handle(handle) = reference else {
            return Ok(None);
        };
        let Some(finding) = storage
            .reader_finding(self.run_id, handle)?
            .and_then(|job| job.finding)
        else {
            return Ok(None);
        };
        let Some(output) = recorded_output(storage, finding.owner, &finding.path, &finding.handle)?
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedResult {
            output,
            name: None,
            owner: finding.owner,
            rows: Some(finding.rows),
            within: None,
            child_source: false,
        }))
    }

    /// The source of a `self.spawn`: one of this run's own results, read as
    /// every read of it is, its range the ref's or the whole body. A source
    /// the run may not read now is refused as that read would be.
    fn delegate_source(
        &mut self,
        source: &str,
    ) -> Result<std::result::Result<DelegatedSource, String>> {
        let target = JsResultTarget::parse(source);
        if self.resolve_result(&target.reference).is_none() {
            return Ok(Err("unknown_handle".to_owned()));
        }
        let read = match self.checked_result(&target)? {
            Ok(read) => read,
            Err(refused) => {
                let code = refused
                    .get("denied")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("denied");
                return Ok(Err(code.to_owned()));
            }
        };
        if read.is_tainted() {
            return Ok(Err("tainted".to_owned()));
        }
        let output = read.output();
        Ok(Ok(DelegatedSource {
            owner: self.run_id,
            path: output.path.clone(),
            handle: output.handle.clone(),
            range: read.range().unwrap_or((0, output.raw_len)),
            rows: self.result_rows(),
        }))
    }

    /// `self.spawn(...)`: the source resolved in this run, then the spawn
    /// dispatched with it bound; the run's record keeps the guest's call. A
    /// reader child's spawn goes straight to its refusal.
    fn spawn_reader(
        &mut self,
        seq: u64,
        mut spawn: SelfReaderSpawnCall,
    ) -> Result<SelfDispatchOutcome> {
        if self.gated_write.reader_child().is_none() {
            match self.delegate_source(&spawn.source)? {
                Ok(source) => spawn.bound = Some(source),
                Err(reason) => {
                    return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                        effect: SelfEffect::ReaderSpawn,
                        outcome: reason,
                        reason_codes: Vec::new(),
                    }));
                }
            }
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        self.gated_write
            .dispatch_for_executor_run(site, SelfCall::ReaderSpawn(Box::new(spawn)))
    }

    /// A reader child's `tasks.update({task_ref, resultRef})`: its finding
    /// resolved among its own results only, a whole stored JSON value, then
    /// the report dispatched with it bound. Its parent's source is not its
    /// own and is refused.
    fn report_finding(
        &mut self,
        seq: u64,
        mut report: SelfReaderReportCall,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::ReaderReport,
                error: code.to_owned(),
            })
        };
        if self.gated_write.reader_child().is_some() {
            let storage = self.storage.ok_or(Error::InvalidConfig(
                "executor result storage unavailable".into(),
            ))?;
            let target = JsResultTarget::parse(&report.result_ref);
            let Some((output, _)) = self
                .resolve_result(&target.reference)
                .filter(|_| target.range.is_none())
            else {
                return Ok(failed("finding_not_own"));
            };
            let card = result_card(storage, self.run_id, &output, None)?;
            if card["taint"]["state"] != "clean" {
                return Ok(failed("finding_tainted"));
            }
            if card["shape"]["format"] != "json" {
                return Ok(failed("finding_not_json"));
            }
            report.bound = Some(ReaderFindingRef {
                owner: self.run_id,
                path: output.path,
                handle: output.handle,
                bytes: output.raw_len,
                rows: self.result_rows(),
            });
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        self.gated_write
            .dispatch_for_executor_run(site, SelfCall::ReaderReport(report))
    }

    /// `describe(r)`: the card of one of the run's results, or of a range
    /// of one.
    fn describe_result(&mut self, target: &JsResultTarget) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        Ok(match self.checked_result(target)? {
            Ok(read) => json!({"output": read.card(storage)?}),
            Err(refused) => refused,
        })
    }

    /// `can({read: r})`: the verdict of the checks a read of `target` makes
    /// (resolved in this run, admitted as a read of its recorded outputs,
    /// its rows and its taint), for this run as the reader, with no preview
    /// and no byte of the body. A refused admission halts the bridge as a
    /// read's does.
    ///
    /// With `child`, a readable result is also checked as a spawn's source
    /// would be, writing nothing: the run's own result, then the seat, the
    /// clock and the scope. The verdict names the children's cutoff and what
    /// their scope may still spend, or why a spawn would be refused.
    fn can_read_result(
        &mut self,
        target: &JsResultTarget,
        child: bool,
    ) -> Result<serde_json::Value> {
        let mut verdict = match self.checked_result(target)? {
            Ok(read) => read.preflight(),
            Err(refused) => result_cannot(refused),
        };
        if !child || verdict["can"] != json!(true) {
            return Ok(json!({"output": verdict}));
        }
        if self.resolve_result(&target.reference).is_none() {
            return Ok(json!({"output": {"can": false, "reason": "unknown_handle"}}));
        }
        match self
            .gated_write
            .preflight_reader_spawn(self.run_id, crate::unix_millis_now())?
        {
            Ok((cutoff, available)) => {
                verdict["child"] = json!({
                    "cutoff_unix_ms": cutoff,
                    "spend_available_units": available,
                });
            }
            Err(reason) => verdict = json!({"can": false, "reason": reason}),
        }
        Ok(json!({"output": verdict}))
    }

    /// One facet of one of the run's results, checked as `describe` is. A
    /// query whose selection is past one reply is stored as a new result of
    /// the run, as `store` stores a value, and answered by its card. It is
    /// read only from a clean body, and its own bytes are scanned for
    /// secrets as they are stored.
    fn read_result(
        &mut self,
        target: &JsResultTarget,
        facet: ResultFacet,
        input: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let read = match self.checked_result(target)? {
            Ok(read) => read,
            Err(refused) => return Ok(refused),
        };
        let mut sink = match facet {
            ResultFacet::Query => Some(storage.code_run_output_sink()?),
            _ => None,
        };
        Ok(match read.read(storage, facet, input, sink.as_mut())? {
            ResultReply::Output(output) => json!({"output": output}),
            ResultReply::Denied(refused) => refused,
            ResultReply::Spilled { count, next } => {
                let sink = sink.ok_or(Error::InvariantViolation(
                    "a result read spilled with no sink",
                ))?;
                let card = self.bind_stored(storage, sink, None)?;
                let mut output = json!({"derived": card, "count": count, "done": next.is_none()});
                if let Some(next) = next {
                    output["next"] = next;
                }
                json!({"output": output})
            }
        })
    }

    /// One chunk of a stored result of this run, read by range, while the
    /// rows it was served from may reach the door's caller.
    fn read_stored_result(
        &self,
        storage: &ExecutorStorage<'_>,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        if self.withholds_results()? {
            return Err(Error::InvalidConfig(
                "stored result read refused: result_withheld".into(),
            ));
        }
        for output in self.results.iter().chain(&self.captured) {
            let base = result_read_path(output.output_ref());
            let Some(offset) = path.strip_prefix(&format!("{base}/chunk/")) else {
                continue;
            };
            let offset = offset
                .parse::<u64>()
                .ok()
                .filter(|parsed| offset == parsed.to_string())
                .ok_or(Error::InvalidConfig(
                    "invalid stored result reference".into(),
                ))?;
            if offset > output.raw_len {
                return Err(Error::InvalidConfig(
                    "stored result offset exceeds its body".into(),
                ));
            }
            return storage
                .read_code_run_raw_output_range(output, offset, RECOVERABLE_OUTPUT_CHUNK_BYTES)?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))
                .map(Some);
        }
        Err(Error::InvalidConfig(
            "stored result is outside this run".into(),
        ))
    }

    /// A recorded-output read answers where the step's next bridge call
    /// would: a step that can no longer close reads nothing more, past a
    /// halted bridge or past a write that did not meet its receipt, in this
    /// attempt or before. A bound door then rules on it as on any other call
    /// the run serves.
    fn admit_recorded_read(&self) -> Result<()> {
        let refused =
            |code: &str| Error::InvalidConfig(format!("recorded output read refused: {code}"));
        if self.hard_failure.is_some() || self.left_a_gap {
            return Err(refused("host_bridge_halted"));
        }
        if self.declined.is_some() {
            return Err(refused("task_declined"));
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq: self.next_seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        if let Some(refusal) = self.gated_write.refusal_past_an_unmet_write(site, None)? {
            return Err(refused(&refusal.outcome));
        }
        self.gated_write
            .admit_run_call(RunCall::RecordedOutput)?
            .map_err(|refusal| refused(&refusal.code))?;
        Ok(())
    }

    /// Admits one read of the run's recorded outputs, answered as a call is,
    /// so a run whose participant left the room hears `NotInRoom`, never the
    /// door's verdict. A gate's rejection halts the bridge, as at a call.
    fn admit_result_read(&mut self, storage: &ExecutorStorage<'_>) -> Result<()> {
        if let Err(err) = storage.answered(|| self.admit_recorded_read()) {
            let Error::Gate(GateError::GateWriteRejected { outcome, .. }) = &err else {
                return Err(err);
            };
            let refused = Error::InvalidConfig(format!("recorded output read refused: {outcome}"));
            self.hard_failure = Some(err);
            return Err(refused);
        }
        Ok(())
    }

    /// The step's streamed result, for the executor to publish.
    pub(super) fn take_streamed(&mut self) -> StreamedOutputs {
        std::mem::take(&mut self.streamed)
    }

    fn budget(&self) -> Option<BudgetLegibilityEnvelope> {
        self.legibility.as_ref().map(ExecutorLegibility::envelope)
    }

    /// The ONE response chokepoint: every guest-visible bridge-call
    /// response — success, wait, or typed error outcome — leaves through
    /// here so the budget envelope can never be skipped. `view` is a verb
    /// hook's view of the outcome, which the guest reads in its place.
    fn respond(
        &self,
        outcome: SelfDispatchOutcome,
        view: Option<serde_json::Value>,
    ) -> SelfDispatchResponse {
        SelfDispatchResponse {
            outcome,
            budget: self.budget(),
            view,
        }
    }
}

impl JsCodeModeHost for RecordingJsHost<'_, '_> {
    fn write_output(&mut self, stream: JsCodeModeStream<'_>, frame: &[u8]) -> Result<bool> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        self.streamed.write(storage, stream, frame)?;
        Ok(true)
    }

    fn read_recoverable_output(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor recoverable output storage unavailable".into(),
        ))?;
        // The run's recorded outputs hold what its calls read.
        self.admit_result_read(storage)?;
        if path.starts_with(RESULT_READ_ROOT) {
            return self.read_stored_result(storage, path);
        }
        for (seq, output, source) in &self.recoverable {
            if !path.starts_with(&format!("/mnt/outputs/.oneiron-context-ref/{seq}/")) {
                continue;
            }
            let base = recoverable_output_path(*seq, *source);
            let offset = path
                .strip_prefix(&format!("{base}/chunk/"))
                .and_then(|value| {
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|offset| value == offset.to_string())
                })
                .ok_or(Error::InvalidConfig(
                    "invalid recoverable output reference".into(),
                ))?;
            if offset as u64 > source.byte_len {
                return Err(Error::InvalidConfig(
                    "recoverable output offset exceeds source".into(),
                ));
            }
            // Only the chunk leaves the store: an inline body is read in
            // place, a file body by range.
            if output.output_ref() != *source {
                return Err(Error::CorruptedIndex("recoverable output integrity"));
            }
            let chunk = storage
                .read_code_run_raw_output_range(
                    output,
                    offset as u64,
                    RECOVERABLE_OUTPUT_CHUNK_BYTES,
                )?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
            return Ok(Some(chunk));
        }
        Err(Error::InvalidConfig(
            "recoverable output is outside this run".into(),
        ))
    }

    fn store_reply(&mut self, reply: &serde_json::Value) -> Result<Option<serde_json::Value>> {
        let Some(storage) = self.storage else {
            return Ok(None);
        };
        let mut sink = storage.code_run_output_sink()?;
        write_json(&mut sink, reply)?;
        self.bind_stored(storage, sink, None).map(Some)
    }

    fn result_call(&mut self, call: JsResultCall) -> Result<serde_json::Value> {
        match call {
            JsResultCall::Store { name } => self.store_result(name),
            JsResultCall::Describe(target) => self.describe_result(&target),
            JsResultCall::CanRead { target, child } => self.can_read_result(&target, child),
            JsResultCall::Read {
                target,
                facet,
                input,
            } => self.read_result(&target, facet, input),
        }
    }

    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        self.dispatch_call(call, None)
    }

    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch_call(call, Some(runtime))
    }
}

/// The output at `path` with `handle` in `run`'s committed record.
fn recorded_output(
    storage: &ExecutorStorage<'_>,
    run: EntityId,
    path: &str,
    handle: &str,
) -> Result<Option<CodeRunRawOutput>> {
    Ok(storage
        .get_code_run_replay_record(&run)?
        .and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == path && output.handle == handle)
        }))
}

fn dispatch_error_outcome(call: &SelfCall, err: &Error) -> Option<SelfDispatchOutcome> {
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
fn records_failed_effect(effect: SelfEffect) -> bool {
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

pub(super) const EXECUTOR_REQUIRED_HOST_IMPORTS: &[&str] = &[
    // The step's streamed result: console lines, the answer and its files.
    "oneiron.output.text",
    "oneiron.output.bytes",
    "vault.agents.put",
    // The verb table at each row's SDK path, the memory rows the run answers included.
    "self.verbs.names",
    "self.verbs.call",
    "self.report_blocked",
    "ask",
    "self.speak",
    "self.think",
    "self.express",
];

pub(super) fn executor_boundary_contract() -> EngineExecutorResult<SandboxBoundaryContract> {
    // Generated code reaches the host through `self.*` and its own recorded
    // outputs alone: a file or credential service a host attached to the
    // runtime is not part of the executor's contract.
    let boundary = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer)
        .without_host_services();
    if boundary.guest_language() != SandboxGuestLanguage::PlainJavaScript {
        return Err(Error::InvariantViolation("executor sandbox is not plain JavaScript").into());
    }
    if boundary.component_boundary() != SandboxComponentBoundary::WasmtimeWit {
        return Err(Error::InvariantViolation("executor sandbox is not the WIT boundary").into());
    }
    if boundary.wit_world() != SANDBOX_WIT_WORLD_NAME {
        return Err(Error::InvariantViolation("executor sandbox WIT world drift").into());
    }
    for required in EXECUTOR_REQUIRED_HOST_IMPORTS {
        if !boundary
            .linked_imports()
            .iter()
            .any(|import| import.name() == *required)
        {
            return Err(Error::InvariantViolation(
                "executor sandbox missing advertised host import",
            )
            .into());
        }
    }
    // The other, more dangerous direction: every verb the prompt-side d.ts
    // TEACHES must be a verb the boundary actually LINKS. An advertised verb
    // with no import behind it is a call the model is instructed to make and
    // the host cannot answer.
    for advertised in boundary.runtime().advertised_prompt_verbs() {
        if !boundary
            .linked_imports()
            .iter()
            .any(|import| import.name() == advertised.as_str())
        {
            return Err(Error::InvariantViolation(
                "executor prompt advertises an unlinked host verb",
            )
            .into());
        }
    }
    Ok(boundary)
}

/// The system and per-turn sites render the SAME resolved prompt-package
/// block. The prose lives outside Rust so agent-facing instructions cannot
/// drift from prompt tooling or be hand-copied between call sites.
pub(super) fn executor_system_prompt(wire: &str) -> String {
    let wire = wire.trim_end();
    let [host_verbs, verbs, runtime_types] = executor_declarations().map(|file| file.text);
    format!(
        "You are Oneiron's engine-native executor.\n{wire}\n\
         The guest runs inside the CODE-1 Wasmtime WIT component boundary.\n\
         Clock and random values are host-controlled imports for replay determinism.\n\
         Use the prompt-side host verb types below as documentation only; runtime effects arrive \
         as typed host imports:\n\n{host_verbs}\n{verbs}\n{runtime_types}"
    )
}

/// The declarations the system prompt teaches, in its order: the WIT host
/// verbs, the verb table at each row's SDK path, and the interpreter's own
/// functions. A shadow check reads these same texts.
pub(super) fn executor_declarations() -> [oneiron_code_check::Declaration<'static>; 3] {
    [
        ("code-run.d.ts", PLAIN_JS_HOST_VERB_DTS),
        (
            "code-mode.d.ts",
            crate::task_verb::sdk::code_mode_declarations(),
        ),
        (
            "runtime.d.ts",
            include_str!("../../../../components/code-run-quickjs/runtime.d.ts"),
        ),
    ]
    .map(|(name, text)| oneiron_code_check::Declaration { name, text })
}

/// The per-turn trailing instruction: the SAME canonical wire teaching, bound
/// to the durable step the model is being asked for.
pub(super) fn executor_turn_instruction(step_seq: u64, wire: &str) -> String {
    let wire = wire.trim_end();
    format!("Emit the source for durable step {step_seq}.\n{wire}")
}
