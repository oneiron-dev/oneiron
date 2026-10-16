//! JS host bridge: recording dispatcher, sandbox contract, and prompt sites.

use super::store::{
    ByteCount, ObservationRef, RECOVERABLE_OUTPUT_CHUNK_BYTES, RESULT_READ_ROOT,
    RESULT_REPLY_INLINE_BYTES, StreamedOutputs, bridge_result_output_path, is_result_output_path,
    recoverable_output_path, result_handle_json, result_read_path, store_result_output_path,
    write_json,
};
use super::types::{
    EngineExecutorResult, ExecutorLegibility, JsCodeModeHost, JsCodeModeStream, JsResultCall,
    JsResultRef, SelfDispatchResponse,
};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput,
    CodeRunReplayRecord, CodeRunResultBinding, ExecutorCallSite, ExecutorStorage, GatedActorWrite,
    RunCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDurableWait, SelfEffect,
    SelfFailedResult, agent_verb_rows_of,
};
use crate::code_sandbox::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_WIT_WORLD_NAME, SandboxBoundaryContract,
    SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestTier,
};
use crate::compaction::output::OutputRef;
use crate::dreamer_wake::BudgetLegibilityEnvelope;
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::secret_rotation::ArtifactTaintState;
use crate::{Error, Result};
use serde_json::json;

/// Live names a refusal for an unknown result lists, newest first.
const UNKNOWN_HANDLE_LIVE_NAMES: usize = 64;

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
        }
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

    /// A verb answer too large for one reply, stored whole as a body of the
    /// run as it is encoded. The guest and the replay row get its handle
    /// (`result_handle_json`), never the answer; nothing is refused for size.
    fn store_large_answer(
        &mut self,
        seq: u64,
        outcome: SelfDispatchOutcome,
    ) -> Result<SelfDispatchOutcome> {
        let SelfDispatchOutcome::AgentVerb(mut answer) = outcome else {
            return Ok(outcome);
        };
        let mut size = ByteCount::default();
        serde_json::to_writer(&mut size, &answer.output).map_err(|error| {
            Error::InvalidConfig(format!("verb answer encoding failed: {error}"))
        })?;
        if size.0 <= RESULT_REPLY_INLINE_BYTES {
            return Ok(SelfDispatchOutcome::AgentVerb(answer));
        }
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let mut sink = storage.code_run_output_sink()?;
        write_json(&mut sink, &answer.output)?;
        let output = storage.publish_code_run_output(
            bridge_result_output_path(seq),
            sink,
            true,
            self.run_id,
        )?;
        let name = self.next_auto_name();
        self.bind(name.clone(), output.handle.clone());
        answer.output = result_handle_json(&output);
        answer.output["name"] = json!(name);
        self.captured.push(output);
        Ok(SelfDispatchOutcome::AgentVerb(answer))
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
        let live = self.live_bindings();
        let mut held = self.results.iter().chain(&self.captured);
        match reference {
            JsResultRef::Name(name) => {
                let binding = live.iter().find(|binding| binding.name == *name)?;
                let output = held.find(|output| output.handle == binding.handle)?;
                Some((output.clone(), Some(binding.name.clone())))
            }
            JsResultRef::Handle(handle) => {
                let output = held.find(|output| names_result(output, handle))?;
                let name = live
                    .iter()
                    .rev()
                    .find(|binding| binding.handle == output.handle)
                    .map(|binding| binding.name.clone());
                Some((output.clone(), name))
            }
        }
    }

    /// The refusal for a reference to no result of this run, with the live
    /// names it could have meant.
    fn unknown_handle(&self) -> serde_json::Value {
        let live = self.live_bindings();
        let names: Vec<&str> = live
            .iter()
            .rev()
            .take(UNKNOWN_HANDLE_LIVE_NAMES)
            .map(|binding| binding.name.as_str())
            .collect();
        json!({
            "denied": "unknown_handle",
            "reasonCodes": ["unknown_handle"],
            "live": names,
            "liveCount": live.len(),
        })
    }

    /// Whether the run's results stay on this device for its door's caller
    /// now (DEC-0005). A result's rows are the run's conservative union:
    /// every row its recorded and this step's verb answers were served from,
    /// or none known when one answer kept no set.
    fn withholds_results(&self) -> Result<bool> {
        let rows = self
            .recorded_rows
            .as_ref()
            .zip(agent_verb_rows_of(&self.bridge_calls))
            .map(|(recorded, step)| [recorded.as_slice(), step.as_slice()].concat());
        self.gated_write
            .withholds_retained(rows.as_deref())
            .map_err(|refusal| {
                Error::InvalidConfig(format!("stored result read refused: {}", refusal.code))
            })
    }

    /// A result's card, from its manifest and taint sidecars, never its
    /// body: the handle facets, its name, and its taint. A body that is not
    /// clean shows no preview.
    fn result_card(
        storage: &ExecutorStorage<'_>,
        output: &CodeRunRawOutput,
        name: Option<&str>,
    ) -> Result<serde_json::Value> {
        let (state, secret) = storage.code_run_result_taint(output)?;
        let mut card = result_handle_json(output);
        card["name"] = json!(name);
        card["taint"] = json!({"state": taint_word(state), "secret": secret});
        if state.is_tainted() {
            card["preview"] = json!(CODE_RUN_OUTPUT_PREVIEW_WITHHELD);
        }
        Ok(card)
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
        Ok(json!({"output": Self::result_card(storage, &output, Some(name.as_str()))?}))
    }

    /// `describe(r)`: the card of one of the run's results, admitted as a
    /// read of it is, rows and taint re-checked now.
    fn describe_result(&mut self, reference: &JsResultRef) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let Some((output, name)) = self.resolve_result(reference) else {
            return Ok(self.unknown_handle());
        };
        self.admit_result_read(storage)?;
        if self.withholds_results()? {
            return Ok(result_refusal("result_withheld"));
        }
        Ok(json!({"output": Self::result_card(storage, &output, name.as_deref())?}))
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
    /// here so the budget envelope can never be skipped.
    fn respond(&self, outcome: SelfDispatchOutcome) -> SelfDispatchResponse {
        SelfDispatchResponse {
            outcome,
            budget: self.budget(),
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

    fn result_call(&mut self, call: JsResultCall) -> Result<serde_json::Value> {
        match call {
            JsResultCall::Store { name } => self.store_result(name),
            JsResultCall::Describe(reference) => self.describe_result(&reference),
        }
    }

    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
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
            return Ok(self.respond(outcome));
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
            return Ok(self.respond(outcome));
        }
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        let dispatched = self
            .gated_write
            .dispatch_for_executor_run(site, call.clone());
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
                self.bridge_calls.push(row);
                self.hard_failure = Some(err);
                return Ok(self.respond(error_outcome));
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
        self.bridge_calls.push(row);
        Ok(self.respond(outcome))
    }
}

/// A result call's refusal, as the guest's thrown error carries it.
fn result_refusal(code: &str) -> serde_json::Value {
    json!({"denied": code, "reasonCodes": [code]})
}

/// Whether `handle` names `output`: its handle as its card gives it, or its
/// digest as model context cites it (`output:blake3:<hex>:<len>`).
fn names_result(output: &CodeRunRawOutput, handle: &str) -> bool {
    output.handle == handle
        || handle
            .strip_prefix("output:blake3:")
            .and_then(|rest| rest.split(':').next())
            .is_some_and(|hex| hex == crate::entity_id::bytes_to_hex_lower(&output.raw_blake3))
}

/// A taint state as a card spells it.
fn taint_word(state: ArtifactTaintState) -> &'static str {
    match state {
        ArtifactTaintState::Clean => "clean",
        ArtifactTaintState::TaintedLive => "tainted_live",
        ArtifactTaintState::TaintedStale => "tainted_stale",
    }
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
