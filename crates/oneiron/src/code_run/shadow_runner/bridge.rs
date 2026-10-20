//! The bridge an arm's program calls (PR-S1): every `self.*` call the
//! program makes joins the arm's proposed-effect trace before it is matched,
//! as the program made it, then is matched against the step's recorded
//! calls by an offset replay cursor and answered with the recorded outcome.
//! No effect is applied, no live dispatcher or gated write is reached, and
//! no secret resolver, lease or credential is here: a call the record does
//! not hold (past the step's last recorded call, or not the recorded one) is
//! unavailable, never answered by anything else. A call that runs a step or
//! a run of its own (a callable skill, a reader child, a summary) recorded
//! its subtree after its own row, which one row cannot replay; it is
//! unavailable too, as is a call the live guest read through a view the
//! record does not keep.
//!
//! The program's results are the arm's own: its streamed result goes to the
//! arm's store, a value it stores or a reply too large for one message is a
//! result of the arm, bound in the arm alone, and its reads (`describe`,
//! `can`, the facets, a chunk) answer from the arm's store and the run's
//! results and observations before the step, frozen with their taint before
//! the arm started.

use serde_json::{Value, json};

use super::super::payload::{decode_self_dispatch_outcome, self_call_request_value};
use super::source::PreparedShadowStep;
use super::store::ShadowBodyStore;
use super::types::{
    ShadowBodyRef, ShadowTraceEntry, ShadowTraceKind, ShadowUnavailable,
    ShadowUnavailableReason as Reason,
};
use crate::code_run::{
    CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayCursor, CodeRunReplayRecord,
    CodeRunResultBinding, ResultFacet, ResultRead, ResultReply, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, SelfDurableWait, resolve_result, result_cannot, result_refusal, unknown_handle,
};
use crate::compaction::output::OutputRef;
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStepOutcome, JsCodeModeStream, JsResultCall,
    JsResultTarget, RESULT_READ_ROOT, SelfDispatchResponse, StepCancellation,
    is_result_output_path, store_result_output_path,
};
use crate::limit_ask::{EngineLimit, EngineLimits, LimitWatch};
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Error, Result};

/// The taint a result reads under: its state and the secret scan's reason.
type Taint = (ArtifactTaintState, Option<String>);

/// Where the arm's program reads its run's bodies back by path, as the
/// executor names them.
pub(crate) struct ArmReads {
    /// Each observation of a step before this one, by the path its chunks
    /// are read under, and whether it was frozen clean.
    pub(crate) recoverable: Vec<(String, CodeRunRawOutput, bool)>,
    /// The path a stored result's chunks are read under.
    pub(crate) result_path: fn(OutputRef) -> String,
    /// Bytes one chunk read answers.
    pub(crate) chunk_bytes: usize,
}

/// One result of the arm's run: frozen from before the step, or the arm's
/// own.
struct ArmResult {
    output: CodeRunRawOutput,
    state: ArtifactTaintState,
    secret: Option<String>,
    own: bool,
}

/// The step's streamed result, written into the arm's store frame by frame.
#[derive(Default)]
pub(crate) struct ArmStreams {
    console: Option<BodySink>,
    finish: Option<BodySink>,
    /// The value the program is passing to `store`, until the host takes it.
    store: Option<BodySink>,
    files: Vec<(String, BodySink)>,
}

impl ArmStreams {
    /// Appends one frame to its target's body, as a run's host does: a
    /// finish frame that starts an answer drops the answer before it, and a
    /// store frame that starts a value drops any value no `store` took.
    fn write(
        &mut self,
        store: &ShadowBodyStore,
        stream: JsCodeModeStream<'_>,
        frame: &[u8],
    ) -> Result<()> {
        let sink = match stream {
            JsCodeModeStream::Console => &mut self.console,
            JsCodeModeStream::Finish { start } => {
                if start {
                    self.finish = None;
                }
                &mut self.finish
            }
            JsCodeModeStream::Store { start } => {
                if start {
                    self.store = None;
                }
                &mut self.store
            }
            JsCodeModeStream::File(path) => {
                let at = match self.files.iter().position(|(held, _)| held == path) {
                    Some(at) => at,
                    None => {
                        self.files.push((path.to_owned(), store.sink()?));
                        self.files.len() - 1
                    }
                };
                return self.files[at].1.write(frame);
            }
        };
        if sink.is_none() {
            *sink = Some(store.sink()?);
        }
        match sink {
            Some(sink) => sink.write(frame),
            None => Err(Error::InvariantViolation("shadow arm stream sink missing")),
        }
    }

    /// The step's bodies once it ran: the answer of a finished step, else
    /// its console lines, and its files, with whatever the runtime returned
    /// in its outcome instead of streaming it.
    pub(crate) fn into_bodies(
        self,
        store: &ShadowBodyStore,
        outcome: &JsCodeModeStepOutcome,
    ) -> Result<(BodySink, Vec<(String, BodySink)>)> {
        let observation = if outcome.done {
            self.finish
        } else {
            self.console
        };
        let mut observation = match observation {
            Some(sink) => sink,
            None => store.sink()?,
        };
        observation.write(outcome.observation.as_bytes())?;
        let mut files = self.files;
        for output in &outcome.outputs {
            let mut sink = store.sink()?;
            sink.write(&output.bytes)?;
            files.push((output.path.clone(), sink));
        }
        Ok((observation, files))
    }

    /// What a step that failed streamed before it failed: its console
    /// lines, else its answer so far, and its files, each kept partial.
    pub(crate) fn into_partial(self) -> (Option<BodySink>, Vec<(String, BodySink)>) {
        (self.console.or(self.finish), self.files)
    }
}

/// The arm's host bridge for one captured step.
pub(crate) struct ShadowBridgeHost<'a> {
    cursor: CodeRunReplayCursor<'a>,
    window: &'a CodeRunReplayRecord,
    store: &'a ShadowBodyStore,
    run_id: EntityId,
    determinism: CodeRunDeterminism,
    next_seq: u64,
    bridge_end: u64,
    reads: ArmReads,
    /// The vault's `[limits]` scan row, frozen for the arm's reads.
    watch: LimitWatch,
    streams: ArmStreams,
    /// The run's results, those before the step first, then the arm's own.
    results: Vec<ArmResult>,
    /// The run's result names before the step.
    bindings: Vec<CodeRunResultBinding>,
    /// The names the arm bound or rebound, in order.
    pub(crate) bound: Vec<CodeRunResultBinding>,
    /// Every call the program made, as it made it, matched or not.
    pub(crate) proposed: Vec<ShadowTraceEntry>,
    /// Every recorded call a call of the program matched, as recorded.
    pub(crate) matched: Vec<ShadowTraceEntry>,
    /// The wait a matched call's recorded outcome parked on.
    pub(crate) durable_wait: Option<SelfDurableWait>,
    /// A matched call's recorded outcome was a refusal or failure the live
    /// guest read as a response: the step fails after, as it did.
    pub(crate) hard_failure: bool,
    /// A matched call's recorded outcome declined the run's TASK.
    pub(crate) declined: bool,
    /// Why the arm stopped, once it did.
    pub(crate) stopped: Option<ShadowUnavailable>,
}

impl<'a> ShadowBridgeHost<'a> {
    /// The bridge for `prepared`'s step, its bodies in `store`, its reads
    /// by path at `reads`.
    pub(crate) fn new(
        prepared: &'a PreparedShadowStep,
        store: &'a ShadowBodyStore,
        reads: ArmReads,
    ) -> Result<Self> {
        let mut limits = EngineLimits::default();
        limits.set(EngineLimit::CodeResultScanBytes, prepared.scan_bytes);
        let results = prepared
            .frozen
            .iter()
            .filter(|frozen| is_result_output_path(&frozen.output.path))
            .map(|frozen| ArmResult {
                output: frozen.output.clone(),
                state: frozen.state,
                secret: frozen.secret.clone(),
                own: false,
            })
            .collect();
        Ok(Self {
            cursor: CodeRunReplayCursor::from_position(&prepared.window, prepared.bridge_start)?,
            window: &prepared.window,
            store,
            run_id: prepared.step.run,
            determinism: prepared.determinism,
            next_seq: prepared.bridge_start,
            bridge_end: prepared.bridge_end,
            reads,
            watch: LimitWatch::new(limits),
            streams: ArmStreams::default(),
            results,
            bindings: prepared.prefix.bindings.clone(),
            bound: Vec::new(),
            proposed: Vec::new(),
            matched: Vec::new(),
            durable_wait: None,
            hard_failure: false,
            declined: false,
            stopped: None,
        })
    }

    /// How far into the run's bridge log the arm matched.
    pub(crate) fn consumed(&self) -> u64 {
        self.cursor.consumed() as u64
    }

    /// The step's streamed result, taken once it ran.
    pub(crate) fn take_streams(&mut self) -> ArmStreams {
        std::mem::take(&mut self.streams)
    }

    /// The results the arm stored, each by its ref.
    pub(crate) fn own_results(&self) -> Vec<ShadowBodyRef> {
        self.results
            .iter()
            .filter(|result| result.own)
            .map(|result| ShadowBodyRef::of(&result.output, result.secret.as_deref()))
            .collect()
    }

    /// Whether the arm's bridge is halted: past a recorded hard failure, or
    /// once the arm stopped.
    fn halted(&self) -> bool {
        self.hard_failure || self.stopped.is_some()
    }

    /// The arm's source still holds its content, or the arm stops for it
    /// (FIX 5718): once an erase or actor scrub of the source run's actor
    /// took it, no read or publication of the arm goes on, and the arm is
    /// unavailable, `SourceWithheld` for `response_erased`.
    fn hold_source(&mut self) -> Result<()> {
        match self.store.source_withheld() {
            Some(withheld) => Err(self.stop(withheld)),
            None => Ok(()),
        }
    }

    /// Stops the arm for `unavailable` (the first reason stands), and the
    /// error the program's call fails with: no guest-visible answer exists.
    fn stop(&mut self, unavailable: ShadowUnavailable) -> Error {
        let error = Error::InvalidConfig(format!(
            "shadow arm stopped: {}",
            unavailable.reason.as_str()
        ));
        if self.stopped.is_none() {
            self.stopped = Some(unavailable);
        }
        error
    }

    /// The arm's live result names, oldest first: its binds over the run's.
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

    /// Binds `name` to the result `handle`; a rebind replaces the name's
    /// entry in place.
    fn bind(&mut self, name: String, handle: String) {
        let binding = CodeRunResultBinding::new(name, handle);
        match self.bound.iter_mut().find(|held| held.name == binding.name) {
            Some(held) => *held = binding,
            None => self.bound.push(binding),
        }
    }

    /// A read of the arm's results is admitted as a run's is: never past a
    /// halted bridge or a declined TASK.
    fn admit_read(&self) -> Result<()> {
        let refused =
            |code: &str| Error::InvalidConfig(format!("recorded output read refused: {code}"));
        if self.halted() {
            return Err(refused("host_bridge_halted"));
        }
        if self.declined {
            return Err(refused("task_declined"));
        }
        Ok(())
    }

    /// The arm's result `target` names, read as a run's read is, with the
    /// taint it reads under, or the refusal the guest gets.
    fn checked(
        &self,
        target: &JsResultTarget,
    ) -> Result<std::result::Result<(ResultRead, Taint), Value>> {
        let live = self.live_bindings();
        let outputs = self.results.iter().map(|result| &result.output);
        let Some((output, name)) = resolve_result(outputs, &live, &target.reference) else {
            return Ok(Err(unknown_handle(&live)));
        };
        self.admit_read()?;
        let taint = self.taint_of(&output);
        Ok(
            ResultRead::in_arm(self.run_id, output, name, target.range, taint.clone())
                .map(|read| (read, taint)),
        )
    }

    /// The taint the arm holds `output` under.
    fn taint_of(&self, output: &CodeRunRawOutput) -> Taint {
        self.results
            .iter()
            .find(|held| held.output.path == output.path && held.output.handle == output.handle)
            .map_or((ArtifactTaintState::Clean, None), |held| {
                (held.state, held.secret.clone())
            })
    }

    /// Finishes the body `sink` wrote as a stored value of the arm, named by
    /// the digest of the bytes the wall admitted (FIX 5718 part 3), the
    /// taint of `inherit` on it, and binds it to `name`, or to the next free
    /// `r<n>`: the result and its card.
    fn bind_stored(
        &mut self,
        sink: BodySink,
        name: Option<String>,
        inherit: &[Taint],
    ) -> Result<(CodeRunRawOutput, Value)> {
        let (output, secret) = self
            .store
            .finish_named(store_result_output_path, sink, true)?;
        let taint = match self
            .results
            .iter()
            .find(|held| held.output.path == output.path)
        {
            Some(held) => (held.state, held.secret.clone()),
            None => {
                let taint = stored_taint(secret, inherit);
                self.results.push(ArmResult {
                    output: output.clone(),
                    state: taint.0,
                    secret: taint.1.clone(),
                    own: true,
                });
                taint
            }
        };
        let name = name.unwrap_or_else(|| self.next_auto_name());
        self.bind(name.clone(), output.handle.clone());
        let card = match ResultRead::in_arm(self.run_id, output.clone(), Some(name), None, taint) {
            Ok(read) => read.arm_card(self.store)?,
            Err(_) => return Err(Error::InvariantViolation("a whole result has no range")),
        };
        Ok((output, card))
    }

    /// `store(value, name?, {sources?, receipt?})`, as a run's host stores
    /// it, in the arm alone. A fold's receipt names reader jobs, which the
    /// arm has none of: unavailable.
    fn store_result(
        &mut self,
        name: Option<String>,
        sources: &[String],
        receipt: bool,
    ) -> Result<Value> {
        let sink = self
            .streams
            .store
            .take()
            .ok_or_else(|| Error::InvalidConfig("store sent no body".to_owned()))?;
        if self.halted() {
            return Ok(result_refusal("host_bridge_halted"));
        }
        if self.declined {
            return Ok(result_refusal("task_declined"));
        }
        if name
            .as_deref()
            .is_some_and(|name| !CodeRunResultBinding::is_valid_name(name))
        {
            return Ok(result_refusal("invalid_result_name"));
        }
        if receipt {
            let nested = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "fold_receipt");
            return Err(self.stop(nested));
        }
        let mut inherit = Vec::with_capacity(sources.len());
        for source in sources {
            match self.checked(&JsResultTarget::parse(source))? {
                Ok((_, taint)) => inherit.push(taint),
                Err(refused) => return Ok(refused),
            }
        }
        let (_, card) = self.bind_stored(sink, name, &inherit)?;
        Ok(json!({ "output": card }))
    }

    /// `describe(r)`: the card of one of the arm's results.
    fn describe_result(&self, target: &JsResultTarget) -> Result<Value> {
        Ok(match self.checked(target)? {
            Ok((read, _)) => json!({ "output": read.arm_card(self.store)? }),
            Err(refused) => refused,
        })
    }

    /// `can({read: r})`: the verdict a read's checks give. With `child`, a
    /// readable result is also asked of a reader spawn, which the arm runs
    /// none of: unavailable.
    fn can_read_result(&mut self, target: &JsResultTarget, child: bool) -> Result<Value> {
        let verdict = match self.checked(target)? {
            Ok((read, _)) => read.preflight(),
            Err(refused) => result_cannot(refused),
        };
        if !child || verdict["can"] != json!(true) {
            return Ok(json!({ "output": verdict }));
        }
        let nested = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "reader_spawn");
        Err(self.stop(nested))
    }

    /// One facet of one of the arm's results. A query whose selection is
    /// past one reply is stored as a new result of the arm.
    fn read_result(
        &mut self,
        target: &JsResultTarget,
        facet: ResultFacet,
        input: Value,
    ) -> Result<Value> {
        let read = match self.checked(target)? {
            Ok((read, _)) => read,
            Err(refused) => return Ok(refused),
        };
        let mut sink = match facet {
            ResultFacet::Query => Some(self.store.sink()?),
            _ => None,
        };
        let reply = read.arm_read(self.store, &self.watch, facet, input, sink.as_mut())?;
        Ok(match reply {
            ResultReply::Output(output) => json!({ "output": output }),
            ResultReply::Denied(refused) => refused,
            ResultReply::Spilled { count, next } => {
                let sink = sink.ok_or(Error::InvariantViolation(
                    "a result read spilled with no sink",
                ))?;
                let (_, card) = self.bind_stored(sink, None, &[])?;
                let mut output = json!({"derived": card, "count": count, "done": next.is_none()});
                if let Some(next) = next {
                    output["next"] = next;
                }
                json!({ "output": output })
            }
        })
    }

    /// One chunk of a body at `offset`, while the arm holds it clean; a
    /// body frozen withheld stops the arm, since its live read read it.
    fn read_chunk(
        &mut self,
        output: &CodeRunRawOutput,
        clean: bool,
        offset: u64,
    ) -> Result<Option<Vec<u8>>> {
        if offset > output.raw_len {
            return Err(Error::InvalidConfig(
                "recoverable output offset exceeds source".to_owned(),
            ));
        }
        if !clean {
            let withheld = ShadowUnavailable::new(Reason::SourceWithheld, "recoverable_output");
            return Err(self.stop(withheld));
        }
        self.store
            .read_range(output.output_ref(), offset, self.reads.chunk_bytes)?
            .ok_or(Error::CorruptedIndex("shadow arm output bytes"))
            .map(Some)
    }

    /// A chunk of one of the arm's stored results, by its read path.
    fn read_stored_result(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let result_path = self.reads.result_path;
        let found = self.results.iter().find_map(|held| {
            let base = result_path(held.output.output_ref());
            let offset = path.strip_prefix(base.as_str())?.strip_prefix("/chunk/")?;
            Some((
                offset.to_owned(),
                held.output.clone(),
                !held.state.is_tainted(),
            ))
        });
        let Some((offset, output, clean)) = found else {
            return Err(Error::InvalidConfig(
                "stored result is outside this run".to_owned(),
            ));
        };
        let offset = canonical_offset(&offset)
            .ok_or_else(|| Error::InvalidConfig("invalid stored result reference".to_owned()))?;
        self.read_chunk(&output, clean, offset)
    }

    /// One matched recorded call, for the bridge trace.
    fn record_matched(&mut self, at: usize) -> Result<()> {
        let window = self.window;
        let stored = window
            .bridge_calls
            .get(at)
            .ok_or(Error::InvariantViolation("a matched bridge row is missing"))?;
        self.matched.push(ShadowTraceEntry {
            kind: ShadowTraceKind::Call,
            seq: stored.seq,
            effect: stored.effect.as_str().to_owned(),
            request: encoded(&stored.request)?,
            outcome: Some(encoded(&stored.outcome)?),
        });
        Ok(())
    }

    /// The recorded outcome of a matched row the cursor answered as a trap:
    /// a refusal or failure the live guest read as a response.
    fn trapped_outcome(&self, at: usize) -> Result<SelfDispatchOutcome> {
        let stored = self
            .window
            .bridge_calls
            .get(at)
            .ok_or(Error::InvariantViolation("a matched bridge row is missing"))?;
        decode_self_dispatch_outcome(&stored.outcome)
    }
}

impl JsCodeModeHost for ShadowBridgeHost<'_> {
    fn write_output(&mut self, stream: JsCodeModeStream<'_>, frame: &[u8]) -> Result<bool> {
        self.hold_source()?;
        self.streams.write(self.store, stream, frame)?;
        Ok(true)
    }

    fn read_recoverable_output(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        self.hold_source()?;
        self.admit_read()?;
        if path.starts_with(RESULT_READ_ROOT) {
            return self.read_stored_result(path);
        }
        let found = self
            .reads
            .recoverable
            .iter()
            .find_map(|(base, output, clean)| {
                let offset = path.strip_prefix(base.as_str())?.strip_prefix("/chunk/")?;
                Some((offset.to_owned(), output.clone(), *clean))
            });
        let Some((offset, output, clean)) = found else {
            return Err(Error::InvalidConfig(
                "recoverable output is outside this run".to_owned(),
            ));
        };
        let offset = canonical_offset(&offset).ok_or_else(|| {
            Error::InvalidConfig("invalid recoverable output reference".to_owned())
        })?;
        self.read_chunk(&output, clean, offset)
    }

    fn store_reply(&mut self, reply: &Value) -> Result<Option<Value>> {
        self.hold_source()?;
        let bytes = serde_json::to_vec(reply).map_err(|error| {
            Error::InvalidConfig(format!("result body encoding failed: {error}"))
        })?;
        let mut sink = self.store.sink()?;
        sink.write(&bytes)?;
        self.bind_stored(sink, None, &[])
            .map(|(_, card)| Some(card))
    }

    fn result_call(&mut self, call: JsResultCall) -> Result<Value> {
        self.hold_source()?;
        match call {
            JsResultCall::Store {
                name,
                sources,
                receipt,
            } => self.store_result(name, &sources, receipt.is_some()),
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
        if let Some(stopped) = self.stopped.clone() {
            return Err(self.stop(stopped));
        }
        self.hold_source()?;
        let seq = self.next_seq;
        self.next_seq = seq.saturating_add(1);
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        let call = call.with_bridge_stamp(seq, started_at_ms);
        // Every effect the program asks for joins the proposed trace first,
        // as it asked, whatever comes of matching it.
        self.proposed.push(ShadowTraceEntry {
            kind: ShadowTraceKind::Call,
            seq,
            effect: call.effect().as_str().to_owned(),
            request: encoded(&self_call_request_value(&call)?)?,
            outcome: None,
        });
        if let Some(unreplayable) = unreplayable(&call) {
            return Err(self.stop(unreplayable));
        }
        let at = self.cursor.consumed();
        if at as u64 >= self.bridge_end {
            let missing = ShadowUnavailable::new(Reason::CapturedOutcomeMissing, "bridge_call");
            return Err(self.stop(missing));
        }
        let outcome = match self.cursor.dispatch(call) {
            Ok(outcome) => outcome,
            // The row matched, and its recorded outcome is one the cursor
            // answers as a trap: the live guest read it as a response.
            Err(_) if self.cursor.consumed() > at => {
                let outcome = self.trapped_outcome(at)?;
                // An erase of its run's actor took the reply the live guest
                // read (FIX 5718): the arm stops there, the call it matched
                // kept, never answered by anything else.
                if response_erased(&outcome) {
                    self.record_matched(at)?;
                    let erased = ShadowUnavailable::new(
                        Reason::SourceWithheld,
                        crate::code_run::RESPONSE_ERASED,
                    );
                    return Err(self.stop(erased));
                }
                if !declined_halt(&outcome) {
                    self.hard_failure = true;
                }
                outcome
            }
            Err(_) => {
                let mismatch = ShadowUnavailable::new(Reason::BridgeReplayMismatch, "bridge_call");
                return Err(self.stop(mismatch));
            }
        };
        self.record_matched(at)?;
        if let SelfDispatchOutcome::DurableWait(wait) = &outcome
            && self.durable_wait.is_none()
        {
            self.durable_wait = Some(wait.clone());
        }
        if let SelfDispatchOutcome::TaskRefusal(refusal) = &outcome
            && refusal.declined()
        {
            self.declined = true;
        }
        Ok(SelfDispatchResponse {
            outcome,
            budget: None,
            view: None,
        })
    }

    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        _runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch_self(call)
    }

    fn dispatch_self_nested_cancellable(
        &mut self,
        call: SelfCall,
        _runtime: &mut dyn JsCodeModeRuntime,
        cancel: &StepCancellation,
    ) -> Result<SelfDispatchResponse> {
        cancel.check()?;
        let answered = self.dispatch_self(call);
        cancel.check()?;
        answered
    }
}

/// Why the arm cannot replay `call` as its run made it, if it cannot (CALLS
/// "nested subtree refusal"): a callable skill, a reader child's spawn or
/// report and a summary run a step or a run of their own, whose calls were
/// recorded after the call's own row, and one matched row cannot replay
/// them; a revealed secret's answer reached the live guest through a view
/// the record does not keep, by design.
fn unreplayable(call: &SelfCall) -> Option<ShadowUnavailable> {
    match call {
        SelfCall::SkillsCall(_)
        | SelfCall::ReaderSpawn(_)
        | SelfCall::ReaderReport(_)
        | SelfCall::Summarize(_) => Some(ShadowUnavailable::new(
            Reason::NestedReplayUnsupported,
            call.effect().as_str(),
        )),
        SelfCall::AgentVerb(verb) if verb.verb == AgentVerb::RevealWait => Some(
            ShadowUnavailable::new(Reason::GuestViewCaptureMissing, "reveal_wait"),
        ),
        _ => None,
    }
}

/// Whether `outcome` is the failure an erase of its run's actor left in a
/// recorded call's place (FIX 5718).
fn response_erased(outcome: &SelfDispatchOutcome) -> bool {
    matches!(
        outcome,
        SelfDispatchOutcome::Failed(failed) if failed.error == crate::code_run::RESPONSE_ERASED
    )
}

/// Whether `outcome` is the fail-closed answer a call gets once its run's
/// TASK was declined: the step closes the run, and fails nothing.
fn declined_halt(outcome: &SelfDispatchOutcome) -> bool {
    matches!(outcome, SelfDispatchOutcome::Failed(failed) if failed.error == "task_declined")
}

/// The taint a value the arm stored reads under: the secret scan's mark on
/// its own bytes, else the first taint among the results it was made from.
fn stored_taint(secret: Option<&'static str>, inherit: &[Taint]) -> Taint {
    if let Some(reason) = secret {
        return (ArtifactTaintState::TaintedLive, Some(reason.to_owned()));
    }
    inherit
        .iter()
        .find(|(state, _)| state.is_tainted())
        .cloned()
        .unwrap_or((ArtifactTaintState::Clean, None))
}

/// An offset as a read path writes it: decimal digits, no sign, no
/// leading zero.
fn canonical_offset(text: &str) -> Option<u64> {
    text.parse::<u64>()
        .ok()
        .filter(|offset| offset.to_string() == text)
}

/// `value` as MessagePack.
fn encoded(value: &rmpv::Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("a shadow trace entry did not encode"))?;
    Ok(bytes)
}
