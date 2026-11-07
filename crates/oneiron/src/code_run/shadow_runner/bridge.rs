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
//! unavailable too, as is a revealed secret's answer, which no capture keeps.
//! A callable branch's arm (FIX 3608, [`callable`]) answers a callable call
//! from the callable the step's replay context froze for it instead: run
//! again against its own recorded calls, or left absent.
//!
//! A matched call is answered as the live guest read it (FIX 6351): the
//! recorded outcome with the response the step's replay context kept for its
//! row, a verb hook's view in the outcome's place or none, and the wake
//! pass's budget envelope or none. A call whose response the context does
//! not hold stops the arm before the guest reads the bare outcome.
//!
//! The program's results are the arm's own: its streamed result goes to the
//! arm's store, a value it stores or a reply too large for one message is a
//! result of the arm, bound in the arm alone, and its reads (`describe`,
//! `can`, the facets, a chunk) answer from the arm's store and the run's
//! results and observations before the step, frozen with their taint before
//! the arm started. A read of another run's result (a reader child's
//! source, a child's finding) answers as the step's live read did, from the
//! step's read context (FIX 6352).
//!
//! Each read of a result frozen from the step's source takes the taint its
//! source occurrence reads under now, at its worst with the frozen one (FIX
//! 9468): a result that went tainted after the freeze is withheld, as a
//! run's read of a tainted result is.

use serde_json::Value;

use super::super::payload::{decode_self_dispatch_outcome, self_call_request_value};
use super::source::{FrozenReply, PreparedShadowStep};
use super::store::ShadowBodyStore;
use super::types::{
    ShadowTraceEntry, ShadowTraceKind, ShadowUnavailable, ShadowUnavailableReason as Reason,
};
use crate::code_run::{
    CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayCursor, CodeRunReplayRecord,
    CodeRunResultBinding, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfDurableWait,
    reveals_secret,
};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStream, JsResultCall, RESULT_READ_ROOT,
    SelfDispatchResponse, StepCancellation, bridge_result_output_path, is_result_output_path,
};
use crate::limit_ask::{EngineLimit, EngineLimits, LimitWatch};
use crate::secret_rotation::ArtifactTaintState;
use crate::{EntityId, Error, Result};

/// The taint a result reads under: its state and the secret scan's reason.
pub(super) type Taint = (ArtifactTaintState, Option<String>);

mod callable;
mod results;
mod streams;
mod taint;
pub(crate) use self::callable::{ArmCallableLoad, ArmCallables};
use self::streams::ArmStreams;

/// Where the arm's program reads its run's bodies back by path, as the
/// executor names them.
pub(crate) struct ArmReads {
    /// Each observation of a step before this one, by the path its chunks
    /// are read under, and whether it was frozen clean.
    pub(crate) recoverable: Vec<(String, CodeRunRawOutput, bool)>,
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

/// The arm's host bridge for one captured step.
pub(crate) struct ShadowBridgeHost<'a> {
    /// The step it replays, its replay context the responses it answers
    /// with (FIX 6351).
    step: &'a PreparedShadowStep,
    cursor: CodeRunReplayCursor<'a>,
    window: &'a CodeRunReplayRecord,
    replies: &'a [FrozenReply],
    store: &'a ShadowBodyStore,
    run_id: EntityId,
    determinism: CodeRunDeterminism,
    next_seq: u64,
    bridge_end: u64,
    reads: ArmReads,
    /// The vault's `[limits]` scan row, frozen for the arm's reads.
    watch: LimitWatch,
    streams: ArmStreams,
    /// The run's full output count as the step started (FIX 1393
    /// follow-up): the base the arm's store ordinals count from, the same
    /// base live execution counts from — every output, not only results.
    output_ordinal_base: usize,
    /// Matched bridge-result spills the arm consumed (live `store_answer`
    /// bodies the arm only matched as cards). Counted in store ordinals,
    /// as live counts them in its captured outputs.
    spilled: usize,
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
    /// A callable branch's treatment of the step's recorded callables
    /// (FIX 3608); `None` for any other arm, which runs no callable.
    callables: Option<&'a ArmCallables>,
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
            step: prepared,
            cursor: CodeRunReplayCursor::from_position(&prepared.window, prepared.bridge_start)?,
            window: &prepared.window,
            replies: &prepared.replies,
            store,
            run_id: prepared.step.run,
            determinism: prepared.determinism,
            next_seq: prepared.bridge_start,
            bridge_end: prepared.bridge_end,
            reads,
            watch: LimitWatch::new(limits),
            streams: ArmStreams::default(),
            output_ordinal_base: crate::engine_executor::store_ordinal_base(&prepared.prefix),
            spilled: 0,
            results,
            bindings: prepared.prefix.bindings.clone(),
            bound: Vec::new(),
            proposed: Vec::new(),
            matched: Vec::new(),
            durable_wait: None,
            hard_failure: false,
            declined: false,
            stopped: None,
            callables: None,
        })
    }

    /// The bridge of a callable branch's arm (FIX 3608): each callable call
    /// answered by `callables`.
    pub(crate) fn with_callables(mut self, callables: &'a ArmCallables) -> Self {
        self.callables = Some(callables);
        self
    }

    /// How far into the run's bridge log the arm matched.
    pub(crate) fn consumed(&self) -> u64 {
        self.cursor.consumed() as u64
    }

    /// The step's streamed result, taken once it ran.
    pub(crate) fn take_streams(&mut self) -> ArmStreams {
        std::mem::take(&mut self.streams)
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
        let clean = clean && self.source_clean(&output)?;
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
        self.dispatch(call, None)
    }

    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.dispatch(call, Some((runtime, &StepCancellation::never())))
    }

    fn dispatch_self_nested_cancellable(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
        cancel: &StepCancellation,
    ) -> Result<SelfDispatchResponse> {
        cancel.check()?;
        let answered = self.dispatch(call, Some((runtime, cancel)));
        cancel.check()?;
        answered
    }
}

impl ShadowBridgeHost<'_> {
    /// One `self.*` call of the arm's program, `nested` the sibling runtime
    /// and the caller's token a call that runs a step of its own runs on,
    /// when its runtime lent one.
    fn dispatch(
        &mut self,
        call: SelfCall,
        nested: Option<(&mut dyn JsCodeModeRuntime, &StepCancellation)>,
    ) -> Result<SelfDispatchResponse> {
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
        let callables = self
            .callables
            .filter(|_| matches!(call, SelfCall::SkillsCall(_)));
        if let Some(callables) = callables {
            return self.dispatch_callable(call, callables, nested);
        }
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
        // The live guest read this row through the response the step's
        // replay context kept for it (FIX 6351); with none kept, the arm
        // stops before its guest reads the bare outcome.
        let step = self.step;
        let response = match step.guest_response(at as u64) {
            Ok(response) => response,
            Err(missing) => return Err(self.stop(missing)),
        };
        // A matched bridge answer live spilled as a body shifts every later
        // store ordinal: the arm counts it, as live counts its captured
        // outputs, or the next store mints a new path instead of reusing
        // its frozen occurrence. Only a row whose answer spilled counts:
        // unavailable, trapped and mismatched answers never became bodies.
        // A StoredReply carrier uses `store_reply`, which can reuse a
        // prefix occurrence. Count only a newly captured occurrence, once.
        let window = self.window;
        if matches!(&outcome, SelfDispatchOutcome::StoredReply(_)) {
            let Some(reply) = self.replies.iter().find(|reply| {
                window
                    .bridge_calls
                    .get(at)
                    .is_some_and(|row| row.seq == reply.seq)
            }) else {
                let missing = ShadowUnavailable::new(Reason::SourceMissing, "stored_reply_body");
                return Err(self.stop(missing));
            };
            if let Some(bytes) = &reply.body.bytes {
                self.store.import(reply.body.output.output_ref(), bytes)?;
            }
            let output = reply.body.output.clone();
            if !self
                .results
                .iter()
                .any(|held| held.output.path == output.path)
            {
                self.results.push(ArmResult {
                    output: output.clone(),
                    state: reply.body.state,
                    secret: reply.body.secret.clone(),
                    own: false,
                });
                self.spilled += 1;
            }
            if let Some(name) = reply.name.clone() {
                self.bind(name, output.handle, output.path);
            }
        } else if window.bridge_calls.get(at).is_some_and(|row| {
            window
                .outputs
                .iter()
                .any(|output| output.path == bridge_result_output_path(row.seq))
        }) {
            self.spilled += 1;
        }
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
            budget: response.budget,
            view: response.view.clone(),
        })
    }
}

/// Why the arm cannot replay `call` as its run made it, if it cannot (CALLS
/// "nested subtree refusal"): a callable skill, a reader child's spawn or
/// report and a summary run a step or a run of their own, whose calls were
/// recorded after the call's own row, and one matched row cannot replay
/// them; a revealed secret's answer reached the live guest through a view
/// no replay context keeps, by design (FIX 6351).
fn unreplayable(call: &SelfCall) -> Option<ShadowUnavailable> {
    match call {
        SelfCall::SkillsCall(_)
        | SelfCall::ReaderSpawn(_)
        | SelfCall::ReaderReport(_)
        | SelfCall::Summarize(_) => Some(ShadowUnavailable::new(
            Reason::NestedReplayUnsupported,
            call.effect().as_str(),
        )),
        _ if reveals_secret(call) => Some(ShadowUnavailable::new(
            Reason::GuestViewCaptureMissing,
            "reveal_wait",
        )),
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
