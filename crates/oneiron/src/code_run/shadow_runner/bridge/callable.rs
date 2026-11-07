//! A callable branch's arm at the step's recorded callables (FIX 3608): the
//! caller's own program runs again from the step's start, and each
//! `self.skills.call` it makes meets the callable the step's replay context
//! froze for that bridge position. With the load present, the callable's
//! stored file runs again on the sibling runtime the call lends, with the
//! arguments it ran with, its own calls matched against the rows recorded
//! after the call's own row, and the call answers as its row recorded it.
//! With the load absent, the call answers what the live host answers when
//! the skill's entity is not found, its own calls never happen, and the
//! caller's program goes on with its own fallback. A callable the context
//! did not freeze, one whose file was not read, or one that does not run
//! to its recorded end stops the arm; it is never answered otherwise.
//!
//! A delivery branch's arm (FIX 3608) runs the caller's program again the
//! same way, every recorded callable present, and treats one call whose
//! answer delivered a skill's body to the program. With the body present,
//! the call answers as its row recorded it. With the body absent, its row is
//! matched as recorded, and the call answers what the live host answers when
//! the skill is not found: the verb's own not-found refusal, never a cut of
//! the recorded answer. A call with no such answer of its own stops the arm.

use super::super::types::{ShadowUnavailable, ShadowUnavailableReason as Reason};
use super::ShadowBridgeHost;
use crate::code_run::{
    CapturedCallable, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDispatcher, SelfEffect,
    SelfFailedResult,
};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStream, SelfDispatchResponse,
    StepCancellation, bridge_result_output_path,
};
use crate::memory::MemoryError;
use crate::store::sandbox_contract::{SandboxBoundaryContract, SandboxGuestTier};
use crate::task_verb::sdk::AgentVerb;
use crate::{Error, Result};

/// Whether a branch runs the load or the skill body it treats, or leaves
/// it absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArmCallableLoad {
    Present,
    Absent,
}

/// What the call a branch treats is (FIX 3608): a callable's load the
/// step's program called, or a call whose answer delivered a skill's body to
/// the step's program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArmTreatedCall {
    Callable,
    Delivery,
}

/// What a callable or delivery branch's arm does at the step's recorded
/// callables: the call it treats, by its bridge position and kind, whether
/// that load or body is present, and each recorded callable's stored file as
/// its load read it, read and checked before the arm starts (`None` for one
/// no arm can run). Every callable but a treated one runs present.
pub(crate) struct ArmCallables {
    pub(crate) treated: u64,
    pub(crate) kind: ArmTreatedCall,
    pub(crate) load: ArmCallableLoad,
    pub(crate) programs: Vec<(u64, Option<String>)>,
}

impl ArmCallables {
    /// Whether the arm leaves out the treated call of `kind` at bridge
    /// position `position`.
    fn leaves_out(&self, kind: ArmTreatedCall, position: u64) -> bool {
        self.kind == kind && self.treated == position && self.load == ArmCallableLoad::Absent
    }
}

/// What the live host answers a call whose skill's entity is not found:
/// the failure its callable call raises, read by the caller's program.
fn absent_callable_outcome() -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: SelfEffect::SkillsCall,
        error: Error::EntityNotFound.to_string(),
        code: None,
        disk_floor: None,
    })
}

/// What the live host answers a call of `verb` whose skill is not found,
/// for a delivery branch without the skill's body (FIX 3608):
/// `vault.skills.get`'s refusal, the code a missing entity's error carries
/// through the verb's door. `None` for any other call, which has no answer
/// of its own for one skill absent: a library page lists the others, an
/// archive or a restore changes state, and the leader's pattern load that
/// finds no pattern ends its step with no reply.
pub(crate) fn absent_delivery_outcome(verb: Option<AgentVerb>) -> Option<SelfDispatchOutcome> {
    (verb == Some(AgentVerb::VaultSkillsGet)).then(|| {
        SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: SelfEffect::AgentVerb,
            outcome: MemoryError::from(Error::EntityNotFound).code,
            reason_codes: Vec::new(),
        })
    })
}

/// The arm's bridge lent to a recorded callable as its host, as the live
/// host lends itself: the callable's finish answer reaches no one (the call
/// answers as its row recorded it), a value it stores has nowhere to go,
/// and its calls and reads are the arm's.
struct ArmCallableHost<'h> {
    host: &'h mut dyn JsCodeModeHost,
}

impl JsCodeModeHost for ArmCallableHost<'_> {
    fn write_output(&mut self, stream: JsCodeModeStream<'_>, _frame: &[u8]) -> Result<bool> {
        match stream {
            JsCodeModeStream::Store { .. } => Err(Error::InvalidConfig(
                "a callable's store needs a result store".to_owned(),
            )),
            JsCodeModeStream::Finish { .. }
            | JsCodeModeStream::Console
            | JsCodeModeStream::File(_) => Ok(true),
        }
    }

    fn read_recoverable_output(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        self.host.read_recoverable_output(path)
    }

    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        self.host.dispatch_self(call)
    }

    fn dispatch_self_nested(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> Result<SelfDispatchResponse> {
        self.host.dispatch_self_nested(call, runtime)
    }

    fn dispatch_self_nested_cancellable(
        &mut self,
        call: SelfCall,
        runtime: &mut dyn JsCodeModeRuntime,
        cancel: &StepCancellation,
    ) -> Result<SelfDispatchResponse> {
        self.host
            .dispatch_self_nested_cancellable(call, runtime, cancel)
    }
}

impl ShadowBridgeHost<'_> {
    /// `call`, a `self.skills.call` stamped at its bridge position, answered
    /// by `callables` against the callable the step's context froze there:
    /// its row matched first, then its load run present or left absent.
    pub(super) fn dispatch_callable(
        &mut self,
        call: SelfCall,
        callables: &ArmCallables,
        nested: Option<(&mut dyn JsCodeModeRuntime, &StepCancellation)>,
    ) -> Result<SelfDispatchResponse> {
        let at = self.cursor.consumed();
        let position = at as u64;
        let step = self.step;
        let Some(captured) = step.callable_at(position) else {
            let missing = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "skills_call");
            return Err(self.stop(missing));
        };
        // The call is the recorded one: its row matches it as recorded.
        let Ok(outcome) = self.cursor.dispatch(call) else {
            let mismatch = ShadowUnavailable::new(Reason::BridgeReplayMismatch, "skills_call");
            return Err(self.stop(mismatch));
        };
        let response = match step.guest_response(position) {
            Ok(response) => response,
            Err(missing) => return Err(self.stop(missing)),
        };
        if callables.leaves_out(ArmTreatedCall::Callable, position) {
            // Its own calls never happen: the next call is the one after.
            self.cursor.skip_to(captured.nested_end)?;
            self.next_seq = captured.nested_end;
            return Ok(SelfDispatchResponse {
                outcome: absent_callable_outcome(),
                budget: response.budget,
                view: None,
            });
        }
        self.record_matched(at)?;
        self.run_callable(captured, callables, nested)?;
        // Its answer, live spilled as a body, counts as the arm's own spill.
        let window = self.window;
        if window
            .outputs
            .iter()
            .any(|output| output.path == bridge_result_output_path(position))
        {
            self.spilled += 1;
        }
        Ok(SelfDispatchResponse {
            outcome,
            budget: response.budget,
            view: response.view.clone(),
        })
    }

    /// Whether the arm is a delivery branch without the skill's body whose
    /// treated call is at its next bridge position (FIX 3608).
    pub(super) fn leaves_out_delivery(&self) -> bool {
        let position = self.cursor.consumed() as u64;
        self.callables
            .is_some_and(|callables| callables.leaves_out(ArmTreatedCall::Delivery, position))
    }

    /// `call`, the call whose answer delivered a skill's body, in a delivery
    /// branch without that body (FIX 3608): its row matched as recorded,
    /// then answered as the live host answers it when the skill is not found
    /// ([`absent_delivery_outcome`]), with the budget envelope its live guest
    /// read and no hook view. A call with no such answer, or another call
    /// than the recorded one, stops the arm.
    pub(super) fn dispatch_absent_delivery(
        &mut self,
        call: SelfCall,
    ) -> Result<SelfDispatchResponse> {
        let position = self.cursor.consumed() as u64;
        let verb = match &call {
            SelfCall::AgentVerb(verb) => Some(verb.verb),
            _ => None,
        };
        let Some(outcome) = absent_delivery_outcome(verb) else {
            let unanswered =
                ShadowUnavailable::new(Reason::WholeRunUnsupported, "delivery_absence");
            return Err(self.stop(unanswered));
        };
        if self.cursor.dispatch(call).is_err() {
            let mismatch = ShadowUnavailable::new(Reason::BridgeReplayMismatch, "skill_delivery");
            return Err(self.stop(mismatch));
        }
        let step = self.step;
        let response = match step.guest_response(position) {
            Ok(response) => response,
            Err(missing) => return Err(self.stop(missing)),
        };
        Ok(SelfDispatchResponse {
            outcome,
            budget: response.budget,
            view: None,
        })
    }

    /// Runs `captured`'s stored file, as `callables` holds it, on the sibling
    /// runtime `nested` lends, under the caller's clock and seed and the
    /// first-party tier without host services: to its finish, its own calls
    /// matched to the recorded end of them, with no failure or declined TASK
    /// among them, since the live call answered. Else the arm stops.
    fn run_callable(
        &mut self,
        captured: &CapturedCallable,
        callables: &ArmCallables,
        nested: Option<(&mut dyn JsCodeModeRuntime, &StepCancellation)>,
    ) -> Result<()> {
        let source = callables
            .programs
            .iter()
            .find(|(seq, _)| *seq == captured.seq)
            .and_then(|(_, source)| source.as_deref());
        let Some(source) = source else {
            let missing = ShadowUnavailable::new(Reason::SourceMissing, "callable_program");
            return Err(self.stop(missing));
        };
        let Some((runtime, cancel)) = nested else {
            let unlent = ShadowUnavailable::new(Reason::NestedReplayUnsupported, "skills_call");
            return Err(self.stop(unlent));
        };
        let script = crate::skill::callable_script(&captured.args, source)?;
        // The arguments line is the host's prelude, as the live call's is.
        let prepared = crate::code_sandbox::source::prepare_source(&script).with_prelude_lines(1);
        let program = JsCodeModeStep {
            run_id: self.run_id,
            seq: captured.seq,
            script: &script,
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer)
                .without_host_services(),
            determinism: self.determinism,
        };
        let (failed, declined) = (self.hard_failure, self.declined);
        let ran = {
            let mut lent = ArmCallableHost { host: &mut *self };
            runtime.run_prepared_step_cancellable(program, &prepared, &mut lent, cancel)
        };
        if let Some(stopped) = self.stopped.clone() {
            return Err(self.stop(stopped));
        }
        let finished = ran.is_ok_and(|outcome| outcome.done);
        if !finished
            || self.cursor.consumed() as u64 != captured.nested_end
            || self.hard_failure != failed
            || self.declined != declined
        {
            let mismatch = ShadowUnavailable::new(Reason::BridgeReplayMismatch, "callable_calls");
            return Err(self.stop(mismatch));
        }
        Ok(())
    }
}
