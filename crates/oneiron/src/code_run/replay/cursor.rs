//! The cursor that replays a code run's recorded bridge calls in order and
//! answers each with its stored outcome, never a live host effect. Each call
//! meets the row at its own bridge position, by seq, effect and canonical
//! request. A resumed pending step meets its recorded calls by the same match
//! (FIX 7703).

use std::cell::Cell;

use super::super::payload::{
    decode_self_dispatch_outcome, replay_denied_trap_error, replay_failed_trap_error,
    self_call_request_value,
};
use super::super::spawn_replay::replay_request_match;
use super::super::support::invalid_code_run_replay;
use super::super::types::{SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect};
use super::{CodeRunBridgeCall, CodeRunReplayRecord};
use crate::Result;

impl CodeRunBridgeCall {
    /// This row's stored outcome for `call`, the call made at bridge
    /// position `index`, by the cursor's strict match: the row sits at that
    /// position, keeps the call's effect, and the call stamped as the row
    /// was meets its request. A spawn's miss is a mismatch, never a live
    /// call. A resumed pending step's replay shares the match (FIX 7703).
    pub(crate) fn strict_replay_answer(
        &self,
        index: u64,
        call: SelfCall,
    ) -> Result<SelfDispatchOutcome> {
        self.strict_replay_answer_held(index, call, None)
    }

    /// [`Self::strict_replay_answer`] for a call whose input `held` may
    /// stand for (FIX 22096): an action's call it holds meets its row by the
    /// request the action recorded for it, the whole input's digests.
    pub(crate) fn strict_replay_answer_held(
        &self,
        index: u64,
        call: SelfCall,
        held: Option<&crate::code_run::actions::ActionBlobInput>,
    ) -> Result<SelfDispatchOutcome> {
        if self.seq != index {
            return Err(invalid_code_run_replay("code-run replay bridge seq drift"));
        }
        if self.effect != call.effect() {
            return Err(invalid_code_run_replay("code-run replay effect mismatch"));
        }

        // ONE-1686: replay re-stamps the HOST-owned bridge identity from the
        // PERSISTED row — its seq and its start clock — exactly as the live
        // bridge stamps it at dispatch. Guest code supplies neither on either
        // path, so a replayed speech call cannot claim a different position or
        // timestamp than the one its bubble was written under, and an
        // unstamped re-dispatch cannot fail the comparison below for a
        // difference the guest was never allowed to control.
        let call = call.with_bridge_stamp(self.seq, self.started_at_ms);
        let request = match (held, &call) {
            (Some(held), SelfCall::AgentVerb(verb)) if held.holds(verb.verb, &verb.input) => {
                held.request_value()
            }
            _ => self_call_request_value(&call)?,
        };
        // A spawn row's erased ask answers only from a coherent row (FIX 9180).
        self.validate_spawn_coherence()?;
        // A stored request keeps the handles the side-row wall placed where
        // the live call still holds the secrets (OF-067). This match issues
        // nothing, so a spawn's miss (FIX 7447) is a mismatch here.
        // A re-offered call meets its row by the guest's original request;
        // hooks never run on replay (FIX 1442 H4: match stays on original).
        // A call whose host held its input as a file meets the row of the
        // same call sent whole, and the reverse, by the whole input's
        // digests (FIX 22096).
        let held_hit = || {
            self.effect == SelfEffect::AgentVerb
                && crate::code_run::actions::held_request_form(&self.request).is_some_and(
                    |stored| Some(stored) == crate::code_run::actions::held_request_form(&request),
                )
        };
        if !replay_request_match(self.effect, &self.request, &request)?.is_hit() && !held_hit() {
            return Err(invalid_code_run_replay("code-run replay request mismatch"));
        }
        // A row can come from an in-memory record that never passed the
        // codec. Recheck speech effect/request/result coherence here before the
        // stored outcome can reach the guest.
        self.validate_speech_coherence()?;

        decode_self_dispatch_outcome(&self.outcome)
    }

    /// This row's stored outcome, decoded.
    pub(crate) fn recorded_outcome(&self) -> Result<SelfDispatchOutcome> {
        decode_self_dispatch_outcome(&self.outcome)
    }

    /// The canonical request `call` meets this row by (L8-23): the call
    /// stamped as the row was, encoded as the strict match encodes it.
    pub(crate) fn replay_request_value(&self, call: SelfCall) -> Result<rmpv::Value> {
        self_call_request_value(&call.with_bridge_stamp(self.seq, self.started_at_ms))
    }
}

/// Cursor that replays bridge calls from a stored record without invoking live host effects.
pub struct CodeRunReplayCursor<'a> {
    pub(super) record: &'a CodeRunReplayRecord,
    pub(super) next: Cell<usize>,
}

impl<'a> CodeRunReplayCursor<'a> {
    #[must_use]
    pub const fn new(record: &'a CodeRunReplayRecord) -> Self {
        Self {
            record,
            next: Cell::new(0),
        }
    }

    #[must_use]
    pub fn consumed(&self) -> usize {
        self.next.get()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.consumed() == self.record.bridge_calls.len()
    }
}

impl SelfDispatcher for CodeRunReplayCursor<'_> {
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        self.dispatch_requested(call, None)
    }
}

impl CodeRunReplayCursor<'_> {
    /// [`SelfDispatcher::dispatch`] for an action's call whose input
    /// `held` stands for (FIX 22096): its row meets the call by the request
    /// the action recorded for it, the whole input's digests.
    pub(crate) fn dispatch_held(
        &self,
        call: SelfCall,
        held: &crate::code_run::actions::ActionBlobInput,
    ) -> Result<SelfDispatchOutcome> {
        self.dispatch_requested(call, Some(held))
    }

    fn dispatch_requested(
        &self,
        call: SelfCall,
        held: Option<&crate::code_run::actions::ActionBlobInput>,
    ) -> Result<SelfDispatchOutcome> {
        let index = self.next.get();
        let stored = self
            .record
            .bridge_calls
            .get(index)
            .ok_or(invalid_code_run_replay(
                "code-run replay bridge log exhausted",
            ))?;
        let outcome = stored.strict_replay_answer_held(index as u64, call, held)?;
        self.next.set(index + 1);
        match outcome {
            // A refused SDK verb reached the guest as a typed refusal it could
            // handle, so replay hands back that same refusal, not a gate trap.
            SelfDispatchOutcome::Denied(result)
                if stored.effect == SelfEffect::AgentVerb
                    && result.effect == SelfEffect::AgentVerb =>
            {
                Ok(SelfDispatchOutcome::Denied(result))
            }
            // So did a host door's refusal of a call the run serves itself. A
            // gate's denial carries the gate's own outcome word and replays as
            // the trap it was; a door's code is never one.
            SelfDispatchOutcome::Denied(result)
                if crate::error::GateDenialOutcome::parse(&result.outcome).is_none() =>
            {
                Ok(SelfDispatchOutcome::Denied(result))
            }
            SelfDispatchOutcome::Denied(result) => Err(replay_denied_trap_error(&result)),
            SelfDispatchOutcome::Failed(result) => Err(replay_failed_trap_error(&result)),
            outcome => Ok(outcome),
        }
    }
}
