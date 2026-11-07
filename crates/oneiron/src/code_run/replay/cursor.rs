//! The replay cursor's matching: each call it is offered meets the row at
//! its own bridge position, by seq, effect and canonical request, before
//! the row's stored outcome is handed back. Nothing is dispatched live. A
//! resumed pending step meets its recorded calls by the same match (FIX
//! 7703).

use super::super::payload::{
    decode_self_dispatch_outcome, replay_denied_trap_error, replay_failed_trap_error,
    self_call_request_value,
};
use super::super::spawn_replay::replay_request_match;
use super::super::support::invalid_code_run_replay;
use super::super::types::{SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect};
use super::{CodeRunBridgeCall, CodeRunReplayCursor};
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
        let request = self_call_request_value(&call)?;
        // A spawn row's erased ask answers only from a coherent row (FIX 9180).
        self.validate_spawn_coherence()?;
        // A stored request keeps the handles the side-row wall placed where
        // the live call still holds the secrets (OF-067). This match issues
        // nothing, so a spawn's miss (FIX 7447) is a mismatch here.
        // A re-offered call meets its row by the guest's original request;
        // hooks never run on replay (FIX 1442 H4: match stays on original).
        if !replay_request_match(self.effect, &self.request, &request)?.is_hit() {
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
}

impl SelfDispatcher for CodeRunReplayCursor<'_> {
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        let index = self.next.get();
        let stored = self
            .record
            .bridge_calls
            .get(index)
            .ok_or(invalid_code_run_replay(
                "code-run replay bridge log exhausted",
            ))?;
        let outcome = stored.strict_replay_answer(index as u64, call)?;
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
