//! The cursor that replays a code run's recorded bridge calls in order and
//! answers each with its stored outcome, never a live host effect.

use std::cell::Cell;

use super::super::payload::{
    decode_self_dispatch_outcome, replay_denied_trap_error, replay_failed_trap_error,
    self_call_request_value,
};
use super::super::spawn_replay::replay_request_match;
use super::super::support::invalid_code_run_replay;
use super::super::types::{SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect};
use super::CodeRunReplayRecord;
use crate::Result;

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
        let index = self.next.get();
        let stored = self
            .record
            .bridge_calls
            .get(index)
            .ok_or(invalid_code_run_replay(
                "code-run replay bridge log exhausted",
            ))?;
        if stored.seq != index as u64 {
            return Err(invalid_code_run_replay("code-run replay bridge seq drift"));
        }
        if stored.effect != call.effect() {
            return Err(invalid_code_run_replay("code-run replay effect mismatch"));
        }

        // ONE-1686: replay re-stamps the HOST-owned bridge identity from the
        // PERSISTED row — its seq and its start clock — exactly as the live
        // bridge stamps it at dispatch. Guest code supplies neither on either
        // path, so a replayed speech call cannot claim a different position or
        // timestamp than the one its bubble was written under, and an
        // unstamped re-dispatch cannot fail the comparison below for a
        // difference the guest was never allowed to control.
        let call = call.with_bridge_stamp(stored.seq, stored.started_at_ms);
        let request = self_call_request_value(&call)?;
        // A spawn row's erased ask answers only from a coherent row (FIX 9180).
        stored.validate_spawn_coherence()?;
        // A stored request keeps the handles the side-row wall placed where
        // the live call still holds the secrets (OF-067). This cursor issues
        // nothing, so a spawn's miss (FIX 7447) is a mismatch here.
        // A re-offered call meets its row by the guest's original request;
        // hooks never run on replay (FIX 1442 H4: match stays on original).
        if !replay_request_match(stored.effect, &stored.request, &request)?.is_hit() {
            return Err(invalid_code_run_replay("code-run replay request mismatch"));
        }
        // A cursor can be built from an in-memory record that never passed the
        // codec. Recheck speech effect/request/result coherence here before the
        // stored outcome can reach the guest.
        stored.validate_speech_coherence()?;

        let outcome = decode_self_dispatch_outcome(&stored.outcome)?;
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
