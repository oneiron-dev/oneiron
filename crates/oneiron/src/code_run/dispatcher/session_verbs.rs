//! The reads a run bound to an off-record session serves through the room's
//! view (WILL L11-01, S01-1).
//!
//! A session-bound run forwards no verb through its door: the door runs on
//! the canonical vault, outside the room's route and saver. Of its verb
//! calls, `vault.notes.create` and `vault.claims.upsert` stage in the room
//! (DOOR-127), and the five reads [`session_read`] names read the room
//! through its view ([`crate::memory::SessionReadContext`]), under the key
//! the run's door admits for its caller at each call. `vault.receipts` reads
//! the vault's receipts beside the served forms the room kept (FIX 7355).
//! Every other verb keeps its refusal. The run's own `vault.search` reads the
//! same way when its door admits it with a key
//! (`ExecutorStorage::search_text_as`).
//!
//! A verb hook bound to one of these reads runs in the room as on base
//! (S01-2c, [`hooks`]): its content reads go through the room's view under
//! the door's key, and its receipt stages in the room's own store. A hook the
//! owner marks blocking hides a read's result when it fails (ARCH-0080,
//! DEC-0006 invariant 8). An outcome that needs canonical work is the hook's
//! own, and the read answers; so does a read whose room keeps no record of
//! its hooks.
//!
//! An anonymous room serves the same five reads (FIX 5166): a read that
//! keeps nothing keeps no memory, which is all ARCH-0052 asks of the room.
//! Its retrieval telemetry and its hooks' records take the room's Discard
//! route, and the read keeps no base receipt, query cache, replay body, job
//! or side row of its own. A hydrate that serves an image form needs a
//! served-form receipt, which the room cannot keep, so that hydrate refuses
//! as the room's writes do. Every write and every other verb keeps its
//! refusal.
//!
//! Nothing here asks where the caller or the vault runs: the door's key
//! carries its caller's Grant and ceiling as the host's own judges made it.

mod hooks;

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbRefusal, SelfAgentVerbCall, SelfCall,
    SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::{MemoryError, SessionAnswer, SessionRead};

use super::{ExecutorCallSite, HostSelfDispatcher};

/// Why a read in a room gives no answer: one typed reason per cause, and the
/// one place each becomes the stable code and the reason codes the guest
/// reads.
enum SessionReadRefusal {
    /// The run's host binds no door to admit the read for a caller.
    Unbound,
    /// The door refused the read for its caller, with its own code and the
    /// reason codes it typed.
    Door {
        code: String,
        reason_codes: Vec<String>,
    },
    /// The read itself refused, with its own Memory code and reason codes.
    Read {
        code: String,
        reason_codes: Vec<String>,
    },
}

impl SessionReadRefusal {
    /// The door's refusal of the read, its reason codes kept (FIX
    /// CODE-MODE-DENIAL-REASONS; review round 2 of #10553: they were
    /// dropped).
    fn door(refusal: AgentVerbRefusal) -> Self {
        Self::Door {
            code: refusal.code,
            reason_codes: refusal.reason_codes,
        }
    }

    /// The read's own refusal, its Memory reason codes kept, as a direct
    /// call's refusal keeps them.
    fn read(refused: MemoryError) -> Self {
        Self::Read {
            code: refused.code,
            reason_codes: refused.reason_codes,
        }
    }

    fn denied(self, effect: SelfEffect) -> SelfDispatchOutcome {
        let (outcome, reason_codes) = match self {
            Self::Unbound => (AGENT_VERB_DOOR_UNBOUND.to_owned(), Vec::new()),
            Self::Door { code, reason_codes } | Self::Read { code, reason_codes } => {
                (code, reason_codes)
            }
        };
        SelfDispatchOutcome::Denied(SelfDeniedResult {
            hook_notice: None,
            effect,
            outcome,
            reason_codes,
        })
    }
}

impl HostSelfDispatcher<'_> {
    /// The read `call` is when this run serves it through its room's view:
    /// a verb [`session_read`] names, from a run bound to a session that is
    /// no scoped child, exactly the call `dispatch_agent_verb` hands to
    /// [`Self::dispatch_session_read`]. The anonymous-room rule passes this
    /// call and no other verb (FIX 5166).
    pub(super) fn room_session_read(&self, call: &SelfCall) -> Option<SessionRead> {
        let SelfCall::AgentVerb(call) = call else {
            return None;
        };
        if !matches!(self.storage, ExecutorStorage::Session(_))
            || self.scoped_child_spec().is_some()
        {
            return None;
        }
        call.verb.session_read()
    }

    /// `read`, the verb `call` names, in the run's room: admitted by the
    /// run's door for its caller at this call, then read on the key it
    /// admitted, through the run-entry route, over one view of the room,
    /// inside its row's verb hooks at `site`, the call's place in the run.
    pub(super) fn dispatch_session_read(
        &self,
        read: SessionRead,
        call: &SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a session read needs a run bound to a session",
            ));
        };
        let key = match &self.agent_verbs {
            Some(door) => door
                .admit_session_read(call.verb)
                .map_err(SessionReadRefusal::door),
            None => Err(SessionReadRefusal::Unbound),
        };
        let key = match key {
            Ok(key) => key,
            Err(refused) => return Ok(refused.denied(SelfEffect::AgentVerb)),
        };
        // The run-entry route must still stand, as for the run's writes: a
        // search registers its run through it.
        binding.route.revalidate()?;
        let context = binding.session.read_context(&binding.route, key.clone())?;
        let (answer, hooks) = self.hooked_session_read(&context, read, call, key, site)?;
        let refused = match answer {
            Ok(SessionAnswer::Answered { output, rows }) => {
                return Ok(SelfDispatchOutcome::AgentVerb(
                    AgentVerbAnswer::new(output, Some(rows)).with_hooks(hooks),
                ));
            }
            Err(refused) => SessionReadRefusal::read(refused),
        };
        Ok(refused.denied(SelfEffect::AgentVerb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review round 2 of #10553: a room read the read itself refused reached
    /// the guest with its Memory code alone. Its reason codes now ride with
    /// it, in the order the read gave them, as a direct call's refusal keeps
    /// them (FIX CODE-MODE-DENIAL-REASONS).
    #[test]
    fn a_refused_room_read_keeps_the_reads_reason_codes() {
        let mut refused = MemoryError::new("FORBIDDEN", "the room refused the read", &["ask"]);
        refused.reason_codes = vec![
            "gate.rooms.upkeep.voice".to_owned(),
            "read.revoked".to_owned(),
        ];
        assert_eq!(
            SessionReadRefusal::read(refused).denied(SelfEffect::AgentVerb),
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                hook_notice: None,
                effect: SelfEffect::AgentVerb,
                outcome: "FORBIDDEN".to_owned(),
                reason_codes: vec![
                    "gate.rooms.upkeep.voice".to_owned(),
                    "read.revoked".to_owned(),
                ],
            })
        );
    }

    /// A run whose host binds no door still reads as unbound, with no reason
    /// of its own.
    #[test]
    fn an_unbound_room_read_names_no_reason() {
        assert_eq!(
            SessionReadRefusal::Unbound.denied(SelfEffect::AgentVerb),
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                hook_notice: None,
                effect: SelfEffect::AgentVerb,
                outcome: AGENT_VERB_DOOR_UNBOUND.to_owned(),
                reason_codes: Vec::new(),
            })
        );
    }
}
