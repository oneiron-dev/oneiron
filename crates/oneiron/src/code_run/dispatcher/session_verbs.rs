//! The reads a run bound to an off-record session serves through the room's
//! view (WILL L11-01, S01-1).
//!
//! A session-bound run forwards no verb through its door: the door runs on
//! the canonical vault, outside the room's route and saver. Of its verb
//! calls, `vault.notes.create` and `vault.claims.upsert` stage in the room
//! (DOOR-127), and the four reads [`session_read`] names read the room
//! through its view ([`crate::memory::SessionReadContext`]), under the key
//! the run's door admits for its caller at each call. Every other verb keeps
//! its refusal. The run's own `vault.search` reads the same way when its door
//! admits it with a key (`ExecutorStorage::search_text_as`).
//!
//! A verb hook bound to one of these reads runs in the room as on base
//! (S01-2c, [`hooks`]): its content reads go through the room's view under
//! the door's key, and its receipt stages in the room's own store. A hook the
//! owner marks blocking hides a read's result when it fails (ARCH-0080,
//! DEC-0006 invariant 8). An outcome that needs canonical work is the hook's
//! own, and the read answers; so does a read whose room keeps no record of
//! its hooks.
//!
//! Nothing here asks where the caller or the vault runs: the door's key
//! carries its caller's Grant and ceiling as the host's own judges made it.

mod hooks;

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, SelfAgentVerbCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::{SessionAnswer, SessionRead};
use crate::task_verb::sdk::AgentVerb;

use super::{ExecutorCallSite, HostSelfDispatcher};

/// The verbs a session-bound run reads through the room's view: an explicit
/// list, never "every verb that writes nothing". A read joins it only with
/// its room enumeration and projection (neighbors, claim lists and history,
/// hybrid search and recall do not have theirs yet).
pub(super) fn session_read(verb: AgentVerb) -> Option<SessionRead> {
    match verb.as_str() {
        "vault.get" => Some(SessionRead::Get),
        "vault.hydrate" => Some(SessionRead::Hydrate),
        "vault.refs.resolve" => Some(SessionRead::RefsResolve),
        "vault.search.bm25" => Some(SessionRead::SearchBm25),
        _ => None,
    }
}

/// Why a read in a room gives no answer: one typed reason per cause, and the
/// one place each becomes the stable code the guest reads.
enum SessionReadRefusal {
    /// The run's host binds no door to admit the read for a caller.
    Unbound,
    /// The door refused the read for its caller, with its own code.
    Door(String),
    /// The read itself refused, with its own Memory code.
    Read(String),
}

impl SessionReadRefusal {
    fn code(self) -> String {
        match self {
            Self::Unbound => AGENT_VERB_DOOR_UNBOUND.to_owned(),
            Self::Door(code) | Self::Read(code) => code,
        }
    }

    fn denied(self, effect: SelfEffect) -> SelfDispatchOutcome {
        SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect,
            outcome: self.code(),
            reason_codes: Vec::new(),
        })
    }
}

impl HostSelfDispatcher<'_> {
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
                .map_err(|refusal| SessionReadRefusal::Door(refusal.code)),
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
        let refused = match self.hooked_session_read(&context, read, call, key, site)? {
            Ok(SessionAnswer::Answered { output, rows }) => {
                return Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
                    output,
                    rows: Some(rows),
                }));
            }
            Err(refused) => SessionReadRefusal::Read(refused.code),
        };
        Ok(refused.denied(SelfEffect::AgentVerb))
    }
}
