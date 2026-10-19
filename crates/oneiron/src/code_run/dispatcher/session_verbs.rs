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
//! A verb hook bound to one of these reads cannot run in the room: its
//! receipts would land on record, and the room keeps no hook receipt yet
//! (S01-2). A hook the owner marks blocking hides a read's result when it
//! cannot run (ARCH-0080, DEC-0006 invariant 8), and this lane cannot yet
//! tell a blocking binding from one that fails open. So a read the room
//! serves newly (these four, and the run's search on its door's key) answers
//! only while no hook binds its verb; while one does, it keeps the refusal it
//! had, named [`SESSION_HOOK_UNRECORDED`]. The run's search with no key
//! answers as it always has, and its hooks' skip is named in the log.
//!
//! Nothing here asks where the caller or the vault runs: the door's key
//! carries its caller's Grant and ceiling as the host's own judges made it.

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, SelfAgentVerbCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::{SessionAnswer, SessionRead};
use crate::off_record::OffRecordSession;
use crate::task_verb::sdk::AgentVerb;

use super::HostSelfDispatcher;

/// What a verb hook bound to a run's read in a room did: it did not run,
/// because the room keeps no receipt for it yet (S01-2). It names the hook's
/// log line, and the refusal of a read the room serves newly.
const SESSION_HOOK_UNRECORDED: &str = "session_hook_unrecorded";

/// The code an image hydrate in a room answers until the room keeps
/// served-form receipts (S01-2).
const SESSION_SERVED_FORM_UNRECORDED: &str = "session_served_form_unrecorded";

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
    /// A hydrate that would serve an image in a resolved form, whose
    /// served-form receipt the room does not keep yet.
    ServedFormUnrecorded,
    /// A read the room serves newly, whose verb a hook binds that cannot run
    /// in the room.
    HookUnrecorded,
}

impl SessionReadRefusal {
    fn code(self) -> String {
        match self {
            Self::Unbound => AGENT_VERB_DOOR_UNBOUND.to_owned(),
            Self::Door(code) | Self::Read(code) => code,
            Self::ServedFormUnrecorded => SESSION_SERVED_FORM_UNRECORDED.to_owned(),
            Self::HookUnrecorded => SESSION_HOOK_UNRECORDED.to_owned(),
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
    /// admitted, through the run-entry route, over one view of the room.
    pub(super) fn dispatch_session_read(
        &self,
        read: SessionRead,
        call: &SelfAgentVerbCall,
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
        if let Some(refused) = hooked_read_refused(&binding.session, call.verb.as_str()) {
            return Ok(refused.denied(SelfEffect::AgentVerb));
        }
        // The run-entry route must still stand, as for the run's writes: a
        // search registers its run through it.
        binding.route.revalidate()?;
        let context = binding.session.read_context(&binding.route, key)?;
        let refused = match context.answer(read, self.actor, &call.input) {
            Ok(SessionAnswer::Answered { output, rows }) => {
                return Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
                    output,
                    rows: Some(rows),
                }));
            }
            Ok(SessionAnswer::ServedFormUnrecorded) => SessionReadRefusal::ServedFormUnrecorded,
            Err(refused) => SessionReadRefusal::Read(refused.code),
        };
        Ok(refused.denied(SelfEffect::AgentVerb))
    }
}

/// The refusal of a read the room serves newly (a verb call, or the run's
/// search on its door's key) while a verb hook binds `verb`: that hook cannot
/// run in `session`'s room, and a blocking one would hide the result. `None`
/// while no hook binds it.
fn hooked_read_refused(session: &OffRecordSession<'_>, verb: &str) -> Option<SessionReadRefusal> {
    note_unrun_hooks(session, verb).then_some(SessionReadRefusal::HookUnrecorded)
}

/// The run's search in `session`'s room on its door's key, refused while a
/// verb hook binds it ([`hooked_read_refused`]); `None` while none does.
pub(super) fn hooked_search_refused(session: &OffRecordSession<'_>) -> Option<SelfDispatchOutcome> {
    hooked_read_refused(session, SelfEffect::MemorySearch.as_str())
        .map(|refused| refused.denied(SelfEffect::MemorySearch))
}

/// Whether a verb hook bound to `verb` would run on a run's read in
/// `session`'s room, where none can run yet; when one would, its skip is
/// logged by name, with the verb and nothing of the room.
pub(super) fn note_unrun_hooks(session: &OffRecordSession<'_>, verb: &str) -> bool {
    let unrun = session.verb_hooks_may_run(verb);
    if unrun {
        tracing::info!(
            verb,
            outcome = SESSION_HOOK_UNRECORDED,
            "a verb hook bound to a read in a room did not run"
        );
    }
    unrun
}
