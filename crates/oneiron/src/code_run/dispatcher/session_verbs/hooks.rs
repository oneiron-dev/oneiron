//! The verb hooks of a read a run serves in its room (WILL L11-01 S01-2c):
//! each of the four forwarded reads runs inside its row's boundary, in the
//! room, once per call (CALLS-10 `session_hook_once_boundary`).

use crate::claim::ScopedReadActorKey;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfAgentVerbCall, SelfCall};
use crate::code_run::{SessionHookDisposition, SessionHookReceipt, SessionHookState};
use crate::error::{Error, Result};
use crate::memory::{MemoryResult, SessionAnswer, SessionRead, SessionReadContext};
use crate::task_verb::verb_hook_boundary::{session_row_call, session_row_post, session_row_pre};

use super::super::{ExecutorCallSite, HostSelfDispatcher};

impl HostSelfDispatcher<'_> {
    /// `read` of `call` on `context`, the call's one view of the run's room,
    /// inside the verb hooks bound to its row. The row's boundary runs once,
    /// under the step's invocation, as the door's does on base, and the
    /// effect boundary leaves a forwarded call alone. Each hook reads under
    /// `key`, the key the door admitted, over the room's view, and a rewrite
    /// is read on that same key. A hook's stop is the answer, as
    /// `Error::VerbHook`; a read refused runs no post chain, and keeps its
    /// pre chain's records. The hooks' records are kept once the read is
    /// done, never before it. The answer is the caller's view, as base's row
    /// boundary hands its door.
    pub(super) fn hooked_session_read(
        &self,
        context: &SessionReadContext<'_>,
        read: SessionRead,
        call: &SelfAgentVerbCall,
        key: ScopedReadActorKey,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<MemoryResult<SessionAnswer>> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a session read's hooks need a run bound to a session",
            ));
        };
        let (session, route) = (&binding.session, &binding.route);
        let verb = call.verb.as_str();
        if !session.verb_hooks_may_run(verb) {
            return Ok(context.answer(read, self.actor, &call.input));
        }
        let invocation = self.verb_invocation(&SelfCall::AgentVerb(call.clone()), site)?;
        let hook_call = session_row_call(self.actor, key, verb, invocation);
        let (pre, hooks) = session_row_pre(session, route, hook_call, call.input.clone())?;
        note_unkept(verb, &hooks);
        let pre = pre.map_err(Error::from)?;
        let (output, rows) = match context.answer(read, self.actor, &pre.args) {
            Ok(SessionAnswer::Answered { output, rows }) => (output, rows),
            other => {
                note_unkept(verb, &session.keep_verb_hooks_in_room(route, pre)?);
                return Ok(other);
            }
        };
        let (view, hooks) = session_row_post(session, route, pre, output)?;
        note_unkept(verb, &hooks);
        let output = view.map_err(Error::from)?;
        Ok(Ok(SessionAnswer::Answered { output, rows }))
    }
}

/// Names in the log each hook of a forwarded read whose consequence its room
/// did not run, or of which its room kept no receipt: a forwarded answer
/// carries no field for it. Only the verb, the hook and why; nothing of the
/// room.
fn note_unkept(verb: &str, hooks: &[SessionHookDisposition]) {
    for hook in hooks {
        let consequence = match &hook.state {
            SessionHookState::Unavailable { consequence, .. } => Some(consequence.as_str()),
            SessionHookState::Applied { .. }
            | SessionHookState::Refused { .. }
            | SessionHookState::Unread { .. } => None,
        };
        let not_kept = match &hook.receipt {
            SessionHookReceipt::NotKept { why } => Some(*why),
            SessionHookReceipt::Kept { .. } | SessionHookReceipt::NoRun => None,
        };
        if consequence.is_some() || not_kept.is_some() {
            tracing::info!(
                verb,
                hook = hook.hook.as_deref().unwrap_or_default(),
                ?consequence,
                ?not_kept,
                "a verb hook on a read in a room left its consequence or its receipt undone"
            );
        }
    }
}
