//! The verb hooks of a call a run serves in its room (WILL L11-01 S01-2c):
//! each forwarded read, and each of the two room writes (FIX 5426), runs
//! inside its row's boundary, in the room, once per call (CALLS-10
//! `session_hook_once_boundary`). What each hook did rides the call's answer
//! (FIX 5425).
//!
//! An anonymous room serves these reads too (FIX 5166). Its route is
//! Discard: each hook's records wait in the stretch's in-memory keep, which
//! its close drops (FIX 5431), never in the room's overlay or in base. A
//! room write never reaches these hooks there; the anonymous rule refuses it
//! first.

use serde_json::Value;

use crate::claim::ScopedReadActorKey;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfAgentVerbCall, SelfCall};
use crate::code_run::{SessionHookDisposition, SessionHookReceipt, SessionHookState};
use crate::error::{Error, Result};
use crate::memory::{MemoryResult, SessionAnswer, SessionRead, SessionReadContext};
use crate::runtime_hooks::{VerbCall, VerbCallScope, VerbHookPre, hook_class};
use crate::task_verb::verb_hook_boundary::{
    row_domain, session_row_call, session_row_post, session_row_pre,
};

use super::super::{ExecutorCallSite, HostSelfDispatcher};

impl HostSelfDispatcher<'_> {
    /// `read` of `call` on `context`, the call's one view of the run's room,
    /// inside the verb hooks bound to its row. The row's boundary runs once,
    /// under the step's invocation, as the door's does on base, and the
    /// effect boundary leaves a forwarded call alone. Each hook reads under
    /// `key`, the key the door admitted, over the room's view, and a rewrite
    /// is read on that same key. A hook's stop is the answer, as
    /// `Error::VerbHook`, a hook's ask pausing the read in the room until
    /// the run makes it again (FIX 5524); a read refused runs no post chain, and keeps its
    /// pre chain's records. The hooks' records are kept once the read is
    /// done, never before it. The answer is the caller's view, as base's row
    /// boundary hands its door, beside what each hook did (FIX 5425).
    pub(super) fn hooked_session_read(
        &self,
        context: &SessionReadContext<'_>,
        read: SessionRead,
        call: &SelfAgentVerbCall,
        key: ScopedReadActorKey,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<(MemoryResult<SessionAnswer>, Vec<SessionHookDisposition>)> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a session read's hooks need a run bound to a session",
            ));
        };
        let (session, route) = (&binding.session, &binding.route);
        let verb = call.verb.as_str();
        let parked = SelfCall::AgentVerb(call.clone());
        let invocation = self.verb_invocation(&parked, site)?;
        // The same call a hook's ask parked names that pause, and resumes
        // it in the room (FIX 5524).
        let resume = self.parked_ask(&parked, site)?;
        let hook_call = session_row_call(self.actor, key, verb, invocation);
        let (pre, mut hooks) =
            session_row_pre(session, route, hook_call, call.input.clone(), resume)?;
        note_unkept(verb, &hooks);
        let pre = pre.map_err(Error::from)?;
        let (output, rows) = match context.answer(read, self.actor, &pre.args) {
            Ok(SessionAnswer::Answered { output, rows }) => (output, rows),
            other => {
                let kept = session.keep_verb_hooks_in_room(route, pre)?;
                note_unkept(verb, &kept);
                hooks.extend(kept);
                return Ok((other, hooks));
            }
        };
        let (view, post) = session_row_post(session, route, pre, output)?;
        note_unkept(verb, &post);
        hooks.extend(post);
        let output = view.map_err(Error::from)?;
        Ok((Ok(SessionAnswer::Answered { output, rows }), hooks))
    }

    /// The pre chain of a room write `call` (FIX 5426), in the room, under
    /// the step's invocation, as a forwarded read's: every hook reads under
    /// `key`, the key the run's door admitted for its caller, or, with none,
    /// on the run actor's own lane over the room's view. A hook's stop is the
    /// answer, as `Error::VerbHook`, and the write stages nothing; a hook's
    /// ask pauses the write in the room until the run makes it again.
    pub(in crate::code_run::dispatcher) fn session_write_pre(
        &self,
        call: &SelfAgentVerbCall,
        key: Option<ScopedReadActorKey>,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<(VerbHookPre, Vec<SessionHookDisposition>)> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a room write's hooks need a run bound to a session",
            ));
        };
        let verb = call.verb.as_str();
        let parked = SelfCall::AgentVerb(call.clone());
        let invocation = self.verb_invocation(&parked, site)?;
        let resume = self.parked_ask(&parked, site)?;
        let hook_call = match key {
            Some(key) => session_row_call(self.actor, key, verb, invocation),
            None => VerbCall {
                verb: verb.to_owned(),
                invocation,
                actor: self.actor.entity_ref(),
                class: hook_class(self.actor.actor_class()),
                scope: None::<VerbCallScope>,
                board_epoch: None,
                turn: None,
                domain: row_domain(verb),
                reader: None,
            },
        };
        let (pre, hooks) = session_row_pre(
            &binding.session,
            &binding.route,
            hook_call,
            call.input.clone(),
            resume,
        )?;
        note_unkept(verb, &hooks);
        Ok((pre.map_err(Error::from)?, hooks))
    }

    /// The post chain of a room write that staged (FIX 5426), over its
    /// answer, in the room: the caller's view and what each hook did. A write
    /// the room staged stays reported as staged: a failure keeping the post
    /// chain's records is logged, not returned, as base's row boundary does
    /// for a committed write; a post hook's stop is the caller's answer.
    pub(in crate::code_run::dispatcher) fn session_write_post(
        &self,
        verb: &str,
        pre: VerbHookPre,
        output: Value,
    ) -> Result<(Value, Vec<SessionHookDisposition>)> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a room write's hooks need a run bound to a session",
            ));
        };
        let staged = output.clone();
        match session_row_post(&binding.session, &binding.route, pre, output) {
            Ok((view, hooks)) => {
                note_unkept(verb, &hooks);
                Ok((view.map_err(Error::from)?, hooks))
            }
            Err(error) => {
                tracing::warn!(verb, %error, "a staged room write's post hooks failed");
                Ok((staged, Vec::new()))
            }
        }
    }

    /// The pre chain's records of a room write that staged nothing: it made
    /// no result, so they are kept as a refused call's are, and no post chain
    /// runs.
    pub(in crate::code_run::dispatcher) fn session_write_keep(
        &self,
        verb: &str,
        pre: VerbHookPre,
    ) -> Result<Vec<SessionHookDisposition>> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a room write's hooks need a run bound to a session",
            ));
        };
        let kept = binding
            .session
            .keep_verb_hooks_in_room(&binding.route, pre)?;
        note_unkept(verb, &kept);
        Ok(kept)
    }
}

/// Names in the log each hook of a call a room served whose consequence its
/// room did not run, or of which its room kept no receipt, beside the
/// answer's own list (FIX 5425). Only the verb, the hook and why; nothing of
/// the room.
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
                "a verb hook on a call in a room left its consequence or its receipt undone"
            );
        }
    }
}
