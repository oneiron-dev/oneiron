//! The run's own `vault.search` in an off-record room takes its verb hooks
//! in the room (WILL L11-01 S01-2c): the effect boundary's pre and post
//! chains, with the room's view for what a hook reads and the room's own
//! store for its records.
//!
//! Only the search takes them here (CALLS-10 `session_hook_once_boundary`):
//! a forwarded read takes its hooks once, at its row's boundary
//! (`session_verbs`), and every other call a room serves runs none, as
//! before. A search with no key keeps its no-key read: its hooks read on the
//! run's actor's own key over the room's view, and attaching them neither
//! admits a key nor swaps in the keyed search. What each hook did rides the
//! search's answer, in the run's record and in the guest's reply, a hook's
//! changed view included.

use serde_json::Value;

use crate::claim::ScopedReadActorKey;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfCall, SelfDispatchOutcome, SessionHookDisposition};
use crate::error::{Error, Result};
use crate::runtime_hooks::{VerbCall, hook_class};

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{
    HookedCall, Rewritten, hook_args, hook_domain, outcome_view, rewrite, stopped, stopped_view,
};

/// The key the guest's reply carries what each hook did under, beside the
/// search's output.
const HOOKS_KEY: &str = "hooks";

impl HostSelfDispatcher<'_> {
    /// [`Self::enter_verb_hooks`] for a run bound to a room. A rewritten
    /// search decodes as the guest's own and reads on the same key, or none,
    /// as the call it replaces: it names no entity to admit again.
    pub(super) fn enter_room_verb_hooks(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<std::result::Result<(SelfCall, HookedCall), SelfDispatchOutcome>> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a room's verb hooks need a run bound to a session",
            ));
        };
        let effect = call.effect();
        if !matches!(call, SelfCall::MemorySearch(_))
            || !binding.session.verb_hooks_may_run(effect.as_str())
        {
            return Ok(Ok((call, HookedCall(None))));
        }
        let invocation = self.verb_invocation(&call, site)?;
        let args = hook_args(&call)?;
        let hook_call = VerbCall {
            verb: effect.as_str().to_owned(),
            invocation,
            actor: self.actor.entity_ref(),
            class: hook_class(self.actor.actor_class()),
            scope: read_as
                .as_ref()
                .and_then(ScopedReadActorKey::room_turn)
                .map(|turn| format!("room:{}", turn.room.to_hex())),
            board_epoch: None,
            domain: hook_domain(&call),
            reader: read_as,
        };
        let check = |rewritten: &Value| -> Rewritten<()> { rewrite(&call, rewritten).map(|_| ()) };
        // A stop keeps the hooks' records at once; a refusal carries no
        // field for what each did. The search with no key answers when its
        // hooks cannot be read, as it did before they ran in a room.
        let answers_unread = hook_call.reader.is_none();
        let (pre, _) = binding.session.pre_verb_hooks_in_room(
            &binding.route,
            hook_call,
            args.clone(),
            &check,
            answers_unread,
        )?;
        let pre = match pre {
            Ok(pre) => pre,
            Err(stop) => return Ok(Err(stopped(effect, stop))),
        };
        if pre.args == args {
            return Ok(Ok((call, HookedCall(Some(pre)))));
        }
        let rewritten = rewrite(&call, &pre.args).map_err(|reason| {
            Error::InvalidConfig(format!("{} rewrite: {reason}", effect.as_str()))
        })?;
        Ok(Ok((rewritten, HookedCall(Some(pre)))))
    }

    /// [`Self::leave_verb_hooks`] for a run bound to a room: the post chain
    /// over the guest's view, in the room, which keeps the call's hook
    /// records once the search answered; then what every hook of the call
    /// did, onto the search's answer. A changed view carries it too. A call
    /// refused, failed or parked made no result: its pre chain's records are
    /// kept, and no post chain runs.
    pub(super) fn leave_room_verb_hooks(
        &self,
        hooked: HookedCall,
        mut outcome: SelfDispatchOutcome,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a room's verb hooks need a run bound to a session",
            ));
        };
        let Some(pre) = hooked.0 else {
            return Ok(outcome);
        };
        let view = match &outcome {
            SelfDispatchOutcome::Denied(_)
            | SelfDispatchOutcome::Failed(_)
            | SelfDispatchOutcome::DurableWait(_) => None,
            answered => outcome_view(answered),
        };
        let Some(view) = view else {
            binding
                .session
                .keep_verb_hooks_in_room(&binding.route, pre)?;
            return Ok(outcome);
        };
        let answers_unread = pre.call().reader.is_none();
        let (seen, hooks) = binding.session.post_verb_hooks_in_room(
            &binding.route,
            pre,
            view.clone(),
            answers_unread,
        )?;
        let seen = seen.unwrap_or_else(|stop| stopped_view(&stop));
        if seen != view {
            *self.hook_view.borrow_mut() = Some(with_hooks(seen, &hooks)?);
        }
        if let SelfDispatchOutcome::MemorySearch(result) = &mut outcome {
            result.hooks = hooks;
        }
        Ok(outcome)
    }
}

/// `view`, the guest's view a hook changed, with what each hook did beside
/// its output, where the search's own reply carries it, so the guest reads it
/// whichever reply it gets. A view whose output is gone carries it on top.
fn with_hooks(mut view: Value, hooks: &[SessionHookDisposition]) -> Result<Value> {
    if hooks.is_empty() {
        return Ok(view);
    }
    let hooks = serde_json::to_value(hooks).map_err(|error| {
        Error::InvalidConfig(format!("verb hook dispositions do not encode: {error}"))
    })?;
    if let Some(output) = view.get_mut("output").and_then(Value::as_object_mut) {
        output.insert(HOOKS_KEY.to_owned(), hooks);
    } else if let Some(view) = view.as_object_mut() {
        view.insert(HOOKS_KEY.to_owned(), hooks);
    }
    Ok(view)
}
