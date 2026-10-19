//! A session-only call's hook ask (FIX 4283; Engine ruling 10-19). The hook
//! asks as on any call: its author opens the ask through the tasks.ask door,
//! and the caller gets Pending. Only the stopped call stays in the session's
//! store, not in the vault: its args, the hook's place and the ask handle.
//! The ask's intent key names a hash of the invocation under this process's
//! own key, never the caller's id. Settlement's drain never runs such a call:
//! only its caller's retry in the same session, in this process, resumes it,
//! and that retry uses the answer up in the session's store, once. The answer
//! is session-scoped: no vault path reads it. After the session ends or the
//! process restarts, nothing resumes, and the ask's own text says so.

use std::sync::Arc;

use serde_json::Value;

use crate::off_record::session_hooks::SessionVerbAsk;
use crate::runtime_hooks::verb::{InvocationId, VerbCall, VerbHookStop};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::task_verb::verb_hook_boundary::HookSession;
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskOptionId, TaskAskQuestion,
    TaskAskSettlementReason, TaskAskSpec, TaskAskStatus,
};
use crate::work_line::TaskWorkTurn;
use crate::{EntityId, Error, MemoryError, Result, Vault};

use super::{
    AskToken, HOLD, PROCEED, Retry, USED, VERB_HOOK_INTENT, author_memory, cut, pending, proceeds,
};

/// What a session-only call's hook ask tells whoever answers it, after the
/// hook's own words.
const SESSION_ASK_NOTE: &str = "This call is off the record: an answer runs it only while its \
     session lasts on this server; after the session ends or the server restarts, the answer \
     runs nothing.";

/// Opens the hook's ask as its author, as [`super::open`] does, and keeps
/// the stopped call in `session`'s store. `write` hands the chain's own rows
/// to the store, in the ask's write, so an answer another try used meanwhile
/// opens no ask. The ask opens on `turn`, the calling operation's task-work
/// turn. `Err(reason)` when the ask door refused: nothing was kept.
#[expect(
    clippy::too_many_arguments,
    reason = "the call, the hook, its place, the args, the label, the session, the call's turn and the chain's write"
)]
pub(in crate::runtime_hooks::verb) fn open(
    vault: &Vault,
    call: &VerbCall,
    hook: (EntityId, &PackHookBinding),
    position: usize,
    args: &Value,
    label: &str,
    session: &HookSession,
    turn: Option<&Arc<TaskWorkTurn>>,
    write: &dyn Fn() -> Result<()>,
) -> Result<std::result::Result<VerbHookStop, String>> {
    let (binding_id, binding) = hook;
    let store = &vault.verb_hook_state.session;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Claim(binding_id));
    what.label = Some(format!("{label} {SESSION_ASK_NOTE}"));
    for (option, text) in [
        (PROCEED, format!("Run {}", cut(&call.verb, 200))),
        (HOLD, "Do not run it".to_owned()),
    ] {
        let option = TaskAskOptionId::new(option)
            .map_err(|_| Error::InvariantViolation("verb hook ask option"))?;
        what.options.insert(option, text);
    }
    let mut spec = TaskAskSpec::shorthand(None, what, None, TaskAskDefault::Hold);
    let hidden = InvocationId(store.hidden_invocation(&session.0, call.invocation.0));
    spec.intent_key = format!(
        "{VERB_HOOK_INTENT}{}/{}",
        hidden.to_hex(),
        binding_id.to_hex()
    );
    let opened = author_memory(vault, binding.author_id(), binding.author_class(), turn)
        .tasks_ask_with_txn_effect(&spec, |_, _| write().map_err(MemoryError::from));
    let receipt = match opened {
        Ok(receipt) => receipt,
        Err(error) => return Ok(Err(format!("{}: {}", error.code, error.message))),
    };
    let group = receipt.handle.group_ref;
    let key = call.invocation.0;
    if receipt.idempotent_replay {
        // The ask stood from an earlier try in this process whose rows did
        // not land here. An unused call of it under the key stands.
        write()?;
        if store
            .ask(vault, &session.0, key)
            .is_some_and(|row| row.ask == group && !row.used)
        {
            return Ok(Ok(pending(call.invocation, group)));
        }
    }
    store.save_ask(
        vault,
        &session.0,
        key,
        SessionVerbAsk {
            verb: call.verb.clone(),
            actor: call.actor,
            class: call.class,
            args: args.clone(),
            position,
            binding: binding_id,
            hook: format!("{}/{}", binding.pack, binding.hook),
            author: binding.author_id(),
            author_class: binding.author_class(),
            ask: group,
            used: false,
        },
    );
    Ok(Ok(pending(call.invocation, group)))
}

/// Reads the call a previous try of this invocation left in `session`, if
/// any, as [`super::retry`] reads a saved one: still open, the same Pending;
/// answered proceed, the call resumes after the asking hook and its commit
/// uses the answer up in the session's store; declined or expired, Skipped.
/// None in this process (another session, or one the server held before it
/// restarted): a fresh call. The ask is read on `turn`.
pub(in crate::runtime_hooks::verb) fn retry(
    vault: &Vault,
    call: &VerbCall,
    session: &HookSession,
    turn: Option<&Arc<TaskWorkTurn>>,
) -> Result<Retry> {
    let key = call.invocation.0;
    let Some(row) = vault.verb_hook_state.session.ask(vault, &session.0, key) else {
        return Ok(Retry::Fresh);
    };
    let skipped = |reason: &str| -> Result<Retry> {
        Ok(Retry::Stop(VerbHookStop::Skipped {
            hook: row.hook.clone(),
            reason: reason.to_owned(),
        }))
    };
    if row.verb != call.verb || row.actor != call.actor || row.class != call.class {
        return skipped("this invocation belongs to another call");
    }
    if row.used {
        return skipped(USED);
    }
    let status = author_memory(vault, row.author, row.author_class, turn)
        .tasks_ask_status(TaskAskHandle { group_ref: row.ask });
    let result = match status {
        Ok(TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. }) => {
            return Ok(Retry::Stop(pending(call.invocation, row.ask)));
        }
        Ok(TaskAskStatus::Settled(result)) => result,
        Err(error) => return skipped(&format!("the hook's ask is unreadable: {}", error.message)),
    };
    if !proceeds(&result) {
        return skipped(match result.settlement.reason {
            TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale => {
                "the hook's ask expired"
            }
            TaskAskSettlementReason::FirstWord | TaskAskSettlementReason::AllResponded => {
                "the hook's ask was declined"
            }
        });
    }
    Ok(Retry::Resume {
        binding: row.binding,
        position: row.position,
        args: row.args,
        token: AskToken {
            key,
            ask: row.ask,
            hook: row.hook,
        },
    })
}

/// Uses up the answer `token` names in `session`'s store, in the resumed
/// chain's commit: false when the session holds no unused call of that ask.
pub(in crate::runtime_hooks::verb) fn use_answer(
    vault: &Vault,
    session: &HookSession,
    token: &AskToken,
) -> bool {
    vault
        .verb_hook_state
        .session
        .use_ask(vault, &session.0, token.key, token.ask)
}
