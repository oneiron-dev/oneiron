//! Wake hints for a host retaining a caller-only verb-hook wait.

use super::{ASKS, VerbAskState, author_memory};
use crate::runtime_hooks::InvocationId;
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::task_verb::{TaskAskHandle, TaskAskStatus};
use crate::{EntityId, Result, Vault};

/// Whether a retained call can retry its hook boundary. This grants no
/// permission to run the verb and never consumes the hook's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbHookWaitStatus {
    /// The same call still waits on the same unanswered ask.
    Waiting,
    /// Retry the boundary, which alone decides whether to resume, refuse,
    /// return an already-used result, or wait on a later hook's ask.
    Ready,
    /// No saved call matches this invocation, verb, actor and class. A host
    /// must not mistake this for a fresh invocation of its retained call.
    Unavailable,
}

pub(in crate::runtime_hooks::verb) fn status(
    vault: &Vault,
    invocation: InvocationId,
    verb: &str,
    actor: EntityId,
    class: HookActorClass,
    ask: EntityId,
) -> Result<VerbHookWaitStatus> {
    let row = {
        let txn = vault.store.env.read_txn()?;
        ASKS.get(&vault.store, &txn, &invocation.0)?
    };
    let Some(row) = row else {
        return Ok(VerbHookWaitStatus::Unavailable);
    };
    if row.verb != verb || row.actor != actor || row.class != class {
        return Ok(VerbHookWaitStatus::Unavailable);
    }
    if row.ask != ask || row.state == VerbAskState::Consumed || row.settled_at.is_some() {
        return Ok(VerbHookWaitStatus::Ready);
    }
    // Use the author kept by this exact call, just as its retry does. The
    // caller need not be in the ask's audience. Reading status may settle an
    // elapsed native ask deadline; it never resumes or consumes this call.
    let status = author_memory(vault, row.author, row.author_class, None)
        .tasks_ask_status(TaskAskHandle { group_ref: row.ask });
    Ok(match status {
        Ok(TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. }) => {
            VerbHookWaitStatus::Waiting
        }
        // The boundary reports declined, expired or unreadable asks by its
        // existing rules. A wake hint must not replace those rules.
        _ => VerbHookWaitStatus::Ready,
    })
}
