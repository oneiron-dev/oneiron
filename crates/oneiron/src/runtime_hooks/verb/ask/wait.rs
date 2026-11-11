//! Wake hints for a host retaining a caller-only verb-hook wait.

use std::sync::Arc;

use super::{ASKS, VerbAskState, author_memory};
use crate::runtime_hooks::InvocationId;
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::task_verb::{TaskAskHandle, TaskAskStatus};
use crate::work_line::TaskWorkTurn;
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
    turn: Option<&Arc<TaskWorkTurn>>,
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
    let status = author_memory(vault, row.author, row.author_class, turn)
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

impl Vault {
    /// Content-free post-commit changes to terminal verb-hook asks. Subscribe
    /// before reading retained waits; this signal conveys no answer or authority.
    pub fn subscribe_verb_hook_ask_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.verb_hook_ask_updates.subscribe()
    }

    pub(crate) fn notify_verb_hook_ask_changes(&self) {
        self.store.verb_hook_ask_updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    pub(crate) fn verb_hook_wait_deadline(
        &self,
        invocation: InvocationId,
        verb: &str,
        actor: EntityId,
        class: HookActorClass,
        ask: EntityId,
    ) -> Result<Option<u64>> {
        let row = {
            let txn = self.store.env.read_txn()?;
            ASKS.get(&self.store, &txn, &invocation.0)?
        };
        let Some(row) = row else { return Ok(None) };
        if row.verb != verb
            || row.actor != actor
            || row.class != class
            || row.ask != ask
            || row.state == VerbAskState::Consumed
            || row.settled_at.is_some()
        {
            return Ok(None);
        }
        author_memory(self, row.author, row.author_class, None).hook_ask_effective_deadline(row.ask)
    }
}
