//! One committed TASK as the board STREAM publisher reads it.

use crate::Vault;
use crate::context_board::TaskIntentPresence;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::presence_scan::task_presence_for_id;

/// One committed TASK as a board subscriber hears of it.
pub(crate) struct BoardTask {
    /// The by-id projection (`task_presence_for_id`).
    pub(crate) presence: TaskIntentPresence,
    /// The actor an open consult addresses (its `ConsultsToMe` lane).
    pub(crate) addressee: Option<EntityId>,
    /// The TASK's durable body revision: it moves on every typed body write,
    /// never on an attempt row's.
    pub(crate) body_revision: u64,
}

pub(crate) fn board_task_for_id(vault: &Vault, task_ref: EntityId) -> Result<Option<BoardTask>> {
    let Some(presence) = task_presence_for_id(vault, task_ref)? else {
        return Ok(None);
    };
    let rtxn = vault.store.env.read_txn()?;
    let addressee = match super::wire_decode::task_verb_body_in(vault, &rtxn, task_ref)? {
        Some(body) if body.task_kind() == super::TaskKind::Consult => match body.assignee {
            Some(
                super::TaskAssignee::Peer { actor_ref }
                | super::TaskAssignee::Child { actor_ref }
                | super::TaskAssignee::Human { actor_ref },
            ) => Some(actor_ref),
            _ => None,
        },
        _ => None,
    };
    let body_revision = super::linear_store::task_revision_in_txn(&vault.store, &rtxn, task_ref)?;
    Ok(Some(BoardTask {
        presence,
        addressee,
        body_revision,
    }))
}
