//! One committed TASK as the board STREAM publisher reads it.

use crate::Vault;
use crate::context_board::TaskIntentPresence;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::presence_scan::task_presence_for_id;

/// One committed TASK as a board subscriber hears of it: the by-id projection
/// (`task_presence_for_id`), plus the actor an open consult addresses (its
/// `ConsultsToMe` lane).
pub(crate) fn board_task_for_id(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<(TaskIntentPresence, Option<EntityId>)>> {
    let Some(presence) = task_presence_for_id(vault, task_ref)? else {
        return Ok(None);
    };
    let addressee = match super::wire_decode::task_verb_body(vault, task_ref)? {
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
    Ok(Some((presence, addressee)))
}
