//! Door for `tests/task_ask_role_routing.rs` (ROLES-EVERYWHERE = A): who a
//! task ask's members are put to, and the target its group keeps.

use crate::task_verb::{TaskAskHandle, TaskAskTarget};
use crate::{EntityId, Result, Vault};

/// The actors `handle`'s member TASKs are put to, in member order, and the
/// target its group was admitted at (a role ask's names the role it
/// reached); `None` when `handle` names no ask group.
pub fn ask_group_route(
    vault: &Vault,
    handle: TaskAskHandle,
) -> Result<Option<(Vec<EntityId>, Option<TaskAskTarget>)>> {
    crate::task_verb::ask_group_route(vault, handle.group_ref)
}
