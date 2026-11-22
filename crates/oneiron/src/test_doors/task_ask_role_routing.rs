//! Door for `tests/task_ask_role_routing.rs` (ROLES-EVERYWHERE = A): who a
//! task ask's members are put to, and the role a role ask reached.

use crate::llm::decision::AskRole;
use crate::task_verb::TaskAskHandle;
use crate::{EntityId, Result, Vault};

/// The actors `handle`'s member TASKs are put to, in member order, and the
/// role a role ask reached (`None` for any other ask); `None` when `handle`
/// names no ask group.
pub fn ask_group_route(
    vault: &Vault,
    handle: TaskAskHandle,
) -> Result<Option<(Vec<EntityId>, Option<AskRole>)>> {
    crate::task_verb::ask_group_route(vault, handle.group_ref)
}
