//! The original MCP credential context lent to a callable skill's host door.
use std::sync::Arc;

use oneiron::code_run::AgentVerbDoor;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

use super::McpCallContext;
use super::code_mode_verbs::McpCodeModeVerbs;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

tokio::task_local! {
    pub(super) static CALLER: McpCallContext;
}

/// `None` means this is not an MCP call: the facade binds its own credential
/// door. A present but different credential is refused, never downgraded.
pub(crate) fn skill_execution_door(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    run: oneiron::EntityId,
) -> MemoryResult<Option<Arc<dyn AgentVerbDoor>>> {
    CALLER
        .try_with(|caller| {
            if !caller
                .auth
                .as_ref()
                .is_some_and(|bound| bound.same_authority(auth))
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "the skill call's MCP credential changed",
                    &[],
                ));
            }
            Ok(Arc::new(McpCodeModeVerbs::new(server, caller, run)) as Arc<dyn AgentVerbDoor>)
        })
        .ok()
        .transpose()
}
