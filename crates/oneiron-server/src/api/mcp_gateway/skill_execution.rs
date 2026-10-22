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

/// Whether this call runs as an MCP tool's (FIX 7608, ASK 1): a direct tool
/// call, a code-mode call and a verb-ask replay each run inside
/// `execute_agent_verb_input`, which binds [`CALLER`]. A repo door reached
/// this way serves the masked projection; no request field sets it.
pub(crate) fn mcp_call_in_scope() -> bool {
    CALLER.try_with(|_| ()).is_ok()
}

/// The agent this MCP call's verified credential registered (FIX 7608
/// 2b-ii, ASK 1 addition), read before any blocking work: `None` off an
/// MCP call, before the gateway attached its proof, and for every caller
/// that is not a registered agent, so the owner's own identity is never
/// offered as an agent's. A call with `None` still reads masked
/// ([`mcp_call_in_scope`]).
pub(crate) fn mcp_call_recipient() -> Option<oneiron::memory::RepoRevealRecipient> {
    CALLER
        .try_with(|caller| {
            (caller.auth.is_some() && caller.actor_class == oneiron::EdgeActorClass::Agent)
                .then(|| oneiron::memory::RepoRevealRecipient::proven_agent(caller.actor_ref))
        })
        .ok()
        .flatten()
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
