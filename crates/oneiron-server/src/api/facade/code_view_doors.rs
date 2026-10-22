//! Typed owner projections of linked working views and account-local cache use.
use super::FacadeApiError;
use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::code_view_doors::*;
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use std::sync::Arc;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = super::owner_binding::facade_owner(server, auth, verb)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    // The agent an MCP call's verified credential registered, read here on
    // the async side: the blocking closure cannot see the call's task-local
    // (FIX 8960). Its per-file reads that say why may ask for real bytes.
    let recipient = crate::api::mcp_gateway::skill_execution::mcp_call_recipient();
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        let memory = match recipient {
            Some(recipient) => memory.for_repo_reveal_recipient(recipient),
            None => memory,
        };
        act(&memory, &owner)
    })
    .await
}

pub(crate) async fn vault_code_views_materialize(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewMaterializeRequest,
) -> Listed<CodeWorkingView> {
    // An MCP tool reads repo bytes masked (FIX 7608, ASK 1); the owner's
    // own door reads them as stored.
    let tool = crate::api::mcp_gateway::skill_execution::mcp_call_in_scope();
    as_owner(
        server,
        auth,
        "vault.code.views.materialize",
        move |memory, owner| {
            if tool {
                memory.code_view_materialize_projected_as(owner, input)
            } else {
                memory.code_view_materialize_as(owner, input)
            }
        },
    )
    .await
}

pub(crate) async fn vault_code_views_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewRequest,
) -> Listed<CodeWorkingView> {
    as_owner(
        server,
        auth,
        "vault.code.views.get",
        move |memory, owner| memory.code_view_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_views_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewReadRequest,
) -> Listed<CodeViewFileBytes> {
    // An MCP tool reads repo bytes masked (FIX 7608, ASK 1); the owner's
    // own door reads them as stored.
    let tool = crate::api::mcp_gateway::skill_execution::mcp_call_in_scope();
    as_owner(
        server,
        auth,
        "vault.code.views.read",
        move |memory, owner| {
            if tool {
                memory.code_view_read_projected_as(owner, input)
            } else {
                memory.code_view_read_as(owner, input)
            }
        },
    )
    .await
}

pub(crate) async fn vault_code_views_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewActionRequest,
) -> Listed<CodeViewAction> {
    as_owner(
        server,
        auth,
        "vault.code.views.action",
        move |memory, owner| memory.code_view_action_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_views_build(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewBuildRequest,
) -> Listed<CodeCacheOutcome> {
    as_owner(
        server,
        auth,
        "vault.code.views.build",
        move |memory, owner| memory.code_view_build_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_cache_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeCacheReadRequest,
) -> Listed<CodeCacheOutcome> {
    as_owner(
        server,
        auth,
        "vault.code.cache.get",
        move |memory, owner| memory.code_cache_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_cache_reuse(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeViewBuildRequest,
) -> Listed<CodeCacheOutcome> {
    as_owner(
        server,
        auth,
        "vault.code.cache.reuse",
        move |memory, owner| memory.code_cache_reuse_as(owner, input),
    )
    .await
}
