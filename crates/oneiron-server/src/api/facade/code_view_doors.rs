//! Typed owner projections of linked working views and account-local cache use.
use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::memory::code_view_doors::*;
use std::sync::Arc;

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
