//! Typed owner projections of linked working views and account-local cache use.
use super::host_doors::support::owner_action::as_owner;
use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::memory::code_view_doors::*;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
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

fn not_a_view_editor(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is a live Owner's, or a Grant holder's whose Grant is bound to the view"),
        &["Present an Owner's credential, or an agent's own credential under its Grant."],
    )
}

/// MCP's filtered gate judges no channel caveat; the facade's lane guard
/// does, before the view edit door binds its caller.
fn view_edit_lane(auth: &CoreAuth) -> MemoryResult<()> {
    auth.require_lane_record_scope().map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a channel-bound credential reaches no working view edit door",
            &[],
        )
    })
}

/// The check the view edit row's door runs before its pre chain
/// (`door_admits`): the lane guard, then a credential that binds a
/// principal. A host root alone binds none. Its Grant is the engine's.
pub(super) fn view_editor_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    view_edit_lane(auth)?;
    super::owner_binding::facade_caller_or(server, auth, || not_a_view_editor(verb)).map(drop)
}

/// `vault.code.views.edit` (row 6 WORKING-VIEW-EDIT): the caller bound from
/// its own credential, the owner's proof when it carries one, else the
/// engine's Grant arm, run on that credential's own lane.
pub(crate) async fn vault_code_views_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: CodeViewEditRequest,
) -> Listed<CodeViewEdit> {
    const VERB: &str = "vault.code.views.edit";
    let bound = || {
        view_edit_lane(auth)?;
        let caller =
            super::owner_binding::facade_caller_or(server, auth, || not_a_view_editor(VERB))?;
        let proof = match super::owner_binding::facade_owner(server, auth, VERB) {
            Ok(owner) => CodeViewEditProof::Owner(owner),
            Err(_) => CodeViewEditProof::Grant,
        };
        Ok::<_, MemoryError>((caller, proof))
    };
    let (caller, proof) = match bound() {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        memory.code_view_edit_as(&proof, input)
    })
    .await
}
