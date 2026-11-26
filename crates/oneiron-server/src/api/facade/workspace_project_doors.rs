//! Typed doors over the owner's folder-to-PROJECT bindings (RECALL-SESSION-PROJECT; Engine ANSWER
//! RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q3 = A, the owner's act only). Each is the owner's,
//! under the owner's proof, and its change records the owner's act with where it was said (the
//! surface the call itself carried, through `host_door_surface`). The vault keys the folder's
//! digest with its own id; the folder's path never reaches it.
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::session_project::{WorkspaceBindRequest, WorkspaceBinding, WorkspaceUnbindRequest};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_projects_workspace_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: WorkspaceBindRequest,
) -> Listed<WorkspaceBinding> {
    as_owner_naming(
        server,
        auth,
        "vault.projects.workspace.bind",
        move |server, owner| {
            Ok(server
                .vault()
                .bind_workspace_as_owner(owner, Some(surface), input)?)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_projects_workspace_unbind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: WorkspaceUnbindRequest,
) -> Listed<WorkspaceBinding> {
    as_owner_naming(
        server,
        auth,
        "vault.projects.workspace.unbind",
        move |server, owner| {
            Ok(server
                .vault()
                .unbind_workspace_as_owner(owner, Some(surface), &input)?)
        },
        |_| Vec::new(),
    )
    .await
}
