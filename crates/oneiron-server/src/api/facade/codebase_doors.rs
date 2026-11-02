//! Credential-bound host projections of the typed code snapshot doors
//! (DOOR-118). HTTP, SDK, MCP and code mode all take the owner's proof here;
//! the engine door revalidates it before any id or folder resolves.
use std::sync::Arc;

use oneiron::memory::codebase_doors::*;

use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_code_snapshots_ingest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSnapshotIngestRequest,
) -> Listed<CodeSnapshotView> {
    as_owner(
        server,
        auth,
        "vault.code.snapshots.ingest",
        move |memory, owner| memory.code_snapshot_ingest_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_snapshots_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSnapshotRequest,
) -> Listed<Option<CodeSnapshotView>> {
    // An MCP tool reads repo bytes masked (FIX 7608, ASK 1); the owner's
    // own door reads them as stored.
    let tool = crate::api::mcp_gateway::skill_execution::mcp_call_in_scope();
    as_owner(
        server,
        auth,
        "vault.code.snapshots.get",
        move |memory, owner| {
            if tool {
                memory.code_snapshot_get_projected_as(owner, input)
            } else {
                memory.code_snapshot_get_as(owner, input)
            }
        },
    )
    .await
}

pub(crate) async fn vault_code_snapshots_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSnapshotReadRequest,
) -> Listed<Option<CodeSnapshotPinnedFile>> {
    // An MCP tool reads repo bytes masked (FIX 7608, ASK 1); the owner's
    // own door reads them as stored.
    let tool = crate::api::mcp_gateway::skill_execution::mcp_call_in_scope();
    as_owner(
        server,
        auth,
        "vault.code.snapshots.read",
        move |memory, owner| {
            if tool {
                memory.code_snapshot_read_projected_as(owner, input)
            } else {
                memory.code_snapshot_read_as(owner, input)
            }
        },
    )
    .await
}

pub(crate) async fn vault_code_symbols_definitions(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSnapshotDefinitionsRequest,
) -> Listed<CodeSnapshotDefinitionsView> {
    as_owner(
        server,
        auth,
        "vault.code.symbols.definitions",
        move |memory, owner| memory.code_snapshot_definitions_as(owner, input),
    )
    .await
}
