//! Credential-bound host projections of the typed code snapshot doors
//! (DOOR-118). HTTP, SDK, MCP and code mode all take the owner's proof here;
//! the engine door revalidates it before any id or folder resolves.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::codebase_doors::*;
use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::facade_owner(server, auth, verb)
}

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(server, auth, verb)?;
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
