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
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
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
    as_owner(
        server,
        auth,
        "vault.code.snapshots.get",
        move |memory, owner| memory.code_snapshot_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_snapshots_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSnapshotReadRequest,
) -> Listed<Option<CodeSnapshotPinnedFile>> {
    as_owner(
        server,
        auth,
        "vault.code.snapshots.read",
        move |memory, owner| memory.code_snapshot_read_as(owner, input),
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
