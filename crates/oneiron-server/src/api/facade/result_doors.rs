//! Owner-authenticated retained-result reads. The credential's own memory
//! handle enforces locality; no run is resumed to recover a result body.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::result_doors::*;
use oneiron::memory::{Memory, MemoryResult};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(auth, server, verb)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, oneiron::memory::MemoryError>((owner, caller))
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

pub(crate) async fn vault_results_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResultRunRequest,
) -> Listed<ResultRunStatus> {
    as_owner(
        server,
        auth,
        "vault.results.status",
        move |memory, owner| memory.result_status_as_owner(owner, input),
    )
    .await
}

pub(crate) async fn vault_results_recover(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResultRunRequest,
) -> Listed<ResultRunStatus> {
    as_owner(
        server,
        auth,
        "vault.results.recover",
        move |memory, owner| memory.result_status_as_owner(owner, input),
    )
    .await
}

pub(crate) async fn vault_results_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResultOccurrenceRequest,
) -> Listed<ResultReadView> {
    as_owner(server, auth, "vault.results.read", move |memory, owner| {
        memory.result_read_as_owner(owner, input)
    })
    .await
}

pub(crate) async fn vault_results_slice(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResultSliceRequest,
) -> Listed<ResultSliceView> {
    as_owner(server, auth, "vault.results.slice", move |memory, owner| {
        memory.result_slice_as_owner(owner, input)
    })
    .await
}
