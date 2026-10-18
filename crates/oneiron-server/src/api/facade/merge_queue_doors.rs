//! Credential-bound host projections of the typed speculative merge queue
//! doors (DOOR-132). HTTP, SDK, MCP and code mode all take the owner's proof
//! here; the engine door revalidates it before any id resolves.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::merge_queue_doors::*;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
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

pub(crate) async fn vault_code_merge_queue_enqueue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueEnqueueRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.enqueue",
        move |memory, owner| memory.merge_queue_enqueue_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_stage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.stage",
        move |memory, owner| memory.merge_queue_stage_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_observe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueObserveRequest,
) -> Listed<MergeQueueObservation> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.observe",
        move |memory, owner| memory.merge_queue_observe_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_requeue_survivors(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueRequeueView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.requeue_survivors",
        move |memory, owner| memory.merge_queue_requeue_survivors_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_land_reviewed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.land_reviewed",
        move |memory, owner| memory.merge_queue_land_reviewed_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_settle_slow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueRepoRequest,
) -> Listed<MergeQueuePointersView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.settle_slow",
        move |memory, owner| memory.merge_queue_settle_slow_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_recover(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueRepoRequest,
) -> Listed<MergeQueuePointersView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.recover",
        move |memory, owner| memory.merge_queue_recover_as(owner, input),
    )
    .await
}
