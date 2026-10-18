//! Owner-bound projections of the typed commitment lifecycle. The generated
//! HTTP, SDK and MCP doors all use the caller's credential and existing gate.
use std::sync::Arc;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::commitment_doors::{
    CommitmentCloseRequest, CommitmentCreateReceipt, CommitmentCreateRequest, CommitmentFulfillRequest,
    CommitmentRefRequest, CommitmentView, CommitmentWakeProposal,
};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof, refused};
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
        let caller = super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| act(&memory, &owner)).await
}

pub(crate) async fn vault_commitments_create(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentCreateRequest,
) -> Listed<CommitmentCreateReceipt> {
    as_owner(server, auth, "vault.commitments.create", move |memory, owner| {
        memory.commitments_create_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_get(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentRefRequest,
) -> Listed<CommitmentView> {
    as_owner(server, auth, "vault.commitments.get", move |memory, owner| {
        memory.commitments_get_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_instances(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentRefRequest,
) -> Listed<Vec<CommitmentView>> {
    as_owner(server, auth, "vault.commitments.instances", move |memory, owner| {
        memory.commitments_instances_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_proposals(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentRefRequest,
) -> Listed<Vec<CommitmentWakeProposal>> {
    as_owner(server, auth, "vault.commitments.proposals", move |memory, owner| {
        memory.commitments_proposals_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_fulfill(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentFulfillRequest,
) -> Listed<CommitmentView> {
    as_owner(server, auth, "vault.commitments.fulfill", move |memory, owner| {
        memory.commitments_fulfill_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_release(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentCloseRequest,
) -> Listed<CommitmentView> {
    as_owner(server, auth, "vault.commitments.release", move |memory, owner| {
        memory.commitments_release_as(owner, input)
    }).await
}

pub(crate) async fn vault_commitments_supersede(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: CommitmentCloseRequest,
) -> Listed<CommitmentView> {
    as_owner(server, auth, "vault.commitments.supersede", move |memory, owner| {
        memory.commitments_supersede_as(owner, input)
    }).await
}
