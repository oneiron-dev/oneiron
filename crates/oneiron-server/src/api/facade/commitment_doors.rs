//! Owner-bound projections of the typed commitment lifecycle. The generated
//! HTTP, SDK and MCP doors all use the caller's credential and existing gate.
use super::host_doors::support::Listed;
use super::host_doors::support::owner_listing::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::memory::commitment_doors::{
    CommitmentCloseRequest, CommitmentCreateReceipt, CommitmentCreateRequest,
    CommitmentFulfillRequest, CommitmentRefRequest, CommitmentView, CommitmentWakeProposal,
};
use std::sync::Arc;

pub(crate) async fn vault_commitments_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentCreateRequest,
) -> Listed<CommitmentCreateReceipt> {
    as_owner(
        server,
        auth,
        "vault.commitments.create",
        move |memory, owner| memory.commitments_create_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentRefRequest,
) -> Listed<CommitmentView> {
    as_owner(
        server,
        auth,
        "vault.commitments.get",
        move |memory, owner| memory.commitments_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_instances(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentRefRequest,
) -> Listed<Vec<CommitmentView>> {
    as_owner(
        server,
        auth,
        "vault.commitments.instances",
        move |memory, owner| memory.commitments_instances_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_proposals(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentRefRequest,
) -> Listed<Vec<CommitmentWakeProposal>> {
    as_owner(
        server,
        auth,
        "vault.commitments.proposals",
        move |memory, owner| memory.commitments_proposals_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_fulfill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentFulfillRequest,
) -> Listed<CommitmentView> {
    as_owner(
        server,
        auth,
        "vault.commitments.fulfill",
        move |memory, owner| memory.commitments_fulfill_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentCloseRequest,
) -> Listed<CommitmentView> {
    as_owner(
        server,
        auth,
        "vault.commitments.release",
        move |memory, owner| memory.commitments_release_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_commitments_supersede(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentCloseRequest,
) -> Listed<CommitmentView> {
    as_owner(
        server,
        auth,
        "vault.commitments.supersede",
        move |memory, owner| memory.commitments_supersede_as(owner, input),
    )
    .await
}
