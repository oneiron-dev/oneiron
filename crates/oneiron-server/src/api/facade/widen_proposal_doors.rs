//! The host doors of the owner's context-widen proposals:
//! `vault.widen_proposals`, `.approve` and `.decline`. `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call them by the name every host door has, and a tool call, a
//! code-mode call and an SDK call meet one admission: the vault owner's
//! proof, as `/v1/owner/widen-proposals` takes it (`owner_routes::owner`).
//! The engine checks the board proof again in its own write.
//!
//! Each lists its rows (`host_door_lists`): a proposal lives in the widen
//! table, which holds no row, so each lists none; an attempt or a row a
//! context names goes by its ref.
use std::sync::Arc;

use oneiron::agent_dispatch::widen_doors::{
    self, WidenProposalAnswer, WidenProposalView, WidenProposalsRequest, WidenProposalsView,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};

use super::host_doors::support::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `act` off the runtime, as the vault owner: every widen door reads or
/// writes LMDB.
async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = super::owner_binding::facade_owner(server, auth, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&*server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

/// [`as_owner`] for a widen door, which reads no row: beside its answer, an
/// empty list.
async fn as_owner_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> Listed<T> {
    (as_owner(server, auth, verb, act).await, Vec::new())
}

/// `vault.widen_proposals`: the proposals, newest first.
pub(crate) async fn vault_widen_proposals(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WidenProposalsRequest,
) -> Listed<WidenProposalsView> {
    as_owner_listing(
        server,
        auth,
        "vault.widen_proposals",
        move |server, owner| widen_doors::widen_proposals_as_owner(server.vault(), owner, &input),
    )
    .await
}

/// `vault.widen_proposals.approve`: the board above approves one.
pub(crate) async fn vault_widen_proposals_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WidenProposalAnswer,
) -> Listed<WidenProposalView> {
    as_owner_listing(
        server,
        auth,
        "vault.widen_proposals.approve",
        move |server, owner| {
            widen_doors::approve_widen_proposal_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}

/// `vault.widen_proposals.decline`: the board above declines one, for good.
pub(crate) async fn vault_widen_proposals_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WidenProposalAnswer,
) -> Listed<WidenProposalView> {
    as_owner_listing(
        server,
        auth,
        "vault.widen_proposals.decline",
        move |server, owner| {
            widen_doors::decline_widen_proposal_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}
