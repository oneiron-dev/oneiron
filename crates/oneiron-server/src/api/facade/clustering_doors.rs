//! The typed clustering judgments bind only the caller's own owner proof or
//! agent Grant. HTTP and MCP share these credential-bound engine doors. An
//! owner's judgment records where his request reached this install
//! (`surface`, the host's own reading of it): audit only (FIX 4650).

use super::FacadeApiError;
use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::clustering::*;
use oneiron::memory::{Memory, MemoryResult};
use std::sync::Arc;

async fn judgment<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    surface: ActSurface,
    write: impl FnOnce(Memory<'_>, Option<&AuthenticatedOwner>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else {
        None
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        write(memory.with_owner_surface(surface), owner.as_ref())
    })
    .await
}

pub(crate) async fn vault_cluster_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ClusterProposeRequest,
) -> Listed<ClusterTopologyReceipt> {
    judgment(
        server,
        auth,
        "vault.cluster.propose",
        surface,
        move |memory, owner| memory.cluster_propose(owner, &input),
    )
    .await
}

pub(crate) async fn vault_cluster_merge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ClusterMergeRequest,
) -> Listed<ClusterTopologyReceipt> {
    judgment(
        server,
        auth,
        "vault.cluster.merge",
        surface,
        move |memory, owner| memory.cluster_merge(owner, &input),
    )
    .await
}

pub(crate) async fn vault_cluster_split(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ClusterSplitRequest,
) -> Listed<ClusterTopologyReceipt> {
    judgment(
        server,
        auth,
        "vault.cluster.split",
        surface,
        move |memory, owner| memory.cluster_split(owner, &input),
    )
    .await
}

pub(crate) async fn vault_cluster_resolve_proposal(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: ClusterResolveRequest,
) -> Listed<ClusterTopologyReceipt> {
    judgment(
        server,
        auth,
        "vault.cluster.resolve_proposal",
        surface,
        move |memory, owner| memory.cluster_resolve_proposal(owner, &input),
    )
    .await
}
