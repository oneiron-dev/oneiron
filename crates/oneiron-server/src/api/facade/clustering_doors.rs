//! The typed clustering judgments bind only the caller's own owner proof or
//! agent Grant. HTTP and MCP share these credential-bound engine doors.

use std::sync::Arc;
use oneiron::memory::{Memory, MemoryResult};
use oneiron::memory::clustering::*;
use oneiron::consent::AuthenticatedOwner;
use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn judgment<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    write: impl FnOnce(Memory<'_>, Option<&AuthenticatedOwner>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else { None };
    credential_listing(server, auth, caller, verb, move |_, _, memory| write(memory, owner.as_ref())).await
}

pub(crate) async fn vault_cluster_propose(server: &Arc<SyncServer>, auth: &CoreAuth, input: ClusterProposeRequest) -> Listed<ClusterTopologyReceipt> {
    judgment(server, auth, "vault.cluster.propose", move |memory, owner| memory.cluster_propose(owner, &input)).await
}

pub(crate) async fn vault_cluster_merge(server: &Arc<SyncServer>, auth: &CoreAuth, input: ClusterMergeRequest) -> Listed<ClusterTopologyReceipt> {
    judgment(server, auth, "vault.cluster.merge", move |memory, owner| memory.cluster_merge(owner, &input)).await
}

pub(crate) async fn vault_cluster_split(server: &Arc<SyncServer>, auth: &CoreAuth, input: ClusterSplitRequest) -> Listed<ClusterTopologyReceipt> {
    judgment(server, auth, "vault.cluster.split", move |memory, owner| memory.cluster_split(owner, &input)).await
}

pub(crate) async fn vault_cluster_resolve_proposal(server: &Arc<SyncServer>, auth: &CoreAuth, input: ClusterResolveRequest) -> Listed<ClusterTopologyReceipt> {
    judgment(server, auth, "vault.cluster.resolve_proposal", move |memory, owner| memory.cluster_resolve_proposal(owner, &input)).await
}
