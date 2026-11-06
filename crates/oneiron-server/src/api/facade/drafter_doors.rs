//! The drafter host doors (FIX 12569): the owner's `vault.drafters.list`,
//! `.status`, `.policy.set` and `.revert`, and the agent's `.list_as` and
//! `.revert_as`. `host_doors` re-exports them, so the generated HTTP facade
//! handler and the MCP dispatcher call them by the name every host door
//! has. Each owner row takes the vault owner's proof as `/v1/owner` takes
//! it, and each engine door revalidates it in its own read or write; each
//! agent row takes the credential's own agent, whose live Grant naming the
//! act the engine door checks in its own snapshot. An owner door's answer is
//! ids, states, counts and times: it lists complete and empty.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::drafter::{
    self, DrafterListRequest, DrafterPolicy, DrafterPolicySetRequest, DrafterRevertReceipt,
    DrafterRevertRequest, DrafterStatus, DrafterStatusRequest, DrafterVersionView,
};
use oneiron::memory::{MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::support::{Listed, credential_listing, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn owned<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        act(server.vault(), &owner).map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(verb))?
}

/// [`owned`] for a door whose answer is ids, states, counts and times only:
/// it lists complete and empty (`host_door_lists`).
async fn owned_control<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> Listed<T> {
    (owned(server, auth, verb, act).await, Vec::new())
}

pub(crate) async fn vault_drafters_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterListRequest,
) -> Listed<Vec<DrafterVersionView>> {
    owned_control(server, auth, "vault.drafters.list", move |vault, owner| {
        drafter::list_drafters_as_owner(vault, owner, &input)
    })
    .await
}

pub(crate) async fn vault_drafters_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterStatusRequest,
) -> Listed<DrafterStatus> {
    owned_control(
        server,
        auth,
        "vault.drafters.status",
        move |vault, owner| drafter::drafter_status_as_owner(vault, owner, &input),
    )
    .await
}

pub(crate) async fn vault_drafters_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterPolicySetRequest,
) -> Listed<DrafterPolicy> {
    owned_control(
        server,
        auth,
        "vault.drafters.policy.set",
        move |vault, owner| drafter::set_drafter_policy_as_owner(vault, owner, &input),
    )
    .await
}

pub(crate) async fn vault_drafters_revert(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterRevertRequest,
) -> Listed<DrafterRevertReceipt> {
    owned_control(
        server,
        auth,
        "vault.drafters.revert",
        move |vault, owner| drafter::revert_drafter_as_owner(vault, owner, &input),
    )
    .await
}

/// `vault.drafters.list_as`: the credential's own actor calls, and the
/// engine row admits an agent with a live Grant naming the read only.
pub(crate) async fn vault_drafters_list_as(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterListRequest,
) -> Listed<Vec<DrafterVersionView>> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.drafters.list_as",
        move |_, _, memory| drafter::list_drafters_as_agent(&memory, input),
    )
    .await
}

/// `vault.drafters.revert_as`: the credential's own actor calls, and the
/// engine row admits an agent with a live Grant naming the revert only,
/// checked again in the revert's write.
pub(crate) async fn vault_drafters_revert_as(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DrafterRevertRequest,
) -> Listed<DrafterRevertReceipt> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.drafters.revert_as",
        move |_, _, memory| drafter::revert_drafter_as_agent(&memory, input),
    )
    .await
}
