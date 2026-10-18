//! Credential-bound host projections of the typed hook regeneration doors
//! (DOOR-077): the due list, one binding's regen record, and the owner's
//! adoption of the candidate pending on it. HTTP, SDK, MCP and code mode all
//! take the owner's proof here, from whichever surface the owner is
//! authenticated on, through the gate `door_admits` runs before any hook;
//! the engine door revalidates it and acts as that caller. No regen runs
//! here, and no record or table is read outside the engine door.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::hook_regen_doors::{
    HookRegenAdoptRequest, HookRegenBindingRequest, HookRegenView,
};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The due list's public spelling.
const DUE_VERB: &str = "vault.hooks.regen.due";

/// The record read's public spelling.
const GET_VERB: &str = "vault.hooks.regen.get";

/// The adoption's public spelling.
const ADOPT_VERB: &str = "vault.hooks.regen.adopt";

/// `act` on the caller's own credential-bound handle, under the owner's
/// proof from the request.
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
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        act(&memory, &owner)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_due(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<EntityId>> {
    as_owner(server, auth, DUE_VERB, |memory, owner| {
        memory.hooks_regen_due_as(owner)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenBindingRequest,
) -> Listed<Option<HookRegenView>> {
    as_owner(server, auth, GET_VERB, move |memory, owner| {
        memory.hooks_regen_record_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_adopt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenAdoptRequest,
) -> Listed<PackPutReceipt> {
    as_owner(server, auth, ADOPT_VERB, move |memory, owner| {
        memory.hooks_regen_adopt_as(owner, input)
    })
    .await
}
