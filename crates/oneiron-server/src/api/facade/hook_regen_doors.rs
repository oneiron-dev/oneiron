//! Credential-bound host projections of the typed hook regeneration doors
//! (DOOR-077): the due list, one binding's regen record, the owner's
//! adoption of the candidate pending on it, the owner's cancel of a waiting
//! decision and revert of an adoption, the regen history (FIX 4690, 4691),
//! and the owner's run of a hook's intent on this host's seat (FIX 4688).
//! HTTP, SDK, MCP and code mode all take the owner's proof here, from whichever surface the owner is
//! authenticated on, through the gate `door_admits` runs before any hook;
//! the engine door revalidates it and acts as that caller, except on due,
//! get and adopt, which take an agent credential to the engine instead while
//! the owner's setting `memory.hook_regen.agent_may_adopt` is on
//! (restriction wave 7, C41). No record or
//! table is read outside the engine door.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::hook_regen_doors::{
    HookRegenAdoptRequest, HookRegenBindingRequest, HookRegenCancelRequest,
    HookRegenHistoryRequest, HookRegenRevertRequest, HookRegenView,
};
use oneiron::memory::{Memory, MemoryResult};
use oneiron::runtime_hooks::{HookRegenCancel, HookRegenReceipt};
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};

use super::host_doors::no_hook_sandbox;
use super::host_doors::support::owner_listing::as_owner;
use super::host_doors::support::{Listed, credential_listing};
use crate::ai_host::hook_regen::ServedHookRegenerator;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The due list's public spelling.
const DUE_VERB: &str = "vault.hooks.regen.due";

/// The record read's public spelling.
const GET_VERB: &str = "vault.hooks.regen.get";

/// The adoption's public spelling.
const ADOPT_VERB: &str = "vault.hooks.regen.adopt";

/// The cancel's public spelling.
const CANCEL_VERB: &str = "vault.hooks.regen.cancel";

/// The revert's public spelling.
const REVERT_VERB: &str = "vault.hooks.regen.revert";

/// The history read's public spelling.
const HISTORY_VERB: &str = "vault.hooks.regen.history";

/// The run's public spelling.
const RUN_VERB: &str = "vault.hooks.regen.run";

/// The due, get and adopt doors for an agent credential (restriction
/// wave 7, C41): the caller's own handle with no owner proof; the engine
/// judges the Grant and the owner's setting. The preflight admitted only
/// the credential's bound actor.
async fn as_granted_agent<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller =
        match super::facade_actor(server, auth).map_err(super::FacadeApiError::into_memory_error) {
            Ok(caller) => caller,
            Err(error) => return (Err(error), Vec::new()),
        };
    credential_listing(server, auth, caller, verb, move |_, _, memory| act(&memory)).await
}

/// Whether this call takes the agent arm of due, get and adopt: an agent
/// credential that is not owner-grade, as the preflight admitted it.
fn is_agent_credential(auth: &CoreAuth) -> bool {
    auth.actor_class() == Some("agent") && !auth.is_owner_grade()
}

pub(crate) async fn vault_hooks_regen_due(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<EntityId>> {
    if is_agent_credential(auth) {
        return as_granted_agent(server, auth, DUE_VERB, |memory| {
            memory.hooks_regen_due_as_reader(None)
        })
        .await;
    }
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
    if is_agent_credential(auth) {
        return as_granted_agent(server, auth, GET_VERB, move |memory| {
            memory.hooks_regen_record_as_reader(None, input)
        })
        .await;
    }
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
    if is_agent_credential(auth) {
        return as_granted_agent(server, auth, ADOPT_VERB, move |memory| {
            memory.hooks_regen_adopt_as_reader(None, input)
        })
        .await;
    }
    as_owner(server, auth, ADOPT_VERB, move |memory, owner| {
        memory.hooks_regen_adopt_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenCancelRequest,
) -> Listed<HookRegenCancel> {
    as_owner(server, auth, CANCEL_VERB, move |memory, owner| {
        memory.hooks_regen_cancel_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_revert(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenRevertRequest,
) -> Listed<PackPutReceipt> {
    as_owner(server, auth, REVERT_VERB, move |memory, owner| {
        memory.hooks_regen_revert_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_hooks_regen_history(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenHistoryRequest,
) -> Listed<Vec<HookRegenReceipt>> {
    as_owner(server, auth, HISTORY_VERB, move |memory, owner| {
        memory.hooks_regen_history_as(owner, input)
    })
    .await
}

/// `vault.hooks.regen.run` (FIX 4688): the owner runs one binding's intent
/// again on this host's hook sandbox and the Coach's seat, off the runtime.
/// The decision lands on the record and enacts nothing.
pub(crate) async fn vault_hooks_regen_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HookRegenBindingRequest,
) -> Listed<Option<HookRegenView>> {
    let handle = tokio::runtime::Handle::current();
    let held = Arc::clone(server);
    as_owner(server, auth, RUN_VERB, move |memory, owner| {
        let runtime = crate::commands::hook_sandbox(&held).map_err(no_hook_sandbox)?;
        let regenerator = ServedHookRegenerator::open(&held, input.binding, handle)?;
        memory.hooks_regen_run_as(owner, input, runtime.as_ref(), &regenerator)
    })
    .await
}
