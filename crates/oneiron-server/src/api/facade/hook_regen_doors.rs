//! Credential-bound host projections of the typed hook regeneration doors
//! (DOOR-077): the due list, one binding's regen record, the owner's
//! adoption of the candidate pending on it, his cancel of a waiting
//! decision, his revert of an adoption, and the regen history (FIX 4690,
//! 4691). HTTP, SDK, MCP and code mode all
//! take the owner's proof here, from whichever surface the owner is
//! authenticated on, through the gate `door_admits` runs before any hook;
//! the engine door revalidates it and acts as that caller. No regen runs
//! here, and no record or table is read outside the engine door.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::hook_regen_doors::{
    HookRegenAdoptRequest, HookRegenBindingRequest, HookRegenCancelRequest,
    HookRegenHistoryRequest, HookRegenRevertRequest, HookRegenView,
};
use oneiron::runtime_hooks::{HookRegenCancel, HookRegenReceipt};
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};

use super::host_doors::support::Listed;
use super::host_doors::support::owner_listing::as_owner;
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
