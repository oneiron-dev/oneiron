//! The free-time host doors (FIX 4453): the owner's
//! `vault.free_time.policy.get`, `.policy.set`, `.cycles` and `.cycle`, and
//! the agent's `.policy.set_as` (FIX 11424). `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has; `/v1/owner/free-time` runs the same engine
//! doors. Each owner row takes the vault owner's proof as `/v1/owner` takes
//! it, and each engine door rechecks it in its own read or write; the agent
//! row takes the credential's own agent under its live Grant naming the act.
//!
//! A cycle's sheet joins this server's usage records: the settled calls
//! stamped with that cycle, matched on the stamp, never on a run's name,
//! whether the engine stamped the run before it began or a poster stamped
//! the event. Each entry's `source` says which (FIX 5724); both count
//! alike. No door here reads a response, a prompt or the agent's diary.
use std::sync::Arc;

use oneiron::dreamer_runner::{
    self, FreeTimeCycleRequest, FreeTimeCycleView, FreeTimeCyclesPage, FreeTimeCyclesRequest,
    FreeTimePolicyRequest, FreeTimePolicySetRequest, FreeTimePolicyView, FreeTimeSpendView,
};
use oneiron::memory::MemoryError;

use super::FacadeApiError;
use super::host_doors::support::{Listed, credential_listing};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use crate::usage::UsageError;

pub(crate) async fn vault_free_time_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FreeTimePolicyRequest,
) -> Listed<FreeTimePolicyView> {
    as_owner_naming(
        server,
        auth,
        "vault.free_time.policy.get",
        move |server, owner| {
            dreamer_runner::free_time_policy_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

/// A set records `surface`, where the owner's say-so reached this install,
/// the host's own reading of the request (the facade call's verified
/// headers, or the MCP connection's proven peer), never its input: audit
/// only, never an admission condition (FIX 5721).
pub(crate) async fn vault_free_time_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: oneiron::authority::ActSurface,
    input: FreeTimePolicySetRequest,
) -> Listed<FreeTimePolicyView> {
    as_owner_naming(
        server,
        auth,
        "vault.free_time.policy.set",
        move |server, owner| {
            dreamer_runner::free_time_policy_set_as_owner(server.vault(), owner, surface, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.free_time.policy.set_as` (FIX 11424): an agent sets or clears one
/// agent's free-time policy under its own live Grant naming the act. The
/// credential's own actor calls, as the clustering judgments admit theirs;
/// the engine row admits an agent only, finds that agent's standing Grant
/// and builds its act from it. An agent's act records this install, never
/// where its call reached it.
pub(crate) async fn vault_free_time_policy_set_as(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FreeTimePolicySetRequest,
) -> Listed<FreeTimePolicyView> {
    let caller = match super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.free_time.policy.set_as",
        move |_, _, memory| oneiron::task_verb::sdk::free_time_policy_set_as_agent(&memory, input),
    )
    .await
}

pub(crate) async fn vault_free_time_cycles(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FreeTimeCyclesRequest,
) -> Listed<FreeTimeCyclesPage> {
    as_owner_naming(
        server,
        auth,
        "vault.free_time.cycles",
        move |server, owner| {
            dreamer_runner::free_time_cycles_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_free_time_cycle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FreeTimeCycleRequest,
) -> Listed<Option<FreeTimeCycleView>> {
    as_owner_naming(
        server,
        auth,
        "vault.free_time.cycle",
        move |server, owner| {
            dreamer_runner::free_time_cycle_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)?
                .map(|sheet| {
                    free_time_cycle_with_spend(server, sheet)
                        .map_err(|error| MemoryError::bad_request(error.to_string()))
                })
                .transpose()
        },
        |_| Vec::new(),
    )
    .await
}

/// `sheet` with the spend records this server's usage ledger holds for its
/// cycle, by label. A server that has not bound its usage ledger to an
/// account leaves the spend unmetered: unknown, never zero.
pub(crate) fn free_time_cycle_with_spend(
    server: &SyncServer,
    mut sheet: FreeTimeCycleView,
) -> Result<FreeTimeCycleView, UsageError> {
    if let Some(usage) = server.vault_usage() {
        let read = server.usage_ledger.cycle_settlements(
            usage.owner(),
            usage.vault_id(),
            &sheet.agent,
            &sheet.cycle,
        )?;
        sheet.spend = FreeTimeSpendView::metered(read.settlements, read.complete);
    }
    Ok(sheet)
}
