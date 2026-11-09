//! The host doors of the Steward rows (untangle 6.3 and 6.6, after 4.2):
//! the member asks a shared vault's Steward files and its Owners and Admins
//! apply or decline (`vault.members.ask*`), under the caller's own shared
//! person proof as the other `vault.members.*` doors take it; and the
//! owner's narrowing of a system agent's grant and read of the engine-control
//! receipts, under the vault owner's proof. `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has. Each engine door checks its grant again in its
//! own writer.
use std::sync::Arc;

use oneiron::federation::{SharedActExecutionReceipt, SharedMemberAsk};
use oneiron::task_verb::sdk::{
    self, EmptyRequest, EngineControlChangeEntry, EngineDefaultGrantEntry,
    SharedMemberAskIdRequest, SharedMemberAskRequest, SharedVaultRequest,
    SystemAgentGrantNarrowRequest, SystemAgentGrantNarrowed,
};

use super::host_doors::support::{Listed, MaybeListed};
use super::legal_hold_doors::as_owner_naming;
use super::shared_act_doors::{as_person_naming, person, receipt_rows, with_slips};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.members.ask`: a Steward files one member ask; no membership
/// changes, so it lists no row.
pub(crate) async fn vault_members_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberAskRequest,
) -> MaybeListed<SharedMemberAsk> {
    const VERB: &str = "vault.members.ask";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, steward| sdk::ask_shared_member_as(server.vault(), &steward, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.asks`: the asks the caller may see; the asks live in a
/// side table, so it lists no row.
pub(crate) async fn vault_members_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<SharedMemberAsk>> {
    const VERB: &str = "vault.members.asks";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, reader| sdk::read_shared_member_asks(server.vault(), &reader, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.asks.apply`: an Owner or Admin applies an ask through the
/// membership door it names, with the host's slip issuer, listing the rows
/// the change's receipt names.
pub(crate) async fn vault_members_asks_apply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberAskIdRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.asks.apply";
    let vault = Arc::clone(server);
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, applier| {
            with_slips(server, VERB, |slips| {
                sdk::apply_shared_member_ask_as(server.vault(), &applier, Some(slips), input)
            })
        },
        move |receipt| receipt_rows(vault.vault(), receipt),
    )
    .await
}

/// `vault.members.asks.decline`: an Owner or Admin declines an ask; no
/// membership changes, so it lists no row.
pub(crate) async fn vault_members_asks_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedMemberAskIdRequest,
) -> MaybeListed<SharedMemberAsk> {
    const VERB: &str = "vault.members.asks.decline";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, applier| sdk::decline_shared_member_ask_as(server.vault(), &applier, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.agents.grants.narrow`: the owner narrows or revokes a system
/// agent's Steward grant, listing the agent and the narrower grant it minted.
pub(crate) async fn vault_agents_grants_narrow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SystemAgentGrantNarrowRequest,
) -> Listed<SystemAgentGrantNarrowed> {
    let agent = input.agent;
    as_owner_naming(
        server,
        auth,
        "vault.agents.grants.narrow",
        move |server, owner| sdk::narrow_system_agent_grant_as(server.vault(), owner, input),
        move |narrowed| match narrowed {
            SystemAgentGrantNarrowed::Narrowed {
                grant: Some(grant), ..
            } => vec![agent, *grant],
            _ => vec![agent],
        },
    )
    .await
}

/// `vault.engine.controls.changes`: the owner reads the engine-control
/// receipts; they live in a side table, so it lists no row.
pub(crate) async fn vault_engine_controls_changes(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<EngineControlChangeEntry>> {
    as_owner_naming(
        server,
        auth,
        "vault.engine.controls.changes",
        move |server, owner| sdk::engine_control_changes_as(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}

/// `vault.engine.defaults`: the owner reads the grants the engine stood by
/// default; each lists its grant row.
pub(crate) async fn vault_engine_defaults(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<EngineDefaultGrantEntry>> {
    as_owner_naming(
        server,
        auth,
        "vault.engine.defaults",
        move |server, owner| sdk::engine_default_grants_as(server.vault(), owner, input),
        |entries| entries.iter().map(|entry| entry.grant).collect(),
    )
    .await
}
