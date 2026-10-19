//! The host doors of the owner's agent grant rows (FIX 5628):
//! `vault.agents.grants.mint` and `.revoke`. `host_doors` re-exports them,
//! so the generated HTTP facade handler and the MCP dispatcher call them by
//! the name every host door has, and a tool call, a code-mode call and an
//! SDK call meet one admission: the vault owner's proof, as
//! `/v1/owner/agent-grants` takes it (`owner_routes::owner`), never a
//! person's or an agent's. Each engine door rechecks that proof in its own
//! writer and records the owner's act with `surface`, where his say-so
//! reached this install (`host_door_surface`). Each lists the grant row it
//! wrote (`host_door_lists`).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::task_verb::sdk::{
    self, AgentGrantMintRequest, AgentGrantMinted, AgentGrantRevokeRequest, AgentGrantRevoked,
};

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.agents.grants.mint`: the owner grants a named agent his explicit
/// scope, listing the grant row it wrote.
pub(crate) async fn vault_agents_grants_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AgentGrantMintRequest,
) -> Listed<AgentGrantMinted> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.grants.mint",
        move |server, owner| sdk::mint_agent_grant_as(server.vault(), owner, surface, input),
        |minted| vec![minted.grant.grant_ref],
    )
    .await
}

/// `vault.agents.grants.revoke`: the owner revokes one agent grant, listing
/// the grant row it names.
pub(crate) async fn vault_agents_grants_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AgentGrantRevokeRequest,
) -> Listed<AgentGrantRevoked> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.grants.revoke",
        move |server, owner| sdk::revoke_agent_grant_as(server.vault(), owner, surface, input),
        |revoked| vec![revoked.grant_ref],
    )
    .await
}
