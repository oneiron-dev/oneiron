//! The host doors of the owner's agent grant rows (FIX 5628):
//! `vault.agents.grants.mint` and `.revoke`, `.from_slip`, the conversion of
//! a named agent's slip that no Grant has named (FIX AGENT-GRANTLESS-VISIBLE),
//! and `vault.agents.base`, the base agents' ids a grant names (FIX 5734).
//! `host_doors` re-exports them,
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
    self, AgentGrantFromSlipOutcome, AgentGrantFromSlipRequest, AgentGrantMintRequest,
    AgentGrantMinted, AgentGrantRevokeRequest, AgentGrantRevoked, BaseAgentList, EmptyRequest,
};

use super::host_doors::support::Listed;
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

/// `vault.agents.grants.from_slip`: the owner converts one slip of a named
/// agent that no Grant has named into its holder's default read Grants,
/// listing the grant rows it wrote; an unchanged answer lists none.
pub(crate) async fn vault_agents_grants_from_slip(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AgentGrantFromSlipRequest,
) -> Listed<AgentGrantFromSlipOutcome> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.grants.from_slip",
        move |server, owner| {
            sdk::mint_agent_grants_from_slip_as(server.vault(), owner, surface, input)
        },
        |outcome| match outcome {
            AgentGrantFromSlipOutcome::Minted { grants } => {
                grants.iter().map(|minted| minted.grant.grant_ref).collect()
            }
            AgentGrantFromSlipOutcome::Unchanged { .. } => Vec::new(),
        },
    )
    .await
}

/// `vault.agents.base`: the base agents' principal ids, for the owner,
/// listing the principal rows it names.
pub(crate) async fn vault_agents_base(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<BaseAgentList> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.base",
        |server, owner| sdk::read_base_agents_as(server.vault(), owner),
        |base| base.agents.iter().map(|agent| agent.id).collect(),
    )
    .await
}
