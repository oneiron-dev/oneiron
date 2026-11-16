//! Typed doors over one agent's world access (ARCH-0067 #tiers; census
//! L2-56): the worlds its owner grants it and its default among them. Both
//! are the owner's, under the owner's proof. A set that changes the access
//! records the owner's act with where it was said (the surface the call
//! itself carried, through `host_door_surface`).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::settings::agent_world_access::{
    AgentWorldAccess, AgentWorldAccessChange, AgentWorldAccessRequest, AgentWorldAccessSetRequest,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_agents_worlds_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentWorldAccessRequest,
) -> Listed<AgentWorldAccess> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.worlds.get",
        move |server, owner| Ok(server.vault().agent_world_access_as_owner(owner, input)?),
        |access| vec![access.agent],
    )
    .await
}

pub(crate) async fn vault_agents_worlds_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AgentWorldAccessSetRequest,
) -> Listed<AgentWorldAccessChange> {
    as_owner_naming(
        server,
        auth,
        "vault.agents.worlds.set",
        move |server, owner| {
            Ok(server
                .vault()
                .set_agent_world_access_as_owner(owner, Some(surface), input)?)
        },
        |change| vec![change.access.agent],
    )
    .await
}
