//! A paused MCP call stays within both its original and live registration.

use oneiron::runtime_hooks::verb::{VerbAskMcpCeiling, VerbAskRefusal};

use crate::mcp::{McpEndpointTool, McpResolvedActor, McpSurfaceMode, try_registered_surface};
use crate::server::SyncServer;

pub(super) fn intersect_registration(
    server: &SyncServer,
    actor: &mut McpResolvedActor,
    saved: &VerbAskMcpCeiling,
) -> Result<(), VerbAskRefusal> {
    if &super::mcp_adapter_ceiling(actor) == saved {
        return Ok(());
    }
    if actor.actor_ref != saved.actor_ref || actor.actor_class != saved.actor_class {
        return Err(VerbAskRefusal::CredentialChanged);
    }
    let world = match (actor.scope.world_ref, saved.world) {
        (Some(current), Some(original)) if current != original => {
            return Err(VerbAskRefusal::ScopeRefused);
        }
        (Some(world), _) | (_, Some(world)) => Some(world),
        (None, None) => None,
    };
    let facets = actor.scope.facets.meet(&saved.facets);
    if facets.is_bottom() {
        return Err(VerbAskRefusal::ScopeRefused);
    }
    let write_facet = crate::api::write_facet::landing_facet(
        server.vault(),
        None,
        &facets,
        actor.scope.facet_ref,
    )
    .map_err(|_| VerbAskRefusal::ScopeRefused)?;
    let bound_verbs = match (&saved.bound_verbs, &actor.bound_verbs) {
        (None, current) => current.clone(),
        (Some(original), Some(current)) => Some(
            current
                .iter()
                .copied()
                .filter(|name| original.contains(*name))
                .collect(),
        ),
        (Some(original), None) => Some(
            try_registered_surface(McpSurfaceMode::ToolFirst)
                .map_err(|_| VerbAskRefusal::ContextUnavailable)?
                .tools()
                .iter()
                .copied()
                .map(McpEndpointTool::name)
                .filter(|name| original.contains(*name))
                .collect(),
        ),
    };
    actor.scope.world_ref = world;
    actor.scope.facets = facets;
    actor.scope.facet_ref = write_facet;
    actor.bound_verbs = bound_verbs;
    actor.subscription_ceiling = actor
        .subscription_ceiling
        .intersection(&actor.scope.subscription_ceiling())
        .copied()
        .collect();
    Ok(())
}
