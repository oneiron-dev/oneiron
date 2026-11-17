//! The host door of the owner's room facet set (L7-39 PR 3; Engine RULING
//! L7-39-ROOM-FACET-SET = A, 14 Nov 17:03): `vault.projects.room_facets.set`.
//! `host_doors` re-exports it, so the generated HTTP facade handler and the
//! MCP dispatcher call it by the name every host door has. It admits the
//! vault owner's proof, as `/v1/owner` takes it, and signs the project's
//! next state with the owner's project signer under the host's slip issuer,
//! as `vault.projects.confirm` does. The engine's
//! `set_project_room_facets_from_request_as` sets or drops the set; the
//! embedded handle's `projects_set_room_facets` keeps refusing.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::workspace_roster::{ProjectRoomFacetsSetRequest, ProjectRoomFacetsState};

use super::host_doors::support::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.projects.room_facets.set`: the owner sets or drops the facets a
/// project's home room reads through. Beside the answer, the project it
/// signed.
pub(crate) async fn vault_projects_room_facets_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProjectRoomFacetsSetRequest,
) -> (MemoryResult<ProjectRoomFacetsState>, Vec<EntityId>) {
    const VERB: &str = "vault.projects.room_facets.set";
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        let vault = server.vault();
        let listed = vec![input.project];
        let set = crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(vault
                .owner_project_signer(issuer)
                .map_err(MemoryError::from)
                .and_then(|signer| {
                    oneiron::workspace_roster::set_project_room_facets_from_request_as(
                        vault, &owner, &signer, input,
                    )
                }))
        })
        .map_err(|_| internal(VERB))
        .and_then(|set| set);
        (set, listed)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), Vec::new()))
}
