//! The host door of the owner's guest revoke row (OF-232):
//! `vault.guests.revoke`. `host_doors` re-exports it, so the generated HTTP
//! facade handler and the MCP dispatcher call it by the name every host door
//! has, and a tool call, a code-mode call and an SDK call meet one admission:
//! the vault owner's proof, as `/v1/owner/guests/revoke` takes it
//! (`owner_routes::owner`). The engine rechecks that proof in its own
//! writer. It signs each pact disconnect with the host's slip issuer, the one
//! `api/pairing.rs` builds for its own slip doors. With `peer` it then
//! queues the courtesy deletes the route queues (`owner::guest_revoke`).
//!
//! It lists its rows (`host_door_lists`): the grant it withdrew and the
//! guest it conferred on. The pact standing its answer reports is the
//! authority log's fold of the pact the grant binds, which holds no row,
//! and the withdrawal and the slips it tombstoned live in side tables.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::GuestRevokeResponse;
use oneiron::task_verb::sdk::{self, GuestRevokeRequest};

use super::host_doors::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::owner::guest_revoke;
use crate::server::SyncServer;

/// `vault.guests.revoke`: the owner withdraws one guest's access (an ask
/// guest's or a Connect peer's) at this host, with the copied-bytes
/// disclosure, and queues a courtesy delete per ended pact to `peer`.
pub(crate) async fn vault_guests_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestRevokeRequest,
) -> Listed<GuestRevokeResponse> {
    const VERB: &str = "vault.guests.revoke";
    let owner = match crate::api::owner_routes::owner(auth, server) {
        Ok(owner) => owner,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{VERB} is the vault owner's"),
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || -> MemoryResult<GuestRevokeResponse> {
        let peer = input.peer.clone();
        let mut revoked = crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::revoke_guest_as(server.vault(), &owner, issuer, input))
        })
        .map_err(|_| internal(VERB))??;
        guest_revoke::queue_courtesy_deletes(&server, &owner, peer.as_deref(), &mut revoked);
        Ok(revoked)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |revoked| vec![revoked.grant_ref, revoked.guest_ref],
    );
    (answer, rows)
}
