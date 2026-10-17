//! The host door of the owner's guest revoke row (OF-232):
//! `vault.guests.revoke`. `host_doors` re-exports it, so the generated HTTP
//! facade handler and the MCP dispatcher call it by the name every host door
//! has, and a tool call, a code-mode call and an SDK call meet one admission:
//! the vault owner's proof, as `/v1/owner/guests/revoke` takes it
//! (`owner_routes::owner`). The engine rechecks that proof in its own
//! writer. It signs each pact disconnect with the host's slip issuer, the one
//! `api/pairing.rs` builds for its own slip doors.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::GuestRevokeResponse;
use oneiron::task_verb::sdk::{self, GuestRevokeRequest};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.guests.revoke`: the owner withdraws one ask guest's access at this
/// host, with the copied-bytes disclosure.
pub(crate) async fn vault_guests_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestRevokeRequest,
) -> MemoryResult<GuestRevokeResponse> {
    const VERB: &str = "vault.guests.revoke";
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<GuestRevokeResponse> {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::revoke_guest_as(server.vault(), &owner, issuer, input))
        })
        .map_err(|_| internal(VERB))?
    })
    .await
    .map_err(|_| internal(VERB))?
}
