//! The host door of the owner's historical secret lift sweep,
//! `vault.secrets.lift_history` (OF-067). `host_doors` re-exports it, so the
//! generated HTTP facade handler and the MCP dispatcher call it by the name
//! every host door has. It takes the vault owner's proof as `/v1/owner` takes
//! it (`owner_routes::owner`); the engine checks the owner again in its own
//! transaction.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::policy_model::{SecretLiftRequest, SecretLiftStatus, secret_lift_as_owner};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.secrets.lift_history";

/// `vault.secrets.lift_history`: the sweep's run in progress, its last
/// receipt and the lift proposals still open, after queueing a run when the
/// input's `start` asks for one.
pub(crate) async fn vault_secrets_lift_history(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SecretLiftRequest,
) -> MemoryResult<SecretLiftStatus> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        secret_lift_as_owner(server.vault(), &owner, &input).map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(VERB))?
}
