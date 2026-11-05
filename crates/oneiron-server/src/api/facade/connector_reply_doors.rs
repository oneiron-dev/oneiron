//! FIX 2405: the owner's retry of one Failed connector reply job, shared by
//! HTTP, SDK and MCP. The native retry revalidates the owner's proof in
//! the same writer that mints the successor.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{self, ConnectorReplyRetryRequest, ConnectorReplyRetryView};

use super::host_doors::support::{MaybeListed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Runs `act` on the vault as the owner `auth` proves, off the async runtime.
async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || act(server.vault(), &owner))
        .await
        .unwrap_or_else(|_| Err(internal(verb)))
}

/// `vault.connectors.replies.retry_failed`: the Failed predecessor's run and
/// dedupe guard reads are no known rows, so it lists none.
pub(crate) async fn vault_connectors_replies_retry_failed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorReplyRetryRequest,
) -> MaybeListed<ConnectorReplyRetryView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.replies.retry_failed",
        move |vault, owner| sdk::retry_failed_connector_reply_as(vault, owner, input),
    )
    .await;
    (answer, None)
}
