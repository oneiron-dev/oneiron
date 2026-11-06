//! The host door of the owner's per-call outbound request erase (FIX 11801):
//! `vault.outbound_calls.request.erase`. `host_doors` re-exports it, so the
//! generated HTTP facade handler and the MCP dispatcher call it by the name
//! every host door has. The vault owner's proof, as `/v1/owner` takes it,
//! is bound before the engine writer runs; the engine door rechecks that
//! proof in its own snapshot before acting.
use std::sync::Arc;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::task_verb::sdk;

pub(crate) async fn vault_outbound_calls_request_erase(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: sdk::OutboundCallRequestEraseRequest,
) -> Listed<sdk::OutboundCallRequestErased> {
    as_owner_naming(
        server,
        auth,
        "vault.outbound_calls.request.erase",
        move |server, owner| {
            sdk::erase_outbound_call_request_as_owner(server.vault(), owner, input)
        },
        |_| Vec::new(),
    )
    .await
}
