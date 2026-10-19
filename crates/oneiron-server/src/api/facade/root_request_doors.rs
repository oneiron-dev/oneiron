//! The owner's root-request cancel door (FIX 5586): `vault.roots.requests.cancel`
//! over the same engine door as `POST /v1/owner/roots/requests/cancel`
//! (`owner_routes::root_routes`, FIX 4739), under the same owner proof
//! (`owner_routes::owner`, after the host preflight every owner door takes)
//! and no gate of its own. `host_doors` re-exports it, so the generated HTTP
//! facade handler and the MCP dispatcher call it by the name every host door
//! has, and a tool call, a code-mode call and an SDK call meet one admission.
//! The route itself is unchanged.

use std::sync::Arc;

use oneiron::task_verb::sdk::{RootRequestCancelRequest, root_request_receipt_rows};
use oneiron::world_keys::OwnerWorkReceipt;

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A cancel names the AUTHORITY_LOG rows its receipt reads: the request's
/// entry and each cancel's. The act records where the owner said so (audit
/// only): `surface`, the host's own reading of the request (the facade
/// call's verified headers, or the MCP connection's proven peer), never its
/// input.
pub(crate) async fn vault_roots_requests_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: oneiron::authority::ActSurface,
    input: RootRequestCancelRequest,
) -> MaybeListed<OwnerWorkReceipt> {
    const VERB: &str = "vault.roots.requests.cancel";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::sdk::cancel_root_request_as(server.vault(), &owner, surface, input)
        },
        |receipt| Some(root_request_receipt_rows(receipt)),
    )
    .await
}
