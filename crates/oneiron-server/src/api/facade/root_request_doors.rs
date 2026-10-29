//! The owner's root-request doors: the cancel (FIX 5586),
//! `vault.roots.requests.cancel`, over the same engine door as
//! `POST /v1/owner/roots/requests/cancel` (`owner_routes::root_routes`, FIX
//! 4739); and its siblings (FIX 5598), `vault.roots.requests.create`,
//! `vault.roots.requests.list` and `vault.owner_work.get`, over the engine
//! doors `POST` and `GET /v1/owner/roots/requests` and
//! `GET /v1/owner/owner-work/{request}` reach (`owner_work_routes`). Each
//! takes the same owner proof (`owner_routes::owner`, after the host
//! preflight every owner door takes) and no gate of its own. `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call each by the name every host door has, and a tool call, a
//! code-mode call and an SDK call meet one admission. The routes themselves
//! are unchanged; `POST /v1/owner/roots/requests/run` carries kit material
//! for the target's own call and stays a route alone.

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, OwnerWorkGetRequest, PendingRootRequestView, RootRequestCancelRequest,
    RootRequestCreateRequest, pending_root_request_rows, root_request_receipt_rows,
};
use oneiron::world_keys::OwnerWorkReceipt;

use super::host_doors::support::{MaybeListed, owner_proof};
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

/// `vault.roots.requests.create` (FIX 5598): the owner's root change for one
/// install, recorded on this install. A create names the AUTHORITY_LOG row
/// its receipt reads, none when nothing was recorded. `surface` is where his
/// say-so reached this install, the host's own reading of the request:
/// audit only.
pub(crate) async fn vault_roots_requests_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: oneiron::authority::ActSurface,
    input: RootRequestCreateRequest,
) -> MaybeListed<OwnerWorkReceipt> {
    const VERB: &str = "vault.roots.requests.create";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::create_root_request_as(server.vault(), &owner, surface, input),
        |receipt| Some(root_request_receipt_rows(receipt)),
    )
    .await
}

/// `vault.roots.requests.list` (FIX 5598): the root requests naming this
/// install with no result yet. It names every row their receipts read.
pub(crate) async fn vault_roots_requests_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: sdk::EmptyRequest,
) -> MaybeListed<Vec<PendingRootRequestView>> {
    const VERB: &str = "vault.roots.requests.list";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::list_root_requests_as(server.vault(), &owner),
        |pending| Some(pending_root_request_rows(pending)),
    )
    .await
}

/// `vault.owner_work.get` (FIX 5598): where one owner work request stands,
/// any kind; it names the rows its receipt reads.
pub(crate) async fn vault_owner_work_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OwnerWorkGetRequest,
) -> MaybeListed<OwnerWorkReceipt> {
    const VERB: &str = "vault.owner_work.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::owner_work_receipt_as(server.vault(), &owner, &input),
        |receipt| Some(root_request_receipt_rows(receipt)),
    )
    .await
}
