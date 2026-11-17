//! `/v1/owner/legal-holds`: the owner's legal holds (OF-470), behind the same
//! owner door as every other owner route. The owner places a hold, widens it,
//! lifts it (destroying its sealed copy), produces it to a named recipient,
//! and reads the holds and the id-only log. Oneiron's host-order doors are
//! never routed here: no owner, member or agent surface may reach them. Each
//! route runs its `vault.legal_holds.*` row's verb hooks once around the
//! engine door (FIX 1466).

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{
    EmptyRequest, LegalHoldLiftRequest, LegalHoldPlaceRequest, LegalHoldProduceRequest,
    LegalHoldWidenRequest, produce_legal_hold_as,
};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/legal-holds",
                summary: "Every customer hold, and each host order the owner may be told of, without its order reference or operator.",
                row: Some("vault.legal_holds.list"),
                shape: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/legal-holds",
                summary: "Places the owner's customer hold on targets, with an optional opaque matter_ref.",
                row: Some("vault.legal_holds.place"),
                shape: None,
            },
            post(place),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/legal-holds/widen",
                summary: "Adds targets to the owner's standing hold hold_id.",
                row: Some("vault.legal_holds.widen"),
                shape: None,
            },
            post(widen),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/legal-holds/lift",
                summary: "Lifts the owner's customer hold hold_id and destroys its sealed copy.",
                row: Some("vault.legal_holds.lift"),
                shape: None,
            },
            post(lift),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/legal-holds/produce",
                summary: "Re-seals the sealed copy of the owner's standing hold hold_id to a named recipient public key.",
                row: Some("vault.legal_holds.produce"),
                shape: None,
            },
            post(produce),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/legal-holds/log",
                summary: "The owner-visible hold log, oldest first: ids, times and reason codes.",
                row: Some("vault.legal_holds.log"),
                shape: None,
            },
            get(log),
        ),
    ]
}

/// `GET /v1/owner/legal-holds`: every customer hold, and each host order the
/// owner may be told of, without its order reference or operator.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let holds = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.list",
            EmptyRequest {},
            |_| Ok(vault.legal_holds(&owner)?),
        )
    })
    .await?;
    Ok(Json(holds))
}

/// `POST /v1/owner/legal-holds`: places the owner's customer hold on
/// `targets`, with an optional opaque `matter_ref` and the future messages
/// it names.
async fn place(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LegalHoldPlaceRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let hold = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.place",
            request,
            |request: LegalHoldPlaceRequest| {
                Ok(vault.place_legal_hold(
                    &owner,
                    request.targets,
                    request.matter_ref,
                    request.future_messages,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(hold))
}

/// `POST /v1/owner/legal-holds/widen`: adds `targets` to the owner's
/// standing hold `hold_id`.
async fn widen(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LegalHoldWidenRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let hold = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.widen",
            request,
            |request: LegalHoldWidenRequest| {
                Ok(vault.widen_legal_hold(&owner, request.hold_id, request.targets)?)
            },
        )
    })
    .await?;
    Ok(Json(hold))
}

/// `POST /v1/owner/legal-holds/lift`: lifts the owner's customer hold
/// `hold_id` and destroys its sealed copy. Nothing in the vault is erased
/// by it.
async fn lift(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LegalHoldLiftRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let hold = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.lift",
            request,
            |request: LegalHoldLiftRequest| Ok(vault.lift_legal_hold(&owner, request.hold_id)?),
        )
    })
    .await?;
    Ok(Json(hold))
}

/// `POST /v1/owner/legal-holds/produce`: re-seals the sealed copy of the
/// owner's standing customer hold `hold_id` to the named recipient public
/// key, and logs the access.
async fn produce(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LegalHoldProduceRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let produced = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.produce",
            request,
            |request: LegalHoldProduceRequest| {
                produce_legal_hold_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(produced))
}

/// `GET /v1/owner/legal-holds/log`: the owner-visible hold log, oldest
/// first: ids, times and reason codes.
async fn log(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let events = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.log",
            EmptyRequest {},
            |_| Ok(vault.legal_hold_log(&owner)?),
        )
    })
    .await?;
    Ok(Json(events))
}
