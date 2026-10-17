//! `/v1/owner/legal-holds`: the owner's legal holds (OF-470), behind the same
//! owner door as every other owner route. The owner places a hold, widens it,
//! reads the holds and the id-only log, and lifts a hold only through the one
//! "Lift the hold and erase?" confirm. Oneiron's host-order doors are never
//! routed here: no owner, member or agent surface may reach them. Each
//! route but the confirm's copy runs its `vault.legal_holds.*` row's verb
//! hooks once around the engine door (FIX 1466).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::deletion::{LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE};
use oneiron::task_verb::sdk::{
    EmptyRequest, LegalHoldLiftAndEraseRequest, LegalHoldLiftAndErased, LegalHoldPlaceRequest,
    LegalHoldWidenRequest,
};
use serde::Serialize;
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::hooked_row;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/legal-holds", get(list).post(place))
        .route("/legal-holds/widen", post(widen))
        .route("/legal-holds/log", get(log))
        .route(
            "/legal-holds/lift-and-erase",
            get(confirm_copy).post(lift_and_erase),
        )
}

/// The one confirm's copy, for the surface to show before it posts.
#[derive(Debug, Serialize)]
struct LiftAndEraseCopy {
    title: &'static str,
    prompt: &'static str,
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
/// `targets`, with an optional opaque `matter_ref`.
async fn place(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<LegalHoldPlaceRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let hold = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.place",
            request,
            |request: LegalHoldPlaceRequest| {
                Ok(vault.place_legal_hold(&owner, request.targets, request.matter_ref)?)
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
    payload: Result<Json<LegalHoldWidenRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
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

/// `GET /v1/owner/legal-holds/lift-and-erase`: the confirm's title and
/// prompt, exactly as the engine words them (C7).
async fn confirm_copy(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<LiftAndEraseCopy> {
    owner(&auth, &server)?;
    Ok(Json(LiftAndEraseCopy {
        title: LIFT_AND_ERASE_TITLE,
        prompt: LIFT_AND_ERASE_PROMPT,
    }))
}

/// `POST /v1/owner/legal-holds/lift-and-erase`: the owner's one confirm. It
/// lifts every customer hold on `records` and erases them; a record a legal
/// order keeps, or one whose erase waits on its receipt, says so and is not
/// reported erased.
async fn lift_and_erase(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<LegalHoldLiftAndEraseRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let outcome = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.legal_holds.lift_and_erase",
            request,
            |request: LegalHoldLiftAndEraseRequest| {
                Ok(LegalHoldLiftAndErased::from(
                    vault.confirm_lift_legal_hold_and_erase(&owner, &request.records)?,
                ))
            },
        )
    })
    .await?;
    Ok(Json(outcome))
}
