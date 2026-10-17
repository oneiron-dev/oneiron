//! `/v1/owner/legal-holds`: the owner's legal holds (OF-470), behind the same
//! owner door as every other owner route. The owner places a hold, widens it,
//! reads the holds and the id-only log, and lifts a hold only through the one
//! "Lift the hold and erase?" confirm. Oneiron's host-order doors are never
//! routed here: no owner, member or agent surface may reach them.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::deletion::{LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE, LegalHold, LegalHoldEvent};
use oneiron::task_verb::sdk::{
    LegalHoldLiftAndEraseRequest, LegalHoldLiftAndErased, LegalHoldPlaceRequest,
    LegalHoldWidenRequest,
};
use serde::Serialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
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
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Vec<LegalHold>> {
    let owner = owner(&auth, &server)?;
    let holds = blocking(move || -> OwnerResult<Vec<LegalHold>> {
        Ok(server.vault().legal_holds(&owner)?)
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
) -> OwnerReply<LegalHold> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let hold = blocking(move || -> OwnerResult<LegalHold> {
        Ok(server
            .vault()
            .place_legal_hold(&owner, request.targets, request.matter_ref)?)
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
) -> OwnerReply<LegalHold> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let hold = blocking(move || -> OwnerResult<LegalHold> {
        Ok(server
            .vault()
            .widen_legal_hold(&owner, request.hold_id, request.targets)?)
    })
    .await?;
    Ok(Json(hold))
}

/// `GET /v1/owner/legal-holds/log`: the owner-visible hold log, oldest
/// first: ids, times and reason codes.
async fn log(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<LegalHoldEvent>> {
    let owner = owner(&auth, &server)?;
    let events = blocking(move || -> OwnerResult<Vec<LegalHoldEvent>> {
        Ok(server.vault().legal_hold_log(&owner)?)
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
) -> OwnerReply<LegalHoldLiftAndErased> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let outcome = blocking(move || -> OwnerResult<LegalHoldLiftAndErased> {
        Ok(server
            .vault()
            .confirm_lift_legal_hold_and_erase(&owner, &request.records)?
            .into())
    })
    .await?;
    Ok(Json(outcome))
}
