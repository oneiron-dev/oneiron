//! `/v1/owner/courtesy-delete`: courtesy unsend (OF-273), behind the same
//! owner door as every other owner route. The peer-facing routes live in
//! `api::cooperative_deletion`, outside it.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::cooperative_deletion::{self, AnswerAsk, IncomingAsk, SendAsk, SentAsk};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/courtesy-delete/send", post(send))
        .route("/courtesy-delete/sent", get(sent))
        .route("/courtesy-delete/incoming", get(incoming))
        .route("/courtesy-delete/answer", post(answer))
}

/// `POST /v1/owner/courtesy-delete/send`: asks a former peer to drop what
/// an ended pact delivered, and queues the ask for delivery.
async fn send(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SendAsk>, JsonRejection>,
) -> OwnerReply<SentAsk> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let sent = blocking(move || cooperative_deletion::send(&server, &owner, &request)).await?;
    Ok(Json(sent))
}

/// `GET /v1/owner/courtesy-delete/sent`: every ask sent, with its status.
async fn sent(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Vec<SentAsk>> {
    owner(&auth, &server)?;
    let sent = blocking(move || cooperative_deletion::sent(&server)).await?;
    Ok(Json(sent))
}

/// `GET /v1/owner/courtesy-delete/incoming`: every ask a former peer sent.
async fn incoming(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<IncomingAsk>> {
    owner(&auth, &server)?;
    let incoming = blocking(move || cooperative_deletion::incoming(&server)).await?;
    Ok(Json(incoming))
}

/// `POST /v1/owner/courtesy-delete/answer`: records the owner's choice on
/// one incoming ask, and sends the answer back when `reply_to` names where.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerAsk>, JsonRejection>,
) -> OwnerReply<IncomingAsk> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let answered =
        blocking(move || cooperative_deletion::answer(&server, &owner, &request)).await?;
    Ok(Json(answered))
}
