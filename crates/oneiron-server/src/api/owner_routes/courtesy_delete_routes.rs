//! `/v1/owner/courtesy-delete`: courtesy unsend (OF-273), behind the same
//! owner door as every other owner route. The peer-facing routes live in
//! `api::courtesy_delete`, outside it. The owner's
//! `vault.courtesy_delete.*` rows are host doors over these same calls
//! (`api::facade::courtesy_delete_doors`), and each route runs its row's
//! verb hooks once around the call, as the owner in person (FIX 8201).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{
    CourtesyDeleteAnswerRequest, CourtesyDeleteIncoming, CourtesyDeleteSendRequest,
    CourtesyDeleteSent, EmptyRequest,
};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::ApiErrorEnvelope;
use crate::owner::{courtesy_delete, hooked_row, hooked_row_admitting};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/courtesy-delete/send", post(send))
        .route("/courtesy-delete/sent", get(sent))
        .route("/courtesy-delete/incoming", get(incoming))
        .route("/courtesy-delete/answer", post(answer))
}

/// The OpenAPI schema of `POST /v1/owner/courtesy-delete/send`'s body
/// (FIX 11611): [`CourtesyDeleteSendRequest`].
pub(crate) fn courtesy_send_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CourtesyDeleteSendRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/courtesy-delete/send`'s answer
/// (FIX 11611): the queued ask, [`CourtesyDeleteSent`].
pub(crate) fn courtesy_sent_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CourtesyDeleteSent>()
}

/// The OpenAPI schema of `POST /v1/owner/courtesy-delete/answer`'s body
/// (FIX 11611): [`CourtesyDeleteAnswerRequest`].
pub(crate) fn courtesy_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CourtesyDeleteAnswerRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/courtesy-delete/answer`'s answer
/// (FIX 11611): the answered ask, [`CourtesyDeleteIncoming`].
pub(crate) fn courtesy_incoming_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CourtesyDeleteIncoming>()
}

/// `POST /v1/owner/courtesy-delete/send`: asks a former peer to drop what
/// an ended pact delivered, and queues the ask for delivery.
#[utoipa::path(post, path = "/v1/owner/courtesy-delete/send",
    operation_id = "owner_courtesy_delete_send",
    request_body(content = Object, description = "`vault.courtesy_delete.send`'s input: `pact` (64 hex), optional `worlds` (32 hex each) and `epoch_cutoff`, the former peer's `peer` origin, and an optional pre-signed `signed` ask (base64).", content_type = "application/json"),
    responses(
        (status = 200, description = "The queued ask: request id, pact, recipient, delivery status and stamps.", body = Object, content_type = "application/json"),
        (status = 400, description = "A malformed pact, world, origin or signed ask.", body = ApiErrorEnvelope),
        (status = 403, description = "Not the vault owner's own verified credential.", body = ApiErrorEnvelope),
        (status = 404, description = "No such pact.", body = ApiErrorEnvelope),
        (status = 409, description = "This host holds no signing key; send an ask signed by the key the peer pinned.", body = ApiErrorEnvelope)))]
pub(crate) async fn send(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CourtesyDeleteSendRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let sent = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.courtesy_delete.send",
            request,
            |request: CourtesyDeleteSendRequest| courtesy_delete::send(&server, &owner, &request),
        )
    })
    .await?;
    Ok(Json(sent))
}

/// `GET /v1/owner/courtesy-delete/sent`: every ask sent, with its status.
#[utoipa::path(get, path = "/v1/owner/courtesy-delete/sent",
    operation_id = "owner_courtesy_delete_sent",
    responses(
        (status = 200, description = "Every ask this vault sent, oldest first, with its delivery status.", body = Object, content_type = "application/json"),
        (status = 403, description = "Not the vault owner's own verified credential.", body = ApiErrorEnvelope)))]
pub(crate) async fn sent(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let sent = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.courtesy_delete.sent",
            EmptyRequest {},
            |_| courtesy_delete::sent(&server),
        )
    })
    .await?;
    Ok(Json(sent))
}

/// `GET /v1/owner/courtesy-delete/incoming`: every ask a former peer sent.
#[utoipa::path(get, path = "/v1/owner/courtesy-delete/incoming",
    operation_id = "owner_courtesy_delete_incoming",
    responses(
        (status = 200, description = "Every ask a former peer sent, oldest first, with each named world's stale stamp and the owner's recorded answer.", body = Object, content_type = "application/json"),
        (status = 403, description = "Not the vault owner's own verified credential.", body = ApiErrorEnvelope)))]
pub(crate) async fn incoming(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let incoming = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.courtesy_delete.incoming",
            EmptyRequest {},
            |_| courtesy_delete::incoming(&server),
        )
    })
    .await?;
    Ok(Json(incoming))
}

/// `POST /v1/owner/courtesy-delete/answer`: records the owner's choice on
/// one incoming ask, and sends the answer back when `reply_to` names where.
#[utoipa::path(post, path = "/v1/owner/courtesy-delete/answer",
    operation_id = "owner_courtesy_delete_answer",
    request_body(content = Object, description = "`vault.courtesy_delete.answer`'s input: `pact` (64 hex), `request` (32 hex), `choice`, and per choice `reason_code`, `review_at`, `delete` or `hold` records; `reply_to` sends the answer back.", content_type = "application/json"),
    responses(
        (status = 200, description = "The answered ask, with the recorded choice and the reply's delivery status.", body = Object, content_type = "application/json"),
        (status = 400, description = "A malformed field, or a choice its fields do not fit.", body = ApiErrorEnvelope),
        (status = 403, description = "Not the vault owner's own verified credential.", body = ApiErrorEnvelope),
        (status = 409, description = "This host holds no signing key to send the answer back.", body = ApiErrorEnvelope)))]
pub(crate) async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CourtesyDeleteAnswerRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    // A rewritten `reply_to` meets the answer's own check, as the row's
    // facade door admits it (FIX 5140).
    let admit: oneiron::memory::RewriteAdmit = Arc::new(|verb: &str, rewritten: &Value| {
        courtesy_delete::check_rewritten_reply_to(verb, rewritten)
    });
    let answered = blocking(move || {
        hooked_row_admitting(
            server.vault(),
            actor,
            "vault.courtesy_delete.answer",
            request,
            Some(admit),
            |request: CourtesyDeleteAnswerRequest| {
                courtesy_delete::answer(&server, &owner, &request)
            },
        )
    })
    .await?;
    Ok(Json(answered))
}
