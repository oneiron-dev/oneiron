//! The peer-facing courtesy deletion routes (OF-273). Keyless like the open
//! inbox: the signed body is the authentication, checked against the key
//! this vault pinned for the pact it names. Nothing is deleted on receipt;
//! an ask is filed for the owner's review.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::deletion::{
    COOP_DELETION_PEER_PATH, COOP_DELETION_REPLY_PEER_PATH, CooperativeDeletionIngress,
};

use crate::server::SyncServer;

/// One signed ask or answer, with room to spare: the codec caps a decode at 32 KiB.
const MAX_BODY_BYTES: usize = 32 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(COOP_DELETION_PEER_PATH, post(take_request))
        .route(COOP_DELETION_REPLY_PEER_PATH, post(take_reply))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// `POST /v1/federation/courtesy-delete`: a former peer's signed ask.
#[utoipa::path(post, path = "/v1/federation/courtesy-delete",
    operation_id = "federation_courtesy_delete",
    request_body(content = Vec<u8>, description = "The former peer's signed ask, in the courtesy codec. No bearer: the signature, checked against the key this vault pinned for the pact it names, is the authentication.", content_type = "application/octet-stream"),
    responses(
        (status = 202, description = "Filed for the owner's review; nothing is deleted on receipt."),
        (status = 200, description = "Already filed."),
        (status = 403, description = "No pact with this peer, or the bytes do not verify against the key it pinned."),
        (status = 409, description = "A different ask under the same nonce is already filed."),
        (status = 503, description = "The vault could not file it now; send it again.")))]
pub(super) async fn take_request(State(server): State<Arc<SyncServer>>, body: Bytes) -> Response {
    land(server, body, |vault, bytes, now| {
        vault.receive_cooperative_deletion_request(bytes, now)
    })
    .await
}

/// `POST /v1/federation/courtesy-delete/reply`: a former peer's answer to
/// an ask this vault sent.
#[utoipa::path(post, path = "/v1/federation/courtesy-delete/reply",
    operation_id = "federation_courtesy_delete_reply",
    request_body(content = Vec<u8>, description = "The former peer's signed answer, in the courtesy codec. No bearer: the signature, checked against the key this vault pinned for the pact it names, is the authentication.", content_type = "application/octet-stream"),
    responses(
        (status = 202, description = "Recorded on the sent ask."),
        (status = 200, description = "Already recorded."),
        (status = 403, description = "No pact with this peer, or the bytes do not verify against the key it pinned."),
        (status = 409, description = "A different answer to the same ask is already recorded."),
        (status = 503, description = "The vault could not record it now; send it again.")))]
pub(super) async fn take_reply(State(server): State<Arc<SyncServer>>, body: Bytes) -> Response {
    land(server, body, |vault, bytes, now| {
        vault.receive_cooperative_deletion_reply(bytes, now)
    })
    .await
}

async fn land(
    server: Arc<SyncServer>,
    body: Bytes,
    take: fn(&oneiron::Vault, &[u8], u64) -> oneiron::Result<CooperativeDeletionIngress>,
) -> Response {
    let vault = Arc::clone(server.vault());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    match tokio::task::spawn_blocking(move || take(&vault, &body, now)).await {
        Ok(Ok(CooperativeDeletionIngress::Filed)) => StatusCode::ACCEPTED.into_response(),
        Ok(Ok(CooperativeDeletionIngress::AlreadyFiled)) => StatusCode::OK.into_response(),
        Ok(Ok(CooperativeDeletionIngress::Unauthenticated)) => {
            StatusCode::FORBIDDEN.into_response()
        }
        Ok(Ok(CooperativeDeletionIngress::Conflict)) => StatusCode::CONFLICT.into_response(),
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "courtesy delete ingress failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
