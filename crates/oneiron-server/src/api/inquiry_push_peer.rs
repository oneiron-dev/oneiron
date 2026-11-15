//! The company host's push route (L7-03; federation.md #inquiry, line 95;
//! lead ruling L7-03-LANDING = A): `POST /v1/federation/inquiry/push`. A
//! member host sends one told statement here (the member's [Now]) under
//! the guest slip this vault minted for it on an inquiry edge's reciprocal
//! grant, with its own signature over the slip's binding transcript on
//! each call; the global binding layer verifies both and spends the nonce.
//! The route admits only such a slip (one that names a live grant, allows
//! the `inquiry_push` class and was not handed on), and the engine's own
//! writer lands the statement at once as a copy: one CLAIM in the foreign
//! WORLD of the member's vault, attributed, with one `inquiry` receipt. A
//! re-delivery of the same push lands nothing more. No verb reaches the
//! landing.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::federation::INQUIRY_PUSH_VERB_CLASS;
use oneiron::inquiry::{INQUIRY_PUSH_PEER_PATH, InquiryPushWire, MAX_INQUIRY_PUSH_WIRE_BYTES};
use oneiron::{EntityId, ErrorKind};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(INQUIRY_PUSH_PEER_PATH, post(take_inquiry_push))
        .layer(DefaultBodyLimit::max(MAX_INQUIRY_PUSH_WIRE_BYTES))
}

/// `POST /v1/federation/inquiry/push`: one statement a member host tells
/// this vault unasked over an inquiry edge.
#[utoipa::path(post, path = "/v1/federation/inquiry/push",
    operation_id = "federation_inquiry_push",
    request_body(content = Vec<u8>, description = "The told statement's wire bytes (JSON). Bearer: the guest slip this vault minted for the member host on an inquiry edge's reciprocal grant, with the host's x-oneiron-binding proof on each call.", content_type = "application/json"),
    responses(
        (status = 204, description = "Landed, now or by an earlier delivery of the same push."),
        (status = 400, description = "The body is no told statement."),
        (status = 401, description = "No slip, or the slip or its holder proof does not verify."),
        (status = 403, description = "The slip is no live reciprocal grant credential, or the grant, its pact or this vault's route to the member does not admit the statement."),
        (status = 503, description = "The vault could not take it now; send it again.")))]
pub(super) async fn take_inquiry_push(
    State(server): State<Arc<SyncServer>>,
    auth: CoreAuth,
    body: Bytes,
) -> Response {
    let Some(proof) = auth.verified_slip().cloned() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let grant = proof
        .claims()
        .grant_ref
        .as_deref()
        .and_then(|grant| EntityId::from_hex(grant).ok());
    let Some(grant) = grant.filter(|_| {
        !proof.is_transferred()
            && proof.allows_verb(INQUIRY_PUSH_VERB_CLASS)
            && auth.credential_is_live(server.vault())
    }) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(wire) = InquiryPushWire::decode_wire(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let vault = Arc::clone(server.vault());
    let landed = tokio::task::spawn_blocking(move || {
        vault.land_pushed_inquiry_statement(grant, &proof, &wire)
    })
    .await;
    match landed {
        Ok(Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        // The engine's refusals: the grant, its pact or the route to the
        // member does not admit the statement.
        Ok(Err(error)) if error.kind() == ErrorKind::InvalidConfig => {
            StatusCode::FORBIDDEN.into_response()
        }
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "told statement landing failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
