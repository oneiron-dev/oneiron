//! The member host's inquiry route (INQUIRE-1 PR 5; federation.md
//! #inquiry; Engine ruling INQUIRE-SHAPE Q2 = A): `POST
//! /v1/federation/inquiry`. A company host sends one inquiry here under the
//! guest slip this vault minted for it on an inquiry edge, with its own
//! signature over the slip's binding transcript on each call; the global
//! binding layer verifies both and spends the nonce. The route admits only
//! such a slip (one that names a live grant, allows the `inquire` verb and
//! was not handed on), and the engine judges the inquiry against the edge,
//! its pact and the pact's current scope, logs it and runs the check-in
//! ladder with the production judgment (unsure). The reply is the answer
//! as it stands: `answered`, `no_answer` or `pending`; a re-send of the
//! same inquiry returns its current answer.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::federation::INQUIRE_VERB_CLASS;
use oneiron::inquiry::{INQUIRY_PEER_PATH, Inquiry, UnsureInquiryJudgment};
use oneiron::{EntityId, ErrorKind};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// One inquiry's wire bytes: a question and a purpose of one line each.
const MAX_BODY_BYTES: usize = 32 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(INQUIRY_PEER_PATH, post(take_inquiry))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// `POST /v1/federation/inquiry`: one inquiry from a company host over an
/// inquiry edge.
#[utoipa::path(post, path = "/v1/federation/inquiry",
    operation_id = "federation_inquiry",
    request_body(content = Vec<u8>, description = "The inquiry's wire bytes (JSON). Bearer: the guest slip this vault minted for the company host on its inquiry edge, with the host's x-oneiron-binding proof on each call.", content_type = "application/json"),
    responses(
        (status = 200, description = "The answer's wire bytes (JSON): answered, no_answer or pending."),
        (status = 400, description = "The body is no inquiry."),
        (status = 401, description = "No slip, or the slip or its holder proof does not verify."),
        (status = 403, description = "The slip is no live inquiry edge credential, or the edge, its pact or its scope does not admit this inquiry."),
        (status = 503, description = "The vault could not take it now; send it again.")))]
pub(super) async fn take_inquiry(
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
            && proof.allows_verb(INQUIRE_VERB_CLASS)
            && auth.credential_is_live(server.vault())
    }) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(inquiry) = Inquiry::decode_wire(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let vault = Arc::clone(server.vault());
    let answered = tokio::task::spawn_blocking(move || {
        vault
            .admit_inquiry(grant, &proof, &inquiry, &UnsureInquiryJudgment)
            .and_then(|answer| answer.encode_wire())
    })
    .await;
    match answered {
        Ok(Ok(bytes)) => ([(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        // The engine's refusals: the edge, its pact or its scope does not
        // admit the inquiry, or the inquiry breaks a field rule.
        Ok(Err(error)) if error.kind() == ErrorKind::InvalidConfig => {
            StatusCode::FORBIDDEN.into_response()
        }
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "inquiry admission failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
