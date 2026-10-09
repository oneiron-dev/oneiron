//! `/v1/ai`: the server's model-backed surfaces — status, chat turns and
//! the session hints the Dreamer's triggers read.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron_driver::SessionHint;
use serde::Deserialize;

use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

mod chat;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/status", get(status))
        .route("/session", post(session))
        .route("/chat", post(chat::chat_turn))
}

pub(super) fn refusal(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({"error": {"code": code, "message": message.into()}})),
    )
        .into_response()
}

/// Every seat and worker: what is configured, what runs, and why not.
async fn status(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> Response {
    if let Err(error) = auth.require(CoreScope::Read) {
        return error.into_response();
    }
    Json(serde_json::json!({
        "ai": server.ai.status(),
        "models": server.ai.models_status(),
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SessionEvent {
    /// The app opened (or is still here): opens a sitting if none is open.
    Open,
    /// The user is active: the idle floor restarts.
    Activity,
    /// The app ended the sitting: its turns dream now.
    End,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    event: SessionEvent,
}

/// An app tells the Dreamer's session policy what it saw. The hint shapes
/// no pass: the driver decides what, if anything, results.
async fn session(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<SessionRequest>,
) -> Response {
    if let Err(error) = auth.require(CoreScope::Write) {
        return error.into_response();
    }
    server.ai.session_hint(match request.event {
        SessionEvent::Open => SessionHint::AppOpen,
        SessionEvent::Activity => SessionHint::Activity,
        SessionEvent::End => SessionHint::ExplicitEnd,
    });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"dreamer": server.ai.status().dreamer.state})),
    )
        .into_response()
}
