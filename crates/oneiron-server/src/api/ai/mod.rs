//! `/v1/ai`: the server's model-backed surfaces — status, chat turns, the
//! session hints the Dreamer's triggers read, the `ai.*` verbs past text
//! (options, image, video, speech, transcribe, embed), and `ask_image`.
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron_driver::SessionHint;
use serde::Deserialize;

use crate::auth::{CoreAuth, CoreScope};
use crate::models::QuotaChoice;
use crate::server::SyncServer;

pub(crate) mod chat;
mod media;
mod vision;
mod waves;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/status", get(status))
        .route("/session", post(session))
        .route("/chat", post(chat::chat_turn))
        .route("/waves", post(waves::enqueue))
        .route("/waves/{attempt}", get(waves::status))
        .route("/options", get(media::options))
        .route("/quota/{question}", post(answer_quota))
        .merge(media_routes())
}

/// The `ai.*` media verbs. Their bodies carry images and audio as base64.
fn media_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/image", post(media::image))
        .route("/video", post(media::video))
        .route(
            "/video/{job}",
            get(media::video_job).delete(media::cancel_video_job),
        )
        .route("/speech", post(media::speech))
        .route("/transcribe", post(media::transcribe))
        .route("/embed", post(media::embed))
        .route("/ask_image", post(vision::ask_image))
        .layer(DefaultBodyLimit::max(MEDIA_BODY_LIMIT))
}

/// The largest media call body: a few reference images or a long recording,
/// as base64.
const MEDIA_BODY_LIMIT: usize = 96 << 20;

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
        "quota_questions": server.ai.model_runtime().quota_questions(),
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaAnswer {
    choice: QuotaChoice,
    /// For `use_fallback`: the engine model id, one of the question's
    /// `fallbacks`, that the parked offer's calls go to.
    #[serde(default)]
    fallback: Option<String>,
}

/// The owner's answer to a quota question in `GET /v1/ai/status` (OF-305):
/// `top_up` or `pay_as_you_go` puts the parked offer back in rotation now,
/// `wait` and `add_account` close the question and leave it parked until
/// its reset, and `use_fallback` (`{"choice": "use_fallback", "fallback":
/// "<model>"}`) sends its calls to that model on another provider while it
/// stays parked.
async fn answer_quota(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(question): Path<String>,
    Json(answer): Json<QuotaAnswer>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "quota questions are the owner's",
        );
    }
    match server.ai.model_runtime().answer_quota(
        &question,
        answer.choice,
        answer.fallback.as_deref(),
    ) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => refusal(
            StatusCode::NOT_FOUND,
            "no_such_question",
            "no open quota question offers that choice or fallback",
        ),
        Err(_) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "quota_unwritable",
            "the answer could not be kept",
        ),
    }
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
    crate::auth::Locality(locality): crate::auth::Locality,
    machine: Option<axum::Extension<oneiron::authority::PeerMachine>>,
    Json(request): Json<SessionRequest>,
) -> Response {
    if let Err(error) = auth.require(CoreScope::Write) {
        return error.into_response();
    }
    let (actor, _) = match chat::principal(&auth, server.vault()) {
        Ok(actor) => actor,
        Err(response) => return *response,
    };
    let peer = machine.map_or(oneiron::authority::PeerMachine::Unknown, |machine| {
        machine.0
    });
    let key = match bound_session_key(&server, actor, peer, locality) {
        Ok(key) => key,
        Err(response) => return *response,
    };
    server.ai.session_hint(
        key,
        match request.event {
            SessionEvent::Open => SessionHint::AppOpen,
            SessionEvent::Activity => SessionHint::Activity,
            SessionEvent::End => SessionHint::ExplicitEnd,
        },
    );
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"dreamer": server.ai.status().dreamer.state})),
    )
        .into_response()
}

/// A remote caller names its machine through the request's verified proof,
/// never a JSON field. Direct on-device callers run on this install.
pub(super) fn bound_session_key(
    server: &SyncServer,
    actor: oneiron::EntityId,
    peer: oneiron::authority::PeerMachine,
    locality: oneiron::claim::CallerLocality,
) -> Result<oneiron::session_lifecycle::SessionKey, Box<Response>> {
    match server.vault().peer_machine_stands(peer) {
        oneiron::authority::PeerMachine::Proven { machine, .. } => {
            Ok(oneiron::session_lifecycle::SessionKey { actor, machine })
        }
        oneiron::authority::PeerMachine::Unknown
            if locality == oneiron::claim::CallerLocality::OnDevice =>
        {
            server.vault().local_session_key(actor).map_err(|_| {
                Box::new(refusal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session_unavailable",
                    "the session identity could not be kept",
                ))
            })
        }
        _ => Err(Box::new(refusal(
            StatusCode::FORBIDDEN,
            "session_machine_required",
            "a remote session requires this request's enrolled machine proof",
        ))),
    }
}
