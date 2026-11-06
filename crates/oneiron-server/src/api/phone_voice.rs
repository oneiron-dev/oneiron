//! Receiving-agent phone audio sessions. Caller metadata supplies no authority.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderName, header};
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{
    ActAnswer, LiveVoiceAckRequest, LiveVoiceAudioRequest, LiveVoiceEvents, LiveVoiceEventsRequest,
    LiveVoiceProcessed, LiveVoiceSession, LiveVoiceSessionRequest, LiveVoiceStartRequest,
    LiveVoiceToolReply, LiveVoiceToolRequest, LiveVoiceUsage, LiveVoiceUsageRequest,
};

use super::body_spool::OwnerJsonBody;
use super::facade::FacadeApiError;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;

type PhoneVoiceReply<T> = Result<([(HeaderName, &'static str); 1], Json<T>), FacadeApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            "/phone-lines/{identity_ref}/arrivals/{arrival_ref}/voice",
            post(start),
        )
        .route("/phone-voice/audio", post(audio))
        .route("/phone-voice/events", post(events))
        .route("/phone-voice/ack", post(ack))
        .route("/phone-voice/usage", post(usage))
        .route("/phone-voice/tool", post(tool))
        .route("/phone-voice/end", post(end))
        .route("/phone-voice/close", post(close))
}

pub(super) fn credential(auth: &CoreAuth) -> Result<(), ApiError> {
    if auth.verified_slip().is_none() {
        return Err(ApiError::unauthorized());
    }
    auth.require(CoreScope::Read)?;
    auth.require(CoreScope::Write)?;
    Ok(())
}

fn private_json<T>(value: T) -> ([(HeaderName, &'static str); 1], Json<T>) {
    ([(header::CACHE_CONTROL, "no-store")], Json(value))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-lines/{identity_ref}/arrivals/{arrival_ref}/voice",
    security(("CoreBearer" = [])),
    params(
        ("identity_ref" = String, Path, description = "Actual receiving ChannelIdentity id"),
        ("arrival_ref" = String, Path, description = "Opaque payload_ref from metadata intake; never caller text or a provider call id")
    ),
    request_body(content = serde_json::Value, description = "LiveVoiceStartRequest JSON: sample_rate, channels, optional room_ref and roster_ref. The anonymous phone factory does not admit room or roster."),
    responses(
        (status = 200, description = "Opaque LiveVoiceSession and audio format; no caller metadata.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn start(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((identity_ref, arrival_ref)): Path<(String, String)>,
    payload: OwnerJsonBody<LiveVoiceStartRequest>,
) -> PhoneVoiceReply<LiveVoiceSession> {
    credential(&auth)?;
    let identity = oneiron::EntityId::from_hex(&identity_ref)
        .map_err(|_| ApiError::bad_request("invalid identity_ref", Some("identity_ref")))?;
    let input = payload.read(&server).await?;
    let session =
        crate::voice_host::start_phone(&server, &auth, identity, &arrival_ref, input).await?;
    Ok(private_json(session))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/audio",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceAudioRequest JSON: session_ref, utterance_id, pcm_base64, speaking, optional end_utterance."),
    responses(
        (status = 200, description = "LiveVoiceProcessed cursor and ended state; no transcript or audio.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn audio(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceAudioRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.audio(input).await?))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/events",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceEventsRequest JSON: session_ref, optional after and limit."),
    responses(
        (status = 200, description = "LiveVoiceEvents page checked against the original phone preparation and current consent.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn events(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceEventsRequest>,
) -> PhoneVoiceReply<LiveVoiceEvents> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    let (page, _) = session.events(input)?;
    Ok(private_json(page))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/ack",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceAckRequest JSON: session_ref, generation, event_sequence, kind (drained or stopped)."),
    responses(
        (status = 200, description = "LiveVoiceProcessed after the correlated playout acknowledgement.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn ack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceAckRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.ack(input).await?))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/usage",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceUsageRequest JSON: session_ref and generation."),
    responses(
        (status = 200, description = "LiveVoiceUsage from the existing run ledger; observing does not settle or charge.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn usage(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceUsageRequest>,
) -> PhoneVoiceReply<LiveVoiceUsage> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.usage(input.generation).await?))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/tool",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceToolRequest JSON: session_ref and call. The receiving agent uses its own connector grant; caller metadata supplies no authority."),
    responses(
        (status = 200, description = "Destination-narrowed connector answer and session processing state; delivered tool context enters the phone brain before its next utterance.", body = serde_json::Value),
        (status = 400, description = "Invalid typed tool request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope or connector grant"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn tool(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceToolRequest>,
) -> PhoneVoiceReply<ActAnswer<LiveVoiceToolReply>> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let (answer, _) = super::facade::phone_voice_tool(&server, &auth, None, input).await;
    Ok(private_json(answer?))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/end",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceSessionRequest JSON: session_ref."),
    responses(
        (status = 200, description = "LiveVoiceProcessed after ending; final events remain available.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn end(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceSessionRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.end().await?))
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-voice/close",
    security(("CoreBearer" = [])),
    request_body(content = serde_json::Value, description = "LiveVoiceSessionRequest JSON: session_ref."),
    responses(
        (status = 200, description = "LiveVoiceProcessed after ending and releasing the retained session.", body = serde_json::Value),
        (status = 400, description = "Invalid typed voice request or phone admission"),
        (status = 401, description = "Missing or invalid holder-bound credential"),
        (status = 403, description = "Credential lacks its required read/write scope"),
        (status = 404, description = "No phone session belongs to this exact credential, or the line is no longer admitted")
    )
)]
pub(crate) async fn close(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceSessionRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    let processed = if session.processed()?.ended {
        session.processed()?
    } else {
        session.end().await?
    };
    server.live_voice.remove(&auth, &input.session_ref)?;
    Ok(private_json(processed))
}
