//! Receiving-agent phone audio sessions. Caller metadata supplies no authority.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderName, header};
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{
    LiveVoiceAckRequest, LiveVoiceAudioRequest, LiveVoiceEvents, LiveVoiceEventsRequest,
    LiveVoiceProcessed, LiveVoiceSession, LiveVoiceSessionRequest, LiveVoiceStartRequest,
    LiveVoiceUsage, LiveVoiceUsageRequest,
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
        .route("/phone-voice/end", post(end))
        .route("/phone-voice/close", post(close))
}

fn credential(auth: &CoreAuth) -> Result<(), ApiError> {
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

async fn start(
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

async fn audio(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceAudioRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.audio(input).await?))
}

async fn events(
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

async fn ack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceAckRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.ack(input).await?))
}

async fn usage(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceUsageRequest>,
) -> PhoneVoiceReply<LiveVoiceUsage> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.usage(input.generation).await?))
}

async fn end(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LiveVoiceSessionRequest>,
) -> PhoneVoiceReply<LiveVoiceProcessed> {
    credential(&auth)?;
    let input = payload.read(&server).await?;
    let session = server.live_voice.get_phone(&auth, &input.session_ref)?;
    Ok(private_json(session.end().await?))
}

async fn close(
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
