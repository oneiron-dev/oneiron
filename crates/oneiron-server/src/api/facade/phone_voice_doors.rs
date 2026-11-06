//! Typed phone-session doors retain the raw transport's receiving-agent admission.
use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::*;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, MaybeListed};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn preflight(auth: &CoreAuth) -> MemoryResult<()> {
    crate::api::phone_voice::credential(auth)
        .map_err(|error| super::FacadeApiError::from(error).into_memory_error())
}

pub(crate) async fn ai_phone_voice_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PhoneVoiceStartRequest,
) -> Listed<LiveVoiceSession> {
    let answer: MemoryResult<LiveVoiceSession> = async {
        preflight(auth)?;
        let identity = EntityId::from_hex(&input.identity_ref)
            .map_err(|_| MemoryError::bad_request("invalid identity_ref"))?;
        crate::voice_host::start_phone(server, auth, identity, &input.arrival_ref, input.voice)
            .await
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn ai_phone_voice_audio(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAudioRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer = async {
        preflight(auth)?;
        server
            .live_voice
            .get_phone(auth, &input.session_ref)?
            .audio(input)
            .await
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn ai_phone_voice_events(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceEventsRequest,
) -> Listed<LiveVoiceEvents> {
    let answer = preflight(auth)
        .and_then(|_| server.live_voice.get_phone(auth, &input.session_ref))
        .and_then(|session| session.events(input));
    match answer {
        Ok((page, rows)) => (Ok(page), rows),
        Err(error) => (Err(error), Vec::new()),
    }
}

pub(crate) async fn ai_phone_voice_ack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAckRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer = async {
        preflight(auth)?;
        server
            .live_voice
            .get_phone(auth, &input.session_ref)?
            .ack(input)
            .await
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn ai_phone_voice_usage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceUsageRequest,
) -> Listed<LiveVoiceUsage> {
    let answer = async {
        preflight(auth)?;
        server
            .live_voice
            .get_phone(auth, &input.session_ref)?
            .usage(input.generation)
            .await
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn ai_phone_voice_tool(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveVoiceToolRequest,
) -> MaybeListed<ActAnswer<LiveVoiceToolReply>> {
    if let Err(error) = preflight(auth) {
        return (Err(error), Some(Vec::new()));
    }
    super::live_voice_doors::phone_voice_tool(server, auth, invocation, input).await
}

pub(crate) async fn ai_phone_voice_end(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer = async {
        preflight(auth)?;
        server
            .live_voice
            .get_phone(auth, &input.session_ref)?
            .end()
            .await
    }
    .await;
    (answer, Vec::new())
}

pub(crate) async fn ai_phone_voice_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer = async {
        preflight(auth)?;
        let session = server.live_voice.get_phone(auth, &input.session_ref)?;
        let processed = if session.processed()?.ended {
            session.processed()?
        } else {
            session.end().await?
        };
        server.live_voice.remove(auth, &input.session_ref)?;
        Ok(processed)
    }
    .await;
    (answer, Vec::new())
}
