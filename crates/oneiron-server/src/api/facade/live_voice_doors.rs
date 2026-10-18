//! Typed public live media doors. The existing owner proof runs before
//! hooks and again here; every later call also names the exact credential
//! that opened its session. The connector boundary keeps its own grant.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::*;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn ai_voice_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceStartRequest,
) -> MemoryResult<LiveVoiceSession> {
    owner_proof(auth, server, "ai.voice.start")?;
    crate::voice_host::start_public(server, auth, input).await
}

pub(crate) async fn ai_voice_audio(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAudioRequest,
) -> MemoryResult<LiveVoiceProcessed> {
    owner_proof(auth, server, "ai.voice.audio")?;
    server
        .live_voice
        .get(auth, &input.session_ref)?
        .audio(input)
        .await
}

pub(crate) async fn ai_voice_events(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceEventsRequest,
) -> MemoryResult<LiveVoiceEvents> {
    owner_proof(auth, server, "ai.voice.events")?;
    server
        .live_voice
        .get(auth, &input.session_ref)?
        .events(input)
}

pub(crate) async fn ai_voice_ack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAckRequest,
) -> MemoryResult<LiveVoiceProcessed> {
    owner_proof(auth, server, "ai.voice.ack")?;
    server
        .live_voice
        .get(auth, &input.session_ref)?
        .ack(input)
        .await
}

pub(crate) async fn ai_voice_usage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceUsageRequest,
) -> MemoryResult<LiveVoiceUsage> {
    owner_proof(auth, server, "ai.voice.usage")?;
    server
        .live_voice
        .get(auth, &input.session_ref)?
        .usage(input.generation)
        .await
}

pub(crate) async fn ai_voice_tool(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveVoiceToolRequest,
) -> Listed<LiveVoiceToolReply> {
    let session = match owner_proof(auth, server, "ai.voice.tool")
        .and_then(|_| server.live_voice.get(auth, &input.session_ref))
    {
        Ok(session) => session,
        Err(error) => return (Err(error), Vec::new()),
    };
    if let Err(error) = session.require_tool_context() {
        return (Err(error), Vec::new());
    }
    let (reply, rows) =
        super::connector_call_doors::connector_call(server, auth, caller, invocation, input.call)
            .await;
    let result = match reply {
        Ok(reply) => {
            let processed = match &reply {
                ConnectorCallReply::Delivered {
                    result: Some(result),
                    ..
                } => session.tool(result.clone()).await,
                _ => session.processed(),
            };
            processed.map(|processed| LiveVoiceToolReply { processed, reply })
        }
        Err(error) => Err(error),
    };
    (result, rows)
}

pub(crate) async fn ai_voice_end(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> MemoryResult<LiveVoiceProcessed> {
    owner_proof(auth, server, "ai.voice.end")?;
    server.live_voice.get(auth, &input.session_ref)?.end().await
}

pub(crate) async fn ai_voice_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> MemoryResult<LiveVoiceProcessed> {
    owner_proof(auth, server, "ai.voice.close")?;
    let session = server.live_voice.get(auth, &input.session_ref)?;
    let processed = if session.processed()?.ended {
        session.processed()?
    } else {
        session.end().await?
    };
    server.live_voice.remove(auth, &input.session_ref)?;
    Ok(processed)
}
