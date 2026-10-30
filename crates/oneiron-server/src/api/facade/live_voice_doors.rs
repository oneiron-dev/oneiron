//! Typed public live media doors. The existing owner proof runs before
//! hooks and again here; every later call also names the exact credential
//! that opened its session. The connector boundary keeps its own grant.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::*;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, MaybeListed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `ai.voice.start` (`host_door_lists`): the reply is the opaque session
/// ref and its audio format. The answering agent's instructions it loads
/// prepare the live stream and are not served here, so the list is complete
/// and empty; `ai.voice.events` serves what the session makes.
pub(crate) async fn ai_voice_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceStartRequest,
) -> Listed<LiveVoiceSession> {
    let answer: MemoryResult<LiveVoiceSession> = async {
        owner_proof(auth, server, "ai.voice.start")?;
        crate::voice_host::start_public(server, auth, input).await
    }
    .await;
    (answer, Vec::new())
}

/// `ai.voice.audio` (`host_door_lists`): the reply is the processing
/// cursor and status, never a transcript, reply text or audio, so the list
/// is complete and empty. What the utterance starts is served by events.
pub(crate) async fn ai_voice_audio(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAudioRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer: MemoryResult<LiveVoiceProcessed> = async {
        owner_proof(auth, server, "ai.voice.audio")?;
        server
            .live_voice
            .get(auth, &input.session_ref)?
            .audio(input)
            .await
    }
    .await;
    (answer, Vec::new())
}

/// `ai.voice.events` (`host_door_lists`): a page serves PCM spoken from
/// the brain's model input, the safeguard verdicts and notices on it, and
/// each turn's memories receipt. It lists the rows its served events were
/// made from, as the journal kept them per generation from the brain's own
/// turn (FIX 4778): the answering agent's definition, the history each turn
/// heard, the memories it heard and its tool contexts' rows, the policy
/// row a notice names and the rows a memories read found. The person's
/// words and the control events list none, and so does a refusal (FIX
/// 6080).
pub(crate) async fn ai_voice_events(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceEventsRequest,
) -> Listed<LiveVoiceEvents> {
    let answer = owner_proof(auth, server, "ai.voice.events")
        .and_then(|_| server.live_voice.get(auth, &input.session_ref))
        .and_then(|session| session.events(input));
    match answer {
        Ok((page, rows)) => (Ok(page), rows),
        Err(error) => (Err(error), Vec::new()),
    }
}

/// `ai.voice.ack` (`host_door_lists`): the reply is the processing cursor
/// and status, so the list is complete and empty.
pub(crate) async fn ai_voice_ack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceAckRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer: MemoryResult<LiveVoiceProcessed> = async {
        owner_proof(auth, server, "ai.voice.ack")?;
        server
            .live_voice
            .get(auth, &input.session_ref)?
            .ack(input)
            .await
    }
    .await;
    (answer, Vec::new())
}

/// `ai.voice.usage` (`host_door_lists`): the reply is run settlements and
/// the terminal and metering state, no content, so the list is complete and
/// empty.
pub(crate) async fn ai_voice_usage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceUsageRequest,
) -> Listed<LiveVoiceUsage> {
    let answer: MemoryResult<LiveVoiceUsage> = async {
        owner_proof(auth, server, "ai.voice.usage")?;
        server
            .live_voice
            .get(auth, &input.session_ref)?
            .usage(input.generation)
            .await
    }
    .await;
    (answer, Vec::new())
}

/// `ai.voice.tool` (`host_door_lists`): the caller's connector call under
/// its own grant, whose delivered result enters the brain before the next
/// utterance, always foreign. Beside it, the rows its reads listed and the
/// rows the call's passes picked (FIX 5815, as `connector.call` answers
/// them): the catalog route key, each standing grant read, the governing
/// key, each slate read and the custody record its send presented; unknown
/// when they are not known. The live session takes the reply whole, with
/// the listed rows, as it did before. For a caller off this device whose
/// reply names or lists a row that stays here, only the answer narrows: a
/// connector's questions as `connector.call` narrows them, beside the
/// session's processing (FIX 11725), and any other reply to the word that
/// it ran.
pub(crate) async fn ai_voice_tool(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveVoiceToolRequest,
) -> MaybeListed<ActAnswer<LiveVoiceToolReply>> {
    let session = match owner_proof(auth, server, "ai.voice.tool")
        .and_then(|_| server.live_voice.get(auth, &input.session_ref))
    {
        Ok(session) => session,
        Err(error) => return (Err(error), Some(Vec::new())),
    };
    if let Err(error) = session.require_tool_context() {
        return (Err(error), Some(Vec::new()));
    }
    let (answer, mut listed) = credential_listing(
        server,
        auth,
        caller,
        "connector.call",
        move |server, _, memory| {
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            super::connector_call_doors::connector_call_listing_as(server, &memory, input.call)
        },
    )
    .await;
    let (reply, picked) = match answer {
        Ok(answer) => answer,
        Err(refusal) => return (Err(refusal), Some(listed)),
    };
    // The session reads what it read before: the rows the call's reads
    // listed.
    let result = match &reply {
        ConnectorCallReply::Delivered {
            result: Some(result),
            ..
        } => session.tool(result.clone(), listed.clone()).await,
        _ => session.processed(),
    };
    // The rows the call's passes picked ride beside them in the answer, as
    // `connector.call` answers them; unknown when they are not known.
    let rows = picked.map(move |mut picked| {
        listed.append(&mut picked);
        listed
    });
    let whole = |processed: LiveVoiceProcessed, reply: ConnectorCallReply| LiveVoiceToolReply {
        processed,
        reply: LiveVoiceToolCallReply::Done(reply),
    };
    match result {
        Ok(processed) if super::connector_call_doors::answers_as_before(&reply) => {
            (Ok(ActAnswer::Done(whole(processed, reply))), rows)
        }
        // FIX 11725: the connector's questions narrow only their text, as
        // `connector.call`'s do, and the session's processing rides beside
        // them.
        Ok(processed) if matches!(reply, ConnectorCallReply::AwaitingInput { .. }) => {
            let (answer, rows) = super::connector_call_doors::narrowed_questions(
                server.vault(),
                &auth.destination(),
                reply,
                rows,
            );
            let answer = answer.map(|answer| match answer {
                ActAnswer::Done(reply) => ActAnswer::Done(whole(processed, reply)),
                ActAnswer::QuestionsNarrowed(questions) => ActAnswer::Done(LiveVoiceToolReply {
                    processed,
                    reply: LiveVoiceToolCallReply::QuestionsNarrowed(questions),
                }),
                ActAnswer::DetailsOnDevice(_) => ActAnswer::details_on_device(),
            });
            (answer, rows)
        }
        result => crate::device_local::act_answer_maybe(
            server.vault(),
            &auth.destination(),
            (result.map(|processed| whole(processed, reply)), rows),
        ),
    }
}

/// `ai.voice.end` (`host_door_lists`): the reply is the processing cursor
/// and status; the final audio and notices stay the events page's, so the
/// list is complete and empty.
pub(crate) async fn ai_voice_end(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer: MemoryResult<LiveVoiceProcessed> = async {
        owner_proof(auth, server, "ai.voice.end")?;
        server.live_voice.get(auth, &input.session_ref)?.end().await
    }
    .await;
    (answer, Vec::new())
}

/// `ai.voice.close` (`host_door_lists`): the reply is the saved processing
/// status; the retained events it releases are not served, so the list is
/// complete and empty.
pub(crate) async fn ai_voice_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceSessionRequest,
) -> Listed<LiveVoiceProcessed> {
    let answer: MemoryResult<LiveVoiceProcessed> = async {
        owner_proof(auth, server, "ai.voice.close")?;
        let session = server.live_voice.get(auth, &input.session_ref)?;
        let processed = if session.processed()?.ended {
            session.processed()?
        } else {
            session.end().await?
        };
        server.live_voice.remove(auth, &input.session_ref)?;
        Ok::<_, oneiron::memory::MemoryError>(processed)
    }
    .await;
    (answer, Vec::new())
}
