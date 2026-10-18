//! Credential-bound public sessions. HTTP and held-socket RPC use the same
//! typed facade rows. No UDS listener, hello or wire DTO is a public API.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::*;
use tokio::sync::{mpsc, oneshot};

use super::boot::{PreparedCall, prepare_call};
use super::public_events::Journal;
use crate::auth::CoreAuth;
use crate::managed::ManagedShutdown;
use crate::server::SyncServer;

#[derive(Default)]
pub(crate) struct LiveVoiceSessions {
    entries: Mutex<HashMap<String, Arc<PublicSession>>>,
}

pub(crate) struct PublicSession {
    pub(super) auth: CoreAuth,
    owner_only: bool,
    pub(super) commands: mpsc::Sender<Command>,
    pub(super) journal: Arc<Mutex<Journal>>,
    pub(super) shutdown: ManagedShutdown,
}

pub(super) enum Command {
    Audio(LiveVoiceAudioRequest, oneshot::Sender<MemoryResult<LiveVoiceProcessed>>),
    Ack(LiveVoiceAckRequest, oneshot::Sender<MemoryResult<LiveVoiceProcessed>>),
    Tool(oneiron::task_verb::sdk::ConnectorToolResult, oneshot::Sender<MemoryResult<LiveVoiceProcessed>>),
    Usage(u64, oneshot::Sender<MemoryResult<LiveVoiceUsage>>),
    End(oneshot::Sender<MemoryResult<LiveVoiceProcessed>>),
}

pub(super) fn unavailable() -> MemoryError {
    MemoryError::not_found("no live voice session belongs to this credential")
}

pub(super) fn invalid(message: &str) -> MemoryError {
    MemoryError::bad_request(message)
}

impl LiveVoiceSessions {
    pub(crate) fn get(&self, auth: &CoreAuth, session_ref: &str) -> MemoryResult<Arc<PublicSession>> {
        let entries = self.entries.lock().map_err(|_| unavailable())?;
        entries.get(session_ref)
            .filter(|entry| entry.auth.same_authority(auth))
            .cloned().ok_or_else(unavailable)
    }

    pub(crate) fn remove(&self, auth: &CoreAuth, session_ref: &str) -> MemoryResult<()> {
        let entry = self.get(auth, session_ref)?;
        entry.shutdown.trigger();
        self.entries.lock().map_err(|_| unavailable())?.remove(session_ref);
        Ok(())
    }
}

impl PublicSession {
    pub(crate) fn require_tool_context(&self) -> MemoryResult<()> {
        let journal = self.journal.lock().map_err(|_| unavailable())?;
        if !self.owner_only || journal.ended || journal.epochs.values().any(|epoch| !epoch.finished) {
            return Err(invalid("live tool context needs an idle owner-only session with no room or roster"));
        }
        Ok(())
    }

    pub(crate) fn processed(&self) -> MemoryResult<LiveVoiceProcessed> {
        Ok(self.journal.lock().map_err(|_| unavailable())?.processed())
    }

    pub(crate) async fn audio(&self, input: LiveVoiceAudioRequest) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::Audio(input, reply)).await.map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn ack(&self, input: LiveVoiceAckRequest) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::Ack(input, reply)).await.map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn tool(&self, result: ConnectorToolResult) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::Tool(result, reply)).await.map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn usage(&self, generation: u64) -> MemoryResult<LiveVoiceUsage> {
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::Usage(generation, reply)).await.map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn end(&self) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::End(reply)).await.map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) fn events(&self, input: LiveVoiceEventsRequest) -> MemoryResult<LiveVoiceEvents> {
        self.journal.lock().map_err(|_| unavailable())?.page(input)
    }
}

pub(crate) async fn start_public(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceStartRequest,
) -> MemoryResult<LiveVoiceSession> {
    let settings = server.ai.voice_settings().cloned()
        .ok_or_else(|| invalid("live voice needs configured models.voice and media routes"))?;
    let shutdown = ManagedShutdown::new();
    let PreparedCall { session_ref, host, brain, media, live } =
        prepare_call(server, &settings, auth, input.clone(), &shutdown)
            .map_err(|_| invalid("live voice admission or configured voice routes refused"))?;
    let (tts, bridge, worker, wire, control) = media.build().map_err(MemoryError::from)?;
    let journal = Arc::new(Mutex::new(Journal::new(session_ref.clone())));
    let (commands, receiver) = mpsc::channel(settings.queue_capacity);
    let entry = Arc::new(PublicSession {
        auth: auth.clone(), owner_only: input.room_ref.is_none() && input.roster_ref.is_none(), commands, journal: Arc::clone(&journal), shutdown: shutdown.clone(),
    });
    server.live_voice.entries.lock().map_err(|_| unavailable())?
        .insert(session_ref.clone(), entry);
    let running = super::public_loop::PublicLoop {
        host, bridge, wire: Some(wire), outputs: super::VoiceOutputs { brain, tts, control },
        journal, session_ref: session_ref.clone(), live,
    };
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::spawn(async move {
        let serving = running.run(&server, receiver, &shutdown);
        tokio::pin!(serving);
        let worker = worker.run();
        tokio::pin!(worker);
        tokio::select! {
            result = &mut serving => { if let Err(error) = result { tracing::warn!(%error.code, "public voice stopped"); } }
            () = &mut worker => { shutdown.trigger(); let _ = serving.await; }
            () = super::boot::revoked(&auth, &server) => { shutdown.trigger(); let _ = serving.await; }
        }
    });
    Ok(LiveVoiceSession { session_ref, sample_rate: input.sample_rate, channels: input.channels })
}
