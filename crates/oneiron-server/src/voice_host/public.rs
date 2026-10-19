//! Credential-bound public sessions. HTTP and held-socket RPC use the same
//! typed facade rows. No UDS listener, hello or wire DTO is a public API.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::*;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::boot::{PreparedCall, prepare_call};
use super::public_events::Journal;
use super::public_hold::{SessionHold, while_held, writes_frozen};
use crate::auth::CoreAuth;
use crate::managed::ManagedShutdown;
use crate::server::{HousekeepingAdmission, SyncServer};

/// What a session start refused once the host is stopping.
const STOPPING: &str = "the host is stopping; no live voice session starts";

#[derive(Default)]
pub(crate) struct LiveVoiceSessions {
    entries: Mutex<HashMap<String, Arc<PublicSession>>>,
    /// Each session's task, owned so the host's stop waits for its teardown
    /// (FIX 5324), behind the gate that stop closes.
    tasks: Mutex<SessionTasks>,
    /// The host's write gate each session holds an admission from
    /// (`public_hold`); unset on a host with no freeze, which admits every
    /// session.
    admit: OnceLock<HousekeepingAdmission>,
}

/// The sessions' tasks, and whether the host has stopped them.
#[derive(Default)]
struct SessionTasks {
    /// Set by [`LiveVoiceSessions::stop_all`]: no session starts after it.
    closing: bool,
    /// Each running session's stop and task.
    running: Vec<(ManagedShutdown, JoinHandle<()>)>,
}

pub(crate) struct PublicSession {
    pub(super) auth: CoreAuth,
    owner_only: bool,
    pub(super) commands: mpsc::Sender<Command>,
    pub(super) journal: Arc<Mutex<Journal>>,
    pub(super) shutdown: ManagedShutdown,
    /// Its admission, released while it idles on a host that freezes.
    hold: Arc<SessionHold>,
}

pub(super) enum Command {
    Audio(
        LiveVoiceAudioRequest,
        oneshot::Sender<MemoryResult<LiveVoiceProcessed>>,
    ),
    Ack(
        LiveVoiceAckRequest,
        oneshot::Sender<MemoryResult<LiveVoiceProcessed>>,
    ),
    /// A delivered tool result, beside the rows its connector call listed.
    Tool(
        oneiron::task_verb::sdk::ConnectorToolResult,
        Vec<oneiron::EntityId>,
        oneshot::Sender<MemoryResult<LiveVoiceProcessed>>,
    ),
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
    /// Binds the write gate each later session holds an admission from:
    /// managed serve's, which a vault frozen for reap refuses. The first
    /// binding stands.
    pub(crate) fn admit_with(&self, admit: HousekeepingAdmission) {
        let _ = self.admit.set(admit);
    }

    /// Whether this host's gate can refuse, so an idle session releases its
    /// admission.
    fn releases(&self) -> bool {
        self.admit.get().is_some()
    }

    /// One session's admission, or `None` from a vault frozen for reap.
    fn admission(&self) -> Option<Box<dyn Send>> {
        match self.admit.get() {
            Some(admit) => admit(),
            // A host with no freeze admits every session, as
            // `admit_every_pass` admits every pass.
            None => Some(Box::new(())),
        }
    }

    /// The session `session_ref` names, for the credential that opened it.
    /// Naming it starts its idle clock again, and a session that released
    /// its admission takes one again first; a vault frozen for reap refuses
    /// with the typed pause.
    pub(crate) fn get(
        &self,
        auth: &CoreAuth,
        session_ref: &str,
    ) -> MemoryResult<Arc<PublicSession>> {
        let entry = self
            .entries
            .lock()
            .map_err(|_| unavailable())?
            .get(session_ref)
            .filter(|entry| entry.auth.same_authority(auth))
            .cloned()
            .ok_or_else(unavailable)?;
        entry.hold.named(|| self.admission())?;
        Ok(entry)
    }

    pub(crate) fn remove(&self, auth: &CoreAuth, session_ref: &str) -> MemoryResult<()> {
        let entry = self.get(auth, session_ref)?;
        entry.shutdown.trigger();
        self.entries
            .lock()
            .map_err(|_| unavailable())?
            .remove(session_ref);
        Ok(())
    }

    /// Ends every session at the host's stop (FIX 5324): no session starts
    /// after this, each running one is told to end, and each ends through
    /// its usual teardown, its journal finished, before this returns. Only
    /// the host's own stop calls it; a reap's pause leaves sessions open.
    pub(crate) async fn stop_all(&self) {
        let running = {
            let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            tasks.closing = true;
            for (shutdown, _) in &tasks.running {
                shutdown.trigger();
            }
            std::mem::take(&mut tasks.running)
        };
        for (_, task) in running {
            let _ = task.await;
        }
    }
}

impl PublicSession {
    pub(crate) fn require_tool_context(&self) -> MemoryResult<()> {
        let journal = self.journal.lock().map_err(|_| unavailable())?;
        if !self.owner_only || journal.ended || journal.epochs.values().any(|epoch| !epoch.finished)
        {
            return Err(invalid(
                "live tool context needs an idle owner-only session with no room or roster",
            ));
        }
        Ok(())
    }

    pub(crate) fn processed(&self) -> MemoryResult<LiveVoiceProcessed> {
        Ok(self.journal.lock().map_err(|_| unavailable())?.processed())
    }

    pub(crate) async fn audio(
        &self,
        input: LiveVoiceAudioRequest,
    ) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command::Audio(input, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn ack(&self, input: LiveVoiceAckRequest) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command::Ack(input, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    /// `rows` are the ones the connector call that delivered `result`
    /// listed: each later turn that hears it is made from them (FIX 4778).
    pub(crate) async fn tool(
        &self,
        result: ConnectorToolResult,
        rows: Vec<oneiron::EntityId>,
    ) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command::Tool(result, rows, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn usage(&self, generation: u64) -> MemoryResult<LiveVoiceUsage> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command::Usage(generation, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub(crate) async fn end(&self) -> MemoryResult<LiveVoiceProcessed> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command::End(reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    /// The page, beside the rows its served events were made from (FIX
    /// 4778), `None` when one of them is unknown.
    pub(crate) fn events(
        &self,
        input: LiveVoiceEventsRequest,
    ) -> MemoryResult<super::public_events::ListedPage> {
        self.journal.lock().map_err(|_| unavailable())?.page(input)
    }
}

pub(crate) async fn start_public(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LiveVoiceStartRequest,
) -> MemoryResult<LiveVoiceSession> {
    let settings = server
        .ai
        .voice_settings()
        .cloned()
        .ok_or_else(|| invalid("live voice needs configured models.voice and media routes"))?;
    // Held by the session until its task ends, first taken and last dropped,
    // as a private call holds its own: a session in flight keeps a managed
    // vault from reading quiescent, and a frozen one opens none.
    let admission = server.live_voice.admission().ok_or_else(writes_frozen)?;
    let shutdown = ManagedShutdown::new();
    let PreparedCall {
        session_ref,
        host,
        brain,
        media,
        live,
    } = prepare_call(server, &settings, auth, input.clone(), &shutdown)
        .map_err(|_| invalid("live voice admission or configured voice routes refused"))?;
    let (tts, bridge, worker, wire, control) = media.build().map_err(MemoryError::from)?;
    let journal = Arc::new(Mutex::new(Journal::new(session_ref.clone())));
    let (commands, receiver) = mpsc::channel(settings.queue_capacity);
    let hold = Arc::new(SessionHold::new(admission, server.live_voice.releases()));
    // The enrolled device the session is opened from, while it stands here
    // as the owner's own: its standing is checked again through the session,
    // as a voice loop call's is (FIX 5323). A caller from any other machine
    // has no device standing to lose.
    let device =
        Some(auth.peer()).filter(|peer| crate::auth::owned_machine_stands(server.vault(), *peer));
    // Registered and spawned under the gate the host's stop closes, so no
    // session starts after it took the tasks it waits for.
    let mut tasks = server.live_voice.tasks.lock().map_err(|_| unavailable())?;
    if tasks.closing {
        return Err(invalid(STOPPING));
    }
    let entry = Arc::new(PublicSession {
        auth: auth.clone(),
        owner_only: input.room_ref.is_none() && input.roster_ref.is_none(),
        commands,
        journal: Arc::clone(&journal),
        shutdown: shutdown.clone(),
        hold: Arc::clone(&hold),
    });
    server
        .live_voice
        .entries
        .lock()
        .map_err(|_| unavailable())?
        .insert(session_ref.clone(), entry);
    let running = super::public_loop::PublicLoop {
        host,
        bridge,
        wire: Some(wire),
        outputs: super::VoiceOutputs {
            brain,
            tts,
            control,
        },
        journal,
        session_ref: session_ref.clone(),
        live,
        hold: Arc::clone(&hold),
    };
    let stop = shutdown.clone();
    let task = {
        let server = Arc::clone(server);
        let auth = auth.clone();
        tokio::spawn(async move {
            {
                let serving = running.run(&server, receiver, &shutdown);
                tokio::pin!(serving);
                // Released, the media worker and the credential's recheck wait
                // with the loop.
                let worker = while_held(worker.run(), hold.watch());
                tokio::pin!(worker);
                let revoked =
                    while_held(super::boot::revoked(&auth, &server, device), hold.watch());
                tokio::select! {
                    result = &mut serving => { if let Err(error) = result { tracing::warn!(%error.code, "public voice stopped"); } }
                    () = &mut worker => { shutdown.trigger(); let _ = serving.await; }
                    () = revoked => { shutdown.trigger(); let _ = serving.await; }
                }
            }
            // Last, once the session's work is dropped: its admission, for good.
            hold.end();
        })
    };
    tasks.running.retain(|(_, ended)| !ended.is_finished());
    tasks.running.push((stop, task));
    drop(tasks);
    Ok(LiveVoiceSession {
        session_ref,
        sample_rate: input.sample_rate,
        channels: input.channels,
    })
}
