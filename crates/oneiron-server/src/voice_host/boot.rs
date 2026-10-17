//! The server's own voice loop at serve start (OF-410). `[models.voice]`'s
//! `socket` names a private socket below the owner-only runtime directory;
//! the sibling that carries the call's audio connects there, one call at a
//! time, and a second connection waits for the first to end.
//!
//! A call opens with `hello{token, binding, sample_rate, channels}`: the
//! owner's capability slip and a fresh transport binding proof, admitted by
//! the doors the HTTP API uses (`bind_transport_once`, then the owner door),
//! at the on-device locality of a kernel-checked local socket. The socket's
//! 0600 mode alone proves no owner. A bad or missing token closes the socket
//! before any audio is admitted; an admitted call is answered `accepted`.
//!
//! The call then runs on the wire's media ops (`wire`): the chat role
//! answers each heard final (`brain`) on the owner's budget line, its
//! sentences are spoken past the session's safeguards (`speech`), and the
//! host's own model calls run on a line of the call's own (`backend`).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::claim::CallerLocality;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, VoiceChunkPolicy};
use oneiron::voice_cascade::VoiceSessionConfig;
use oneiron::voice_cascade::uds::{MAX_FRAME_BYTES, SocketGuard};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, EntityId, Vault, WriteActor};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::backend::CallBackend;
use super::{
    ChatBrain, ChatBrainBindings, VoiceHost, VoiceHostBindings, VoiceServeBindings,
    VoiceWireBindings,
};
use crate::auth::{BindingProof, CoreAuth, CoreScope};
use crate::config::models::VoiceSettings;
use crate::managed::{ManagedShutdown, ShutdownSignal};
use crate::server::SyncServer;

/// The agent that answers a call, as the chat route's default.
const DEFAULT_AGENT: &str = "sys.default";
/// How long a connection may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a call's slip is checked again: a slip revoked mid-call ends
/// the call within this.
const LIVENESS_EVERY: Duration = Duration::from_secs(5);
/// Brain events the host holds before the brain waits.
const BRAIN_QUEUE: usize = 256;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Hello {
    Hello {
        token: String,
        binding: BindingProof,
        sample_rate: u32,
        channels: u16,
    },
}

/// The running voice loop; [`Self::stop`] ends it.
pub(crate) struct VoiceBoot {
    shutdown: ManagedShutdown,
    task: JoinHandle<()>,
}

impl VoiceBoot {
    /// Off unless `settings` names a socket. A socket that cannot be bound
    /// (a missing or shared directory, an occupied path, a path past the
    /// platform's socket length, a platform other than Linux or macOS) is
    /// logged and leaves voice off.
    pub(crate) fn start(
        server: &Arc<SyncServer>,
        settings: Option<&VoiceSettings>,
    ) -> Option<Self> {
        let settings = settings?;
        let socket = settings.socket.as_ref()?;
        let (Some(directory), Some(name)) = (socket.parent(), socket.file_name()) else {
            tracing::warn!("voice: models.voice.socket names no socket");
            return None;
        };
        let bound = SocketGuard::bind(directory, name).and_then(|guard| {
            let listener = tokio::net::UnixListener::from_std(guard.try_clone_listener()?)?;
            Ok((guard, listener))
        });
        let (guard, listener) = match bound {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, socket = %socket.display(), "voice: socket not bound; voice is off");
                return None;
            }
        };
        tracing::info!(socket = %socket.display(), "voice: listening");
        let shutdown = ManagedShutdown::new();
        let task = tokio::spawn(accept(
            Arc::clone(server),
            settings.clone(),
            guard,
            listener,
            shutdown.clone(),
        ));
        Some(Self { shutdown, task })
    }

    /// Stops admission, ends the call in flight through its usual teardown
    /// and removes the socket.
    pub(crate) async fn stop(self) {
        self.shutdown.trigger();
        let _ = self.task.await;
    }
}

async fn accept(
    server: Arc<SyncServer>,
    settings: VoiceSettings,
    guard: SocketGuard,
    listener: tokio::net::UnixListener,
    shutdown: ManagedShutdown,
) {
    // The guard removes the socket once the loop ends.
    let _guard = guard;
    loop {
        let stream = tokio::select! {
            () = shutdown.triggered() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    tracing::warn!(%error, "voice: accept failed");
                    continue;
                }
            },
        };
        // One call at a time: the next connection waits in the backlog.
        if let Err(error) = call(&server, &settings, stream, &shutdown).await {
            tracing::warn!(%error, "voice: call ended");
        }
    }
}

fn refused(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("voice: {reason}"))
}

fn failed(reason: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("voice: {reason}"))
}

/// One call: hello, admission, the call's host and bindings, then serving
/// until the sibling hangs up or the server stops.
async fn call(
    server: &Arc<SyncServer>,
    settings: &VoiceSettings,
    mut stream: UnixStream,
    shutdown: &ManagedShutdown,
) -> io::Result<()> {
    let Hello::Hello {
        token,
        binding,
        sample_rate,
        channels,
    } = tokio::time::timeout(HELLO_TIMEOUT, hello(&mut stream))
        .await
        .map_err(|_| refused("no hello"))??;
    let vault = server.vault();
    // The same doors as the HTTP API: the slip with a fresh binding proof,
    // admitted once, then the owner door.
    if !token.starts_with("v2.slip.") {
        return Err(refused("not a capability slip"));
    }
    let auth = CoreAuth::bind_transport_once(&token, &binding, vault)
        .map_err(|_| refused("credential"))?
        .at(CallerLocality::OnDevice);
    for scope in [CoreScope::Read, CoreScope::Write] {
        auth.require(scope).map_err(|_| refused("scope"))?;
    }
    let owner = crate::api::owner(&auth, server).map_err(|_| refused("owner"))?;
    let actor = auth
        .principal_ref()
        .and_then(|principal| EntityId::from_hex(principal).ok())
        .ok_or_else(|| refused("principal"))?;
    let payer = WriteActor::new(actor, EdgeActorClass::Human);
    let instructions = instructions(&auth, vault)?;

    let call_ref = format!("voice-call:{}", EntityId::now().to_hex());
    let mut session = VoiceSessionConfig::new(
        call_ref.clone(),
        InterlocutorResolutionInput {
            owner_session: true,
            parties: Vec::new(),
            voice_session_ref: None,
        },
    );
    session.policy_caller_ref = auth.principal_ref().map(str::to_owned);
    session.policy_person = Some(owner);

    // The host's own model calls run on the call's line, and the host
    // meters them on an observer of its own, as a pass's host does.
    let units = settings.call_budget_units;
    let line = vault
        .policy_budget_guard(
            call_ref.clone(),
            units,
            DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            payer.clone(),
        )
        .map_err(failed)?;
    let router = server
        .ai
        .models()
        .router()
        .ok_or_else(|| failed("no [models] router"))?;
    let run = server.ai.undeclared_run(call_ref.clone(), line);
    let host = VoiceHost::new(
        Arc::clone(vault),
        &server.config.runtime,
        VoiceHostBindings {
            backend: Arc::new(CallBackend::new(Arc::clone(server), router, run)),
            budget: BudgetGuard::new(
                format!("{call_ref}:host"),
                units,
                BudgetExhaustionPolicy::Suspend,
            ),
            extraction_prompt: settings.extraction_prompt.clone().unwrap_or_default(),
            session,
            shutdown: shutdown.clone(),
        },
    )
    .map_err(failed)?;

    let (out, brain_out) = mpsc::channel(BRAIN_QUEUE);
    let brain = ChatBrain::new(ChatBrainBindings {
        ai: server.ai.clone(),
        vault: Arc::clone(vault),
        instructions,
        payer,
        out,
    })
    .map_err(failed)?;
    let render = settings
        .render
        .clone()
        .ok_or_else(|| failed("no voice to speak in"))?;
    // The reply is written before the stream is handed over: nothing else
    // is written to it until then.
    stream.write_all(b"{\"op\":\"accepted\"}\n").await?;
    let bindings = VoiceServeBindings::with_wire(
        stream,
        brain,
        VoiceWireBindings {
            door: Arc::clone(server.ai.models()),
            vault: Arc::clone(vault),
            render,
            sample_rate,
            channels,
            brain_out,
            chunking: VoiceChunkPolicy::default(),
            queue_capacity: settings.queue_capacity,
        },
    )
    .map_err(failed)?;
    let connection = bindings
        .take()
        .map_err(failed)?
        .ok_or_else(|| failed("connection already claimed"))?;
    // The slip passed the door once, at hello; it is checked again through
    // the call, and a revoked one ends it as the server's stop would.
    let stopping = shutdown.triggered();
    let vault = Arc::clone(vault);
    let stop: ShutdownSignal = Box::pin(async move {
        tokio::select! {
            () = stopping => {}
            () = revoked(&auth, &vault) => {
                tracing::info!("voice: the call's credential was revoked; ending the call");
            }
        }
    });
    connection.serve_until(host, stop).await
}

/// Resolves once the call's credential is no longer live.
async fn revoked(auth: &CoreAuth, vault: &Vault) {
    let mut every = tokio::time::interval(LIVENESS_EVERY);
    loop {
        every.tick().await;
        if !auth.credential_is_live(vault) {
            return;
        }
    }
}

/// The first frame, read a byte at a time so nothing after it is taken
/// from the stream the call is served on.
async fn hello(stream: &mut UnixStream) -> io::Result<Hello> {
    let mut frame = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if frame.len() >= MAX_FRAME_BYTES {
            return Err(refused("hello exceeds the frame limit"));
        }
        frame.push(byte);
    }
    serde_json::from_slice(&frame).map_err(|_| refused("not a hello"))
}

/// The answering agent's instructions, as the chat route reads them: the
/// seeded default, dispatchable, and readable by the caller.
fn instructions(auth: &CoreAuth, vault: &Vault) -> io::Result<Option<String>> {
    let (id, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)
        .map_err(failed)?
        .ok_or_else(|| failed("no default agent"))?;
    let definition = AgentDispatcher::new(vault)
        .dispatchable_definition(&AgentDispatchTarget::Custom(id))
        .map_err(failed)?;
    if !auth.can_read_entity(vault, &id).unwrap_or(false) {
        return Err(refused("agent not readable"));
    }
    Ok(definition
        .instructions
        .filter(|text| !text.trim().is_empty()))
}
