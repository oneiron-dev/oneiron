//! The server's own voice loop at serve start (OF-410). `[models.voice]`'s
//! `socket` names a private socket below the owner-only runtime directory;
//! the sibling that carries the call's audio connects there, one call at a
//! time, and a second connection waits for the first to end.
//!
//! A call opens with `hello{token, binding, sample_rate, channels}`: the
//! owner's capability slip and a fresh transport binding proof, admitted by
//! the doors the HTTP API uses (`bind_transport_once`, then the owner door),
//! at the on-device locality of a kernel-checked local socket. The socket's
//! 0600 mode alone proves no owner. A refused hello (a bad or missing token
//! among them) is answered with one line, `{"op":"refused","code":..,
//! "reason":..}` ([`Refusal`]), and the socket closes before any audio is
//! admitted; an admitted call is answered `accepted`.
//! On a managed vault (FIX 2391) the hello carries no slip. It carries
//! `managed_owner`, a supervisor's `ManagedOwnerAction` for the vault's
//! owner, signed over the room and roster the hello names, its `issued_at`
//! and its `nonce`, 16 fresh random bytes as 32 lowercase hex characters;
//! the vault takes it once, near its time, through the verifier managed
//! serve hands in. The call's auth is the attested owner as the managed
//! facade takes him (`CoreAuth::for_attested_owner`), off-device, and the
//! owner door then admits it as it admits a managed facade request. A
//! managed host also takes the owner's own enrolled device (FIX 1949 = B):
//! its slip and binding proof, admitted by the same doors, and `machine`,
//! its install key's claim over that very proof, for a machine that stands
//! here as the owner's own. That call reads off this device, toward the
//! machine, and ends once the machine no longer stands so. An invited
//! person's slip stays refused by the owner door, and a hello mixing an
//! attestation with a slip, or a slip with a nonce, is refused. A plain host
//! takes no managed hello and no machine claim.
//! The hello may name the `room` the call is heard in and the voice
//! `roster` its speakers are matched under. A room the caller cannot read
//! closes the socket. A bound call is live in its room until it ends: each
//! speaker it hears that no member covers enters the room, the room's reads
//! meet them (FIX 1388/1389), and an attendee's entry stops the call's
//! output (OF-365 P5).
//!
//! The call then runs on the wire's media ops (`wire`): the chat role
//! answers each heard final (`brain`) on the owner's budget line, its
//! sentences are spoken past the session's safeguards (`speech`), and the
//! host's own model calls run on a line of the call's own (`backend`).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::disclosure::RoomParty;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, VoiceChunkPolicy};
use oneiron::voice_cascade::uds::SocketGuard;
use oneiron::voice_cascade::{
    VOICE_IDENTITY_ASK_SECONDS, VoiceContainerBinding, VoiceSessionConfig,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, EntityId, Vault, WriteActor};
use oneiron_vault_contract::{MANAGED_VOICE_NONCE_BYTES, ManagedOwnerAction};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::backend::CallBackend;
use super::hello_refusal::{Refusal, refuse, refused};
use super::{
    ChatBrain, ChatBrainBindings, VoiceHost, VoiceHostBindings, VoiceServeBindings,
    VoiceWireBindings,
};
use crate::ai_host::payer_funding::{PayerFault, room_launch_funding};
use crate::auth::{BindingProof, CoreAuth, CoreScope, MachineClaim};
use crate::config::models::VoiceSettings;
use crate::managed::{ManagedShutdown, ShutdownSignal};
use crate::server::{HousekeepingAdmission, SyncServer};

/// The agent that answers a call, as the chat route's default.
const DEFAULT_AGENT: &str = "sys.default";
/// How long a connection may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a call's credential is checked again: a slip revoked mid-call,
/// or a managed owner no longer the vault's live owner, ends the call
/// within this.
const LIVENESS_EVERY: Duration = Duration::from_secs(5);
/// Brain events the host holds before the brain waits.
const BRAIN_QUEUE: usize = 256;
/// A roster ref is a speaker entry's session key, which holds this many
/// bytes at most.
const MAX_ROSTER_REF_BYTES: usize = 128;
/// The live contacts a speaker's "who is this?" ask offers at most: the
/// entry's own cap.
const MAX_ROOM_CANDIDATES: usize = 32;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Hello {
    Hello {
        /// The owner's capability slip, on a plain host or from his own
        /// enrolled device on a managed one.
        #[serde(default)]
        token: Option<String>,
        /// Its fresh transport binding proof.
        #[serde(default)]
        binding: Option<BindingProof>,
        /// On a managed host, the owner's enrolled machine: its install
        /// key's signature over the token and the binding's timestamp and
        /// nonce, as `x-oneiron-machine` carries one.
        #[serde(default)]
        machine: Option<MachineClaim>,
        /// The supervisor's attestation of the vault's owner, on a managed
        /// host.
        #[serde(default)]
        managed_owner: Option<ManagedOwnerAction>,
        /// When the supervisor attested the hello, in Unix seconds.
        #[serde(default)]
        issued_at: Option<u64>,
        /// The attestation's fresh nonce, 32 lowercase hex characters,
        /// signed after `issued_at`: required beside `managed_owner`, and
        /// carried by no other hello.
        #[serde(default)]
        nonce: Option<String>,
        sample_rate: u32,
        channels: u16,
        /// The room the call is heard in, by its id.
        #[serde(default)]
        room: Option<String>,
        /// The voice roster the call's speakers are matched under.
        #[serde(default)]
        roster: Option<String>,
    },
}

/// A managed host's check of a hello's supervisor attestation: the owner it
/// names, given the room and roster the hello names (empty when absent), its
/// `issued_at` and its nonce's raw bytes, or `None`.
pub(crate) type ManagedVoiceVerifier = Arc<
    dyn Fn(
            &ManagedOwnerAction,
            &str,
            &str,
            u64,
            &[u8; MANAGED_VOICE_NONCE_BYTES],
        ) -> Option<EntityId>
        + Send
        + Sync,
>;

/// What a call is admitted under, and how its hello is authenticated.
#[derive(Clone)]
struct CallDoors {
    /// `Some` on a managed host: its hellos carry an attestation, or the
    /// owner's own enrolled device's slip and machine claim.
    managed: Option<ManagedVoiceVerifier>,
    /// Held for each call's whole length, as a served write is.
    admit: HousekeepingAdmission,
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
    /// logged and leaves voice off. `managed` checks a managed host's hellos
    /// (`None` on a plain host, whose hellos carry a slip), and each call
    /// holds an admission from `admit` for its whole length; a refused one
    /// closes the connection.
    pub(crate) fn start(
        server: &Arc<SyncServer>,
        settings: Option<&VoiceSettings>,
        managed: Option<ManagedVoiceVerifier>,
        admit: HousekeepingAdmission,
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
            CallDoors { managed, admit },
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
    doors: CallDoors,
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
        if let Err(error) = call(&server, &settings, &doors, stream, &shutdown).await {
            tracing::warn!(%error, "voice: call ended");
        }
    }
}

fn failed(reason: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("voice: {reason}"))
}

/// One call: hello, admission, the call's host and bindings, then serving
/// until the sibling hangs up or the server stops. A hello refused before
/// the call is admitted is answered with its `refused` line, then closed.
async fn call(
    server: &Arc<SyncServer>,
    settings: &VoiceSettings,
    doors: &CallDoors,
    mut stream: UnixStream,
    shutdown: &ManagedShutdown,
) -> io::Result<()> {
    // Held until the call and its teardown end, first taken and last dropped.
    let admission = (doors.admit)();
    let opened = if admission.is_some() {
        open(server, settings, doors, &mut stream, shutdown).await
    } else {
        Err(refused(Refusal::WritesFrozen))
    };
    let (auth, device, prepared) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            refuse(&mut stream, &error).await;
            return Err(error);
        }
    };
    let PreparedCall {
        host,
        brain,
        media,
        live: _live_call,
        ..
    } = prepared;
    // The reply is written before the stream is handed over: nothing else
    // is written to it until then.
    stream.write_all(b"{\"op\":\"accepted\"}\n").await?;
    let bindings = VoiceServeBindings::with_wire(stream, brain, media).map_err(failed)?;
    let connection = bindings
        .take()
        .map_err(failed)?
        .ok_or_else(|| failed("connection already claimed"))?;
    // The credential passed the door once, at hello; it is checked again
    // through the call, and a revoked one ends it as the server's stop would.
    let stopping = shutdown.triggered();
    let server = Arc::clone(server);
    let stop: ShutdownSignal = Box::pin(async move {
        tokio::select! {
            () = stopping => {}
            () = call_revoked(&auth, &server, device) => {
                tracing::info!("voice: the call's credential was revoked; ending the call");
            }
        }
    });
    connection.serve_until(host, stop).await
}

/// The hello, read and admitted: its credential through the doors its
/// fields name, then the call's dependencies ([`prepare_call`]). The caller,
/// the enrolled machine its call reads toward, and the prepared call; each
/// refusal is a [`Refusal`].
async fn open(
    server: &Arc<SyncServer>,
    settings: &VoiceSettings,
    doors: &CallDoors,
    stream: &mut UnixStream,
    shutdown: &ManagedShutdown,
) -> io::Result<(CoreAuth, Option<PeerMachine>, PreparedCall)> {
    let Hello::Hello {
        token,
        binding,
        machine,
        managed_owner,
        issued_at,
        nonce,
        sample_rate,
        channels,
        room,
        roster,
    } = tokio::time::timeout(HELLO_TIMEOUT, hello(stream))
        .await
        .map_err(|_| refused(Refusal::NoHello))??;
    let vault = server.vault();
    let (auth, device) = match (
        token,
        binding,
        machine,
        managed_owner,
        issued_at,
        nonce,
        &doors.managed,
    ) {
        // The same doors as the HTTP API: the slip with a fresh binding
        // proof, admitted once, then the owner door.
        (Some(token), Some(binding), None, None, None, None, None) => {
            if !token.starts_with("v2.slip.") {
                return Err(refused(Refusal::NotCapabilitySlip));
            }
            let auth = CoreAuth::bind_transport_once(&token, &binding, vault)
                .map_err(|_| refused(Refusal::Credential))?
                .at(CallerLocality::OnDevice);
            (auth, None)
        }
        // A managed vault's owner on his own enrolled device (FIX 1949 =
        // B): the same doors, and the machine his hello names proves itself
        // over this very proof and stands here as his own. The supervisor
        // forwarded it, so the call reads off this device, toward it.
        (Some(token), Some(binding), Some(machine), None, None, None, Some(_)) => {
            if server.managed_issuer.is_none() {
                return Err(refused(Refusal::Credential));
            }
            if !token.starts_with("v2.slip.") {
                return Err(refused(Refusal::NotCapabilitySlip));
            }
            let auth = CoreAuth::bind_transport_once(&token, &binding, vault)
                .map_err(|_| refused(Refusal::Credential))?;
            let device = crate::auth::owned_machine(&machine, &token, &binding, vault)
                .ok_or_else(|| refused(Refusal::NotEnrolledDevice))?;
            (auth.toward(device), Some(device))
        }
        // The managed facade's attested owner, once the attestation over
        // the hello's room, roster, time and fresh nonce checks out.
        (None, None, None, Some(action), Some(issued_at), nonce, Some(verify)) => {
            if server.managed_issuer.is_none() {
                return Err(refused(Refusal::Credential));
            }
            if room.as_deref() == Some("") || roster.as_deref() == Some("") {
                return Err(refused(Refusal::Room));
            }
            let nonce = nonce
                .as_deref()
                .and_then(oneiron_vault_contract::managed_voice_nonce)
                .ok_or_else(|| refused(Refusal::Nonce))?;
            let holder = verify(
                &action,
                room.as_deref().unwrap_or_default(),
                roster.as_deref().unwrap_or_default(),
                issued_at,
                &nonce,
            )
            .ok_or_else(|| refused(Refusal::ManagedOwner))?;
            let auth = CoreAuth::for_attested_owner(holder, server)
                .map_err(|_| refused(Refusal::Credential))?;
            (auth, None)
        }
        _ => return Err(refused(Refusal::Credential)),
    };
    let prepared = prepare_call(
        server,
        settings,
        &auth,
        oneiron::task_verb::sdk::LiveVoiceStartRequest {
            sample_rate,
            channels,
            room_ref: room,
            roster_ref: roster,
        },
        shutdown,
    )?;
    Ok((auth, device, prepared))
}

/// Call dependencies built only after the existing owner and credential gates.
pub(super) struct PreparedCall {
    pub(super) session_ref: String,
    pub(super) host: VoiceHost,
    pub(super) brain: ChatBrain,
    pub(super) media: VoiceWireBindings,
    pub(super) live: Option<oneiron::conversation::LiveSpeakerCall>,
}

pub(super) fn prepare_call(
    server: &Arc<SyncServer>,
    settings: &VoiceSettings,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::LiveVoiceStartRequest,
    shutdown: &ManagedShutdown,
) -> io::Result<PreparedCall> {
    let oneiron::task_verb::sdk::LiveVoiceStartRequest {
        sample_rate,
        channels,
        room_ref: room,
        roster_ref: roster,
    } = input;
    let vault = server.vault();
    for scope in [CoreScope::Read, CoreScope::Write] {
        auth.require(scope).map_err(|_| refused(Refusal::Scope))?;
    }
    let owner = crate::api::owner(auth, server).map_err(|_| refused(Refusal::Owner))?;
    let actor = auth
        .principal_ref()
        .and_then(|principal| EntityId::from_hex(principal).ok())
        .ok_or_else(|| refused(Refusal::Principal))?;
    let payer = WriteActor::new(actor, EdgeActorClass::Human);
    let (agent, instructions) = instructions(auth, vault)?;
    if roster.as_deref().is_some_and(|roster| {
        roster.is_empty() || roster.trim() != roster || roster.len() > MAX_ROSTER_REF_BYTES
    }) {
        return Err(refused(Refusal::Roster));
    }
    let container = room
        .as_deref()
        .map(|room| bind_room(vault, auth, actor, room))
        .transpose()?;
    // A call heard in a room bills the payer whose consent on its answering
    // agent's join funds that room (FIX 805), resolved once, before any
    // provider work; a call with no payer to bill is refused, typed. The
    // host's run, each brain turn and the media door all bill it.
    let funding = match &container {
        Some(binding) => crate::server::blocking(|| {
            room_launch_funding(vault, binding.container, None, agent, actor)
        })
        .map_err(|fault| {
            tracing::info!(%fault, "voice: the room's funding refused the call");
            refused(match fault {
                PayerFault::Missing { .. } => Refusal::PayerMissing,
                PayerFault::Needed { .. } => Refusal::PayerNeeded,
            })
        })?,
        None => None,
    };
    // The call is live in its room from here, whichever way it then ends:
    // the registration drops with this frame, after the call is served.
    let live = container
        .as_ref()
        .map(|bound| vault.register_live_speaker_call(bound.container, roster.clone()));

    let call_ref = format!("voice-call:{}", EntityId::now().to_hex());
    let mut session = VoiceSessionConfig::new(
        call_ref.clone(),
        InterlocutorResolutionInput {
            owner_session: true,
            parties: Vec::new(),
            voice_session_ref: roster,
        },
    );
    session.policy_caller_ref = auth.principal_ref().map(str::to_owned);
    session.policy_person = Some(owner);
    let brain_room = container.as_ref().map(|bound| bound.container);
    session.container = container;

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
    let run = server
        .ai
        .model_runtime()
        .funded_run(call_ref.clone(), line, funding.clone());
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
        auth: auth.clone(),
        room: brain_room,
        instructions,
        payer,
        funding: funding.clone(),
        out,
    })
    .map_err(failed)?;
    let render = settings
        .render
        .clone()
        .ok_or_else(|| failed("no voice to speak in"))?;
    Ok(PreparedCall {
        session_ref: call_ref,
        host,
        brain,
        media: VoiceWireBindings {
            door: server.media_door(funding),
            vault: Arc::clone(vault),
            render,
            sample_rate,
            channels,
            brain_out,
            chunking: VoiceChunkPolicy::default(),
            queue_capacity: settings.queue_capacity,
        },
        live,
    })
}

/// The room `room` names, bound as the call's container: one the caller
/// reads, with its members as the caller reads them. Each speaker the call
/// must place there enters it as the caller, and one it cannot place is
/// offered as any of the room's contacts.
fn bind_room(
    vault: &Vault,
    auth: &CoreAuth,
    caller: EntityId,
    room: &str,
) -> io::Result<VoiceContainerBinding> {
    let room = EntityId::from_hex(room).map_err(|_| refused(Refusal::Room))?;
    let read =
        crate::api::scoped_read_for_core_auth(vault, auth).map_err(|_| refused(Refusal::Room))?;
    // A room the caller cannot read is one that does not exist.
    let members = vault
        .room_audience_members_under(&read, room, Some(caller))
        .map_err(|_| refused(Refusal::Room))?;
    let mut candidates = Vec::new();
    for party in vault.room_parties(&members).map_err(failed)? {
        if let RoomParty::Contact(contact) = party
            && !candidates.contains(&contact)
            && candidates.len() < MAX_ROOM_CANDIDATES
        {
            candidates.push(contact);
        }
    }
    Ok(VoiceContainerBinding {
        container: room,
        writer: caller,
        writer_class: EdgeActorClass::Human,
        candidates,
        ask_seconds: VOICE_IDENTITY_ASK_SECONDS,
    })
}

/// Resolves once the call's credential is no longer live: its slip, or for
/// a managed owner, the person's standing as the vault's live owner.
pub(super) async fn revoked(auth: &CoreAuth, server: &SyncServer) {
    let mut every = tokio::time::interval(LIVENESS_EVERY);
    loop {
        every.tick().await;
        let live = if auth.managed_owner().is_some() {
            crate::api::owner(auth, server).is_ok()
        } else {
            auth.credential_is_live(server.vault())
        };
        if !live {
            return;
        }
    }
}

/// [`revoked`], for one call: an enrolled device's call (FIX 1949 = B) also
/// ends once its slip is revoked, its person is no longer the vault's live
/// owner, or its machine no longer stands here as his own.
async fn call_revoked(auth: &CoreAuth, server: &SyncServer, device: Option<PeerMachine>) {
    let Some(device) = device else {
        return revoked(auth, server).await;
    };
    let mut every = tokio::time::interval(LIVENESS_EVERY);
    loop {
        every.tick().await;
        let live = auth.credential_is_live(server.vault())
            && crate::api::owner(auth, server).is_ok()
            && crate::auth::owned_machine_stands(server.vault(), device);
        if !live {
            return;
        }
    }
}

/// The first frame, read a byte at a time so nothing after it is taken
/// from the stream the call is served on.
async fn hello(stream: &mut UnixStream) -> io::Result<Hello> {
    let mut frame = Vec::new();
    loop {
        // A stream that closes before its hello said none.
        let byte = stream
            .read_u8()
            .await
            .map_err(|_| refused(Refusal::NoHello))?;
        if byte == b'\n' {
            break;
        }
        frame.push(byte);
    }
    serde_json::from_slice(&frame).map_err(|_| refused(Refusal::NotHello))
}

/// The answering agent and its instructions, as the chat route reads them:
/// the seeded default, dispatchable, and readable by the caller.
fn instructions(auth: &CoreAuth, vault: &Vault) -> io::Result<(EntityId, Option<String>)> {
    let (id, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)
        .map_err(failed)?
        .ok_or_else(|| failed("no default agent"))?;
    let definition = AgentDispatcher::new(vault)
        .dispatchable_definition(&AgentDispatchTarget::Custom(id))
        .map_err(failed)?;
    if !auth.can_read_entity(vault, &id).unwrap_or(false) {
        return Err(refused(Refusal::Agent));
    }
    Ok((
        id,
        definition
            .instructions
            .filter(|text| !text.trim().is_empty()),
    ))
}
