//! The host doors of the off-record session rows (DOOR-127, e2e
//! PRIVACY-06). `host_doors` re-exports them, so the generated HTTP facade
//! handler and the MCP dispatcher call them by the name every host door has.
//!
//! Who manages a session (WILL-PLAN L13 row 03, Engine ruling 2026-10-19):
//! a stretch entered alone is managed by the person or agent who entered
//! it, on their own slip, live again on every call, and by the vault's live
//! owner on their proof (`owner_routes::owner`). A stretch the owner entered
//! is the owner's alone. Neither the session's name nor a broad read Grant
//! manages one: the registry keeps the creator per instance, in RAM
//! (`OffRecordSessionVault::bind_as_creator`), so a name taken again after
//! close carries none of the closed instance's authority. Each creator names
//! their stretches in their own space (FIX 4597): start answers the
//! instance's opaque handle as its `session_ref`, which later calls and the
//! session header name, as the caller's own name for it does among their
//! own; no answer says that a name someone else holds is taken. The owner
//! manages a creator's instance by its handle, on their proof.
//!
//! A stretch in a room keeps its members' own bounded acts: status reads it
//! as their membership shows it, witness speaks in it as one of them, and
//! the room's routes (`/v1/core/off-record/*`) save and export. Recalling
//! everyone's overlay at once, writing or running in it, and discarding it
//! for the room answer `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE` to a
//! caller on its roster ([`room_management`]), and a stranger the same 404
//! as none.
//!
//! - `vault.off_record.start` enters a stretch alone, off record or
//!   anonymous: the owner's through the owner adapter (`owner::off_record`),
//!   anyone else's as its creator.
//! - `vault.off_record.status`, `.witness` and `.discard` read it, speak in
//!   it and close it; close without a save is the discard.
//! - `vault.off_record.recall` reads the session's overlay with base, on the
//!   caller's own credential handle (`Memory::recall_in_session`).
//! - `vault.off_record.notes.create` and `.claims.upsert` write through the
//!   session's handle into it (`Memory::create_note_in_session`,
//!   `Memory::claim_upsert_in_session`).
//! - `self.off_record.execute` runs one entry of a durable code-mode run
//!   bound to the session, on the server's code-mode host.
//! - `self.off_record.results.list`, `.results.read`, `.waits.get` and
//!   `.waits.answer` read that run's results and answer its wait through
//!   the session ([`run_reads`], FIX 4284).
//!
//! None keeps a call receipt (`no_record`): ARCH-0052 keeps no wire receipt
//! that a session ran. Each lists its rows (`host_door_lists`): a recall
//! lists the rows its reads derived it from; the others read none a caller
//! does not name, and list none.
use std::sync::Arc;

use oneiron::authority::VerifiedSlip;
use oneiron::code_run::ProgramStepFeedbackRelease;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    CommitReceipt, Effort, EntityRefReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_ROOM_MANAGEMENT,
    MemoryError, MemoryPack, MemoryResult, ProducerRows, RecallScope, WitnessReceipt,
};
use oneiron::off_record::{OffRecordCreator, OffRecordSession};
use oneiron::task_verb::sdk::{
    OffRecordClaimRequest, OffRecordClosed, OffRecordEnterMode, OffRecordExecuteRequest,
    OffRecordExecuted, OffRecordNoteRequest, OffRecordRecallRequest, OffRecordRunStatus,
    OffRecordSessionRequest, OffRecordSessionView, OffRecordStartRequest, OffRecordWitnessRequest,
};
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault, WriteActor};

use super::host_doors::support::{Listed, internal, naming, off_runtime_listing, refused};
use crate::auth::CoreAuth;
use crate::mcp::{McpCodeExecutionError, OffRecordRunSession};
use crate::owner::OwnerError;
use crate::owner::off_record as owner_off_record;
use crate::server::SyncServer;

mod run_reads;

pub(crate) use self::run_reads::*;

/// Who calls a session row.
enum Caller {
    /// The vault's live owner, on their proof: every stretch entered alone
    /// is theirs to manage.
    Owner(AuthenticatedOwner),
    /// A person or agent on their own slip: the stretches they entered
    /// alone are theirs to manage while that slip stays live.
    Principal {
        who: OffRecordCreator,
        credential: VerifiedSlip,
    },
}

impl Caller {
    /// The creator a stretch must name for this caller to manage it; `None`
    /// for the owner, who manages every stretch entered alone.
    fn creator(&self) -> Option<OffRecordCreator> {
        match self {
            Self::Owner(_) => None,
            Self::Principal { who, .. } => Some(*who),
        }
    }
}

/// The caller a session row admits: the vault's owner on their proof, as
/// `/v1/owner/off-record` takes it, or else a person or agent on a slip
/// that binds them. A host credential names no person, and a managed
/// owner's attestation keeps no slip to check again, so neither is the
/// second.
fn caller(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Caller> {
    super::owner_binding::host_preflight(server, auth)?;
    if let Ok(owner) = crate::api::owner_routes::owner(auth, server) {
        return Ok(Caller::Owner(owner));
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} takes the vault owner's proof, or the slip of a person or agent"),
            &[
                "Present the owner's own verified credential, or your own slip bound to a person or agent.",
            ],
        )
    };
    if auth.is_host_holder() || auth.managed_owner().is_some() {
        return Err(refused());
    }
    let (actor, class) = super::facade_actor(server, auth).map_err(|_| refused())?;
    if !matches!(class, EdgeActorClass::Human | EdgeActorClass::Agent) {
        return Err(refused());
    }
    let credential = auth.verified_slip().cloned().ok_or_else(refused)?;
    Ok(Caller::Principal {
        who: OffRecordCreator { actor, class },
        credential,
    })
}

/// [`caller`] as `door_admits` runs it before a row's hooks fire: a caller
/// these rows admit at all. Each door admits it again for the stretch it
/// binds.
pub(super) fn off_record_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    caller(server, auth, verb).map(drop)
}

/// A principal's slip, live again for this call: a revoked or lapsed slip
/// manages nothing, whatever it started.
fn live(vault: &Vault, credential: &VerifiedSlip, verb: &str) -> MemoryResult<()> {
    if vault.capability_slip_is_live(credential)? {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb}: the slip presented is no longer live"),
        &["Pair again, then call with the new slip."],
    ))
}

/// `act` off the runtime, for the caller the row admits.
async fn as_caller<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Caller) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let caller = caller(server, auth, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || act(&server, &caller))
        .await
        .map_err(|_| internal(verb))?
}

/// [`as_caller`] for a door whose answer derives from no row it reads
/// (`host_door_lists`): it lists none.
async fn as_caller_unlisted<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Caller) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    naming(as_caller(server, auth, verb, act).await, |_| Vec::new())
}

/// [`as_caller`] for a door that lists its rows: `act` gets a fresh
/// collector its handles list into, and beside its answer come the rows
/// they listed. A refused caller lists none.
async fn as_caller_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Caller, &ProducerRows) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match caller(server, auth, verb) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    off_runtime_listing(verb, move |producers| act(&server, &caller, producers)).await
}

/// The owner adapter's refusal as the row's: the same statuses, in the
/// facade's error shape.
fn refusal(verb: &str, error: OwnerError) -> MemoryError {
    match error {
        OwnerError::Invalid(message) => MemoryError::bad_request(message),
        OwnerError::NotFound(what, which) => MemoryError::not_found(format!("no {what} {which}")),
        OwnerError::Changed(message) => MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[]),
        OwnerError::Refused(message) => MemoryError::new(MEMORY_CODE_FORBIDDEN, message, &[]),
        OwnerError::Engine(error) => MemoryError::from(*error),
        OwnerError::Host(_) => internal(verb),
    }
}

/// The engine's session refusal as the row's, as the owner adapter words it.
fn session_refusal(error: oneiron::Error, session_ref: &str) -> MemoryError {
    match error.kind() {
        ErrorKind::OffRecordSessionNotFound | ErrorKind::OffRecordNotInRoom => {
            MemoryError::not_found(format!("no off-record session {session_ref}"))
        }
        ErrorKind::OffRecordSessionClosing => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("off-record session {session_ref} is closing"),
            &[],
        ),
        ErrorKind::OffRecordSessionAlreadyExists => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("off-record session {session_ref} already exists"),
            &["Start it under another name."],
        ),
        ErrorKind::KillSwitchDisabled => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "off-record sessions are turned off for this vault",
            &[],
        ),
        _ => MemoryError::from(error),
    }
}

/// A session row that would manage a room's stretch whole: read everyone's
/// overlay at once, write or run in it, or discard it for the room (Engine
/// ruling 2026-10-19). The caller is on the room's roster, so the refusal
/// names itself rather than reading as none. This is a missing consent
/// record, not a location refusal: no record holds the room audience's
/// consent to one caller managing its stretch (canon is silent on one), so
/// a hosted server, a self-hosted one and an embedded engine refuse it
/// alike. The members' bounded acts stay open.
fn room_management(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_ROOM_MANAGEMENT,
        format!(
            "{verb} would manage a room's whole off-record stretch, and no record holds the \
             room's consent to that: a missing consent record, not a limit of where the vault \
             runs"
        ),
        &[
            "Read the stretch or speak in it as a member, with vault.off_record.status or vault.off_record.witness.",
            "Save or export your own copy through the room's routes, /v1/core/off-record/save and /v1/core/off-record/export.",
        ],
    )
}

/// Whether `session_ref` names a live stretch in a room. A room's key never
/// names a stretch entered alone, so the answer holds for any instance the
/// name binds.
fn in_room(vault: &Vault, session_ref: &str) -> MemoryResult<bool> {
    Ok(vault
        .off_record_session(session_ref)
        .map_err(|error| session_refusal(error, session_ref))?
        .is_some_and(|record| record.room.is_some()))
}

/// The stretch `session_ref`, bound for `caller` to manage with `verb`: one
/// entered alone, the owner's to manage or its creator's. A room's stretch
/// is [`room_management`] to a caller on its roster, checked before the
/// name, and the same 404 as none to anyone else.
fn managed_session<'vault>(
    vault: &'vault Vault,
    caller: &Caller,
    verb: &str,
    session_ref: &str,
) -> MemoryResult<OffRecordSession<'vault>> {
    let rooms = vault.off_record_session_vault();
    let session = match caller {
        Caller::Owner(owner) => rooms.bind_for(session_ref, owner.revalidate(vault)?),
        Caller::Principal { who, credential } => {
            live(vault, credential, verb)?;
            if in_room(vault, session_ref)? {
                rooms.bind_for(session_ref, who.actor)
            } else {
                rooms.bind_as_creator(session_ref, *who)
            }
        }
    }
    .map_err(|error| session_refusal(error, session_ref))?;
    if session.room()?.is_some() {
        return Err(room_management(verb));
    }
    Ok(session)
}

fn view(session: owner_off_record::Session) -> OffRecordSessionView {
    OffRecordSessionView {
        session_ref: session.session_ref,
        mode: session.mode,
        backend: session.backend,
        entered_at: session.entered_at,
        promoted_turns: session.promoted_turns,
        closing: session.closing,
    }
}

/// `vault.off_record.start`: enters a session alone, off record or
/// anonymous: the owner's as `POST /v1/owner/off-record` does, anyone
/// else's with them as its creator.
pub(crate) async fn vault_off_record_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordStartRequest,
) -> Listed<OffRecordSessionView> {
    const VERB: &str = "vault.off_record.start";
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let vault = server.vault();
        let (who, credential) = match caller {
            Caller::Owner(owner) => {
                let request = owner_off_record::Enter {
                    session_ref: input.session_ref,
                    mode: match input.mode {
                        OffRecordEnterMode::OffRecord => owner_off_record::EnterMode::OffRecord,
                        OffRecordEnterMode::Anonymous => owner_off_record::EnterMode::Anonymous,
                    },
                    backend: input.backend,
                };
                return owner_off_record::enter(vault, owner, &request)
                    .map(view)
                    .map_err(|error| refusal(VERB, error));
            }
            Caller::Principal { who, credential } => (*who, credential),
        };
        live(vault, credential, VERB)?;
        let rooms = vault.off_record_session_vault();
        let session_ref = &input.session_ref;
        let record = match input.mode {
            OffRecordEnterMode::OffRecord => {
                rooms.enter_as_creator(session_ref, input.backend, who)
            }
            OffRecordEnterMode::Anonymous => {
                rooms.enter_anonymous_as_creator(session_ref, input.backend, who)
            }
        }
        .and_then(|session| session.record())
        .map_err(|error| session_refusal(error, session_ref))?;
        Ok(view(owner_off_record::Session::from(record)))
    })
    .await
}

/// `vault.off_record.status`: one live session as its manager sees it, as
/// `GET /v1/owner/off-record` reads it; a room's stretch as the caller's
/// membership shows it.
pub(crate) async fn vault_off_record_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordSessionRequest,
) -> Listed<OffRecordSessionView> {
    const VERB: &str = "vault.off_record.status";
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let vault = server.vault();
        let session_ref = &input.session_ref;
        let (who, credential) = match caller {
            Caller::Owner(owner) => {
                return owner_off_record::record(vault, owner, session_ref)
                    .map(view)
                    .map_err(|error| refusal(VERB, error));
            }
            Caller::Principal { who, credential } => (*who, credential),
        };
        live(vault, credential, VERB)?;
        let rooms = vault.off_record_session_vault();
        // A room's stretch reads as the room's own route reads it to a
        // member; one entered alone, whole, to its creator.
        let record = if in_room(vault, session_ref)? {
            rooms
                .bind_for(session_ref, who.actor)
                .and_then(|session| session.record_for(who.actor))
        } else {
            rooms
                .bind_as_creator(session_ref, who)
                .and_then(|session| session.record())
        }
        .map_err(|error| session_refusal(error, session_ref))?;
        Ok(view(owner_off_record::Session::from(record)))
    })
    .await
}

/// `vault.off_record.witness`: witnesses one turn into the session as its
/// manager, as `POST /v1/owner/off-record/witness` does; into a room's
/// stretch as one of its members.
pub(crate) async fn vault_off_record_witness(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordWitnessRequest,
) -> Listed<WitnessReceipt> {
    const VERB: &str = "vault.off_record.witness";
    let locality = auth.locality();
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let vault = server.vault();
        let (who, credential) = match caller {
            Caller::Owner(owner) => {
                let request = owner_off_record::Witness {
                    session_ref: input.session_ref,
                    turn: input.turn,
                    summary: input.summary,
                };
                return owner_off_record::witness(vault, owner, &request)
                    .map_err(|error| refusal(VERB, error));
            }
            Caller::Principal { who, credential } => (*who, credential),
        };
        live(vault, credential, VERB)?;
        let session_ref = &input.session_ref;
        let rooms = vault.off_record_session_vault();
        let memory = vault.memory(who.actor, who.class).at(locality);
        let summary = input.summary.as_deref();
        if in_room(vault, session_ref)? {
            // A member speaks as the room's own route has them speak.
            let session = rooms
                .bind_for(session_ref, who.actor)
                .map_err(|error| session_refusal(error, session_ref))?;
            return memory.witness_into_session_as_member(
                &session,
                &input.turn,
                summary,
                Some(credential),
            );
        }
        let session = rooms
            .bind_as_creator(session_ref, who)
            .map_err(|error| session_refusal(error, session_ref))?;
        session.witness_as_creator(&memory, &input.turn, summary, credential)
    })
    .await
}

/// `vault.off_record.discard`: closes the session without saving it, as
/// `POST /v1/owner/off-record/close` does; what was not promoted is gone.
/// It closes the instance it bound, never one that took the name since.
pub(crate) async fn vault_off_record_discard(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordSessionRequest,
) -> Listed<OffRecordClosed> {
    const VERB: &str = "vault.off_record.discard";
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let session_ref = &input.session_ref;
        let closed = managed_session(server.vault(), caller, VERB, session_ref)?
            .close()
            .map_err(|error| session_refusal(error, session_ref))?;
        Ok(OffRecordClosed {
            session_ref: input.session_ref,
            turns_dropped: closed.turns_deleted,
            context_receipts_dropped: closed.context_receipts_deleted,
            emit_receipts_dropped: closed.emit_receipts_deleted,
            emit_receipts_kept: closed.emit_receipts_retained.len(),
            promoted_turns_kept: closed.promoted_turns_kept,
        })
    })
    .await
}

/// `vault.off_record.recall`: a light recall over the session's overlay
/// and base, on the caller's own credential handle, listing every row its
/// reads derive the answer from.
pub(crate) async fn vault_off_record_recall(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordRecallRequest,
) -> Listed<MemoryPack> {
    const VERB: &str = "vault.off_record.recall";
    let (actor, class) = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return (Err(error.into_memory_error()), Vec::new()),
    };
    let held = auth.clone();
    as_caller_listing(server, auth, VERB, move |server, caller, producers| {
        let session = managed_session(server.vault(), caller, VERB, &input.session_ref)?;
        crate::api::credential_memory(&server.vault, Some(&held), actor, class)
            .at(held.locality())
            .listing_producers(producers)
            .recall_in_session(
                &session,
                &input.query,
                Effort::Light,
                &RecallScope::default(),
                input.limit,
                None,
                None,
            )
    })
    .await
}

/// `vault.off_record.notes.create`: one NOTE written into the session
/// through its handle.
pub(crate) async fn vault_off_record_notes_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordNoteRequest,
) -> Listed<EntityRefReceipt> {
    const VERB: &str = "vault.off_record.notes.create";
    let (actor, class) = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return (Err(error.into_memory_error()), Vec::new()),
    };
    let held = auth.clone();
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let session = managed_session(server.vault(), caller, VERB, &input.session_ref)?;
        crate::api::credential_memory(&server.vault, Some(&held), actor, class)
            .at(held.locality())
            .create_note_in_session(
                &session,
                &input.note.kind,
                &input.note.markdown,
                &input.evidence_turn_refs,
            )
    })
    .await
}

/// `vault.off_record.claims.upsert`: one claim admitted into the session
/// through its handle.
pub(crate) async fn vault_off_record_claims_upsert(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordClaimRequest,
) -> Listed<CommitReceipt> {
    const VERB: &str = "vault.off_record.claims.upsert";
    let (actor, class) = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return (Err(error.into_memory_error()), Vec::new()),
    };
    let held = auth.clone();
    as_caller_unlisted(server, auth, VERB, move |server, caller| {
        let session = managed_session(server.vault(), caller, VERB, &input.session_ref)?;
        crate::api::credential_memory(&server.vault, Some(&held), actor, class)
            .at(held.locality())
            .claim_upsert_in_session(&session, &input.claim)
    })
    .await
}

/// A session run's refusal as the row's.
fn run_refusal(error: &McpCodeExecutionError) -> MemoryError {
    let (code, suggestion) = match error {
        McpCodeExecutionError::HostUnbound
        | McpCodeExecutionError::RunWaitedOut
        | McpCodeExecutionError::ProviderUnavailable { .. } => (
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "Call again with the same run_ref.",
        ),
        McpCodeExecutionError::RunBinding(_) => (
            MEMORY_CODE_INVALID_STATE,
            "Check that the session is live and off record, then call again.",
        ),
        McpCodeExecutionError::Run(_) => (
            MEMORY_CODE_INTERNAL,
            "Call again with the same run_ref; the run goes on from its last step.",
        ),
    };
    MemoryError::new(code, error.to_string(), &[suggestion])
}

/// [`self_off_record_execute`]'s answer.
async fn off_record_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordExecuteRequest,
) -> MemoryResult<OffRecordExecuted> {
    const VERB: &str = "self.off_record.execute";
    let (actor, class) =
        super::facade_actor(server, auth).map_err(|error| error.into_memory_error())?;
    let session_ref = input.session_ref.clone();
    // The caller's own stretch by that handle or name, before a run is
    // entered: the run binds the instance's key again on its own thread, for
    // its creator when the caller manages it as one.
    let (session_ref, creator) = as_caller(server, auth, VERB, move |server, caller| {
        managed_session(server.vault(), caller, VERB, &session_ref)
            .map(|session| (session.session_ref().to_owned(), caller.creator()))
    })
    .await?;
    let host = server
        .code_execution_host()
        .and_then(|host| host.engine_native())
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "this server runs no code-mode host",
                &["Configure the server's code-mode host, then call again."],
            )
        })?;
    let run_id = crate::mcp::off_record_run_id(&session_ref, actor, &input.run_ref);
    let outcome = host
        .execute_in_off_record_session(
            Arc::clone(&server.vault),
            // The run's reads in the room read under this request's own
            // caller, credential and place (WILL L11-01).
            OffRecordRunSession {
                session_ref,
                creator,
                caller: auth.clone(),
            },
            WriteActor::new(actor, class),
            input.run_ref.clone(),
            input.task,
            run_id,
        )
        .await
        .map_err(|error| run_refusal(&error))?;
    let (status, next_step_seq) = match &outcome.status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => {
            (OffRecordRunStatus::Complete, None)
        }
        oneiron::engine_executor::EngineExecutorStatus::Waiting(_) => {
            (OffRecordRunStatus::Waiting, None)
        }
        oneiron::engine_executor::EngineExecutorStatus::Yielded { next_step_seq } => {
            (OffRecordRunStatus::Yielded, Some(*next_step_seq))
        }
        oneiron::engine_executor::EngineExecutorStatus::WindowFull { next_step_seq, .. } => {
            (OffRecordRunStatus::WindowFull, Some(*next_step_seq))
        }
    };
    Ok(OffRecordExecuted {
        run_ref: input.run_ref,
        run_id: run_id.to_hex(),
        status,
        next_step_seq,
        steps_run: outcome.steps_run,
        bridge_calls: outcome.replay_record.bridge_calls.len(),
        // Each step's feedback the run keeps on the session's route, whole:
        // the reply's destination release judges each apart (FIX 10389).
        program_steps: outcome
            .program_steps
            .into_iter()
            .map(ProgramStepFeedbackRelease::Released)
            .collect(),
    })
}

/// `self.off_record.execute`: one entry of a durable code-mode run bound to
/// the caller's session, listing no row: the run's rows are the session's.
pub(crate) async fn self_off_record_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordExecuteRequest,
) -> Listed<OffRecordExecuted> {
    naming(off_record_execute(server, auth, input).await, |_| {
        Vec::<EntityId>::new()
    })
}
