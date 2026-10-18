//! The host doors of the owner's off-record session rows (DOOR-127, e2e
//! PRIVACY-06). `host_doors` re-exports them, so the generated HTTP facade
//! handler and the MCP dispatcher call them by the name every host door has.
//! Each takes the vault owner's proof as `/v1/owner/off-record` takes it
//! (`owner_routes::owner`), and acts on the owner's own 1:1 stretch only
//! (`OFF_RECORD_OWNER_ONE_TO_ONE`): a stretch in a room is the same 404 as
//! none.
//!
//! - `vault.off_record.start`, `.status`, `.witness` and `.discard` run the
//!   owner adapter's own enter, record, witness and close
//!   (`owner::off_record`), and answer its shapes. Close without a save is
//!   the discard.
//! - `vault.off_record.recall` reads the room's overlay with base, on the
//!   caller's own credential handle (`Memory::recall_in_session`).
//! - `vault.off_record.notes.create` and `.claims.upsert` write through the
//!   session's handle into the room (`Memory::create_note_in_session`,
//!   `Memory::claim_upsert_in_session`).
//! - `self.off_record.execute` runs one entry of a durable code-mode run
//!   bound to the session, on the server's code-mode host.
//!
//! None keeps a call receipt (`no_record`): ARCH-0052 keeps no wire receipt
//! that a session ran. Each lists its rows (`host_door_lists`): a recall
//! lists the rows its reads derived it from; the others read none a caller
//! does not name, and list none.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    CommitReceipt, Effort, EntityRefReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryPack,
    MemoryResult, RecallScope, WitnessReceipt,
};
use oneiron::off_record::OffRecordSession;
use oneiron::task_verb::sdk::{
    OFF_RECORD_OWNER_ONE_TO_ONE, OffRecordClaimRequest, OffRecordClosed, OffRecordEnterMode,
    OffRecordExecuteRequest, OffRecordExecuted, OffRecordNoteRequest, OffRecordRecallRequest,
    OffRecordRunStatus, OffRecordSessionRequest, OffRecordSessionView, OffRecordStartRequest,
    OffRecordWitnessRequest,
};
use oneiron::{EntityId, ErrorKind, Vault, WriteActor};

use super::host_doors::{Listed, internal, naming};
use super::legal_hold_doors::{as_owner, as_owner_listing, as_owner_naming};
use crate::auth::CoreAuth;
use crate::mcp::McpCodeExecutionError;
use crate::owner::OwnerError;
use crate::owner::off_record as owner_off_record;
use crate::server::SyncServer;

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
        ErrorKind::KillSwitchDisabled => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "off-record sessions are turned off for this vault",
            &[],
        ),
        _ => MemoryError::from(error),
    }
}

/// Refuses a stretch in a room as the same 404 as none, before the owner
/// adapter would act on it (`OFF_RECORD_OWNER_ONE_TO_ONE`).
fn one_to_one(vault: &Vault, session_ref: &str) -> MemoryResult<()> {
    let in_room = vault
        .off_record_session(session_ref)
        .map_err(|error| session_refusal(error, session_ref))?
        .is_some_and(|record| record.room.is_some());
    if OFF_RECORD_OWNER_ONE_TO_ONE && in_room {
        return Err(MemoryError::not_found(format!(
            "no off-record session {session_ref}"
        )));
    }
    Ok(())
}

/// The owner's own live 1:1 stretch `session_ref`, bound for them.
fn own_session<'vault>(
    vault: &'vault Vault,
    owner: &AuthenticatedOwner,
    session_ref: &str,
) -> MemoryResult<OffRecordSession<'vault>> {
    let actor = owner.revalidate(vault)?;
    let session = vault
        .off_record_session_vault()
        .bind_for(session_ref, actor)
        .map_err(|error| session_refusal(error, session_ref))?;
    if OFF_RECORD_OWNER_ONE_TO_ONE && session.room()?.is_some() {
        return Err(MemoryError::not_found(format!(
            "no off-record session {session_ref}"
        )));
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

/// `vault.off_record.start`: enters a session, off record or anonymous, as
/// `POST /v1/owner/off-record` does.
pub(crate) async fn vault_off_record_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordStartRequest,
) -> Listed<OffRecordSessionView> {
    const VERB: &str = "vault.off_record.start";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            let request = owner_off_record::Enter {
                session_ref: input.session_ref,
                mode: match input.mode {
                    OffRecordEnterMode::OffRecord => owner_off_record::EnterMode::OffRecord,
                    OffRecordEnterMode::Anonymous => owner_off_record::EnterMode::Anonymous,
                },
                backend: input.backend,
            };
            owner_off_record::enter(server.vault(), owner, &request)
                .map(view)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.off_record.status`: one live session as its owner sees it, as
/// `GET /v1/owner/off-record` reads it.
pub(crate) async fn vault_off_record_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordSessionRequest,
) -> Listed<OffRecordSessionView> {
    const VERB: &str = "vault.off_record.status";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            one_to_one(server.vault(), &input.session_ref)?;
            owner_off_record::record(server.vault(), owner, &input.session_ref)
                .map(view)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.off_record.witness`: witnesses one turn into the session as its
/// owner, as `POST /v1/owner/off-record/witness` does.
pub(crate) async fn vault_off_record_witness(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordWitnessRequest,
) -> Listed<WitnessReceipt> {
    const VERB: &str = "vault.off_record.witness";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            one_to_one(server.vault(), &input.session_ref)?;
            let request = owner_off_record::Witness {
                session_ref: input.session_ref,
                turn: input.turn,
                summary: input.summary,
            };
            owner_off_record::witness(server.vault(), owner, &request)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.off_record.discard`: closes the session without saving it, as
/// `POST /v1/owner/off-record/close` does; what was not promoted is gone.
pub(crate) async fn vault_off_record_discard(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordSessionRequest,
) -> Listed<OffRecordClosed> {
    const VERB: &str = "vault.off_record.discard";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            one_to_one(server.vault(), &input.session_ref)?;
            owner_off_record::close(server.vault(), owner, &input.session_ref)
                .map(|closed| OffRecordClosed {
                    session_ref: closed.session_ref,
                    turns_dropped: closed.turns_dropped,
                    context_receipts_dropped: closed.context_receipts_dropped,
                    emit_receipts_dropped: closed.emit_receipts_dropped,
                    emit_receipts_kept: closed.emit_receipts_kept,
                    promoted_turns_kept: closed.promoted_turns_kept,
                })
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.off_record.recall`: a light recall over the room's overlay and
/// base, on the caller's own credential handle, listing every row its reads
/// derive the answer from.
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
    as_owner_listing(server, auth, VERB, move |server, owner, producers| {
        let session = own_session(server.vault(), owner, &input.session_ref)?;
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

/// `vault.off_record.notes.create`: one NOTE written into the session's
/// room through its handle.
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
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            let session = own_session(server.vault(), owner, &input.session_ref)?;
            crate::api::credential_memory(&server.vault, Some(&held), actor, class)
                .at(held.locality())
                .create_note_in_session(&session, &input.note.kind, &input.note.markdown)
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.off_record.claims.upsert`: one claim admitted into the session's
/// room through its handle.
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
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            let session = own_session(server.vault(), owner, &input.session_ref)?;
            crate::api::credential_memory(&server.vault, Some(&held), actor, class)
                .at(held.locality())
                .claim_upsert_in_session(&session, &input.claim)
        },
        |_| Vec::new(),
    )
    .await
}

/// A session run's refusal as the row's.
fn run_refusal(error: &McpCodeExecutionError) -> MemoryError {
    let (code, suggestion) = match error {
        McpCodeExecutionError::RunBusy => (
            MEMORY_CODE_INVALID_STATE,
            "Call again once the run's current entry ends.",
        ),
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
    // The owner's proof, and their own live 1:1 stretch by that name, before
    // a run is entered: the run binds it again on its own thread.
    as_owner(server, auth, VERB, move |server, owner| {
        own_session(server.vault(), owner, &session_ref).map(drop)
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
    let run_id = crate::mcp::off_record_run_id(&input.session_ref, actor, &input.run_ref);
    let outcome = host
        .execute_in_off_record_session(
            Arc::clone(&server.vault),
            input.session_ref,
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
    })
}

/// `self.off_record.execute`: one entry of a durable code-mode run bound to
/// the owner's session, listing no row: the run's rows are the room's.
pub(crate) async fn self_off_record_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OffRecordExecuteRequest,
) -> Listed<OffRecordExecuted> {
    naming(off_record_execute(server, auth, input).await, |_| {
        Vec::<EntityId>::new()
    })
}
