//! Off-record stretches for everyone in a room (ARCH-0052 D5, the notice
//! model, owner ruling 2026-10-10). The owner's own routes stay under
//! `/v1/owner/off-record`; these serve the room's participants, each acting
//! as the person or agent their slip names, under the scopes they already
//! hold: `core:write` to start, speak or save, `core:propose` or
//! `core:write` to suggest, `core:read` to read the room or take an export.
//!
//! - Anyone on the room's roster may start a stretch there.
//! - Anyone may keep their own copy. A holder of this vault's write grant,
//!   person or agent, saves the whole talk into it, or saves from here on
//!   (#d5-save-grant, owner ruling 2026-10-16). Everyone else takes an
//!   export file; nothing here writes another vault.
//! - Each save or export posts a notice to the room's timeline, naming who
//!   and what, never the content. An agent without the grant is told to ask
//!   a holder: its suggestion posts a notice, saves nothing and waits until
//!   a holder confirms (their own save) or declines it.
//! - A person starts a stretch, and so does an agent acting within its
//!   admitted Write Grant, as itself, so it must be on the roster too
//!   (FIX 4596). Only a person exports.
//!
//! A stretch is named by its room and the host's `session_ref`; each room
//! names its own. The owner's routes address it as
//! `room:<room id>:<session_ref>`.
//!
//! These routes stay out of the idempotency layer, which keeps request and
//! response bodies in the vault, and out of the wire receipts, which keep
//! who called which route. Nothing of an off-record talk may land there.

use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::header::CONTENT_DISPOSITION;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron::memory::{MemoryError, WitnessReceipt};
use oneiron::off_record::{OffRecordSession, OffRecordSessionRecord, OffRecordTalk};
use oneiron::share_travel::effective_copy_refs;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    OffRecordRoomExport as Export, OffRecordRoomExportRequest as ExportRequest,
    OffRecordRoomExportTurn as ExportTurn, OffRecordRoomNotice as Notice,
    OffRecordRoomRequest as Stretch, OffRecordRoomSaved as Saved,
    OffRecordRoomStartRequest as Start, OffRecordRoomSuggestion as Suggestion,
    OffRecordRoomView as Room, OffRecordRoomWitnessRequest as Witness,
};
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault};

use super::{parse_entity_id_param, unix_seconds_now};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::owner::stamp::rfc3339_secs;
use crate::server::SyncServer;

type Reply<T> = Result<Json<T>, EnvelopedApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/", get(read_room))
        .route("/start", post(start))
        .route("/witness", post(witness))
        .route("/save", post(save))
        .route("/export", post(export))
        .route("/save-from-here", post(save_from_here))
        .route("/suggest-save", post(suggest_save))
        .route("/confirm-save", post(confirm_save))
        .route("/decline-save", post(decline_save))
}

async fn read_room(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<Stretch>, QueryRejection>,
) -> Reply<Room> {
    let Query(request) = query.map_err(|error| ApiError::bad_request(error.body_text(), None))?;
    Ok(Json(room_status(&server, &auth, request).await?))
}

async fn start(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Start>, JsonRejection>,
) -> Reply<Room> {
    Ok(Json(room_start(&server, &auth, json(payload)?).await?))
}

async fn witness(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Witness>, JsonRejection>,
) -> Reply<WitnessReceipt> {
    Ok(Json(room_witness(&server, &auth, json(payload)?).await?))
}

async fn save(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Saved> {
    Ok(Json(room_save(&server, &auth, json(payload)?).await?))
}

async fn save_from_here(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Room> {
    Ok(Json(
        room_save_from_here(&server, &auth, json(payload)?).await?,
    ))
}

async fn export(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ExportRequest>, JsonRejection>,
) -> Result<impl IntoResponse, EnvelopedApiError> {
    let export = room_export(&server, &auth, json(payload)?).await?;
    Ok((
        [(
            CONTENT_DISPOSITION,
            "attachment; filename=\"off-record-talk.json\"",
        )],
        Json(export),
    ))
}

async fn suggest_save(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Room> {
    Ok(Json(
        room_suggest_save(&server, &auth, json(payload)?).await?,
    ))
}

async fn confirm_save(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Saved> {
    Ok(Json(
        room_confirm_save(&server, &auth, json(payload)?).await?,
    ))
}

async fn decline_save(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Room> {
    Ok(Json(
        room_decline_save(&server, &auth, json(payload)?).await?,
    ))
}

fn room_view(record: OffRecordSessionRecord, session_ref: &str) -> Room {
    Room {
        session_ref: session_ref.to_owned(),
        room: record.room.map(hex),
        started_by: record.started_by.map(hex),
        mode: record.mode,
        backend: record.backend,
        entered_at: rfc3339_secs(record.entered_at),
        closing: record.closing,
        notices: record
            .notices
            .into_iter()
            .map(|notice| Notice {
                act: notice.act,
                by: hex(notice.by),
                at: rfc3339_secs(notice.at),
            })
            .collect(),
        waiting_suggestions: record
            .suggestions
            .into_iter()
            .map(|suggestion| Suggestion {
                by: hex(suggestion.by),
                at: rfc3339_secs(suggestion.at),
            })
            .collect(),
    }
}

fn export_view(talk: OffRecordTalk, session_ref: &str, exported_at: u64) -> Export {
    Export {
        session_ref: Some(session_ref.to_owned()),
        room: talk.room.map(hex),
        exported_at: rfc3339_secs(exported_at),
        turns: talk
            .turns
            .into_iter()
            .map(|turn| ExportTurn {
                turn: hex(turn.turn),
                speaker: turn.speaker.map(hex),
                occurred_at: rfc3339_secs(turn.occurred_at),
                saved: turn.saved,
                messages: turn.messages.into_iter().map(Into::into).collect(),
            })
            .collect(),
        copy: None,
    }
}

pub(crate) async fn room_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Room, ApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let (actor, _) = participant(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let server = Arc::clone(server);
    let view = blocking(move || {
        let session = bind(server.vault(), room, &request.session_ref, actor)?;
        view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(view)
}

pub(crate) async fn room_start(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Start,
) -> Result<Room, ApiError> {
    let actor = starter(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    // The stretch's memory, queued for on the retained line before anything
    // is made (FIX 5991). A caller gone while it waits starts nothing.
    let charge = RoomCharge::reserve(server, &request.session_ref).await;
    let server = Arc::clone(server);
    let view = blocking(move || {
        let session = server
            .vault()
            .off_record_session_vault()
            .enter_in_room_charged(
                &request.session_ref,
                request.backend,
                (room, actor),
                Box::new(charge),
            )
            .map_err(|error| engine_error(error, &request.session_ref))?;
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(view)
}

/// A room stretch's charge on the server's retained-memory line (FIX 5991):
/// reserved before the stretch is entered, then moved to what it holds as
/// its overlay changes, never refused and never waited on, and handed back
/// once its overlay is gone.
struct RoomCharge {
    line: Arc<crate::byte_line::ByteLine>,
    held: std::sync::Mutex<crate::byte_line::HeldBytes>,
    questions: Arc<crate::wire_telemetry::LimitQuestions>,
}

/// How long one place in the line waits before it queues again. Waiting
/// never refuses a start (Rule 5): only the caller leaving ends it.
const ROOM_CHARGE_WAIT: std::time::Duration = std::time::Duration::from_secs(3600);

impl RoomCharge {
    /// Queues, in arrival order and outside every engine lock, for the
    /// bytes a stretch named `session_ref` holds once entered.
    async fn reserve(server: &SyncServer, session_ref: &str) -> Self {
        let bytes = oneiron::off_record::room_entry_bytes(session_ref);
        let questions = Arc::clone(server.wire_telemetry.limit_questions());
        loop {
            let reserved = server
                .retained
                .reserve_alone(bytes, ROOM_CHARGE_WAIT, &questions)
                .await;
            if let Some(held) = reserved {
                return Self {
                    line: Arc::clone(&server.retained),
                    held: std::sync::Mutex::new(held),
                    questions,
                };
            }
        }
    }
}

impl oneiron::off_record::RetainedCharge for RoomCharge {
    fn charge(&self, bytes: usize) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.line.charge(&mut held, bytes, &self.questions);
    }
}

pub(crate) async fn room_witness(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Witness,
) -> Result<WitnessReceipt, ApiError> {
    auth.require(CoreScope::Write)?;
    let (actor, class) = participant(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let locality = auth.locality();
    let server = Arc::clone(server);
    let receipt = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        vault
            .memory(actor, class)
            .at(locality)
            .witness_into_session_as_member(
                &session,
                &request.turn,
                request.summary.as_deref(),
                credential.as_ref(),
            )
            .map_err(witness_error)
    })
    .await?;
    Ok(receipt)
}

pub(crate) async fn room_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Saved, ApiError> {
    let (actor, class) = holder(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let saved = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        // The save names its holder in its receipts: on their own slip, or,
        // with no slip (a dev server), on the owner's proof for them.
        match credential {
            Some(slip) => session.save_talk_by(actor, &slip),
            None => owner_proof(vault, actor).and_then(|owner| session.save_talk_as(&owner)),
        }
        .map_err(|error| holder_error(error, class, &request.session_ref))
    })
    .await?;
    Ok(Saved::from(saved))
}

/// A holder puts the stretch on record: later turns are saved as they land,
/// while the holder still holds the grant and stays in the room.
pub(crate) async fn room_save_from_here(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Room, ApiError> {
    let (actor, class) = holder(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let view = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        match credential {
            Some(slip) => session.flip_on_record_by(actor, &slip),
            None => owner_proof(vault, actor).and_then(|owner| session.flip_on_record_as(&owner)),
        }
        .map_err(|error| holder_error(error, class, &request.session_ref))?;
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(view)
}

/// The caller's own copy of the talk they could see: as the room holds it,
/// or without its vault refs when they ask for that (FIX 1199).
pub(crate) async fn room_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: ExportRequest,
) -> Result<Export, ApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let actor = exporter(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    // The slip was checked with the headers; the body may have arrived long
    // after. The copy is released only if it is still live once the talk is
    // gathered.
    let credential = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let export = blocking(move || {
        let talk = bind(server.vault(), room, &request.session_ref, actor)?
            .export_talk_by(actor, credential.as_ref())
            .map_err(|error| match error.kind() {
                ErrorKind::OffRecordPromoteUnauthenticated => ApiError::unauthorized(),
                _ => engine_error(error, &request.session_ref),
            })?;
        Ok(export_view(talk, &request.session_ref, unix_seconds_now())
            .with_refs(effective_copy_refs(request.travel.as_ref())))
    })
    .await?;
    Ok(export)
}

pub(crate) async fn room_suggest_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Room, ApiError> {
    // An agent without the write grant may still ask, on any slip that writes
    // or proposes, record-bounded too: a suggestion lands nothing until a
    // holder answers it.
    let actor = suggesting_agent(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let server = Arc::clone(server);
    let view = blocking(move || {
        let session = bind(server.vault(), room, &request.session_ref, actor)?;
        session
            .suggest_save_by(actor)
            .map_err(|error| engine_error(error, &request.session_ref))?;
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(view)
}

/// A holder confirms the waiting save suggestions: their own save of the
/// whole talk. 409 when no suggestion waits.
pub(crate) async fn room_confirm_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Saved, ApiError> {
    let (actor, class) = holder(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let saved = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        match credential {
            Some(slip) => session.confirm_save_by(actor, &slip),
            None => owner_proof(vault, actor).and_then(|owner| session.confirm_save_as(&owner)),
        }
        .map_err(|error| holder_error(error, class, &request.session_ref))?
        .ok_or_else(nothing_waits)
    })
    .await?;
    Ok(Saved::from(saved))
}

/// A holder declines the waiting save suggestions; nothing is saved. 409 when
/// no suggestion waits.
pub(crate) async fn room_decline_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: Stretch,
) -> Result<Room, ApiError> {
    let (actor, class) = holder(auth)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let view = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        let declined = match credential {
            Some(slip) => session.decline_save_by(actor, &slip),
            None => owner_proof(vault, actor).and_then(|owner| session.decline_save_as(&owner)),
        }
        .map_err(|error| holder_error(error, class, &request.session_ref))?;
        if !declined {
            return Err(nothing_waits());
        }
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(view)
}

/// The participant route's authority guard, before a facade hook can fire.
pub(crate) fn door_admits(auth: &CoreAuth, verb: &str) -> Result<(), ApiError> {
    match verb {
        "vault.off_record.rooms.start" => starter(auth).map(drop),
        "vault.off_record.rooms.status" => {
            auth.require(CoreScope::Read)?;
            auth.require_unrestricted_record_scope()?;
            participant(auth).map(drop)
        }
        "vault.off_record.rooms.witness" => {
            auth.require(CoreScope::Write)?;
            participant(auth).map(drop)
        }
        "vault.off_record.rooms.export" => {
            auth.require(CoreScope::Read)?;
            auth.require_unrestricted_record_scope()?;
            exporter(auth).map(drop)
        }
        "vault.off_record.rooms.suggest_save" => suggesting_agent(auth).map(drop),
        _ => holder(auth).map(drop),
    }
}

fn suggesting_agent(auth: &CoreAuth) -> Result<EntityId, ApiError> {
    auth.require_granted(if auth.has_scope(CoreScope::Write) {
        CoreScope::Write
    } else {
        CoreScope::Propose
    })?;
    match participant(auth)? {
        (actor, EdgeActorClass::Agent) => Ok(actor),
        _ => Err(forbidden(
            "only an agent suggests a save; a person saves or exports",
        )),
    }
}

/// The person or agent the slip names. An owner-grade credential names
/// nobody, so it cannot act as a participant.
fn participant(auth: &CoreAuth) -> Result<(EntityId, EdgeActorClass), ApiError> {
    let actor = auth
        .principal_ref()
        .ok_or_else(|| forbidden("a participant slip names its person with principal_ref"))
        .and_then(|value| parse_entity_id_param(value, "principal_ref"))?;
    let class = match auth.actor_class() {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        _ => return Err(ApiError::forbidden_scope("human_or_agent")),
    };
    Ok((actor, class))
}

/// Who starts a stretch in a room, on a credential that admits Write (FIX
/// 4596): a person, or an agent acting within its Grant on a verified slip
/// of its own. Either starts as itself: `enter_in_room` asks that it is on
/// the room's roster now, so an agent that is no member starts none,
/// whoever it acts for. REST and the pre-hook admission ask this alike.
fn starter(auth: &CoreAuth) -> Result<EntityId, ApiError> {
    auth.require(CoreScope::Write)?;
    match participant(auth)? {
        (actor, EdgeActorClass::Human) => Ok(actor),
        (actor, EdgeActorClass::Agent) if auth.verified_slip().is_some() => Ok(actor),
        _ => Err(forbidden(
            "an agent starts an off-record stretch only on a Write slip of its own",
        )),
    }
}

/// Who exports a stretch: a person, or an agent acting within its Grant on a
/// verified slip of its own (FIX 7854). Either takes only its own copy:
/// `export_talk_by` asks that it is in the room and gathers only the turns
/// its membership shows it, with the same live-credential check.
fn exporter(auth: &CoreAuth) -> Result<EntityId, ApiError> {
    match participant(auth)? {
        (actor, EdgeActorClass::Human) => Ok(actor),
        (actor, EdgeActorClass::Agent) if auth.verified_slip().is_some() => Ok(actor),
        _ => Err(forbidden(
            "an agent exports an off-record stretch only on a slip of its own",
        )),
    }
}

/// A participant who would save, on a credential that writes over every
/// record; the engine checks that it carries this vault's write grant. An
/// agent holds the grant only on such a slip of its own, so one without asks
/// a holder instead; with no slips at all (a dev server) only a person saves,
/// on the owner's proof, as before.
fn holder(auth: &CoreAuth) -> Result<(EntityId, EdgeActorClass), ApiError> {
    let (actor, class) = participant(auth)?;
    let admitted = auth.require(CoreScope::Write);
    if class == EdgeActorClass::Agent && (admitted.is_err() || auth.verified_slip().is_none()) {
        return Err(ask_a_holder());
    }
    admitted.map(|()| (actor, class))
}

/// The owner's proof for `actor`, for a server with no slips (a dev server).
fn owner_proof(
    vault: &Vault,
    actor: EntityId,
) -> oneiron::Result<oneiron::consent::AuthenticatedOwner> {
    vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
}

/// An agent's refusal to save is the typed "ask a holder" answer; anyone
/// else's is the engine's.
fn holder_error(error: oneiron::Error, class: EdgeActorClass, session_ref: &str) -> ApiError {
    match error.kind() {
        ErrorKind::OffRecordPromoteUnauthenticated | ErrorKind::ConsentOwnerNotAuthenticated
            if class == EdgeActorClass::Agent =>
        {
            ask_a_holder()
        }
        _ => engine_error(error, session_ref),
    }
}

/// An agent without this vault's write grant: it may ask a holder, who
/// confirms or declines.
fn ask_a_holder() -> ApiError {
    ApiError::new(
        "this agent does not hold this vault's write grant, so it cannot save the talk",
        ApiErrorDetails::Forbidden {
            required_scope: Some(CoreScope::Write.as_str().to_owned()),
        },
        [
            "Ask a holder: POST /v1/core/off-record/suggest-save; anyone holding this vault's write grant confirms or declines it.",
        ],
    )
}

fn nothing_waits() -> ApiError {
    ApiError::invalid_state(Some("no_suggestion"))
}

/// The stretch `session_ref` in `room`, when `actor` is in that room now. A
/// room the actor is not in and no stretch at all are the same 404.
fn bind<'vault>(
    vault: &'vault Vault,
    room: EntityId,
    session_ref: &str,
    actor: EntityId,
) -> Result<OffRecordSession<'vault>, ApiError> {
    vault
        .off_record_session_vault()
        .bind_in_room(session_ref, room, actor)
        .map_err(|error| engine_error(error, session_ref))
}

/// The stretch as `actor` may see it.
fn view(
    session: &OffRecordSession<'_>,
    session_ref: &str,
    actor: EntityId,
) -> Result<Room, ApiError> {
    session
        .record_for(actor)
        .map(|record| room_view(record, session_ref))
        .map_err(|error| engine_error(error, session_ref))
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal_server_error("off-record task failed"))?
}

fn json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload
        .map(|Json(payload)| payload)
        .map_err(|error| ApiError::bad_request(error.body_text(), None))
}

fn forbidden(message: &str) -> ApiError {
    ApiError::new(
        message,
        ApiErrorDetails::Forbidden {
            required_scope: None,
        },
        ["Act as the person the stretch belongs to."],
    )
}

fn engine_error(error: oneiron::Error, session_ref: &str) -> ApiError {
    match error.kind() {
        ErrorKind::OffRecordSessionNotFound | ErrorKind::OffRecordNotInRoom => {
            ApiError::not_found("off-record stretch", Some(session_ref))
        }
        ErrorKind::OffRecordSessionClosing => ApiError::invalid_state(Some("closing")),
        ErrorKind::OffRecordSessionAlreadyExists => ApiError::invalid_state(Some("exists")),
        ErrorKind::OffRecordPromoteUnauthenticated | ErrorKind::ConsentOwnerNotAuthenticated => {
            ApiError::new(
                "this vault is not yours, so the talk cannot be saved into it",
                ApiErrorDetails::Forbidden {
                    required_scope: None,
                },
                ["Take your own copy with POST /v1/core/off-record/export."],
            )
        }
        ErrorKind::KillSwitchDisabled => forbidden("off-record stretches are turned off here"),
        ErrorKind::OffRecordTalkOnly => forbidden("an anonymous stretch keeps nothing to save"),
        ErrorKind::OffRecordOverlayFull => ApiError::invalid_state(Some("full")),
        ErrorKind::OffRecordCopyConflict => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("conflict".to_owned()),
            },
            ["Export the talk to keep a copy of what the save could not keep."],
        ),
        ErrorKind::InvalidConfig => ApiError::bad_request(error.to_string(), Some("session_ref")),
        _ => {
            tracing::error!(kind = ?error.kind(), "off-record participant act failed");
            ApiError::internal_server_error("off-record act failed")
        }
    }
}

fn witness_error(error: MemoryError) -> ApiError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => ApiError::bad_request(error.message, None),
        oneiron::memory::MEMORY_CODE_FORBIDDEN => forbidden(&error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => ApiError::invalid_state(None),
        _ => {
            tracing::error!(
                code = error.code.as_str(),
                "off-record participant witness failed"
            );
            ApiError::internal_server_error("witness into the off-record stretch failed")
        }
    }
}

fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
