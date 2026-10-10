//! Off-record stretches for everyone in a room (ARCH-0052 D5, the notice
//! model, owner ruling 2026-10-10). The owner's own routes stay under
//! `/v1/owner/off-record`; these serve the room's participants, each acting
//! as the person or agent their slip names, under the scopes they already
//! hold: `core:write` to start, speak, save or suggest, `core:read` to read
//! the room or take an export.
//!
//! - Anyone on the room's roster may start a stretch there.
//! - Anyone may keep their own copy. A live owner of this vault saves the
//!   whole talk into it, since it is theirs. This vault is nobody else's, so
//!   everyone else takes an export file; nothing here writes another vault.
//! - Each save or export posts a notice to the room's timeline, naming who
//!   and what, never the content. Agents may suggest a save, which posts a
//!   notice and saves nothing; only a person starts, saves or exports.
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
use oneiron::memory::{MemoryError, WitnessReceipt, WitnessTurn};
use oneiron::off_record::{
    OffRecordBackendClass, OffRecordMode, OffRecordNoticeAct, OffRecordSession,
    OffRecordSessionRecord, OffRecordTalk, SavedTurns,
};
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault};
use serde::{Deserialize, Serialize};

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
        .route("/suggest-save", post(suggest_save))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    /// The room: a conversation whose roster the starter is on.
    room: String,
    /// The host's own name for the stretch, 1 to 256 bytes.
    session_ref: String,
    /// `local` when inference stays on this device, `remote_provider` when a
    /// model provider sees the turns.
    backend: OffRecordBackendClass,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stretch {
    room: String,
    session_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    room: String,
    session_ref: String,
    /// The turn, as `POST /v1/core/facade/witness` takes it; leave
    /// `conversation_ref` empty to write into the stretch's own conversation.
    turn: WitnessTurn,
    #[serde(default)]
    summary: Option<String>,
}

/// One stretch as everyone in its room sees it.
#[derive(Debug, Serialize)]
struct Room {
    session_ref: String,
    room: Option<String>,
    started_by: Option<String>,
    /// `off_record` or `on_record`.
    mode: OffRecordMode,
    backend: OffRecordBackendClass,
    entered_at: String,
    closing: bool,
    /// The room's timeline of saves, exports and save suggestions.
    notices: Vec<Notice>,
}

#[derive(Debug, Serialize)]
struct Notice {
    act: OffRecordNoticeAct,
    by: String,
    at: String,
}

impl Room {
    fn new(record: OffRecordSessionRecord, session_ref: &str) -> Self {
        Self {
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
        }
    }
}

/// What one save wrote into this vault.
#[derive(Debug, Serialize)]
struct Saved {
    saved: Vec<SavedTurn>,
}

#[derive(Debug, Serialize)]
struct SavedTurn {
    turn: String,
    /// Every row that entered the vault, by id.
    replayed: Vec<String>,
    /// Each in-room short id beside the vault's own short id for that row.
    short_ids: Vec<ShortIdPair>,
}

#[derive(Debug, Serialize)]
struct ShortIdPair {
    room: String,
    vault: String,
}

impl From<SavedTurns> for Saved {
    fn from(turns: SavedTurns) -> Self {
        Self {
            saved: turns
                .into_iter()
                .map(|(turn, outcome)| SavedTurn {
                    turn: turn.to_hex(),
                    replayed: outcome.replayed.iter().map(EntityId::to_hex).collect(),
                    short_ids: outcome
                        .short_id_mapping
                        .into_iter()
                        .map(|(room, vault)| ShortIdPair { room, vault })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// The export file: the talk as the person who took it could see it.
#[derive(Debug, Serialize)]
struct Export {
    session_ref: String,
    room: Option<String>,
    exported_at: String,
    turns: Vec<ExportTurn>,
}

#[derive(Debug, Serialize)]
struct ExportTurn {
    turn: String,
    speaker: Option<String>,
    occurred_at: String,
    saved: bool,
    messages: Vec<oneiron::off_record::OffRecordTalkMessage>,
}

impl Export {
    fn new(talk: OffRecordTalk, session_ref: &str, exported_at: u64) -> Self {
        Self {
            session_ref: session_ref.to_owned(),
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
                    messages: turn.messages,
                })
                .collect(),
        }
    }
}

async fn read_room(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<Stretch>, QueryRejection>,
) -> Reply<Room> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let (actor, _) = participant(&auth)?;
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.body_text(), None))?;
    let room = parse_entity_id_param(&query.room, "room")?;
    let view = blocking(move || {
        let session = bind(server.vault(), room, &query.session_ref, actor)?;
        view(&session, &query.session_ref, actor)
    })
    .await?;
    Ok(Json(view))
}

async fn start(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Start>, JsonRejection>,
) -> Reply<Room> {
    auth.require(CoreScope::Write)?;
    let actor = person(&auth)?;
    let request = json(payload)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let view = blocking(move || {
        let session = server
            .vault()
            .off_record_session_vault()
            .enter_in_room(&request.session_ref, request.backend, room, actor)
            .map_err(|error| engine_error(error, &request.session_ref))?;
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(Json(view))
}

async fn witness(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Witness>, JsonRejection>,
) -> Reply<WitnessReceipt> {
    auth.require(CoreScope::Write)?;
    let (actor, class) = participant(&auth)?;
    let request = json(payload)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let receipt = blocking(move || {
        let vault = server.vault();
        let session = bind(vault, room, &request.session_ref, actor)?;
        vault
            .memory(actor, class)
            .witness_into_session_as_member(
                &session,
                &request.turn,
                request.summary.as_deref(),
                credential.as_ref(),
            )
            .map_err(witness_error)
    })
    .await?;
    Ok(Json(receipt))
}

async fn save(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Reply<Saved> {
    auth.require(CoreScope::Write)?;
    let actor = person(&auth)?;
    let request = json(payload)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let credential = auth.verified_slip().cloned();
    let saved = blocking(move || {
        bind(server.vault(), room, &request.session_ref, actor)?
            .save_talk_by(actor, credential.as_ref())
            .map_err(|error| engine_error(error, &request.session_ref))
    })
    .await?;
    Ok(Json(Saved::from(saved)))
}

async fn export(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Stretch>, JsonRejection>,
) -> Result<impl IntoResponse, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let actor = person(&auth)?;
    let request = json(payload)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let export = blocking(move || {
        let talk = bind(server.vault(), room, &request.session_ref, actor)?
            .export_talk_by(actor)
            .map_err(|error| engine_error(error, &request.session_ref))?;
        Ok(Export::new(talk, &request.session_ref, unix_seconds_now()))
    })
    .await?;
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
    auth.require(CoreScope::Write)?;
    let (actor, class) = participant(&auth)?;
    if class != EdgeActorClass::Agent {
        return Err(forbidden("only an agent suggests a save; a person saves or exports").into());
    }
    let request = json(payload)?;
    let room = parse_entity_id_param(&request.room, "room")?;
    let view = blocking(move || {
        let session = bind(server.vault(), room, &request.session_ref, actor)?;
        session
            .suggest_save_by(actor)
            .map_err(|error| engine_error(error, &request.session_ref))?;
        self::view(&session, &request.session_ref, actor)
    })
    .await?;
    Ok(Json(view))
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

/// Starting, saving and exporting are a person's own acts; an agent only
/// suggests.
fn person(auth: &CoreAuth) -> Result<EntityId, ApiError> {
    match participant(auth)? {
        (actor, EdgeActorClass::Human) => Ok(actor),
        _ => Err(forbidden(
            "only a person starts, saves or exports an off-record stretch",
        )),
    }
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
        .map(|record| Room::new(record, session_ref))
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
        ErrorKind::OffRecordPromoteUnauthenticated => ApiError::new(
            "this vault is not yours, so the talk cannot be saved into it",
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Take your own copy with POST /v1/core/off-record/export."],
        ),
        ErrorKind::KillSwitchDisabled => forbidden("off-record stretches are turned off here"),
        ErrorKind::OffRecordTalkOnly => forbidden("an anonymous stretch keeps nothing to save"),
        ErrorKind::OffRecordOverlayFull => ApiError::invalid_state(Some("full")),
        ErrorKind::InvalidConfig => ApiError::bad_request(error.to_string(), Some("session_ref")),
        _ => {
            tracing::error!(error = %error, "off-record participant act failed");
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
