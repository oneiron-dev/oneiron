//! Board history on the board's own surface (ARCH-0067 §3). A hydration that
//! names its TURN records that turn's board, delta-only; a past turn's board
//! is reconstructed at the frontier it recorded, or refused explicitly.

use super::super::core_engine_error;
use super::super::parse_entity_id_param;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::State;
use axum::response::Json;
use base64::Engine;
use oneiron::EntityId;
use oneiron::context_board::BoardHistoryError;
use oneiron::context_board::BoardSelection;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use utoipa::ToSchema;

/// Names the TURN this board is assembled for, so the board joins the
/// caller's board history. Needs `core:write`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ContextBoardTurnControls {
    /// Hex TURN entity id the caller can read.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
}

/// What recording this turn's board wrote.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardTurnRecord {
    /// Hex TURN entity id.
    turn: String,
    /// Hex history reference of the frontier this turn recorded.
    source_revision_ref: String,
    /// Hex ids of the selection claims this turn wrote. Empty when the
    /// selection did not change.
    changed_claims: Vec<String>,
}

/// One turn's persisted board selection; index-only handles never persist.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardSelectionView {
    allowed: Vec<String>,
    default_on: Vec<String>,
    active: Vec<String>,
    pinned: Vec<String>,
    top_snippet: Vec<String>,
}

/// A past turn's board, folded at the frontier that turn recorded.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardTurnHistory {
    /// Hex TURN entity id.
    turn: String,
    /// Hex id of the board owner.
    owner: String,
    /// The turn's position on its owner's board timeline.
    at: u64,
    /// Hex history reference of the frontier this turn recorded.
    source_revision_ref: String,
    selection: ContextBoardSelectionView,
    /// Base64 body bytes of each selected document as it stood at the turn.
    documents: BTreeMap<String, String>,
}

/// The board owner and TURN a hydration records, checked before any work.
pub(super) fn board_turn_target(
    server: &SyncServer,
    auth: &CoreAuth,
    controls: Option<&ContextBoardTurnControls>,
) -> Result<Option<(EntityId, EntityId)>, ApiError> {
    let Some(controls) = controls else {
        return Ok(None);
    };
    auth.require(CoreScope::Write)?;
    let turn = parse_entity_id_param(&controls.id, "turn.id")?;
    let owner = auth
        .principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok())
        .ok_or_else(|| {
            ApiError::bad_request("board history needs an entity principal", Some("turn"))
        })?;
    if !auth
        .can_read_entity(&server.vault, &turn)
        .map_err(|error| core_engine_error("board turn read failed", error))?
    {
        return Err(ApiError::not_found("turn", Some(&controls.id)));
    }
    Ok(Some((turn, owner)))
}

/// Records the board this hydration rendered for its TURN. The engine writes
/// selection claims only for families that changed.
pub(super) fn record_board_turn(
    server: &SyncServer,
    (turn, owner): (EntityId, EntityId),
    memories: Option<&oneiron::MemoriesSection>,
) -> Result<ContextBoardTurnRecord, ApiError> {
    let selection = memories.map_or_else(BoardSelection::default, BoardSelection::from_memories);
    let receipt = server
        .vault
        .record_board_turn_now(turn, owner, &selection)
        .map_err(|error| board_history_error(&turn, error))?;
    Ok(ContextBoardTurnRecord {
        turn: receipt.turn.to_hex(),
        source_revision_ref: hex(&receipt.source_revision_ref.0),
        changed_claims: receipt
            .changed_claims
            .iter()
            .map(EntityId::to_hex)
            .collect(),
    })
}

/// Reconstruct the caller's board as it stood at one past turn: the
/// selection and document bytes at the frontier that turn recorded. Never a
/// current-board stand-in: a turn beyond the compaction horizon is refused.
#[utoipa::path(
    get,
    path = "/v1/core/context-board/turns/{turn}",
    params(("turn" = String, Path, description = "Hex TURN entity id")),
    responses(
        (status = 200, description = "The turn's board, reconstructed.", body = ContextBoardTurnHistory, content_type = "application/json"),
        (status = 400, description = "Malformed turn id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No board history for this turn and caller.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The turn predates the board's compaction horizon, or a selected document is no longer readable.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Board reconstruction failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_turn_history(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(turn): Path<String>,
) -> Result<Json<ContextBoardTurnHistory>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let id = parse_entity_id_param(&turn, "turn")?;
    // A board is its owner's context: another principal learns nothing,
    // not even that the turn has one.
    let owner = server
        .vault
        .board_turn_owner(&id)
        .map_err(|error| board_history_error(&id, error))?;
    let caller = auth
        .principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok());
    if owner.is_none() || (caller != owner && !auth.is_owner_grade()) {
        return Err(ApiError::not_found("board turn", Some(&turn)).into());
    }
    let board = server
        .vault
        .reconstruct_board(&id)
        .map_err(|error| board_history_error(&id, error))?;
    let ids = |set: &BTreeSet<EntityId>| set.iter().map(EntityId::to_hex).collect();
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(Json(ContextBoardTurnHistory {
        turn: board.turn.to_hex(),
        owner: board.owner.to_hex(),
        at: board.at,
        source_revision_ref: hex(&board.source_revision_ref.0),
        selection: ContextBoardSelectionView {
            allowed: ids(&board.selection.allowed),
            default_on: ids(&board.selection.default_on),
            active: ids(&board.selection.active),
            pinned: ids(&board.selection.pinned),
            top_snippet: ids(&board.selection.top_snippet),
        },
        documents: board
            .documents
            .iter()
            .map(|(id, body)| (id.to_hex(), engine.encode(body)))
            .collect(),
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn board_history_error(turn: &EntityId, error: BoardHistoryError) -> ApiError {
    let id = turn.to_hex();
    match error {
        BoardHistoryError::BeyondCompactionHorizon { .. } => ApiError::new(
            format!("turn {id} predates the board's compaction horizon"),
            crate::error::ApiErrorDetails::InvalidState {
                state: Some("beyond_compaction_horizon".to_owned()),
            },
            ["Only turns inside the retained board history reconstruct."],
        ),
        BoardHistoryError::UnreadableDocument(_) => {
            ApiError::invalid_state(Some("board_document_unreadable"))
        }
        BoardHistoryError::UnknownTurn(_) => ApiError::not_found("board turn", Some(&id)),
        BoardHistoryError::UnknownOwner(_) => ApiError::not_found("board owner", None),
        BoardHistoryError::InvalidSelection("turn is already anchored") => {
            ApiError::invalid_state(Some("board_turn_already_recorded"))
        }
        BoardHistoryError::InvalidSelection(reason) => ApiError::bad_request(reason, Some("turn")),
        BoardHistoryError::Storage(error) => core_engine_error("board history failed", error),
        BoardHistoryError::MissingFrontier | BoardHistoryError::Database(_) => {
            ApiError::internal_server_error("board history failed")
        }
    }
}
