//! ROOT TASKS layout over raw HTTP (FIX 12570, HTTP slice).
//!
//! `GET|POST /v1/core/context-board/layout/tasks`: one actor's durable ROOT
//! TASKS-row token budget. GET reads the caller's own live default plus its
//! one pending staged write; POST stages ONE pending batch for a later
//! explicit TURN. This is parent 12570 PART, ROOT raw HTTP only: no fork
//! store or copy, no MCP/run/chat integration, no full-board shares, folds,
//! filters, notes or owner defaults. See
//! `docs/ops/context-board-tasks-layout.md`.
//!
//! POST `budget_tok` is REQUIRED nullable unsigned: missing is 400 and never
//! resets, `null` stages a reset to 100-row behavior, `0` stages a literal
//! zero for optional rows. Repeated writes replace the pending batch.
//! Hydration selection lives here too: explicit per-request `Some` wins with
//! its exact budget and never consumes pending (this slice ignores pending
//! entirely then: no candidate); otherwise TURN projects the staged pending
//! snapshot now and the SAME accepted TURN commit activates it, while a
//! hydration without TURN reads live only and never activates.

use super::super::core_engine_error;
use super::super::credential_memory;
use super::super::json_payload;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// One ROOT TASKS layout stage: the REQUIRED nullable unsigned allotment.
/// Missing `budget_tok` is 400 and never resets; explicit `null` stages a
/// reset to 100-row behavior.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextBoardTasksLayoutStageRequest {
    /// Staged concrete-row allotment: `Some(0)` a literal zero, `None` a
    /// reset to 100-row behavior. Required even for `null`.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<usize>, required = true, example = 400)]
    pub(crate) budget_tok: Option<Option<usize>>,
}

/// A field that is present, even as `null`; `#[serde(default)]` leaves an
/// omitted one `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// One actor's ROOT TASKS layout state: its live default plus its one
/// pending staged write. `live_budget_tok: None` is the 100-row behavior;
/// `pending: None` is no pending, while `Some` with `budget_tok: None` is a
/// staged reset (never flattened together).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardTasksLayoutState {
    /// Live default this actor's ROOT board renders under.
    #[schema(nullable = true, example = 400)]
    pub(crate) live_budget_tok: Option<usize>,
    /// Staged write awaiting TURN activation; `None` is no pending.
    #[schema(nullable = true)]
    pub(crate) pending: Option<ContextBoardTasksLayoutPending>,
}

/// The staged write of [`ContextBoardTasksLayoutState`].
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
pub(crate) struct ContextBoardTasksLayoutPending {
    /// Staged value: `None` resets to 100-row behavior.
    #[schema(nullable = true, example = 400)]
    pub(crate) budget_tok: Option<usize>,
}

/// Reads the caller's own ROOT TASKS layout state. GET never mutates.
#[utoipa::path(
    get,
    path = "/v1/core/context-board/layout/tasks",
    responses(
        (status = 200, description = "The caller's ROOT TASKS layout state.", body = ContextBoardTasksLayoutState, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read or has a restricted record scope.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "TASKS layout read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_tasks_layout(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<ContextBoardTasksLayoutState>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let Some(actor) = tasks_layout_actor(&auth) else {
        return Ok(Json(ContextBoardTasksLayoutState {
            live_budget_tok: None,
            pending: None,
        }));
    };
    let state = server
        .vault
        .tasks_layout_state(actor)
        .map_err(|error| core_engine_error("tasks layout read failed", error))?;
    Ok(Json(tasks_layout_dto(state)?))
}

/// Stages the caller's ROOT TASKS layout as ONE pending batch for a later
/// explicit TURN. Missing `budget_tok` is 400 and never resets.
#[utoipa::path(
    post,
    path = "/v1/core/context-board/layout/tasks",
    request_body(content = ContextBoardTasksLayoutStageRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Staged; pending awaits an explicit TURN.", body = ContextBoardTasksLayoutState, content_type = "application/json"),
        (status = 400, description = "Missing budget_tok or malformed layout request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write, or names no entity principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "TASKS layout stage failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_tasks_layout_stage(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardTasksLayoutStageRequest>, JsonRejection>,
) -> Result<Json<ContextBoardTasksLayoutState>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_unrestricted_record_scope()?;
    let req = json_payload(payload)?;
    let Some(staged) = req.budget_tok else {
        return Err(ApiError::bad_request("budget_tok is required", Some("budget_tok")).into());
    };
    let memory = tasks_layout_memory(&server, &auth)?;
    let state = memory
        .stage_tasks_layout(staged)
        .map_err(tasks_layout_error)?;
    Ok(Json(tasks_layout_dto(state)?))
}

/// Selects the caller's ROOT TASKS budget for hydration: the effective
/// projection budget plus the exact candidate the SAME accepted TURN commit
/// must activate (or `None` when no activation follows).
///
/// Call only when the explicit per-request budget is `None` (explicit `Some`
/// wins with its exact budget and never consumes pending, so hydration
/// skips selection entirely then). Without TURN this reads LIVE only and
/// never activates; with TURN it projects PENDING when present else LIVE.
pub(crate) fn hydrate_tasks_selection(
    server: &SyncServer,
    auth: &CoreAuth,
    has_turn: bool,
    cap_tok: usize,
) -> Result<
    (
        Option<usize>,
        Option<oneiron::context_board::TasksLayoutCandidate>,
    ),
    ApiError,
> {
    let Some(actor) = tasks_layout_actor(auth) else {
        return Ok((None, None));
    };
    server
        .vault
        .select_tasks_layout(actor, has_turn, cap_tok)
        .map_err(|error| core_engine_error("tasks layout selection failed", error))
}

/// The caller's entity principal as its TASKS layout owner, gated exactly
/// like the scratchpad door minus session: a declared actor class plus a
/// hex principal. `None` reads as no row (100-row behavior, no pending).
fn tasks_layout_actor(auth: &CoreAuth) -> Option<EntityId> {
    match auth.actor_class()? {
        "human" | "agent" | "system" => (),
        _ => return None,
    }
    EntityId::from_hex(auth.principal_ref()?).ok()
}

/// The layout belongs to the authenticated entity principal under its
/// declared class; the engine re-checks both on every write.
fn tasks_layout_memory<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
) -> Result<oneiron::memory::Memory<'a>, ApiError> {
    let refused = |message: &str| {
        ApiError::new(
            message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Present a slip minted with --principal-ref and --actor-class."],
        )
    };
    let actor = auth
        .principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok())
        .ok_or_else(|| refused("the tasks layout needs an entity principal"))?;
    let class = match auth.actor_class() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        _ => return Err(refused("the tasks layout needs a declared actor class")),
    };
    Ok(credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()))
}

/// The engine's refusal on the board's error contract: its code picks the
/// status, its message and suggestions pass through. Staging never refuses
/// on revision contention: every staged write wins unconditionally.
fn tasks_layout_error(error: oneiron::MemoryError) -> ApiError {
    let details = match error.code.as_str() {
        oneiron::MEMORY_CODE_BAD_REQUEST => ApiErrorDetails::BadRequest { field: None },
        oneiron::MEMORY_CODE_NOT_FOUND => return ApiError::not_found("tasks layout", None),
        oneiron::MEMORY_CODE_FORBIDDEN | oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED => {
            ApiErrorDetails::Forbidden {
                required_scope: None,
            }
        }
        oneiron::MEMORY_CODE_INVALID_STATE => ApiErrorDetails::InvalidState {
            state: Some("tasks_layout".to_owned()),
        },
        _ => {
            tracing::error!(code = %error.code, error = %error.message, "tasks layout failed");
            return ApiError::internal_server_error("tasks layout failed");
        }
    };
    ApiError::new(error.message, details, error.suggestions)
}

/// Converts the engine `u64` layout state to the wire `usize` DTO,
/// losslessly on 64-bit. Stored values were staged from `usize`, so a value
/// that no longer fits is corruption and fails closed, never
/// `usize::MAX`-clamped.
fn tasks_layout_dto(
    state: oneiron::context_board::TasksLayoutState,
) -> Result<ContextBoardTasksLayoutState, ApiError> {
    let live_budget_tok = state.live.map(stored_usize).transpose()?;
    let pending = state
        .pending
        .map(|pending| {
            Ok::<_, ApiError>(ContextBoardTasksLayoutPending {
                budget_tok: pending.value.map(stored_usize).transpose()?,
            })
        })
        .transpose()?;
    Ok(ContextBoardTasksLayoutState {
        live_budget_tok,
        pending,
    })
}

fn stored_usize(value: u64) -> Result<usize, ApiError> {
    usize::try_from(value).map_err(|_| {
        core_engine_error(
            "tasks layout value does not fit",
            oneiron::Error::InvariantViolation("tasks layout stored value does not fit usize"),
        )
    })
}
