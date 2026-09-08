//! The context-board API: POST /v1/core/context-board hydrates the assembled context — session prefix, optional retrieval with its MEMORIES projection, and the per-session cursor (ARCH-0067 §2).
//!
//! Step two: `EmptyContext`/`memories` when retrieval is skipped: today `memories: None`; the tail always renders MEMORIES once the renderer lands.

mod cursor;
mod memories;
mod prefix;

pub(crate) use cursor::*;
pub(crate) use memories::*;
pub(crate) use prefix::*;

use super::CoreContextPackRequest;
use super::CoreContextPackResponse;
use super::json_payload;
use super::run_context_pack;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use utoipa::ToSchema;

/// Context-board hydration request. Every block is optional; an empty body
/// returns the session prefix beside the caller's current cursor.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[schema(example = json!({
    "retrieval": { "query": "blue hallway", "limit": 10 },
    "memories": { "slots": { "turns": 2 } },
    "session": { "session_id": "session-123" }
}))]
pub(crate) struct ContextBoardRequest {
    /// Retrieval for this turn. When present the shared context-pack pipeline
    /// runs, its MEMORIES projection and pack ride the response, and the
    /// cursor advances.
    #[serde(default)]
    retrieval: Option<CoreContextPackRequest>,
    /// MEMORIES section controls: whether to project it and the per-slot row caps.
    #[serde(default)]
    memories: Option<ContextBoardMemoriesControls>,
    /// Session controls: the session id that carries the cursor across calls.
    #[serde(default)]
    session: Option<ContextBoardSessionControls>,
    /// Companion scope that influences MEMORIES assembly.
    #[serde(default)]
    companion: Option<ContextBoardCompanionControls>,
}

/// The assembled context for one turn.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardResponse {
    /// Session prefix: API level, entity counts, latest activity.
    #[schema(value_type = ContextBoardSession)]
    session: oneiron::SessionContext,
    /// Pending notifications scoped to the caller and not yet surfaced.
    #[schema(value_type = Vec<ContextBoardNotification>)]
    notifications: Vec<oneiron::NotificationItem>,
    /// Work items that still need caller-side processing.
    #[schema(value_type = Vec<ContextBoardUnprocessedItem>)]
    unprocessed: Vec<oneiron::UnprocessedItem>,
    /// Token meter snapshot.
    #[schema(value_type = ContextBoardBudget)]
    budget: oneiron::HydrationBudget,
    /// The caller's MEMORIES cursor: advanced when retrieval ran, otherwise current.
    #[schema(value_type = ContextBoardMemoriesCursor)]
    cursor: oneiron::MemoriesCursor,
    /// This turn's MEMORIES section; absent when retrieval was skipped or disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<ContextBoardMemories>)]
    memories: Option<oneiron::MemoriesSection>,
    /// The context pack retrieval produced; absent when retrieval was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pack: Option<CoreContextPackResponse>,
}

/// Session prefix: API level, entity counts by numeric type, latest activity.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardSession {
    /// Stable API level string.
    #[serde(rename = "api_version")]
    #[schema(example = "v1")]
    api_version: String,
    /// Live entity counts keyed by numeric entity type; zero counts are omitted.
    #[schema(example = json!({ "16": 1 }))]
    counts: BTreeMap<String, u64>,
    /// Latest learned-at timestamp across agent-visible entities.
    #[serde(rename = "last_activity")]
    #[schema(example = 1_770_000_000_u64)]
    last_activity: Option<u64>,
}

/// One pending notification.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardNotification {
    /// Hex notification entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Learned-at timestamp of the notification.
    #[serde(rename = "learned_at")]
    #[schema(example = 1_770_000_000_u64)]
    learned_at: u64,
    /// Decoded notification body.
    #[schema(value_type = Object)]
    body: serde_json::Value,
}

/// One work item that still needs caller-side processing.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardUnprocessedItem {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type")]
    #[schema(example = 1)]
    entity_type: u8,
    /// Learned-at timestamp of the item.
    #[serde(rename = "learned_at")]
    #[schema(example = 1_770_000_000_u64)]
    learned_at: u64,
    /// Decoded item body.
    #[schema(value_type = Object)]
    body: serde_json::Value,
}

/// Token meter snapshot.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardBudget {
    /// Tokens consumed so far.
    #[serde(rename = "tokens_used")]
    #[schema(example = 0_u64)]
    tokens_used: u64,
    /// Token limit for the session.
    #[serde(rename = "tokens_limit")]
    #[schema(example = 0_u64)]
    tokens_limit: u64,
    /// Saturated `tokens_limit - tokens_used`.
    #[serde(rename = "tokens_remaining")]
    #[schema(example = 0_u64)]
    tokens_remaining: u64,
}

/// Hydrate the assembled context for one turn: the session prefix, pending
/// notifications and work, the token meter, this turn's retrieval with its
/// MEMORIES projection, and the caller's cursor.
#[utoipa::path(
    post,
    path = "/v1/core/context-board",
    request_body(content = ContextBoardRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Context board hydrated.", body = ContextBoardResponse, content_type = "application/json"),
        (status = 400, description = "Malformed context-board request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-board hydration failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardRequest>, JsonRejection>,
) -> Result<Json<ContextBoardResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    // Identity keys on the authenticated actor, never on a free label: the
    // same key the MEMORIES cursor store already uses.
    let caller = auth.principal_ref().unwrap_or(auth.principal()).trim();

    let session = session_prefix(&server).await?;
    let notifications = pending_notifications(&server, caller)?;
    let unprocessed = pending_unprocessed_items(&server, caller);
    let budget = current_hydration_budget(&server);

    let (pack, memories, advanced) = match req.retrieval {
        Some(retrieval) => {
            let memories = resolve_memories_request(
                &server.vault,
                req.memories.as_ref(),
                req.session.as_ref(),
                req.companion.as_ref(),
                retrieval.retrieval_budget_shape(),
                &auth,
            )?;
            let (pack, memories, cursor) =
                run_context_pack(&server, &auth, retrieval, Some(memories)).await?;
            (Some(pack), memories, cursor)
        }
        None => (None, None, None),
    };
    let cursor = match advanced {
        Some(cursor) => cursor,
        None => current_memories_cursor(&server.vault, caller).await,
    };

    Ok(Json(ContextBoardResponse {
        session,
        notifications,
        unprocessed,
        budget,
        cursor,
        memories,
        pack,
    }))
}
