//! The context-board API: POST /v1/core/context-board hydrates the assembled context — session prefix, optional retrieval with its MEMORIES projection, and the per-session cursor (ARCH-0067 §2).
//!
//! Step two: `EmptyContext`/`memories` when retrieval is skipped: today `memories: None`; the tail always renders MEMORIES once the renderer lands.

mod cursor;
mod memories;
mod prefix;
mod session;
mod standing;

pub(crate) use cursor::*;
pub(crate) use memories::*;
pub(crate) use prefix::*;
pub(crate) use session::*;

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
    /// Configured standing block reservation for an agent session.
    #[serde(default)]
    standing: Option<standing::StandingSessionControls>,
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
    /// The pinned block precedes all dynamic retrieval content.
    #[serde(skip_serializing_if = "Option::is_none")]
    standing: Option<standing::StandingSessionPrefix>,
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
    /// One-way renderer: foreign worlds are guest-attributed evidence, never first-party memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    rendered_memories: Option<String>,
    /// The context pack retrieval produced; absent when retrieval was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pack: Option<CoreContextPackResponse>,
    /// Read-time lifecycle changes; never an unsolicited push.
    changed: Vec<String>,
    /// Turn discovery rows plus the session-long loaded skill line.
    skills: Vec<String>,
    /// This turn's capability agent candidates.
    agents: Vec<String>,
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
    auth.require_unrestricted_record_scope()?;
    let mut req = json_payload(payload)?;
    let standing = standing::standing_prefix(&server, &auth, req.standing.as_ref()).await?;
    if let Some(prefix) = &standing
        && let Some(retrieval) = &mut req.retrieval
    {
        if prefix.other_context_tokens == 0 {
            return Err(crate::error::ApiError::bad_request(
                "standing floor leaves no retrieval budget",
                Some("standing.token_budget"),
            )
            .into());
        }
        retrieval.cap_serialized_tokens(prefix.other_context_tokens);
    }
    // Identity keys on the authenticated actor, never on a free label: the
    // same key the MEMORIES cursor store already uses.
    let caller = auth.principal_ref().unwrap_or(auth.principal()).trim();

    let session = session_prefix(&server).await?;
    let notifications = pending_notifications(&server, caller)?;
    let unprocessed = pending_unprocessed_items(&server, caller);
    let budget = standing.as_ref().map_or_else(
        || current_hydration_budget(&server),
        |prefix| {
            oneiron::HydrationBudget::from_meter(
                prefix.reserved_tokens as u64,
                prefix.total_tokens as u64,
            )
        },
    );

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

    let read = super::scoped_read_for_core_auth(&server.vault, &auth)?;
    let reads = session_read_set(
        &server,
        caller,
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
    )
    .await?;
    let changed = reads
        .as_deref()
        .map(|reads| reads.refresh(&read, 16))
        .transpose()
        .map_err(|error| super::core_engine_error("board lifecycle resolution failed", error))?
        .unwrap_or_default()
        .render();
    let empty = oneiron::context_board::SessionReadSet::default();
    let hits = pack
        .as_ref()
        .map(|pack| pack.capabilities.as_slice())
        .unwrap_or_default();
    let agents = oneiron::context_board::AgentsSection { rows: Vec::new() }
        .with_candidates(hits)
        .rows
        .into_iter()
        .map(|row| row.line)
        .collect();
    let skills =
        oneiron::context_board::SkillsSection::project(hits, reads.as_deref().unwrap_or(&empty));
    let skills = std::iter::once(skills.loaded).chain(skills.found).collect();
    drop(reads);
    let cursor = match advanced {
        Some(cursor) => cursor,
        None => current_memories_cursor(&server, caller).await,
    };

    let rendered_memories = memories
        .as_ref()
        .map(|memories| {
            memories.render_board(
                &oneiron::context_board::BoardBlockHeader {
                    epoch: cursor.revision,
                    scope: caller.to_owned(),
                },
                oneiron::context_board::BoardBudgetRequest {
                    harness_default_tok: usize::try_from(budget.tokens_remaining)
                        .unwrap_or(usize::MAX),
                    caller_limit_tok: None,
                    explicit_override_tok: None,
                },
            )
        })
        .transpose()
        .map_err(|_| {
            crate::error::ApiError::bad_request("memory board render failed", Some("memories"))
        })?
        .map(|render| render.text);

    let response = ContextBoardResponse {
        standing,
        session,
        notifications,
        unprocessed,
        budget,
        cursor,
        memories,
        rendered_memories,
        pack,
        changed,
        skills,
        agents,
    };
    if let Some(prefix) = &response.standing {
        let wire = serde_json::to_string(&response).map_err(|_| {
            crate::error::ApiError::internal_server_error("context serialization failed")
        })?;
        if oneiron::count_context_pack_tokens(&wire) > prefix.total_tokens {
            return Err(crate::error::ApiError::bad_request(
                "session prefix and retrieval exceed the token budget",
                Some("standing.token_budget"),
            )
            .into());
        }
    }
    Ok(Json(response))
}
