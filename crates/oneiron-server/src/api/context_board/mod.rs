//! The context-board API: POST /v1/core/context-board hydrates the assembled context — session prefix, optional retrieval with its MEMORIES projection, the per-session cursor (ARCH-0067 §2), and the one rendered board frame: WORLDS, MEMORIES, TASKS, SKILLS, ROOM and INBOX (§1), plus an agent run's SCRATCHPAD and an agent's READERS.
//!
//! The board renders on every call; without retrieval it carries no MEMORIES section.

mod board;
mod cursor;
mod explain;
mod history;
mod memories;
mod prefix;
mod scratchpad;
mod session;
mod standing;

pub(crate) use board::{
    ContextBoardProjectControls, ContextBoardRenderBudget, ContextBoardRoomControls,
};
pub(crate) use cursor::*;
pub(crate) use explain::*;
pub(crate) use history::*;
pub(crate) use memories::*;
pub(crate) use prefix::*;
pub(crate) use scratchpad::*;
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
    /// Session controls: the session id that carries the cursor across calls,
    /// and the branch the board renders for.
    #[serde(default)]
    session: Option<ContextBoardSessionControls>,
    /// Companion scope that influences MEMORIES assembly.
    #[serde(default)]
    companion: Option<ContextBoardCompanionControls>,
    /// Append a current describe(self) card to the tail of an existing run.
    #[serde(default)]
    describe_self: bool,
    /// The TURN this board is assembled for: its board joins the caller's
    /// board history (ARCH-0067 §3). Needs `core:write`.
    #[serde(default)]
    turn: Option<ContextBoardTurnControls>,
    /// The room whose ROOM section the board renders; the caller must sit in
    /// it. Absent, the retrieval's `conversation_id` renders ROOM when the
    /// caller sits in that room. Needs an entity principal with an actor class.
    #[serde(default)]
    #[schema(inline)]
    room: Option<ContextBoardRoomControls>,
    /// The project whose view rides TASKS. Absent, the room's project rides
    /// there when the room is a project's.
    #[serde(default)]
    #[schema(inline)]
    project: Option<ContextBoardProjectControls>,
    /// The caller's board token limit. The board renders under the smaller
    /// of it and the harness default; it never widens the cap.
    #[serde(default)]
    #[schema(example = 1200)]
    board_budget_tok: Option<usize>,
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
    /// This turn's MEMORIES section; absent when retrieval was skipped or disabled, unless a
    /// hook block reaching the board pins rows, which then ride it alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<ContextBoardMemories>)]
    memories: Option<oneiron::MemoriesSection>,
    /// The one rendered board frame (one-way renderer): WORLDS, MEMORIES,
    /// TASKS, SKILLS, ROOM and INBOX in canon order, then an agent run's
    /// SCRATCHPAD and an agent's READERS, under the board budget. Foreign worlds render as
    /// guest-attributed evidence, never first-party memory.
    board: String,
    /// How the board's budget settled and what it shed.
    #[schema(inline)]
    board_budget: ContextBoardRenderBudget,
    /// WORLDS rows: the counts line, then each allowed world the caller's
    /// read reads, ACTIVE or AVAILABLE-OFF.
    worlds: Vec<String>,
    /// The caller's `you:` line: its forks, where each runs and what it
    /// does; absent when it has no fork.
    #[serde(skip_serializing_if = "Option::is_none")]
    you: Option<String>,
    /// TASKS detail rows: the project view when one rides, the caller's
    /// readable task rows, and the overflow footer.
    tasks: Vec<String>,
    /// ROOM rows; absent when the board renders no room. A board whose
    /// session id names a SESSION also names the room's host, or no host and
    /// its candidates.
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<Vec<String>>,
    /// The context pack retrieval produced; absent when retrieval was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pack: Option<CoreContextPackResponse>,
    /// Read-time lifecycle changes; never an unsolicited push.
    changed: Vec<String>,
    /// The session-long loaded skill line, then this turn's found rows, each
    /// with its learning view (`rel=`, `fit=`) where the vault holds one.
    skills: Vec<String>,
    /// Host-authenticated self brief, in the prefix only at open/fold and
    /// otherwise appended in the tail on an explicit describe(self) read.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<serde_json::Value>)]
    self_brief: Option<oneiron::context_board::PlacedSelfBrief>,
    /// The full-view rows of the frame's SCRATCHPAD section, an agent run's
    /// live session pad; absent for any other caller, a run without a
    /// session, or a session with no live pad.
    #[serde(skip_serializing_if = "Option::is_none")]
    scratchpad: Option<Vec<String>>,
    /// The full-view rows of the frame's READERS section: who may read an
    /// agent's diary and sealed scratchpads, and who did and why. Absent for
    /// any caller but an agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    readers: Option<Vec<String>>,
    /// What recording the named TURN's board wrote; absent without `turn`.
    #[serde(skip_serializing_if = "Option::is_none")]
    board_turn: Option<ContextBoardTurnRecord>,
}

/// Session prefix: API level, entity counts by numeric type, latest activity.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardSession {
    /// Stable API level string.
    #[serde(rename = "api_version")]
    #[schema(example = "v1")]
    api_version: String,
    /// Live entity counts keyed by numeric entity type; zero counts are omitted.
    /// Always empty: a count may count only rows the caller's key reads, and
    /// no key reads every row.
    #[schema(example = json!({ "16": 1 }))]
    counts: BTreeMap<String, u64>,
    /// Latest learned-at timestamp across agent-visible entities. Always
    /// null, for the same reason.
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
        (status = 400, description = "Malformed context-board request, a room the caller does not sit in, or a project it cannot read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read, or core:write when naming a turn.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The named turn is not readable.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The named turn's board is already recorded, the turn is another actor's, or a selected document is not readable.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-board hydration failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardRequest>, JsonRejection>,
) -> Result<
    (
        axum::Extension<crate::idempotency::ServedRows>,
        Json<ContextBoardResponse>,
    ),
    EnvelopedApiError,
> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let mut req = json_payload(payload)?;
    if let Some(retrieval) = &mut req.retrieval {
        retrieval.check_query_bytes(
            &server,
            &auth,
            crate::server::QueryDoor::ContextBoard,
            "retrieval.query",
        )?;
        // The MEMORIES slot defaults derive from the served limit.
        retrieval.clamp_limits();
    }
    let board_turn = board_turn_target(&server, &auth, req.turn.as_ref())?;
    let targets = board::board_targets(
        &auth,
        req.room.as_ref(),
        req.retrieval
            .as_ref()
            .and_then(CoreContextPackRequest::conversation_id),
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
        req.project.as_ref(),
    )?;
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

    let read = super::scoped_read_for_core_auth(&server.vault, &auth)?;
    // The vault's counts and latest activity span rows no key reads all of
    // (another principal's claims), so every caller reads an empty inventory.
    let session = empty_session_prefix();
    let notifications = pending_notifications(&server, &read, caller)?;
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

    let named_refs = req
        .retrieval
        .as_ref()
        .map(CoreContextPackRequest::named_refs)
        .unwrap_or_default();
    // The hook blocks that reach this board's session and branch: timed pins
    // on its MEMORIES and TASKS rows (ARCH-0080 §11, OI-1 = A).
    let branch = req.session.as_ref().and_then(|s| s.branch.as_deref());
    if let Some(branch) = branch {
        validate_session_id(branch, "session.branch")?;
    }
    let hook_pins = server
        .vault
        .board_hook_pins(
            req.session
                .as_ref()
                .and_then(|s| s.session_id.as_deref())
                .unwrap_or_default(),
            branch,
        )
        .map_err(|error| super::core_engine_error("board hook blocks failed", error))?;
    let (pack, memories, advanced) = match req.retrieval {
        Some(retrieval) => {
            let mut memories = resolve_memories_request(
                &server.vault,
                req.memories.as_ref(),
                req.session.as_ref(),
                req.companion.as_ref(),
                retrieval.retrieval_budget_shape(),
                &auth,
            )?;
            memories.hook_pins = hook_pins.clone();
            let (pack, memories, cursor) =
                run_context_pack(&server, &auth, retrieval, Some(memories)).await?;
            (Some(pack), memories, cursor)
        }
        // OF-579: a board that runs no retrieval still carries its pins
        // (explicit, the manifest's and its hook blocks' rows), read under
        // the clamp a pack reads its pins under.
        None => (
            None,
            board_pins_section(
                &server,
                &auth,
                req.memories.as_ref(),
                targets.room_id(),
                &hook_pins,
            )
            .await?,
            None,
        ),
    };

    // The pack inventory the rider folds and the session records is the
    // caller's: a pack whose source row it cannot read is not installed.
    let mut installed_packs: Vec<(String, String)> = Vec::new();
    let mut pack_sources = Vec::new();
    for row in server
        .vault
        .installed_packs()
        .map_err(|error| super::core_engine_error("pack inventory failed", error))?
    {
        let Ok(source) = oneiron::EntityId::from_hex(&row.source_id) else {
            continue;
        };
        if read
            .is_entity_readable(&source)
            .map_err(|error| super::core_engine_error("pack inventory failed", error))?
        {
            installed_packs.push((row.pack_name, row.content_hash));
            pack_sources.push(source);
        }
    }
    // The rider is folded from, and acknowledged into, this one session.
    let session_id = resolved_session_id(
        &server,
        caller,
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
    )
    .await?;
    let reads = session_read_set(&server, caller, session_id.as_deref()).await?;
    // The authenticated principal's own proposal outcomes and connector
    // changes ride the same line, each only while the caller's read reads it.
    let own = auth
        .principal_ref()
        .and_then(|reference| oneiron::EntityId::from_hex(reference).ok());
    let changed_line = reads
        .as_deref()
        .map(|reads| {
            let mut changed = reads.refresh(&read, 16)?;
            let installs = reads.pack_changes(
                &installed_packs,
                16_usize.saturating_sub(changed.rows.len()),
            );
            changed.rows.extend(installs.rows);
            changed.overflow += installs.overflow;
            reads.fold_own_changes(&read, own, auth.locality(), &mut changed, 16)?;
            Ok::<_, oneiron::Error>(changed)
        })
        .transpose()
        .map_err(|error| super::core_engine_error("board lifecycle resolution failed", error))?
        .unwrap_or_default();
    let changed = changed_line.render();
    let observed_reads = reads.as_deref().cloned().unwrap_or_default();
    drop(reads);
    let cursor = match advanced {
        Some(cursor) => cursor,
        None => current_memories_cursor(&server, caller).await,
    };

    // One frame over every producer, rendered whether or not retrieval ran.
    let hits = pack
        .as_ref()
        .map(|pack| pack.capabilities.as_slice())
        .unwrap_or_default();
    // PEOPLE: every person by handle, with names inline for those the
    // caller's cached prefix roster does not hold.
    let (people, resident) = board::board_people(
        &server,
        &auth,
        &read,
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
    )
    .await?;
    let mut parts = board::board_parts(
        &server,
        &auth,
        &read,
        &targets,
        memories.as_ref(),
        hits,
        &observed_reads,
        &oneiron::context_board::PeopleView::new(&people, &resident),
        &hook_pins,
    )?;
    // An agent run's own live pad joins the frame as its SCRATCHPAD section.
    let scratchpad = served_scratchpad(
        &server,
        &auth,
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
    )?;
    let scratchpad_pad = scratchpad.as_ref().map(|served| served.pad);
    let scratchpad = scratchpad.map(|served| {
        parts.sections.push(served.section);
        served.rows
    });
    // An agent's reader list joins it as its READERS section.
    let readers = served_readers(
        &server,
        &auth,
        &oneiron::context_board::PeopleView::new(&people, &resident),
    )
    .map(|(section, rows)| {
        parts.sections.push(section);
        rows
    });
    let board_render = oneiron::context_board::render_board_block(
        &oneiron::context_board::BoardFrame {
            header: &oneiron::context_board::BoardBlockHeader {
                epoch: cursor.revision,
                scope: parts.scope.clone(),
            },
            legend: &oneiron::context_board::BoardLegend::canonical(),
            sections: &parts.sections,
            you: parts.you.as_deref(),
            changes: Some(&changed_line),
        },
        oneiron::context_board::BoardBudgetRequest {
            harness_default_tok: standing
                .as_ref()
                .map_or(crate::mcp::MCP_BOARD_BUDGET_TOK, |prefix| {
                    prefix.other_context_tokens
                }),
            caller_limit_tok: req.board_budget_tok,
            explicit_override_tok: None,
        },
    )
    .map_err(board::board_frame_error)?;
    let board_budget = ContextBoardRenderBudget::of(&board_render);

    // Only a trusted host may install a run snapshot. Caller-controlled HTTP
    // fields choose neither authority nor the epoch; an absent snapshot is
    // never filled with fabricated grant or budget data.
    // Stage prefix bytes and epoch under one session lock. The response may
    // still fail the full token-budget check below; on failure neither moves.
    let mut runs = server.self_brief_sessions.lock().await;
    let mut staged_prefix = None;
    let self_brief = if let (Some(actor_ref), Some(session_id)) = (
        auth.principal_ref()
            .filter(|_| auth.actor_class() == Some("agent")),
        req.session.as_ref().and_then(|s| s.session_id.as_deref()),
    ) {
        let actor = oneiron::EntityId::from_hex(actor_ref).map_err(|_| {
            crate::error::ApiError::bad_request("invalid agent actor", Some("session"))
        })?;
        let key = (actor, session_id.to_owned());
        if let Some(run) = runs.get_mut(&key) {
            if run.emitted_epoch.is_none() || run.emitted_epoch != Some(run.epoch) {
                let mut candidate = run.render.clone();
                let card = if run.emitted_epoch.is_none() {
                    candidate.turn_one(&server.vault, &run.state, &observed_reads, Some(&people))
                } else {
                    candidate.fold(&server.vault, &run.state, &observed_reads, Some(&people))
                }
                .map_err(|error| super::core_engine_error("self brief failed", error))?;
                staged_prefix = Some((key, candidate, run.epoch));
                Some(card)
            } else if req.describe_self {
                Some(
                    run.render
                        .describe_self(&server.vault, &run.state, &observed_reads, Some(&people))
                        .map_err(|error| super::core_engine_error("self brief failed", error))?,
                )
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let mut response = ContextBoardResponse {
        standing,
        session,
        notifications,
        unprocessed,
        budget,
        cursor,
        memories,
        board: board_render.text,
        board_budget,
        worlds: parts.worlds,
        you: parts.you,
        tasks: parts.tasks,
        room: parts.room,
        pack,
        changed,
        skills: parts.skills,
        scratchpad,
        readers,
        self_brief,
        board_turn: None,
    };
    match board_turn {
        // The turn's record is part of the response the budget counts, so the
        // check runs inside the recording transaction, with the real record:
        // a refused hydration leaves the turn free to record its board.
        Some(target) => {
            record_board_turn(
                &server,
                &read,
                target,
                &parts.authority,
                &mut response,
                within_standing_budget,
            )?;
        }
        None => within_standing_budget(&response)?,
    }
    // The response is final: each hook block it carried spends a delivery. A
    // failed record leaves the block to show again, never to vanish unseen.
    let mut hook_blocks = parts.hook_blocks.clone();
    if let Some(memories) = &response.memories {
        hook_blocks.extend(memories.hook_blocks_delivered(&hook_pins));
    }
    if let Err(error) = server.vault.record_board_hook_deliveries(&hook_blocks) {
        tracing::warn!(kind = ?error.kind(), "board hook delivery record failed");
    }
    let prefix_committed = staged_prefix.is_some();
    if let Some((key, render, epoch)) = staged_prefix {
        let run = runs
            .get_mut(&key)
            .expect("run remains locked through response validation");
        run.render = render;
        run.emitted_epoch = Some(epoch);
    }
    drop(runs);
    // Every row the board delivered: its MEMORIES rows (pins included), its
    // capability hits, and the task intents, worlds, room and project it named.
    let mut delivered: Vec<_> = response
        .memories
        .iter()
        .flat_map(|memories| &memories.rows)
        .filter_map(|row| oneiron::EntityId::from_hex(&row.id).ok())
        .collect();
    delivered.extend(hits_of(response.pack.as_ref()));
    delivered.extend(parts.named.iter().copied());
    if let Some(mut reads) = session_read_set(&server, caller, session_id.as_deref()).await? {
        reads
            .observe_rows(&read, &delivered)
            .map_err(|error| super::core_engine_error("board read set failed", error))?;
        // The tier each MEMORIES row rode, and its hook, for an explain read.
        for row in response.memories.iter().flat_map(|memories| &memories.rows) {
            let tier = match row.tier {
                oneiron::context_board::MemoryTier::Pinned => "pinned",
                oneiron::context_board::MemoryTier::Snippet => "snippet",
                oneiron::context_board::MemoryTier::IndexOnly => "index_only",
            };
            reads.served_on_board(&row.id, tier, row.hook.as_deref());
        }
        reads.observe_pack_inventory(&installed_packs);
        // The response is final: the rider it carries is delivered, and a
        // committed prefix now holds the current connector state.
        if prefix_committed {
            reads.keyframe_committed(&changed_line);
        } else {
            reads.acknowledge(&changed_line);
        }
    }
    // The rows this board was derived from, kept beside a keyed replay of it.
    // A replay re-admits each row it named beyond its documents: every
    // notification, rider row (those its overflow counts too), pack source,
    // named or stamped contact, named reader definition and discovered
    // capability.
    let mut admit: Vec<_> = response
        .notifications
        .iter()
        .filter_map(|notification| oneiron::EntityId::from_hex(&notification.id).ok())
        .collect();
    admit.extend(rider_admits(&changed_line));
    admit.extend(pack_sources);
    admit.extend(named_refs);
    admit.extend(parts.named);
    admit.extend(scratchpad_pad);
    if let Some(pack) = &response.pack {
        admit.extend(pack.replay_admits());
    }
    let mut served: Vec<_> = crate::device_local::changed_line_rows(&changed_line).collect();
    served.extend(admit.iter().copied());
    if let Some(pack) = &response.pack {
        served.extend(
            pack.served_rows()
                .map_err(|error| super::core_engine_error("board rows failed", error))?,
        );
    }
    let memories = response.memories.iter().flat_map(|memories| &memories.rows);
    let standing = response.standing.iter().map(|prefix| &prefix.world_ref);
    served.extend(
        memories
            .map(|row| &row.id)
            .chain(standing)
            .filter_map(|id| oneiron::EntityId::from_hex(id).ok()),
    );
    Ok((
        axum::Extension(crate::idempotency::ServedRows {
            rows: served,
            admit: Some(admit),
        }),
        Json(response),
    ))
}

/// The capability hits a pack carried.
fn hits_of(pack: Option<&CoreContextPackResponse>) -> impl Iterator<Item = oneiron::EntityId> + '_ {
    pack.into_iter()
        .flat_map(|pack| &pack.capabilities)
        .map(|hit| hit.id)
}

/// The rows a board's rider named or counted, each of which a replay of the
/// board re-admits (`ChangedLine::named_rows`): every lifecycle row and its
/// successor, every installed skill, every own proposal whose outcome it
/// carried, and the key of every connector it mounted, those its overflow
/// counts included. An erased proposal has no row left to admit, and a
/// removed connector's key is one the reader was already shown.
fn rider_admits(
    line: &oneiron::context_board::ChangedLine,
) -> impl Iterator<Item = oneiron::EntityId> + '_ {
    line.named_rows().filter_map(|id| {
        let hex = id.rsplit_once(':').map_or(id, |(_, hex)| hex);
        oneiron::EntityId::from_hex(hex).ok()
    })
}

/// A standing session's response must fit its whole token budget.
fn within_standing_budget(response: &ContextBoardResponse) -> Result<(), crate::error::ApiError> {
    let Some(prefix) = &response.standing else {
        return Ok(());
    };
    let wire = serde_json::to_string(response).map_err(|_| {
        crate::error::ApiError::internal_server_error("context serialization failed")
    })?;
    if oneiron::count_context_pack_tokens(&wire) > prefix.total_tokens {
        return Err(crate::error::ApiError::bad_request(
            "session prefix and retrieval exceed the token budget",
            Some("standing.token_budget"),
        ));
    }
    Ok(())
}

/// The authenticated SDK describe(self) path uses the same run snapshot and
/// renderer as context-board assembly. It cannot accept authority in the body.
/// The brief is rendered whole, so a record-narrowed credential is refused.
pub(crate) async fn describe_self_for_auth(
    server: &SyncServer,
    auth: &CoreAuth,
    body: &serde_json::Value,
) -> Result<serde_json::Value, crate::error::ApiError> {
    auth.require_unrestricted_record_scope()?;
    oneiron::task_verb::sdk::validate_input("describe", body).map_err(|_| {
        crate::error::ApiError::bad_request("invalid describe(self) input", Some("self"))
    })?;
    let request: oneiron::task_verb::sdk::DescribeRequest = serde_json::from_value(body.clone())
        .map_err(|_| {
            crate::error::ApiError::bad_request("invalid describe(self) input", Some("self"))
        })?;
    if !request.self_target || request.task_ref.is_some() || auth.actor_class() != Some("agent") {
        return Err(crate::error::ApiError::bad_request(
            "describe(self) requires an agent run",
            Some("self"),
        ));
    }
    let actor = auth
        .principal_ref()
        .and_then(|id| oneiron::EntityId::from_hex(id).ok())
        .ok_or_else(|| crate::error::ApiError::bad_request("missing agent actor", Some("self")))?;
    let session_id = request.session_id.as_deref().ok_or_else(|| {
        crate::error::ApiError::bad_request("missing run session", Some("session_id"))
    })?;
    validate_session_id(session_id, "session_id")?;
    let read = super::scoped_read_for_core_auth(&server.vault, auth)?;
    let (people, _) = board::board_people(server, auth, &read, Some(session_id)).await?;
    let mut runs = server.self_brief_sessions.lock().await;
    let run = runs
        .get_mut(&(actor, session_id.to_owned()))
        .ok_or_else(|| {
            crate::error::ApiError::bad_request("run has no self brief", Some("session_id"))
        })?;
    let read_set = server
        .memories_cursors
        .lock()
        .await
        .session_reads(&actor.to_hex(), Some(session_id))
        .clone();
    let card = run
        .render
        .describe_self(&server.vault, &run.state, &read_set, Some(&people))
        .map_err(|error| super::core_engine_error("self brief failed", error))?;
    let tail = card.tail.ok_or_else(|| {
        crate::error::ApiError::internal_server_error("self brief tail is missing")
    })?;
    serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
        .map_err(|_| crate::error::ApiError::internal_server_error("self brief encoding failed"))
}
