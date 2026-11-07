//! Execute-code and board-verb executors.

mod execute_code;

pub(super) use self::execute_code::enter_mcp_code_run;
pub(crate) use self::execute_code::execute_mcp_execute_code;
// `execute_code` reaches the gateway's names through this module.
use super::{
    McpBoardOmissions, McpBoardState, McpCallContext, McpCarrierPolicy, McpGatewayError,
    actor_dispatch, code_mode_verbs, device_release, hex_bytes, mcp_actor_result,
    mcp_board_frame_error, mcp_board_verb_error, mcp_current_board, mcp_endpoint_result,
    mcp_engine_error, mcp_page_cursor_error, type_feedback_release,
};
use crate::mcp::McpPageBudget;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRetrievalHealth;
use crate::server::SyncServer;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

/// The live board one board verb reads, assembled from the same sections the
/// primary keyframe renders. The engine's `dispatch_board_verb` owns every
/// board semantic; this only supplies the current view.
pub(super) struct McpLiveBoard {
    /// The world this view was BUILT for, taken from the registered credential
    /// scope. `read_current` refuses any other, so the scope argument is
    /// enforced rather than ignored.
    world: oneiron::EntityId,
    view: oneiron::board_verb::LiveBoardView,
}

impl oneiron::board_verb::LiveBoardSource for McpLiveBoard {
    fn read_current(
        &self,
        scope: &oneiron::board_verb::BoardWorldScope,
    ) -> Result<oneiron::board_verb::LiveBoardView, oneiron::board_verb::BoardVerbError> {
        if scope.world() != self.world {
            return Err(oneiron::board_verb::BoardVerbError::Source(format!(
                "board world scope {requested} is not the scope this view was built for",
                requested = scope.world().to_hex(),
            )));
        }
        Ok(self.view.clone())
    }
}

/// The world one connector's board is read under.
///
/// Taken from the REGISTERED scope; a vault-wide credential reads its own
/// actor's board. Nothing a caller sends reaches this.
fn mcp_board_world(actor: &McpResolvedActor) -> oneiron::EntityId {
    actor.scope.world_ref.unwrap_or(actor.actor_ref)
}

fn mcp_live_board(
    actor: &McpResolvedActor,
    board: &McpBoardState,
    cap_tok: usize,
) -> Result<McpLiveBoard, McpGatewayError> {
    let header = oneiron::context_board::BoardBlockHeader {
        epoch: board.epoch,
        scope: board.scope_label.clone(),
    };
    let render = oneiron::board_verb::render_current_keyframe(
        &header,
        &board.laid_out,
        oneiron::context_board::BoardBudgetRequest {
            harness_default_tok: cap_tok,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .map_err(mcp_board_frame_error)?;

    let mut rows = std::collections::BTreeMap::new();
    let mut expansions = std::collections::BTreeMap::new();
    for section in &board.sections {
        let lines = section
            .pinned_rows()
            .iter()
            .chain(section.detail_rows())
            .cloned()
            .collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            rows.insert(format!("{}:{index}", section.name()), line.clone());
        }
        expansions.insert(section.name().to_owned(), lines);
    }
    Ok(McpLiveBoard {
        world: mcp_board_world(actor),
        view: oneiron::board_verb::LiveBoardView {
            snapshot: oneiron::context_board::BoardSnapshot {
                epoch: board.epoch,
                keyframe: render.text,
                rows,
            },
            expansions,
        },
    })
}

pub(super) fn mcp_verb_family_error(args: &crate::mcp::McpVerbToolArgs) -> McpGatewayError {
    McpGatewayError::new(
        -32603,
        "verb_dispatch_failed",
        format!(
            "{name} is not dispatched by the {family} verb executor",
            name = args.tool.name,
            family = args.tool.family.as_str(),
        ),
    )
}

fn mcp_board_verb_output_value(
    output: &oneiron::board_verb::BoardVerbOutput,
) -> Result<Value, McpGatewayError> {
    serde_json::to_value(output).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })
}

/// A keyed `describe` and `self.focus.*`: dispatched by the engine's own verb
/// dispatcher, over this connector's process-local STREAM state and the
/// STATE-fenced board snapshot.
pub(super) async fn execute_mcp_board_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    served: &mut Vec<oneiron::EntityId>,
    hooks: &mut Option<super::board_setup::McpBoardHooks>,
    call: impl FnOnce(
        &mut oneiron::board_verb::BoardVerbContext<'_, McpLiveBoard>,
    ) -> Result<
        oneiron::board_verb::BoardVerbOutput,
        oneiron::board_verb::BoardVerbError,
    >,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let board = mcp_current_board(server, actor).await?;
    served.extend_from_slice(&board.rows);
    let omissions = board.omissions();
    let cap_tok =
        crate::api::context_board::board_cap_tok(&server.vault, crate::mcp::MCP_BOARD_BUDGET_TOK);
    let source = mcp_live_board(actor, &board, cap_tok)?;
    let scope = oneiron::board_verb::BoardWorldScope::single(mcp_board_world(actor));
    let output = {
        let mut registry = server.mcp_registry.lock().await;
        let mut context = oneiron::board_verb::BoardVerbContext {
            connection: &actor.stream_connection,
            scope: &scope,
            source: &source,
            streams: registry.streams_mut(),
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: cap_tok,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        call(&mut context)
    }
    .map_err(mcp_board_verb_error)?;

    let output = match output {
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => {
            // A keyframe of the laid-out board goes back: the actor's layout
            // batch it shows becomes live (BOARD-LAYOUT).
            activate_board_layout(server, &board)?;
            let frame = board
                .changes
                .ride(Some(frame))
                .expect("rider preserves an existing frame");
            let keyframe = matches!(frame.kind, oneiron::context_board::FrameKind::Keyframe(_));
            super::board_observations::delivered(
                server,
                actor,
                &board.changes,
                keyframe,
                frame.epoch,
            )
            .await;
            oneiron::board_verb::BoardVerbOutput::Frame(frame)
        }
        other => other,
    };
    // The hook rows this answer shows go out with it: the caller records
    // their receipt and spends their blocks once it is released (OF-579).
    *hooks = match &output {
        oneiron::board_verb::BoardVerbOutput::Frame(_) => Some(board.hooks),
        oneiron::board_verb::BoardVerbOutput::Expanded { key, .. } => {
            Some(board.hooks.shown_by(key))
        }
        oneiron::board_verb::BoardVerbOutput::Subscription(_) => None,
    };
    // The present board producer serves TASKS, presence and loaded metadata.
    // None are new CLAIM/SKILL/AGENT_DEF body observations. An expansion has no
    // typed entity mapping, so its renderer strings are never parsed for ids.
    let value = mcp_board_verb_output_value(&output)?;
    let page_source = mcp_board_verb_page_source(&output, omissions);
    // A verb that just minted a fresh keyframe returns it as the RESULT; the
    // central chokepoint supersedes and drains the queue behind it, so it is
    // never also attached as a carrier beside itself and nothing is stranded.
    let carrier = if matches!(output, oneiron::board_verb::BoardVerbOutput::Frame(_)) {
        McpCarrierPolicy::FreshKeyframe(None)
    } else {
        McpCarrierPolicy::Drain
    };
    Ok((value, page_source, carrier, Some(board.epoch)))
}

/// What this board verb actually produced, what the REQUESTED SCOPE removed,
/// and what the board's own render window truncated.
///
/// ONE-1704 repair: the two are reported on separate axes, and only the section
/// the omissions are OF carries them. A `describe` of `VERBS` is not partial
/// because a TASKS row was outside the credential's ceiling, and rows the render
/// row cap dropped are a window fact rather than a scope one.
pub(crate) fn mcp_board_verb_page_source(
    output: &oneiron::board_verb::BoardVerbOutput,
    omissions: McpBoardOmissions,
) -> crate::mcp::McpPageSource {
    match output {
        oneiron::board_verb::BoardVerbOutput::Expanded { key, lines } => {
            let produced = lines.len();
            let source = if key == MCP_BOARD_TASKS_SECTION {
                crate::mcp::McpPageSource::scoped_window(
                    produced,
                    omissions.scope_omitted,
                    omissions.window_truncated,
                    omissions.source_exhausted,
                )
            } else {
                crate::mcp::McpPageSource::complete(produced)
            };
            source.rows_at("lines")
        }
        // A refresh renders the WHOLE board, so both axes apply to it.
        oneiron::board_verb::BoardVerbOutput::Frame(_) => crate::mcp::McpPageSource::scoped_window(
            1,
            omissions.scope_omitted,
            omissions.window_truncated,
            omissions.source_exhausted,
        ),
        // A subscription receipt is one row and states itself completely.
        oneiron::board_verb::BoardVerbOutput::Subscription(_) => {
            crate::mcp::McpPageSource::complete(1)
        }
    }
}

/// The board section the TASKS producer's omissions belong to.
pub(crate) const MCP_BOARD_TASKS_SECTION: &str = "TASKS";

/// A pumped run's `self.focus.*` and keyed `describe` (OF-533): the engine's
/// own board dispatcher over the run's own board connection and its agent's
/// board, as [`execute_mcp_board_verb`] serves a connector's. Answers the
/// verb's wire value and every row the board was derived from. A refresh's
/// frame is the answer, so the queue behind it is superseded and drained.
/// Leaves the hook blocks the answer shows in `hooks`, for
/// [`deliver_run_board_hooks`] once the answer returns to the run. A pumped
/// run's host door binds no session, so its board renders no SCRATCHPAD.
pub(crate) async fn execute_run_board_verb(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    call: oneiron::board_verb::BoardVerbCall,
    hooks: &mut Option<super::board_setup::McpBoardHooks>,
) -> Result<(Value, Vec<oneiron::EntityId>), oneiron::memory::MemoryError> {
    execute_run_board_verb_in_session(server, actor, connection, None, call, hooks).await
}

/// [`execute_run_board_verb`] over a board bound to `session`, the session
/// the call's host origin names (FIX 2340): its SCRATCHPAD is that
/// session's live pad.
pub(crate) async fn execute_run_board_verb_in_session(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    session: Option<&str>,
    call: oneiron::board_verb::BoardVerbCall,
    hooks: &mut Option<super::board_setup::McpBoardHooks>,
) -> Result<(Value, Vec<oneiron::EntityId>), oneiron::memory::MemoryError> {
    let board = super::board_setup::run_current_board(server, actor, connection, session)
        .await
        .map_err(run_board_error)?;
    let world = actor.entity_ref();
    let source = McpLiveBoard {
        world,
        view: live_board_view(server, &board).map_err(run_board_error)?,
    };
    let scope = oneiron::board_verb::BoardWorldScope::single(world);
    let output = {
        let mut registry = server.mcp_registry.lock().await;
        let mut context = oneiron::board_verb::BoardVerbContext {
            connection,
            scope: &scope,
            source: &source,
            streams: registry.streams_mut(),
            budget: run_board_budget_request(server),
        };
        oneiron::board_verb::dispatch_board_verb(&mut context, call)
    }
    .map_err(|error| run_board_error(mcp_board_verb_error(error)))?;
    let output = match output {
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => {
            // The run's next turn sees this keyframe of its laid-out board,
            // so the layout batch it shows becomes live (BOARD-LAYOUT).
            activate_board_layout(server, &board).map_err(run_board_error)?;
            let frame = board
                .changes
                .ride(Some(frame))
                .expect("rider preserves an existing frame");
            let keyframe = matches!(frame.kind, oneiron::context_board::FrameKind::Keyframe(_));
            super::board_observations::run_delivered(
                server,
                actor,
                connection,
                &board.changes,
                keyframe,
                frame.epoch,
            )
            .await;
            let _superseded = server
                .mcp_registry
                .lock()
                .await
                .next_carrier_frame(connection);
            oneiron::board_verb::BoardVerbOutput::Frame(frame)
        }
        other => other,
    };
    *hooks = match &output {
        oneiron::board_verb::BoardVerbOutput::Frame(_) => Some(board.hooks),
        oneiron::board_verb::BoardVerbOutput::Expanded { key, .. } => {
            Some(board.hooks.shown_by(key))
        }
        oneiron::board_verb::BoardVerbOutput::Subscription(_) => None,
    };
    Ok((
        mcp_board_verb_output_value(&output).map_err(run_board_error)?,
        board.rows,
    ))
}

/// A pumped run's board answer has returned to the run: the receipt its hook
/// rows owe is recorded and their blocks spent, as a code-mode board read's
/// are (OF-579).
pub(crate) async fn deliver_run_board_hooks(
    server: &SyncServer,
    mut hooks: super::board_setup::McpBoardHooks,
) -> Result<(), oneiron::memory::MemoryError> {
    hooks
        .record_receipt(server)
        .await
        .map_err(run_board_error)?;
    hooks.spend(server);
    Ok(())
}

/// Drops a pumped run's board connection, snapshot and stream reader (FIX
/// 4888), and the self brief snapshot installed for that connection (FIX
/// 2086). Its session, cursor and read set, stays until the run ends, when
/// the host's live runs close it (FIX 8143): a run parked on a durable wait
/// keeps it.
pub(crate) async fn drop_run_board(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
) {
    server.mcp_registry.lock().await.drop_run_board(connection);
    server
        .self_brief_sessions
        .lock()
        .await
        .remove(&(actor.entity_ref(), connection.0.clone()));
}

/// A keyframe of the board just went back with its actor's layout batch:
/// the actor's next turn sees it, so the batch becomes live (BOARD-LAYOUT).
/// A describe, a subscription or a refused verb shows no keyframe and
/// leaves the batch pending.
fn activate_board_layout(
    server: &SyncServer,
    board: &McpBoardState,
) -> Result<(), McpGatewayError> {
    if let Some(candidate) = &board.layout_candidate {
        server
            .vault
            .activate_board_layout_now(candidate)
            .map_err(|error| mcp_engine_error("board layout activation failed", error))?;
    }
    Ok(())
}

/// The native run board's harness cap, shared by section projection and its
/// final keyframe: the owner's board cap, else the MCP harness default. Run
/// boards have no caller limit or explicit override.
pub(super) fn run_board_budget_request(
    server: &SyncServer,
) -> oneiron::context_board::BoardBudgetRequest {
    oneiron::context_board::BoardBudgetRequest {
        harness_default_tok: crate::api::context_board::board_cap_tok(
            &server.vault,
            crate::mcp::MCP_BOARD_BUDGET_TOK,
        ),
        caller_limit_tok: None,
        explicit_override_tok: None,
    }
}

/// [`mcp_live_board`]'s view of one rendered board.
fn live_board_view(
    server: &SyncServer,
    board: &McpBoardState,
) -> Result<oneiron::board_verb::LiveBoardView, McpGatewayError> {
    let header = oneiron::context_board::BoardBlockHeader {
        epoch: board.epoch,
        scope: board.scope_label.clone(),
    };
    let render = oneiron::board_verb::render_current_keyframe(
        &header,
        &board.laid_out,
        run_board_budget_request(server),
    )
    .map_err(mcp_board_frame_error)?;
    let mut rows = std::collections::BTreeMap::new();
    let mut expansions = std::collections::BTreeMap::new();
    for section in &board.sections {
        let lines = section
            .pinned_rows()
            .iter()
            .chain(section.detail_rows())
            .cloned()
            .collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            rows.insert(format!("{}:{index}", section.name()), line.clone());
        }
        expansions.insert(section.name().to_owned(), lines);
    }
    Ok(oneiron::board_verb::LiveBoardView {
        snapshot: oneiron::context_board::BoardSnapshot {
            epoch: board.epoch,
            keyframe: render.text,
            rows,
        },
        expansions,
    })
}

/// A board refusal as the run's door states it: the verb's own refusal is
/// the caller's, anything else the host's.
fn run_board_error(error: McpGatewayError) -> oneiron::memory::MemoryError {
    let mut refusal = if error.kind == "legal_hold" {
        oneiron::memory::MemoryError::new(
            oneiron::memory::MEMORY_CODE_INVALID_STATE,
            error.message,
            &[oneiron::error::LEGAL_HOLD_SUGGESTION],
        )
    } else if error.kind == "verb_dispatch_failed" {
        oneiron::memory::MemoryError::bad_request(error.message)
    } else {
        oneiron::memory::MemoryError::new(
            oneiron::memory::MEMORY_CODE_INTERNAL,
            error.message,
            &["Report this host-door failure."],
        )
    };
    refusal.legal_hold = error.legal_hold;
    // FIX 7398: the refusal's reason codes ride back to the run.
    refusal.reason_codes = error.reason_codes;
    refusal
}
