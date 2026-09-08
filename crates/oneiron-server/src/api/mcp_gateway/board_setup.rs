//! Board state, setup grammar, and page preflight.

use super::{
    McpCallContext, McpGatewayError, mcp_actor_result, mcp_engine_error, mcp_facade_error,
    mcp_scope_covers_entity, mcp_scoped_read, mcp_text_content,
};
use crate::mcp::McpPageBudget;
use crate::mcp::McpPageCursorState;
use crate::mcp::McpPageSnapshot;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRetrievalHealth;
use crate::server::SyncServer;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

/// How one result relates to this connector's queued STREAM state.
#[derive(Debug)]
pub(super) enum McpCarrierPolicy {
    /// An ordinary result: drain AT MOST ONE pending frame beside it.
    Drain,
    /// This result carries its OWN freshly minted keyframe. `Some` is a frame
    /// the producer has not enqueued yet (setup mints one outside the
    /// registry); `None` is one the producer already enqueued (the engine's own
    /// `board.refresh` does). Either way the queue behind it is EXPLICITLY
    /// superseded and then drained, so no older carrier rides beside a fresh
    /// keyframe and none is left stranded.
    ///
    /// Only a result that states a keyframe the caller has NOT already been
    /// given may say this. A paged producer states its keyframe on page ONE;
    /// its continuations restate that same retained frame and therefore
    /// [`McpCarrierPolicy::Drain`] instead — re-superseding on an already
    /// delivered keyframe destroys the transitions queued behind it.
    FreshKeyframe(Option<oneiron::context_board::BoardStreamFrame>),
}

/// The ONE post-success result chokepoint (ONE-1704 M7 / B4).
///
/// Every actor-derived tool result leaves through here and this is the only
/// place a CARRIER frame is drained, `tasks.*` included. A queued frame
/// therefore rides the NEXT arbitrary successful result exactly once, and a
/// remainder the engine's coalescer kept behind it rides the one after that.
/// No branch hand-builds an envelope beside this one: after M1 there is no
/// unlisted executor left that could.
///
/// ONE-1704 B4: a world- or facet-NARROWED connection is delivered ZERO carrier
/// frames here. The engine's router matches a carrier subscription by category
/// and actor equality only, so two credentials for one actor with disjoint
/// worlds or facets are eligible for the same events; until the router can
/// filter those axes, the truthful delivery for a narrowed connection is none
/// at all. This is a delivery ceiling, not a discard: the server takes no
/// payload for such a connection, so nothing the engine queued is destroyed
/// here. Vault-wide connections are untouched.
pub(super) async fn mcp_endpoint_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    message: impl Into<String>,
    structured: Value,
    policy: McpCarrierPolicy,
) -> Value {
    let carrier = if actor.scope.is_narrow() {
        None
    } else {
        let mut registry = server.mcp_registry.lock().await;
        match policy {
            McpCarrierPolicy::Drain => registry.next_carrier_frame(&actor.stream_connection),
            McpCarrierPolicy::FreshKeyframe(minted) => {
                if let Some(frame) = minted {
                    registry.enqueue_stream_frame(&actor.stream_connection, frame);
                }
                let _superseded = registry.next_carrier_frame(&actor.stream_connection);
                None
            }
        }
    };
    let mut result = json!({
        "content": mcp_negotiated_content(message.into(), &structured),
        "structuredContent": structured,
        "isError": false,
    });
    if let Some(frame) = carrier
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "carrier".to_owned(),
            json!({ "class": "carrier", "frame": frame }),
        );
    }
    result
}

/// The result data a client reads over the NEGOTIATED protocol.
///
/// [`MCP_PROTOCOL_VERSION`] is what this server negotiates, and its
/// `CallToolResult` carries `content` alone — `structuredContent` is a later
/// protocol addition. A result that put its data ONLY there handed a conforming
/// client one sentence of prose and no data at all (ONE-1704 repair). The same
/// typed structured payload is therefore ALSO stated as protocol text content,
/// serialized canonically so the bytes are stable, while `structuredContent`
/// stays exactly as it was for clients that read it.
///
/// The carrier frame is deliberately not folded in: it is stream data BESIDE
/// the result, and mixing it into the tool's own content would be the carrier
/// leak the envelope keeps out.
fn mcp_negotiated_content(message: String, structured: &Value) -> Value {
    json!([
        mcp_text_content(message),
        mcp_text_content(crate::mcp::mcp_canonical_json(structured)),
    ])
}

pub(super) fn mcp_board_frame_error(
    error: oneiron::context_board::BoardFrameError,
) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

fn mcp_setup_payload_error(error: crate::mcp::McpSetupPayloadError) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

fn mcp_surface_construction_error(
    error: crate::mcp::McpSurfaceConstructionError,
) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

pub(super) fn mcp_board_verb_error(error: oneiron::board_verb::BoardVerbError) -> McpGatewayError {
    McpGatewayError::new(-32020, "verb_dispatch_failed", format!("{error:?}"))
}

/// One connector's CURRENT board: the sections, the state-derived snapshot
/// epoch, and the scope label the header states.
pub(super) struct McpBoardState {
    pub(super) sections: Vec<oneiron::context_board::BoardSection>,
    pub(super) scope_label: String,
    /// The monotonic snapshot epoch this exact state owns (ONE-1704 M5).
    pub(super) epoch: u64,
    /// TASKS rows the credential's REQUESTED SCOPE ceiling removed.
    scope_omitted: usize,
    /// TASKS rows the engine's own render row cap truncated away. A page
    /// WINDOW fact, kept apart from the scope fact above (ONE-1704 repair).
    window_truncated: usize,
    /// False when the producer's own TASK scan stopped at its cap, so the
    /// truncation count above is a lower bound rather than a census.
    source_exhausted: bool,
}

impl McpBoardState {
    /// The COMPLETE omission facts this rendered board carries, on both axes
    /// and with the producer's own exhaustion bit.
    ///
    /// Every consumer of a board's honesty reads it from here, so no caller can
    /// derive a result fact from one axis while the board states two.
    pub(super) const fn omissions(&self) -> McpBoardOmissions {
        McpBoardOmissions {
            scope_omitted: self.scope_omitted,
            window_truncated: self.window_truncated,
            source_exhausted: self.source_exhausted,
        }
    }
}

/// Reads the current board for one connector and fences it to a STATE epoch.
///
/// The epoch is minted by the registry from a hash of the rendered state, not
/// from a clock: a call a minute later over identical state gets the SAME
/// epoch, and a mutation a millisecond later gets the next one. The registry
/// RETAINS that snapshot, so a later `board.expand`/`board.refresh` fences
/// against the exact snapshot setup returned.
pub(super) async fn mcp_current_board(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<McpBoardState, McpGatewayError> {
    let (sections, omissions) = mcp_board_sections(server, actor)?;
    let scope_label = crate::mcp::mcp_effective_scope_label(&actor.scope);
    let state_hash =
        crate::mcp::mcp_board_state_hash(&scope_label, &mcp_board_state_rows(&sections));
    let epoch = {
        let mut registry = server.mcp_registry.lock().await;
        registry.board_snapshot_epoch(&actor.stream_connection, state_hash)
    };
    Ok(McpBoardState {
        sections,
        scope_label,
        epoch,
        scope_omitted: omissions.scope_omitted,
        window_truncated: omissions.window_truncated,
        source_exhausted: omissions.source_exhausted,
    })
}

/// What one rendered board did NOT show, on its two independent axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct McpBoardOmissions {
    /// Rows the REQUESTED ACTOR SCOPE removed.
    pub(crate) scope_omitted: usize,
    /// Rows the producer's own render window truncated away.
    pub(crate) window_truncated: usize,
    pub(crate) source_exhausted: bool,
}

impl McpBoardOmissions {
    /// The retrieval health these omission facts force, in the SAME meanings
    /// every other producer states ([`crate::mcp::McpPageSource::health`]).
    ///
    /// ONE-1704 repair: a board that withheld rows on EITHER axis is not
    /// healthy, and a board whose own TASK scan stopped at its cap is degraded
    /// rather than partial, because it does not know what it skipped. Reading
    /// only the scope axis let a board the render WINDOW had truncated be
    /// reported healthy, which told a caller an incomplete working set was the
    /// whole one.
    ///
    /// `produced` is not a health axis — [`crate::mcp::McpPageSource::health`]
    /// reads only the two omission counts and the exhaustion bit — so the row
    /// count is deliberately not restated here.
    pub(crate) const fn health(self) -> McpRetrievalHealth {
        crate::mcp::McpPageSource::scoped_window(
            0,
            self.scope_omitted,
            self.window_truncated,
            self.source_exhausted,
        )
        .health()
    }
}

/// Every board row, in section order: the exact material the snapshot epoch is
/// the epoch OF.
fn mcp_board_state_rows(sections: &[oneiron::context_board::BoardSection]) -> Vec<String> {
    let mut rows = Vec::new();
    for section in sections {
        rows.push(section.name().to_owned());
        rows.extend(section.pinned_rows().iter().cloned());
        rows.extend(section.detail_rows().iter().cloned());
    }
    rows
}

/// The board sections the primary keyframe renders over.
///
/// TASKS comes from the engine's own gated `tasks.check` facade, NARROWED to
/// this credential's world/facet ceiling before it ever reaches the renderer,
/// so a board a narrow connector reads is never the actor-wide board. The
/// pinned VERBS section restates the generated grammar as board state.
fn mcp_board_sections(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
) -> Result<(Vec<oneiron::context_board::BoardSection>, McpBoardOmissions), McpGatewayError> {
    let verbs = crate::mcp::generated_verb_tools().map_err(mcp_surface_construction_error)?;
    let verb_section = crate::mcp::mcp_verb_board_section(&verbs).map_err(mcp_board_frame_error)?;
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);
    let tasks = facade.tasks_check().map_err(mcp_facade_error)?;
    let (tasks, scope_omitted) = mcp_scoped_tasks_section(server, actor, tasks)?;
    // The engine's own footer states the render WINDOW's truncation and
    // whether its scan was exhausted. That is a different fact from the scope
    // filtering above, and the two are carried separately from here on.
    let omissions = McpBoardOmissions {
        scope_omitted,
        window_truncated: tasks
            .overflow
            .map_or(0, |overflow| overflow.known_omitted_rows),
        source_exhausted: tasks
            .overflow
            .is_none_or(|overflow| overflow.source_exhausted),
    };
    let agents = oneiron::context_board::render_agents_section(&[], &[]);
    let [tasks_section, agents_section] =
        oneiron::context_board::assemble_task_agent_sections(&tasks, &agents)
            .map_err(mcp_board_frame_error)?;
    Ok((vec![verb_section, tasks_section, agents_section], omissions))
}

/// Narrows one TASKS section to the credential's registered world/facet.
///
/// A vault-wide credential is unchanged and pays nothing. A NARROWED one keeps
/// only rows the store itself says the scope covers; the count it removed is
/// returned so the page metadata can state the omission instead of hiding it.
pub(super) fn mcp_scoped_tasks_section(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    section: oneiron::context_board::TasksSection,
) -> Result<(oneiron::context_board::TasksSection, usize), McpGatewayError> {
    if !actor.scope.is_narrow() {
        return Ok((section, 0));
    }
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let mut kept = Vec::with_capacity(section.rows.len());
    let mut omitted = 0_usize;
    for row in section.rows {
        if mcp_scope_admits_row(&scoped_read, &actor.scope, &row.id)? {
            kept.push(row);
        } else {
            omitted += 1;
        }
    }
    Ok((
        oneiron::context_board::TasksSection {
            rows: kept,
            overflow: section.overflow,
        },
        omitted,
    ))
}

/// True when the registered scope covers the row this board id names.
///
/// A row whose id is not an entity id cannot be proven in scope, so a narrowed
/// credential does not see it: this fails closed.
fn mcp_scope_admits_row(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    scope: &crate::mcp::McpConnectorScope,
    row_id: &str,
) -> Result<bool, McpGatewayError> {
    let Ok(id) = oneiron::EntityId::from_hex(row_id) else {
        return Ok(false);
    };
    let readable = scoped_read
        .is_entity_readable(&id)
        .map_err(|error| mcp_engine_error("mcp board row admission failed", error))?;
    Ok(readable && mcp_scope_covers_entity(scoped_read, scope, &id)?)
}

/// What a caller can actually DO next on this endpoint.
///
/// ONE-1704 B1: every line is true of the release that is shipping. There is no
/// `execute_code` lane to point at, so none is offered.
fn mcp_setup_help() -> Vec<String> {
    vec![
        "register the tool-first endpoint for one generated tool per verb".to_owned(),
        "execute_code is not shipped in this release; a direct call is refused with \
         execute_code_unavailable"
            .to_owned(),
        "a More result carries an opaque cursor; send it back as page.cursor with the same \
         arguments"
            .to_owned(),
    ]
}

/// The whole grammar list the setup result pages over.
fn mcp_setup_grammar_rows(structured: &Value) -> Vec<Value> {
    structured
        .get("verb_grammar")
        .and_then(|grammar| grammar.get("verbs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// ENFORCES the resolved page window on the grammar list, in place.
fn mcp_cap_setup_grammar(structured: &mut Value, rows: Vec<Value>, page: &McpPageBudget) {
    let capped = page.cap(rows);
    if let Some(grammar) = structured
        .get_mut("verb_grammar")
        .and_then(Value::as_object_mut)
    {
        grammar.insert("verbs".to_owned(), Value::Array(capped));
    }
}

/// The pre-dispatch page state. A live cursor is consumed here, before the
/// producer is allowed to call a facade or mutate a registry. Its retained
/// snapshot is then used directly for the continuation, so no second producer
/// read can replace page one's result.
#[derive(Clone, Debug)]
pub(super) struct McpPageDispatchState {
    pub(super) continuation: Option<McpPageCursorState>,
    continuable: bool,
    pub(super) producer_epoch: Option<u64>,
}

/// Verifies or rejects page.cursor before any producer dispatch.
///
/// A cursor on a one-row/non-continuable operation is refused at this door.
/// For a continuable operation, successful consumption returns the exact
/// producer snapshot retained with the handle. A mismatch returns before any
/// facade, board dispatcher, stream operation, or vault write, and consumes
/// nothing — this connection's other live continuations survive a refusal.
///
/// The fence is the IMMUTABLE snapshot RETAINED with the handle, never the
/// latest board epoch (ONE-1704 repair). A continued page is served from that
/// retained producer result, so a board mutation somewhere else between page
/// one and page two cannot make page two wrong — and refusing it there simply
/// destroyed a valid enumeration. Connector, tool, argument, and producer
/// identity stay bound: the registry checks all four against the retained row.
pub(super) async fn mcp_preflight_page(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    argument_digest: [u8; 32],
    request: Option<&crate::mcp::McpPageRequest>,
    continuable: bool,
) -> Result<McpPageDispatchState, McpGatewayError> {
    let Some(cursor) = request.and_then(|page| page.cursor.as_deref()) else {
        return Ok(McpPageDispatchState {
            continuation: None,
            continuable,
            producer_epoch: None,
        });
    };
    if !continuable {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::Unsupported,
        ));
    }
    let mut registry = server.mcp_registry.lock().await;
    // Read only: this lookup does not render a board or touch stream state.
    let state = registry
        .consume_page_cursor_state(
            &actor.stream_connection,
            tool,
            argument_digest,
            None,
            cursor,
        )
        .map_err(mcp_page_cursor_error)?;
    if state.snapshot.is_none() {
        // Registry-only callers may mint an old position-only handle, but the
        // gateway cannot safely dispatch it: without the retained producer set
        // there is no exact continuation to return.
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::SnapshotMismatch,
        ));
    }
    Ok(McpPageDispatchState {
        continuation: Some(state),
        continuable,
        producer_epoch: None,
    })
}

/// Resolves one page after the producer has either supplied a fresh snapshot or
/// the pre-dispatch door has supplied its retained one.
pub(super) async fn mcp_resolve_page(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    argument_digest: [u8; 32],
    request: Option<&crate::mcp::McpPageRequest>,
    dispatch: &McpPageDispatchState,
    snapshot: &McpPageSnapshot,
) -> Result<McpPageBudget, McpGatewayError> {
    let mut registry = server.mcp_registry.lock().await;
    let snapshot_epoch = dispatch.continuation.as_ref().map_or_else(
        || dispatch.producer_epoch.unwrap_or(0),
        |continuation| continuation.snapshot_epoch,
    );
    let mut page = if dispatch.continuable {
        McpPageBudget::resolve_page(
            request,
            snapshot.source,
            dispatch
                .continuation
                .as_ref()
                .map_or(0, |state| state.position),
        )
    } else {
        McpPageBudget::resolve(request, snapshot.source)
    };
    if let Some(position) = page.successor_position() {
        let cursor = registry.mint_page_cursor_with_snapshot(
            &actor.stream_connection,
            tool,
            argument_digest,
            snapshot_epoch,
            position,
            Some(snapshot.clone()),
        );
        page.attach_cursor(cursor);
    }
    Ok(page)
}

pub(super) fn mcp_page_cursor_error(error: crate::mcp::McpPageCursorError) -> McpGatewayError {
    McpGatewayError::new(-32602, error.error_code(), error.to_string()).with_field("page.cursor")
}

/// `setup_oneiron`: board keyframe + verb grammar + instructions, in ONE
/// result.
pub(crate) async fn execute_mcp_setup(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpSetupToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    // Bind BEFORE any board/facade read. A presented cursor is consumed only
    // after its connector/tool/arguments checks pass against the row retained
    // with it, and its retained producer result is then used directly below.
    let argument_digest = crate::mcp::mcp_page_argument_digest(&args);
    let mut dispatch = mcp_preflight_page(
        server,
        actor,
        crate::mcp::MCP_SETUP_TOOL,
        argument_digest,
        args.page.as_ref(),
        true,
    )
    .await?;
    let (mut structured, keyframe, health, snapshot, producer_epoch) = if let Some(continuation) =
        dispatch.continuation.as_ref()
    {
        let snapshot = continuation.snapshot.clone().ok_or_else(|| {
            mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
        })?;
        let keyframe = snapshot.keyframe.clone().ok_or_else(|| {
            mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
        })?;
        (
            snapshot.output.clone(),
            keyframe,
            snapshot.health,
            snapshot,
            None,
        )
    } else {
        // No cursor: this is page one, so produce and retain the exact
        // un-capped grammar/result before resolving its window.
        let board = mcp_current_board(server, actor).await?;
        // The GRAMMAR rows this page partitions are complete, but the health
        // this result states is the BOARD's, and the board has two omission
        // axes plus its own exhaustion bit. Deriving it from scope omission
        // alone reported a keyframe the render window had truncated — or one
        // whose TASK scan stopped at its cap — as healthy (ONE-1704 repair).
        let health = board.omissions().health();
        let header = oneiron::context_board::BoardBlockHeader {
            epoch: board.epoch,
            scope: board.scope_label,
        };
        let payload =
            crate::mcp::mcp_setup_payload(&header, &board.sections, args.board_budget_request())
                .map_err(mcp_setup_payload_error)?;
        let keyframe = oneiron::context_board::BoardStreamFrame {
            epoch: board.epoch,
            kind: oneiron::context_board::FrameKind::Keyframe(payload.board.text.clone()),
        };
        let structured = payload.to_value();
        let source = crate::mcp::McpPageSource::complete(mcp_setup_grammar_rows(&structured).len());
        let snapshot = McpPageSnapshot {
            output: structured.clone(),
            source,
            health,
            keyframe: Some(keyframe.clone()),
        };
        (structured, keyframe, health, snapshot, Some(board.epoch))
    };
    dispatch.producer_epoch = producer_epoch;
    let page = mcp_resolve_page(
        server,
        actor,
        crate::mcp::MCP_SETUP_TOOL,
        argument_digest,
        args.page.as_ref(),
        &dispatch,
        &snapshot,
    )
    .await?;
    let grammar_rows = mcp_setup_grammar_rows(&structured);
    mcp_cap_setup_grammar(&mut structured, grammar_rows, &page);
    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(crate::mcp::MCP_SETUP_TOOL.to_owned()),
        );
        object.insert("actor".to_owned(), mcp_actor_result(actor));
        object.insert(
            "meta".to_owned(),
            actor.metadata(health, page, mcp_setup_help(), args.cache),
        );
    }
    // ONE-1704 carrier repair: PAGE ONE carries the keyframe it just minted and
    // supersedes the queue behind it. A CONTINUATION restates the SAME retained
    // keyframe page one already delivered, so treating it as fresh re-enqueued a
    // DUPLICATE: that push cleared the same-epoch delta rows queued behind it in
    // the engine's coalescer and was then consumed as the superseded drain, so
    // the continuation carried nothing and every later result had lost the
    // transition. A continuation is an ordinary result — it drains AT MOST ONE
    // already-queued carrier and re-enqueues nothing.
    let carrier_policy = if dispatch.continuation.is_some() {
        McpCarrierPolicy::Drain
    } else {
        McpCarrierPolicy::FreshKeyframe(Some(keyframe))
    };
    Ok(mcp_endpoint_result(
        server,
        actor,
        "board keyframe, verb grammar, and instructions returned",
        structured,
        carrier_policy,
    )
    .await)
}
