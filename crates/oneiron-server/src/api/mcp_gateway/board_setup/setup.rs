//! The MCP `setup` tool: its help text, its grammar and its one keyframe-minting call.
//! `execute_mcp_setup` is its call surface.
//! The board_setup root defines `McpBoardState`; `oneiron::context_board` owns the board records.

use super::*;

/// What a caller can actually DO next on this endpoint.
///
/// Execution help follows the server's verified host binding, not a static
/// release-wide assumption that no interpreter exists.
pub(super) fn mcp_setup_help(server: &SyncServer) -> Vec<String> {
    vec![
        "register the tool-first endpoint for one generated tool per verb".to_owned(),
        if server.code_execution_host().is_some() {
            "execute_code resumes a durable run when called with the same run_ref and task"
                .to_owned()
        } else {
            "execute_code has no verified runtime on this server; direct calls receive code_host_unbound".to_owned()
        },
        "a More result carries an opaque cursor; send it back as page.cursor with the same \
         arguments"
            .to_owned(),
    ]
}

/// The whole grammar list the setup result pages over.
pub(super) fn mcp_setup_grammar_rows(structured: &Value) -> Vec<Value> {
    structured
        .get("verb_grammar")
        .and_then(|grammar| grammar.get("verbs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// ENFORCES the resolved page window on the grammar list, in place.
pub(super) fn mcp_cap_setup_grammar(
    structured: &mut Value,
    rows: Vec<Value>,
    page: &McpPageBudget,
) {
    let capped = page.cap(rows);
    if let Some(grammar) = structured
        .get_mut("verb_grammar")
        .and_then(Value::as_object_mut)
    {
        grammar.insert("verbs".to_owned(), Value::Array(capped));
    }
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
    let mut rider = None;
    let mut hooks = None;
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
        let mut payload =
            crate::mcp::mcp_setup_payload(&header, &board.sections, args.board_budget_request())
                .map_err(mcp_setup_payload_error)?;
        payload.instructions =
            crate::mcp::setup_instructions_for(server.code_execution_host().is_some());
        let keyframe = board
            .changes
            .ride(Some(oneiron::context_board::BoardStreamFrame {
                epoch: board.epoch,
                kind: oneiron::context_board::FrameKind::Keyframe(payload.board.text.clone()),
            }))
            .expect("rider preserves an existing frame");
        if let oneiron::context_board::FrameKind::Keyframe(text) = &keyframe.kind {
            payload.board.text.clone_from(text);
            payload.board.metadata.rendered_tok = oneiron::count_context_pack_tokens(text);
            payload.board.metadata.floor_exceeds_cap =
                payload.board.metadata.rendered_tok > payload.board.metadata.budget_tok;
        }
        let structured = payload.to_value();
        let source = crate::mcp::McpPageSource::complete(mcp_setup_grammar_rows(&structured).len());
        let snapshot = McpPageSnapshot {
            output: structured.clone(),
            source,
            health,
            keyframe: Some(keyframe.clone()),
            // A board's rows are known (FIX 5988).
            rows: Some(board.rows.clone()),
        };
        hooks = Some(board.hooks);
        rider = Some((board.changes, board.epoch));
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
            actor.metadata(health, page, mcp_setup_help(server), args.cache),
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
    // Page one returns the keyframe it rendered, rider and connector state
    // included; a continuation restates it and moves nothing.
    if let Some(hooks) = &mut hooks {
        hooks.record_receipt(server).await?;
    }
    if let Some((rider, epoch)) = &rider {
        super::board_observations::delivered(server, actor, rider, true, *epoch).await;
    }
    #[cfg(test)]
    super::device_release::release_hook::run(server);
    let continued = dispatch.continuation.is_some();
    let result = mcp_endpoint_result(
        server,
        actor,
        "board keyframe, verb grammar, and instructions returned",
        structured,
        carrier_policy,
    )
    .await;
    let result = mcp_release_listed(server, actor, snapshot.rows.as_deref(), continued, result);
    // Page one went out: each hook block it carried spends a delivery. A
    // continuation restates that keyframe and spends nothing again.
    if result.is_ok()
        && let Some(hooks) = &hooks
    {
        hooks.spend(server);
    }
    result
}
