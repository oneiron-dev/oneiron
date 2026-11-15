//! The MCP result carrier: the one chokepoint a tool result leaves through, and its paging.
//! `mcp_endpoint_result`, `mcp_preflight_page` and `mcp_resolve_page` are its call surface.
//! The board_setup root defines `McpCarrierPolicy` and `McpPageDispatchState`.

use super::*;

/// The ONE post-success result chokepoint (ONE-1704 M7 / B4).
///
/// Every actor-derived tool result leaves through here and this is the only
/// place a CARRIER frame is drained, `tasks.*` included. A queued frame
/// therefore rides the NEXT arbitrary successful result exactly once, and a
/// remainder the engine's coalescer kept behind it rides the one after that.
/// No branch hand-builds an envelope beside this one: after M1 there is no
/// unlisted executor left that could.
///
/// ONE-1704 B4: a world- or facet-NARROWED connection, or one whose credential
/// carries record-scope caveats, is delivered its own-task `tasks:` lines and
/// nothing else. The board publisher admits each own-task event under that
/// connection's own read of the TASK, projected through its world and facet
/// ceiling (`mcp_stream_reads_task`), so two
/// credentials for one actor with disjoint worlds or facets hear disjoint
/// events. No other carrier row is projected through those ceilings, so none
/// rides, and the rider never runs for such a connection. Its setup keyframe
/// is still taken, so its carrier holds the epoch a delta rides at.
///
/// Every call binds this credential as the connection's reader, the one the
/// board publisher admits own-task events under, and every queued TASK line
/// is read again before it rides: a line whose TASK was erased, or that this
/// credential may no longer read, is dropped.
pub(in crate::api::mcp_gateway) async fn mcp_endpoint_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    message: impl Into<String>,
    structured: Value,
    policy: McpCarrierPolicy,
) -> Value {
    let mut capabilities = Vec::new();
    let carrier = {
        let mut registry = server.mcp_registry.lock().await;
        registry.bind_stream_reader(actor);
        match policy {
            McpCarrierPolicy::Drain => registry.next_carrier_frame(&actor.stream_connection),
            McpCarrierPolicy::DrainWithCapabilities(hits) => {
                capabilities = hits;
                registry.next_carrier_frame(&actor.stream_connection)
            }
            McpCarrierPolicy::FreshKeyframe(minted) => {
                if let Some(frame) = minted {
                    registry.enqueue_stream_frame(&actor.stream_connection, frame);
                }
                let _superseded = registry.next_carrier_frame(&actor.stream_connection);
                None
            }
        }
    };
    // A queued frame derived from a row a device-local world keeps now
    // stays here.
    let carrier = carrier.filter(|frame| mcp_carrier_releases(server, actor, frame, &[]));
    let carrier = carrier.and_then(|frame| mcp_live_task_lines(server, actor, frame));
    // Never turn lifecycle movement into a push. A narrowed connector never
    // reaches the rider and an empty queue remains empty.
    let (carrier, rider_rows) = if actor.scope.is_narrow() || !actor.has_unrestricted_record_scope()
    {
        (carrier.and_then(mcp_own_task_lines), Vec::new())
    } else if carrier.is_some() {
        let original = carrier.clone();
        match super::board_observations::ride(server, actor, carrier, &capabilities).await {
            Ok(Some((frame, rows))) => (Some(frame), rows),
            Ok(None) => (None, Vec::new()),
            Err(_) => (original, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };
    #[cfg(test)]
    super::device_release::release_hook::run(server);
    // Judged again once the call has nothing left to wait on, for every
    // result: the rows it was derived from may all still leave this device.
    let carrier = carrier.filter(|frame| mcp_carrier_releases(server, actor, frame, &rider_rows));
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
/// `2024-11-05`, the oldest version this server negotiates, carries
/// `content` alone in its `CallToolResult` — `structuredContent` is a later
/// protocol addition, and the later versions ask a tool that returns it to
/// state the same JSON as text content too, so every version gets both (FIX
/// 4902). A result that put its data ONLY there handed a conforming
/// client one sentence of prose and no data at all (ONE-1704 repair). The same
/// typed structured payload is therefore ALSO stated as protocol text content,
/// serialized canonically so the bytes are stable, while `structuredContent`
/// stays exactly as it was for clients that read it.
///
/// The carrier frame is deliberately not folded in: it is stream data BESIDE
/// the result, and mixing it into the tool's own content would be the carrier
/// leak the envelope keeps out.
pub(super) fn mcp_negotiated_content(message: String, structured: &Value) -> Value {
    json!([
        mcp_text_content(message),
        mcp_text_content(crate::mcp::mcp_canonical_json(structured)),
    ])
}

pub(in crate::api::mcp_gateway) fn mcp_board_frame_error(
    error: oneiron::context_board::BoardFrameError,
) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

pub(super) fn mcp_setup_payload_error(error: crate::mcp::McpSetupPayloadError) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

pub(super) fn mcp_surface_construction_error(
    error: crate::mcp::McpSurfaceConstructionError,
) -> McpGatewayError {
    McpGatewayError::new(-32603, "board_render_failed", error.to_string())
}

pub(in crate::api::mcp_gateway) fn mcp_board_verb_error(
    error: oneiron::board_verb::BoardVerbError,
) -> McpGatewayError {
    McpGatewayError::new(-32020, "verb_dispatch_failed", format!("{error:?}"))
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
///
/// The retained page is judged again under the caller's CURRENT read, as a
/// fresh call is (ARCH-0028 #mcp-continuation-open): a row its read admitted
/// at page one that it may no longer read (a Grant narrowed or revoked, the
/// row moved out of its ceiling) refuses the continuation, and the caller
/// starts over from page one under the read it holds now. Which rows its read
/// admitted is judged at page one's mint, after its producer ran, so the
/// vault's authority is read here, before the producer: a Grant revoked in
/// between moves its generation, one that expires in between its
/// authorization time, and page one then keeps every row it was made from
/// (`mcp_page_rows_read_now`).
pub(in crate::api::mcp_gateway) async fn mcp_preflight_page(
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
            produced_under: if continuable {
                McpAuthorityReading::read(&server.vault)
            } else {
                None
            },
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
    let Some(snapshot) = state.snapshot.as_ref() else {
        // Registry-only callers may mint an old position-only handle, but the
        // gateway cannot safely dispatch it: without the retained producer set
        // there is no exact continuation to return.
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::SnapshotMismatch,
        ));
    };
    // A retained page derived from a row a device-local world keeps now
    // never leaves this device again: the caller starts over from page one.
    // A page of the owner's own whole-vault export, as the continued tool
    // and his fresh proof name it, is released as his will (owner ruling
    // 1-EXPORT = B).
    let owner_whole_vault_export =
        super::super::device_release::owner_whole_vault_export_call(server, actor, tool);
    if !mcp_snapshot_releases(server, actor, snapshot, owner_whole_vault_export)? {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::SnapshotMismatch,
        ));
    }
    drop(registry);
    if !mcp_page_rows_still_read(server, actor, &snapshot.read_rows)? {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::SnapshotMismatch,
        ));
    }
    Ok(McpPageDispatchState {
        continuation: Some(state),
        continuable,
        producer_epoch: None,
        produced_under: None,
    })
}

/// Resolves one page after the producer has either supplied a fresh snapshot or
/// the pre-dispatch door has supplied its retained one.
pub(in crate::api::mcp_gateway) async fn mcp_resolve_page(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    argument_digest: [u8; 32],
    request: Option<&crate::mcp::McpPageRequest>,
    dispatch: &McpPageDispatchState,
    snapshot: &McpPageSnapshot,
) -> Result<McpPageBudget, McpGatewayError> {
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
        let mut retained = snapshot.clone();
        // Page one's cursor keeps the rows its caller reads now, which each
        // continuation of it is judged again by; a continuation's own
        // successor keeps the ones it was judged by.
        if dispatch.continuation.is_none() {
            #[cfg(oneiron_test_support)]
            crate::test_doors::mcp_page_mint::run_before_page_mint(&server.vault);
            retained.read_rows =
                mcp_page_rows_read_now(server, actor, snapshot, dispatch.produced_under)?;
        }
        let mut registry = server.mcp_registry.lock().await;
        let cursor = registry.mint_page_cursor_with_snapshot(
            &actor.stream_connection,
            tool,
            argument_digest,
            snapshot_epoch,
            position,
            Some(retained),
        );
        page.attach_cursor(cursor);
    }
    Ok(page)
}

/// The rows of a page one's `rows` its caller read, sorted and unique, by the
/// predicate the board door admits a row with (`mcp_scope_admits_row`): its
/// credential reads the row, inside its registered world and facet ceiling.
///
/// They are judged at the mint, after the producer ran. That answers which
/// rows the producer's read admitted only while the vault's authority is
/// still `produced_under`, read before the producer ran: no authority commit
/// landed and the authorization time did not move, so no Grant was revoked
/// and none expired while page one was made. After either, or with no
/// reading, that is unknown, and every row is kept: each continuation is then
/// judged by all of them. A caller with no scoped read, or a page whose rows
/// are unknown (FIX 5988), keeps none.
fn mcp_page_rows_read_now(
    server: &SyncServer,
    actor: &McpResolvedActor,
    snapshot: &McpPageSnapshot,
    produced_under: Option<McpAuthorityReading>,
) -> Result<Vec<oneiron::EntityId>, McpGatewayError> {
    let rows = snapshot
        .rows
        .iter()
        .flatten()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(read) = mcp_scoped_read(&server.vault, actor) else {
        return Ok(Vec::new());
    };
    let mut kept = Vec::with_capacity(rows.len());
    for row in &rows {
        if mcp_page_row_read(server, actor, &read, row)? {
            kept.push(*row);
        }
    }
    if !mcp_authority_unchanged_since(server, produced_under) {
        return Ok(rows.into_iter().collect());
    }
    Ok(kept)
}

/// Whether the vault's authority is still `produced_under`. Read after the
/// rows are judged, so no authority commit and no expiry before the
/// judgement goes unseen.
fn mcp_authority_unchanged_since(
    server: &SyncServer,
    produced_under: Option<McpAuthorityReading>,
) -> bool {
    produced_under.is_some() && McpAuthorityReading::read(&server.vault) == produced_under
}

/// Whether the caller's read at this call still admits every row page one's
/// read admitted. Its scoped read failing now refuses with its own error.
fn mcp_page_rows_still_read(
    server: &SyncServer,
    actor: &McpResolvedActor,
    read_rows: &[oneiron::EntityId],
) -> Result<bool, McpGatewayError> {
    if read_rows.is_empty() {
        return Ok(true);
    }
    let read = mcp_scoped_read(&server.vault, actor)?;
    for row in read_rows {
        if !mcp_page_row_read(server, actor, &read, row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mcp_page_row_read(
    server: &SyncServer,
    actor: &McpResolvedActor,
    read: &oneiron::claim::ScopedRead<'_>,
    row: &oneiron::EntityId,
) -> Result<bool, McpGatewayError> {
    let readable = mcp_credential_reads(&server.vault, actor, row)
        .map_err(|error| mcp_engine_error("mcp page row admission failed", error))?;
    Ok(readable && mcp_scope_covers_entity(read, &actor.scope, row)?)
}

pub(in crate::api::mcp_gateway) fn mcp_page_cursor_error(
    error: crate::mcp::McpPageCursorError,
) -> McpGatewayError {
    McpGatewayError::new(-32602, error.error_code(), error.to_string()).with_field("page.cursor")
}
