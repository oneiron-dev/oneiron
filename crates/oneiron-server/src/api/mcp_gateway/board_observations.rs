//! Session-clock read observations and turn-local riders for MCP boards.

use super::{
    McpGatewayError, mcp_board_frame_error, mcp_credential_reads, mcp_engine_error,
    mcp_scope_covers_entity, mcp_scoped_read,
};
use crate::{mcp::McpResolvedActor, server::SyncServer};
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardLegend, BoardStreamFrame, CapabilityHit,
    ChangedLine, DeltaRow, FrameKind, SessionReadSet, SkillsSection,
};
use tokio::sync::{MappedMutexGuard, MutexGuard};

/// A tagged connector key cannot alias Core's two-element session key,
/// even if a Core principal deliberately chooses an MCP-looking name.
/// Both namespaces share the server-owned store and its eviction policy.
pub(super) async fn read_set<'a>(
    server: &'a SyncServer,
    actor: &McpResolvedActor,
) -> MappedMutexGuard<'a, SessionReadSet> {
    let key = serde_json::to_string(&(
        "mcp",
        actor.gate_actor_class,
        &actor.gate_actor_ref,
        &actor.stream_connection.0,
        actor.scope.world_ref.map(|id| id.to_hex()),
        actor.scope.facet_ref.map(|id| id.to_hex()),
    ))
    .expect("string tuple serializes");
    let mut store = server.memories_cursors.lock().await;
    store.current(key.clone(), &actor.stream_connection.0);
    MutexGuard::map(store, |store| store.read_sets.entry(key).or_default())
}

/// The session's read state, the changed line with this session's own
/// deliveries fitted in, and the same line before they were: board state an
/// epoch hashes never depends on what a delivery displaced.
pub(super) async fn state(
    server: &SyncServer,
    actor: &McpResolvedActor,
) -> Result<(SessionReadSet, ChangedLine, ChangedLine), McpGatewayError> {
    let packs = super::board_setup::mcp_visible_pack_inventory(server, actor)?;
    let observations = read_set(server, actor).await.clone();
    let read = mcp_scoped_read(&server.vault, actor)?;
    let mut changed = observations
        .refresh(&read, 4096)
        .map_err(|error| mcp_engine_error("mcp session refresh failed", error))?;
    let mut visible = Vec::new();
    for receipt in changed.install_rows.drain(..) {
        let id = oneiron::EntityId::from_hex(&receipt.entity)
            .map_err(|error| mcp_engine_error("mcp install receipt id invalid", error))?;
        if mcp_scope_covers_entity(&read, &actor.scope, &id)?
            && mcp_credential_reads(&server.vault, actor, &id)
                .map_err(|error| mcp_engine_error("mcp install receipt credential failed", error))?
        {
            visible.push(receipt);
        }
    }
    changed.install_overflow = visible.len().saturating_sub(16);
    changed.install_rows = visible.into_iter().take(16).collect();
    changed.overflow += changed.rows.len().saturating_sub(16);
    changed.rows.truncate(16);
    let installs = observations.pack_changes(&packs, 16_usize.saturating_sub(changed.rows.len()));
    changed.rows.extend(installs.rows);
    changed.overflow += installs.overflow;
    // Own proposal outcomes and connector changes reach only a vault-wide
    // connection, the same ceiling the carrier rider keeps.
    let own = (!actor.scope.is_narrow() && actor.has_unrestricted_record_scope())
        .then_some(actor.actor_ref);
    let board = changed.clone();
    observations
        .fold_own_changes(&read, own, actor.locality(), &mut changed, 16)
        .map_err(|error| mcp_engine_error("mcp session refresh failed", error))?;
    Ok((observations, changed, board))
}

/// The rider in `changed` was delivered on a frame of board `epoch`: move the
/// session past it. A keyframe also moves the connector state into the
/// prefix. A frame older than the last keyframe this connection's carrier
/// took is one the receiver ignores, so its rider stays owed.
pub(super) async fn delivered(
    server: &SyncServer,
    actor: &McpResolvedActor,
    changed: &ChangedLine,
    keyframe: bool,
    epoch: u64,
) {
    let mut reads = read_set(server, actor).await;
    let superseded = server
        .mcp_registry
        .lock()
        .await
        .streams_mut()
        .carrier_epoch(&actor.stream_connection)
        .is_some_and(|carrier| carrier > epoch);
    if superseded {
        return;
    }
    if keyframe {
        reads.keyframe_committed(changed);
    } else {
        reads.acknowledge(changed);
    }
}

/// The empty queue is checked before reading session state or rendering. This
/// function neither creates a frame nor enqueues an event. Beside the frame
/// it returns the rows the changed line it fitted in names.
pub(super) async fn ride(
    server: &SyncServer,
    actor: &McpResolvedActor,
    frame: Option<BoardStreamFrame>,
    hits: &[CapabilityHit],
) -> Result<Option<(BoardStreamFrame, Vec<oneiron::EntityId>)>, McpGatewayError> {
    let Some(mut frame) = frame else {
        return Ok(None);
    };
    if let FrameKind::Delta(rows) = &mut frame.kind {
        rows.retain(|row| !matches!(row.key.as_str(), "changed" | "SKILLS"));
    }
    let (observations, changed, _) = state(server, actor).await?;
    let frame = changed
        .ride(Some(frame))
        .expect("rider preserves an existing frame");
    let frame = ride_capabilities(frame, hits, &observations)?;
    delivered(server, actor, &changed, false, frame.epoch).await;
    let rows = crate::device_local::changed_line_rows(&changed).collect();
    Ok(Some((frame, rows)))
}

fn ride_capabilities(
    mut frame: BoardStreamFrame,
    hits: &[CapabilityHit],
    observations: &SessionReadSet,
) -> Result<BoardStreamFrame, McpGatewayError> {
    // Skills and agent definitions the channel found share SKILLS `found`
    // (PEOPLE, ARCH-0067: the AGENTS section is gone).
    let skills = SkillsSection::project(hits, observations);
    let sections = [skills.board_section().map_err(mcp_board_frame_error)?];
    let header = BoardBlockHeader {
        epoch: frame.epoch,
        scope: "carrier".to_owned(),
    };
    // Reserve the already-produced payload first. Discovery is the cheapest
    // tier and may not evict that payload. The loaded floor never sheds.
    let occupied = match &frame.kind {
        FrameKind::Keyframe(text) => oneiron::count_context_pack_tokens(text),
        FrameKind::Delta(rows) => oneiron::count_context_pack_tokens(
            &rows
                .iter()
                .map(|row| row.line.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    };
    let render = oneiron::context_board::render_board_block(
        &BoardFrame {
            header: &header,
            legend: &BoardLegend::canonical(),
            sections: &sections,
            you: None,
            changes: None,
        },
        BoardBudgetRequest {
            harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK.saturating_sub(occupied),
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .map_err(mcp_board_frame_error)?;
    let skill_rows = &render.shed.sections[0].rows;
    match &mut frame.kind {
        FrameKind::Delta(rows) => {
            // Whole-lane replacement clears prior-turn discoveries, including
            // on an unrelated call whose hit slice is empty.
            rows.push(DeltaRow {
                key: "SKILLS".to_owned(),
                line: skill_rows.join(" "),
            });
        }
        FrameKind::Keyframe(text) => {
            if hits.is_empty() && observations.loaded_skills().next().is_none() {
                return Ok(frame);
            }
            // Fixed renderer insertion boundary, exactly like ChangedLine::ride.
            // No ids or state are recovered from renderer text.
            if let Some(at) = text.find("\nlegend:") {
                let mut lines = vec!["SKILLS".to_owned()];
                lines.extend(skill_rows.iter().cloned());
                text.insert_str(
                    at,
                    &format!(
                        "\n{}",
                        lines
                            .iter()
                            .map(|line| xml_leaf(line))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                );
            }
        }
    }
    Ok(frame)
}

fn xml_leaf(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            c if c.is_control() => escaped.push(' '),
            c => escaped.push(c),
        }
    }
    escaped
}

/// A pumped run's own session read set (OF-533): keyed on the run's board
/// connection under its agent, tagged apart from a connector's and Core's.
pub(super) async fn run_read_set<'a>(
    server: &'a SyncServer,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
) -> MappedMutexGuard<'a, SessionReadSet> {
    let key = run_read_set_key(actor, connection);
    let mut store = server.memories_cursors.lock().await;
    store.current(key.clone(), &connection.0);
    MutexGuard::map(store, |store| store.read_sets.entry(key).or_default())
}

pub(super) fn run_read_set_key(
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
) -> String {
    serde_json::to_string(&(
        "run",
        actor.actor_class().gate_actor_class(),
        actor.entity_ref().to_hex(),
        &connection.0,
    ))
    .expect("string tuple serializes")
}

/// [`state`] for a pumped run: what changed under the agent's own read lane,
/// with the agent's own outcomes folded in, as a vault-wide connector's are.
pub(super) async fn run_state(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    read: &oneiron::claim::ScopedRead<'_>,
    packs: &[(String, String)],
) -> Result<(SessionReadSet, ChangedLine, ChangedLine), McpGatewayError> {
    let observations = run_read_set(server, actor, connection).await.clone();
    let mut changed = observations
        .refresh(read, 4096)
        .map_err(|error| mcp_engine_error("run session refresh failed", error))?;
    let mut visible = Vec::new();
    for receipt in changed.install_rows.drain(..) {
        let id = oneiron::EntityId::from_hex(&receipt.entity)
            .map_err(|error| mcp_engine_error("run install receipt id invalid", error))?;
        if read
            .is_entity_readable(&id)
            .map_err(|error| mcp_engine_error("run install receipt read failed", error))?
        {
            visible.push(receipt);
        }
    }
    changed.install_overflow = visible.len().saturating_sub(16);
    changed.install_rows = visible.into_iter().take(16).collect();
    changed.overflow += changed.rows.len().saturating_sub(16);
    changed.rows.truncate(16);
    let installs = observations.pack_changes(packs, 16_usize.saturating_sub(changed.rows.len()));
    changed.rows.extend(installs.rows);
    changed.overflow += installs.overflow;
    let board = changed.clone();
    observations
        .fold_own_changes(
            read,
            Some(actor.entity_ref()),
            oneiron::claim::CallerLocality::OnDevice,
            &mut changed,
            16,
        )
        .map_err(|error| mcp_engine_error("run session refresh failed", error))?;
    Ok((observations, changed, board))
}

/// [`delivered`] for a pumped run's board connection.
pub(super) async fn run_delivered(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    changed: &ChangedLine,
    keyframe: bool,
    epoch: u64,
) {
    let mut reads = run_read_set(server, actor, connection).await;
    let superseded = server
        .mcp_registry
        .lock()
        .await
        .streams_mut()
        .carrier_epoch(connection)
        .is_some_and(|carrier| carrier > epoch);
    if superseded {
        return;
    }
    if keyframe {
        reads.keyframe_committed(changed);
    } else {
        reads.acknowledge(changed);
    }
}
