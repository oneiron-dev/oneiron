//! Session-clock read observations and turn-local riders for MCP boards.

use super::{McpGatewayError, mcp_board_frame_error, mcp_engine_error, mcp_scoped_read};
use crate::{mcp::McpResolvedActor, server::SyncServer};
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardLegend, BoardStreamFrame, CapabilityHit,
    ChangedLine, DeltaRow, FrameKind, SessionReadSet, ShedRank, SkillsSection,
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
        actor.scope.world_ref,
        actor.scope.facet_ref,
    ))
    .expect("string tuple serializes");
    let mut store = server.memories_cursors.lock().await;
    store.current(key.clone(), &actor.stream_connection.0);
    MutexGuard::map(store, |store| store.read_sets.entry(key).or_default())
}

pub(super) async fn state(
    server: &SyncServer,
    actor: &McpResolvedActor,
) -> Result<(SessionReadSet, ChangedLine), McpGatewayError> {
    let observations = read_set(server, actor).await.clone();
    let read = mcp_scoped_read(&server.vault, actor)?;
    let changed = observations
        .refresh(&read, 16)
        .map_err(|error| mcp_engine_error("mcp session refresh failed", error))?;
    Ok((observations, changed))
}

/// The empty queue is checked before reading session state or rendering. This
/// function neither creates a frame nor enqueues an event.
pub(super) async fn ride(
    server: &SyncServer,
    actor: &McpResolvedActor,
    frame: Option<BoardStreamFrame>,
    hits: &[CapabilityHit],
) -> Result<Option<BoardStreamFrame>, McpGatewayError> {
    let Some(mut frame) = frame else {
        return Ok(None);
    };
    if let FrameKind::Delta(rows) = &mut frame.kind {
        rows.retain(|row| !matches!(row.key.as_str(), "changed" | "SKILLS" | "AGENTS:cand"));
    }
    let (observations, changed) = state(server, actor).await?;
    let frame = changed
        .ride(Some(frame))
        .expect("rider preserves an existing frame");
    Ok(Some(ride_capabilities(frame, hits, &observations)?))
}

fn ride_capabilities(
    mut frame: BoardStreamFrame,
    hits: &[CapabilityHit],
    observations: &SessionReadSet,
) -> Result<BoardStreamFrame, McpGatewayError> {
    let skills = SkillsSection::project(hits, observations);
    let agents = oneiron::context_board::render_agents_section(&[], &[]).with_candidates(hits);
    let tasks = oneiron::context_board::TasksSection {
        rows: Vec::new(),
        overflow: None,
    };
    let [_, agent_section] = oneiron::context_board::assemble_task_agent_sections(&tasks, &agents)
        .map_err(mcp_board_frame_error)?;
    let sections = [
        skills.board_section().map_err(mcp_board_frame_error)?,
        agent_section,
    ];
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
    let candidate_rows: Vec<_> = if render.shed.applied.contains(&ShedRank::CapabilityDiscovery) {
        Vec::new()
    } else {
        agents.rows.iter().map(|row| row.line.clone()).collect()
    };
    match &mut frame.kind {
        FrameKind::Delta(rows) => {
            // Whole-lane replacement clears prior-turn discoveries, including
            // on an unrelated call whose hit slice is empty.
            rows.push(DeltaRow {
                key: "SKILLS".to_owned(),
                line: skill_rows.join(" "),
            });
            rows.push(DeltaRow {
                key: "AGENTS:cand".to_owned(),
                line: candidate_rows.join(" "),
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
                if !candidate_rows.is_empty() {
                    lines.push("AGENTS".to_owned());
                    lines.extend(candidate_rows);
                }
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
