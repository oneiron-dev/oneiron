//! A code-mode run's Context Board: the run's lane, its pins, its sections and its packs.
//! `run_current_board` is its call surface.
//! The board_setup root defines `McpBoardState`; `oneiron::context_board` owns the board records.

use super::*;

/// A pumped run's CURRENT board (OF-533): [`mcp_current_board`] for the run's
/// agent, which holds no MCP credential. It binds no room turn, so it renders
/// no ROOM (FIX 1051). Its SCRATCHPAD is the live pad of `session`, the
/// session the run's host origin binds (FIX 2340): a pumped run's host door
/// binds none, so its board renders no pad, and a live run's board doors
/// bind the session the attached agent's own request names. Its rows are
/// read under the agent's own lane on this device, its epoch and STREAM
/// state are keyed on the run's own connection, and nothing is narrowed: the
/// agent reads its board as a vault-wide connector of its own would:
/// MEMORIES pins the policy manifest's rows its lane reads (FIX 2646). Its
/// hook rows are those of the blocks [`run_hook_pins`] keeps.
pub(crate) async fn run_current_board(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    session: Option<&str>,
) -> Result<McpBoardState, McpGatewayError> {
    let read = run_lane(server, actor)?;
    let packs = run_visible_pack_inventory(server, &read)?;
    let (observations, changes, board) =
        super::board_observations::run_state(server, actor, connection, &read, &packs).await?;
    let mut rows = Vec::new();
    let pins = run_hook_pins(server, &read)?;
    let (mut sections, omissions, hooks) =
        run_board_sections(server, actor, &read, &packs, &pins, session, &mut rows)?;
    rows.extend(crate::device_local::changed_line_rows(&changes));
    rows.extend(crate::device_local::changed_line_rows(&board));
    sections.push(
        oneiron::context_board::SkillsSection::project_with_learning(
            &[],
            &observations,
            &server.vault,
            Some(actor.entity_ref()),
        )
        .map_err(|error| mcp_engine_error("board skills failed", error))?
        .board_section()
        .map_err(mcp_board_frame_error)?,
    );
    let scope_label =
        crate::mcp::mcp_effective_scope_label(&crate::mcp::McpConnectorScope::vault_wide());
    let mut state_rows = mcp_board_state_rows(&sections);
    state_rows.extend(board.render());
    let state_hash = crate::mcp::mcp_board_state_hash(&scope_label, &state_rows);
    // The connection's published events are read under the run's own key,
    // as its host door's calls are, bound again on every attach and refresh
    // (FIX 4888). A key that cannot be built binds none.
    let reader = server
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .at(oneiron::claim::CallerLocality::OnDevice)
        .read_key()
        .ok();
    let epoch = {
        let mut registry = server.mcp_registry.lock().await;
        registry.attach_run_board(connection, &actor.entity_ref().to_hex());
        registry.bind_run_reader(connection, reader);
        registry.board_snapshot_epoch(connection, state_hash)
    };
    super::board_observations::run_read_set(server, actor, connection)
        .await
        .observe_pack_inventory(&packs);
    Ok(McpBoardState {
        sections,
        scope_label,
        epoch,
        changes,
        rows,
        scope_omitted: omissions.scope_omitted,
        window_truncated: omissions.window_truncated,
        source_exhausted: omissions.source_exhausted,
        hooks,
    })
}

/// The hook blocks that reach a pumped run's board: those addressed to no
/// session, since the run's host door names none, each kept to the refs the
/// agent's own lane reads (OF-579).
pub(super) fn run_hook_pins(
    server: &SyncServer,
    read: &oneiron::claim::ScopedRead<'_>,
) -> Result<Vec<oneiron::context_board::HookPin>, McpGatewayError> {
    let mut pins = server
        .vault
        .board_hook_pins("", None)
        .map_err(|error| mcp_engine_error("board hook blocks failed", error))?;
    for pin in &mut pins {
        let mut refs = Vec::with_capacity(pin.refs.len());
        for id in std::mem::take(&mut pin.refs) {
            if read
                .is_entity_readable(&id)
                .map_err(|error| mcp_engine_error("run board hook admission failed", error))?
            {
                refs.push(id);
            }
        }
        pin.refs = refs;
    }
    pins.retain(|pin| !pin.refs.is_empty());
    Ok(pins)
}

/// The agent's own read lane, on this device.
pub(super) fn run_lane(
    server: &SyncServer,
    actor: oneiron::WriteActor,
) -> Result<oneiron::claim::ScopedRead<'_>, McpGatewayError> {
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| McpGatewayError::new(-32603, "engine_error", "run actor key invalid"))?;
    Ok(server
        .vault
        .scoped_read(key.at(oneiron::claim::CallerLocality::OnDevice)))
}

/// The installed packs whose source the agent's lane reads.
pub(super) fn run_visible_pack_inventory(
    server: &SyncServer,
    read: &oneiron::claim::ScopedRead<'_>,
) -> Result<Vec<(String, String)>, McpGatewayError> {
    let mut visible = Vec::new();
    for pack in server
        .vault
        .installed_packs()
        .map_err(|error| mcp_engine_error("pack inventory failed", error))?
    {
        if run_lane_reads(read, &pack.source_id)? {
            visible.push((pack.pack_name, pack.content_hash));
        }
    }
    Ok(visible)
}

/// Whether the agent's lane reads the row a board id names; a row whose id
/// is no entity id is not shown.
pub(super) fn run_lane_reads(
    read: &oneiron::claim::ScopedRead<'_>,
    row_id: &str,
) -> Result<bool, McpGatewayError> {
    let Ok(id) = oneiron::EntityId::from_hex(row_id) else {
        return Ok(false);
    };
    read.is_entity_readable(&id)
        .map_err(|error| mcp_engine_error("run board row admission failed", error))
}

/// [`mcp_board_sections`] for a pumped run's agent: VERBS, WORLDS, the
/// MEMORIES the policy manifest and its hook `pins` reach, TASKS with its
/// people and children, the SCRATCHPAD of the run's bound `session`, PACKS
/// and the packs' own sections. `pins` tag the TASKS rows they name and pin
/// their other rows into MEMORIES, as on a connector's board.
pub(super) fn run_board_sections(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    read: &oneiron::claim::ScopedRead<'_>,
    packs: &[(String, String)],
    pins: &[oneiron::context_board::HookPin],
    session: Option<&str>,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<
    (
        Vec<oneiron::context_board::BoardSection>,
        McpBoardOmissions,
        McpBoardHooks,
    ),
    McpGatewayError,
> {
    let verbs = crate::mcp::generated_verb_tools().map_err(mcp_surface_construction_error)?;
    let verb_section = crate::mcp::mcp_verb_board_section(&verbs).map_err(mcp_board_frame_error)?;
    let mut rows = server
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .at(oneiron::claim::CallerLocality::OnDevice)
        .describe_rows()
        .map_err(mcp_facade_error)?;
    let children =
        oneiron::context_board::child_states_for_actor(&server.vault, actor.entity_ref())
            .map_err(|error| mcp_engine_error("board children failed", error))?;
    let people = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let mut people = oneiron::context_board::People::load(&server.vault, now, &mut |person| {
            read.is_entity_readable(&person)
        })
        .map_err(|error| mcp_engine_error("board people failed", error))?;
        people
            .disclose_names(&server.vault, read.actor_key())
            .map_err(|error| mcp_engine_error("board people disclosure failed", error))?;
        people
    };
    let resident = std::collections::BTreeSet::new();
    rows.attach_people(
        &oneiron::context_board::PeopleView::new(&people, &resident),
        &children,
    );
    served.extend(
        rows.intents
            .iter()
            .map(|intent| intent.id.as_str())
            .chain(rows.bare_jobs.iter().map(|job| job.id.as_str()))
            .filter_map(|id| oneiron::EntityId::from_hex(id).ok()),
    );
    let mut tasks = rows.render();
    tasks.pin_hook_tasks(&rows.intents, pins);
    let mut hooks = McpBoardHooks {
        blocks: tasks.tag_hook_pins(pins),
        receipt: None,
        memories: std::collections::BTreeMap::new(),
    };
    let omissions = McpBoardOmissions {
        scope_omitted: 0,
        window_truncated: tasks
            .overflow
            .map_or(0, |overflow| overflow.known_omitted_rows),
        source_exhausted: tasks
            .overflow
            .is_none_or(|overflow| overflow.source_exhausted),
    };
    let worlds_section = {
        let authority = server
            .vault
            .board_world_authority(Some(actor.entity_ref()), None)
            .map_err(|error| mcp_engine_error("board world authority failed", error))?;
        let allowed: Vec<oneiron::EntityId> =
            authority.allowed_set.worlds().iter().copied().collect();
        let presences = oneiron::context_board::WorldPresence::read_admitted(read, &allowed)
            .map_err(|error| mcp_engine_error("board worlds failed", error))?;
        served.extend(presences.iter().map(|world| world.id));
        oneiron::context_board::WorldsSection::project(&presences, &authority, MCP_BOARD_WORLDS_CAP)
            .board_section()
            .map_err(mcp_board_frame_error)?
    };
    // The fan-out launches that wait on an approver (OF-393): the agent's own
    // and those whose bound project lead or board role it holds live.
    let launches = server
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .at(oneiron::claim::CallerLocality::OnDevice)
        .pending_task_fanout_launches()
        .map_err(mcp_facade_error)?;
    let tasks_section = oneiron::context_board::assemble_tasks_section(
        &tasks,
        oneiron::context_board::fanout_action_rows(&launches),
    )
    .map_err(mcp_board_frame_error)?;
    let mut sections = vec![verb_section, worlds_section];
    if let Some(memories) =
        crate::api::context_board::lane_pins_projection(read, pins).map_err(super::mcp_api_error)?
    {
        hooks.memories = memories.section.hook_shares(pins);
        served.extend_from_slice(memories.receipt.delivered());
        sections.extend(
            oneiron::context_board::assemble_memories_sections(&memories.section)
                .map_err(mcp_board_frame_error)?,
        );
        hooks.receipt = Some(memories.receipt);
    }
    sections.push(tasks_section);
    sections.extend(run_scratchpad_section(server, actor, session, served));
    sections.push(
        oneiron::context_board::BoardSection::new(
            "PACKS".to_owned(),
            Vec::new(),
            packs
                .iter()
                .map(|(name, hash)| {
                    format!(
                        "{}: {}",
                        oneiron::context_board::quoted_leaf(name),
                        oneiron::context_board::quoted_leaf(hash)
                    )
                })
                .collect(),
            vec![format!("count: {}", packs.len())],
            oneiron::context_board::SectionPolicy {
                pinned: false,
                shed_rank: Some(oneiron::context_board::ShedRank::PluginSections),
            },
        )
        .map_err(mcp_board_frame_error)?,
    );
    sections.extend(run_pack_sections(server, read, served)?);
    sections.extend(agent_readers_section(
        &server
            .vault
            .memory(actor.entity_ref(), actor.actor_class())
            .at(oneiron::claim::CallerLocality::OnDevice),
        actor.actor_class(),
        &oneiron::context_board::PeopleView::new(&people, &resident),
    ));
    Ok((sections, omissions, hooks))
}

/// SCRATCHPAD (FIX 2340): the live pad of `session`, the session the run's
/// host origin binds, read as the run's agent itself on this device, as the
/// MCP and HTTP boards serve an agent's. No bound session, an actor that is
/// not an agent, or a session with no live pad renders none: no pad is made
/// and no session is picked in its place.
fn run_scratchpad_section(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    session: Option<&str>,
    served: &mut Vec<oneiron::EntityId>,
) -> Option<oneiron::context_board::BoardSection> {
    let session = session?;
    if actor.actor_class() != oneiron::EdgeActorClass::Agent {
        return None;
    }
    let memory = server
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .at(oneiron::claim::CallerLocality::OnDevice);
    match memory.scratchpad_board_section(session) {
        Ok(Some(board)) => {
            served.push(board.pad);
            Some(board.section)
        }
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(code = %error.code, "run board scratchpad omitted");
            None
        }
    }
}

/// [`mcp_pack_sections`] under the agent's own lane.
pub(super) fn run_pack_sections(
    server: &Arc<SyncServer>,
    read: &oneiron::claim::ScopedRead<'_>,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<Vec<oneiron::context_board::BoardSection>, McpGatewayError> {
    use oneiron::context_board::{
        PluginSectionRegistry, PluginSectionRow, PluginSectionSnapshot, SectionId,
        render_pack_sections,
    };
    let registry = PluginSectionRegistry::rebuild(&server.vault, &McpPackSectionBindings).map_err(
        |error| McpGatewayError::new(-32603, "board_render_failed", format!("{error:?}")),
    )?;
    let mut snapshots = Vec::new();
    let mut visible = Vec::new();
    for entry in registry.pack_sections() {
        if !run_lane_reads(read, &entry.source_id)? {
            continue;
        }
        let mut rows = Vec::new();
        for id in server
            .vault
            .pack_section_claim_ids(&entry.pack_name, &entry.section.section_id)
            .map_err(|error| mcp_engine_error("pack section claim inventory failed", error))?
        {
            let Some((kind, _, body)) = read
                .get_entity_parts_with_receipt(&id, None)
                .map_err(|error| mcp_engine_error("pack section claim read failed", error))?
                .value
            else {
                continue;
            };
            if kind != oneiron::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let claim = oneiron::claim::decode_claim_body(&body, false)
                .map_err(|error| mcp_engine_error("pack section claim decode failed", error))?;
            if claim.lifecycle != oneiron::claim::ClaimLifecycleStatus::Active
                || !matches!(
                    claim.approval,
                    oneiron::claim::ClaimApprovalStatus::Approved
                        | oneiron::claim::ClaimApprovalStatus::Auto
                )
                || claim.stale
            {
                continue;
            }
            served.push(id);
            rows.push(PluginSectionRow {
                row_id: id.to_hex(),
                cells: vec![
                    claim.predicate,
                    format!("{:?}", claim.value).chars().take(256).collect(),
                ],
            });
        }
        snapshots.push(PluginSectionSnapshot {
            section_id: SectionId(entry.section.section_id.clone()),
            rows,
        });
        visible.push(entry.section.section_id.clone());
    }
    let rendered = render_pack_sections(&registry, &snapshots).map_err(|error| {
        McpGatewayError::new(-32603, "board_render_failed", format!("{error:?}"))
    })?;
    Ok(registry
        .pack_sections()
        .zip(rendered)
        .filter_map(|(entry, section)| {
            visible
                .contains(&entry.section.section_id)
                .then_some(section)
        })
        .collect())
}
