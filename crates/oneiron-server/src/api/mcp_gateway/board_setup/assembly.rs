//! An MCP connection's Context Board: its keyframe, sections, pins, readers, worlds and packs.
//! `mcp_current_board` and `mcp_visible_pack_inventory` are its call surface.
//! The board_setup root defines `McpBoardState` and `McpBoardHooks`.

use super::*;

/// Reads the current board for one connector and fences it to a STATE epoch.
///
/// The epoch is minted by the registry from a hash of the rendered state, not
/// from a clock: a call a minute later over identical state gets the SAME
/// epoch, and a mutation a millisecond later gets the next one. The registry
/// RETAINS that snapshot, so a later `describe`/`self.focus.refresh` fences
/// against the exact snapshot setup returned.
pub(in crate::api::mcp_gateway) async fn mcp_current_board(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<McpBoardState, McpGatewayError> {
    let (observations, changes, board) = super::board_observations::state(server, actor).await?;
    let mut rows = Vec::new();
    let pins = mcp_hook_pins(server, actor)?;
    let (mut sections, omissions, hooks) = mcp_board_sections(server, actor, &pins, &mut rows)?;
    rows.extend(crate::device_local::changed_line_rows(&changes));
    rows.extend(crate::device_local::changed_line_rows(&board));
    sections.push(
        oneiron::context_board::SkillsSection::project_with_learning(
            &[],
            &observations,
            &server.vault,
            Some(actor.actor_ref),
        )
        .map_err(|error| mcp_engine_error("board skills failed", error))?
        .board_section()
        .map_err(mcp_board_frame_error)?,
    );
    let scope_label = crate::mcp::mcp_effective_scope_label(&actor.scope);
    let mut state_rows = mcp_board_state_rows(&sections);
    // Own outcomes and connector changes are deliveries, not board state:
    // the epoch hashes the line before they were fitted in, so acknowledging
    // one never makes the epoch just returned stale.
    state_rows.extend(board.render());
    let state_hash = crate::mcp::mcp_board_state_hash(&scope_label, &state_rows);
    let epoch = {
        let mut registry = server.mcp_registry.lock().await;
        registry.board_snapshot_epoch(&actor.stream_connection, state_hash)
    };
    let packs = mcp_visible_pack_inventory(server, actor)?;
    super::board_observations::read_set(server, actor)
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

/// The session a connector's board names to its hook blocks: the one its
/// request names (`x-oneiron-session`), or none, which reaches only blocks
/// addressed to no session. A connection names no branch.
pub(super) fn mcp_hook_recipient(actor: &McpCallContext) -> &str {
    actor.off_record_session.as_deref().unwrap_or_default()
}

/// The hook blocks that reach this connector's board, each kept to the refs
/// its registered scope admits, so a narrowed connector's board pins nothing
/// outside its world and facet.
pub(super) fn mcp_hook_pins(
    server: &SyncServer,
    actor: &McpCallContext,
) -> Result<Vec<oneiron::context_board::HookPin>, McpGatewayError> {
    let mut pins = server
        .vault
        .board_hook_pins(mcp_hook_recipient(actor), None)
        .map_err(|error| mcp_engine_error("board hook blocks failed", error))?;
    if pins.is_empty() {
        return Ok(pins);
    }
    let read = mcp_scoped_read(&server.vault, actor)?;
    for pin in &mut pins {
        let mut refs = Vec::with_capacity(pin.refs.len());
        for id in std::mem::take(&mut pin.refs) {
            if mcp_scope_admits_row(&server.vault, actor, &read, &id.to_hex())? {
                refs.push(id);
            }
        }
        pin.refs = refs;
    }
    pins.retain(|pin| !pin.refs.is_empty());
    Ok(pins)
}

/// A keyframe's MEMORIES, which runs no retrieval: the policy manifest's pins
/// and the rows its hook blocks pin, read as the HTTP board reads them
/// ([`crate::api::context_board::board_pins_projection`]) under this
/// credential, in the bound `room` its own read admitted, else with no room
/// (FIX 1051). The credential's read is not narrowed to its world or facet,
/// so a narrowed or record-restricted connector reads no manifest pin, and
/// only the hook rows [`mcp_hook_pins`] kept. `None` when no pin reaches a
/// row.
pub(super) fn mcp_pinned_memories(
    server: &SyncServer,
    actor: &McpResolvedActor,
    hook_pins: &[oneiron::context_board::HookPin],
    room: Option<oneiron::EntityId>,
) -> Result<Option<crate::api::context_board::BoardPins>, McpGatewayError> {
    let pins = crate::api::context_board::BoardPinSources {
        refs: &[],
        manifest: !actor.scope.is_narrow() && actor.has_unrestricted_record_scope(),
        hooks: hook_pins,
    };
    let read = mcp_scoped_read(&server.vault, actor)?;
    let auth = actor
        .auth
        .as_ref()
        .expect("a scoped read holds the connector's proof");
    crate::api::context_board::board_pins_projection(&server.vault, auth, read, room, &pins)
        .map_err(super::mcp_api_error)
}

/// ROOM (FIX 1051): the room the caller's authenticated request binds, its
/// room turn, read fresh through the caller's own facade handle as the HTTP
/// board reads one. No room turn, or a room the caller cannot read, renders
/// no ROOM: omitted silently, never an ambient room guessed in its place.
pub(super) fn mcp_bound_room(
    server: &SyncServer,
    actor: &McpCallContext,
) -> Option<oneiron::context_board::RoomSection> {
    let room = actor.room_turn?;
    let memory = crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality());
    match memory.rooms_render_hosted(room, None) {
        Ok(section) => Some(section),
        Err(error) => {
            tracing::debug!(code = %error.code, "mcp board room omitted");
            None
        }
    }
}

/// SCRATCHPAD (FIX 2340): the live pad of the session the caller's
/// authenticated request binds (`x-oneiron-session`), read as the agent
/// itself, as the HTTP board serves an agent's. An unbound request, a caller
/// that is not an agent, or a session with no live pad renders none.
pub(super) fn mcp_scratchpad_section(
    server: &SyncServer,
    actor: &McpCallContext,
    served: &mut Vec<oneiron::EntityId>,
) -> Option<oneiron::context_board::BoardSection> {
    let session = actor.off_record_session.as_deref()?;
    if actor.actor_class != oneiron::EdgeActorClass::Agent {
        return None;
    }
    let memory = crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality());
    match memory.scratchpad_board_section(session) {
        Ok(Some(board)) => {
            served.push(board.pad);
            Some(board.section)
        }
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(code = %error.code, "mcp board scratchpad omitted");
            None
        }
    }
}

/// Every board row, in section order: the exact material the snapshot epoch is
/// the epoch OF.
pub(super) fn mcp_board_state_rows(
    sections: &[oneiron::context_board::BoardSection],
) -> Vec<String> {
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
/// TASKS comes from the rows of the engine's own gated `describe` facade,
/// NARROWED to this credential's world/facet ceiling before they ever reach
/// the renderer, so a board a narrow connector reads is never the actor-wide
/// board. The pinned VERBS section restates the generated grammar
/// as board state. `pins` tag the TASKS rows they name and pin their other
/// rows into MEMORIES, beside the policy manifest's pins.
pub(super) fn mcp_board_sections(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    pins: &[oneiron::context_board::HookPin],
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
    let rows = crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality())
    .describe_rows()
    .map_err(mcp_facade_error)?;
    // PEOPLE (ARCH-0067): every person by handle, name inline (a connector
    // holds no cached roster), and the actor's own live children on the task
    // they realize. Children are actor-wide, bound to no world or facet, so a
    // narrowed connector reads none of them.
    let mut rows = rows;
    let children = if actor.scope.is_narrow() || !actor.has_unrestricted_record_scope() {
        Vec::new()
    } else {
        oneiron::context_board::child_states_for_actor(&server.vault, actor.actor_ref)
            .map_err(|error| mcp_engine_error("board children failed", error))?
    };
    let people = {
        let read = mcp_scoped_read(&server.vault, actor)?;
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
    let (mut tasks, scope_omitted) = mcp_scoped_tasks_section(server, actor, rows, pins, served)?;
    let mut hooks = McpBoardHooks {
        blocks: tasks.tag_hook_pins(pins),
        receipt: None,
        memories: std::collections::BTreeMap::new(),
    };
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
    let worlds_section = mcp_worlds_section(server, actor, served)?;
    let tasks_section =
        oneiron::context_board::assemble_tasks_section(&tasks, mcp_fanout_rows(server, actor)?)
            .map_err(mcp_board_frame_error)?;
    let mut sections = vec![verb_section, worlds_section];
    let room = mcp_bound_room(server, actor);
    if let Some(memories) =
        mcp_pinned_memories(server, actor, pins, room.as_ref().map(|room| room.room))?
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
    if let Some(room) = &room {
        served.push(room.room);
        served.extend(
            room.claims
                .iter()
                .filter_map(|claim| oneiron::EntityId::from_hex(&claim.claim_ref).ok()),
        );
        sections.push(
            room.board_section(&oneiron::context_board::PeopleView::new(&people, &resident))
                .map_err(mcp_board_frame_error)?,
        );
    }
    sections.extend(mcp_scratchpad_section(server, actor, served));
    let packs = mcp_visible_pack_inventory(server, actor)?;
    let rows: Vec<String> = packs
        .iter()
        .map(|(name, hash)| {
            format!(
                "{}: {}",
                oneiron::context_board::quoted_leaf(name),
                oneiron::context_board::quoted_leaf(hash)
            )
        })
        .collect();
    sections.push(
        oneiron::context_board::BoardSection::new(
            "PACKS".to_owned(),
            Vec::new(),
            rows,
            vec![format!("count: {}", packs.len())],
            oneiron::context_board::SectionPolicy {
                pinned: false,
                shed_rank: Some(oneiron::context_board::ShedRank::PluginSections),
            },
        )
        .map_err(mcp_board_frame_error)?,
    );
    sections.extend(mcp_pack_sections(server, actor, served)?);
    sections.extend(mcp_readers_section(
        server,
        actor,
        &oneiron::context_board::PeopleView::new(&people, &resident),
    ));
    Ok((sections, omissions, hooks))
}

/// The fan-out launches that wait on an approver, as TASKS lead rows
/// (OF-393): the agent's own and those whose bound project lead or board role
/// it holds live, or every one for an owner's connector. They are actor-wide,
/// as its children are, so a world/facet-narrowed or record-restricted
/// connector reads none.
pub(super) fn mcp_fanout_rows(
    server: &SyncServer,
    actor: &McpResolvedActor,
) -> Result<Vec<String>, McpGatewayError> {
    if actor.scope.is_narrow() || !actor.has_unrestricted_record_scope() {
        return Ok(Vec::new());
    }
    let launches = crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality())
    .pending_task_fanout_launches()
    .map_err(mcp_facade_error)?;
    Ok(oneiron::context_board::fanout_action_rows(&launches))
}

/// A connector's READERS: its agent's own reader list, which is actor-wide
/// as its children are, so a world/facet-narrowed or record-restricted
/// connector reads none of it.
pub(super) fn mcp_readers_section(
    server: &SyncServer,
    actor: &McpResolvedActor,
    people: &oneiron::context_board::PeopleView<'_>,
) -> Option<oneiron::context_board::BoardSection> {
    if actor.scope.is_narrow() || !actor.has_unrestricted_record_scope() {
        return None;
    }
    let memory = crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality());
    agent_readers_section(&memory, actor.actor_class, people)
}

/// The READERS section of an agent's board (ARCH-0067; ARCH-0032
/// #private-reads: the agent sees who may read its diary and sealed pads,
/// and who did), from the engine's one producer the HTTP board serves too
/// ([`oneiron::memory::Memory::board_readers_section`]). Any other actor
/// class gets none. A list that does not read is logged by its code and
/// left off, so it never costs the agent its board.
pub(super) fn agent_readers_section(
    memory: &oneiron::memory::Memory<'_>,
    class: oneiron::EdgeActorClass,
    people: &oneiron::context_board::PeopleView<'_>,
) -> Option<oneiron::context_board::BoardSection> {
    if class != oneiron::EdgeActorClass::Agent {
        return None;
    }
    match memory.board_readers_section(people) {
        Ok(section) => Some(section),
        Err(error) => {
            tracing::warn!(code = %error.code, "board readers section left off");
            None
        }
    }
}

/// The board's WORLDS: the tiers the actor's planner reads, over the WORLD
/// bodies this credential's read admits; a world-narrowed connector sees its
/// own world alone.
pub(super) fn mcp_worlds_section(
    server: &SyncServer,
    actor: &McpResolvedActor,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<oneiron::context_board::BoardSection, McpGatewayError> {
    let read = mcp_scoped_read(&server.vault, actor)?;
    let authority = server
        .vault
        .board_world_authority(Some(actor.actor_ref), None)
        .map_err(|error| mcp_engine_error("board world authority failed", error))?;
    let allowed: Vec<oneiron::EntityId> = authority
        .allowed_set
        .worlds()
        .iter()
        .copied()
        .filter(|world| actor.scope.world_ref.is_none_or(|scoped| scoped == *world))
        .collect();
    let presences = oneiron::context_board::WorldPresence::read_admitted(&read, &allowed)
        .map_err(|error| mcp_engine_error("board worlds failed", error))?;
    served.extend(presences.iter().map(|world| world.id));
    oneiron::context_board::WorldsSection::project(&presences, &authority, MCP_BOARD_WORLDS_CAP)
        .board_section()
        .map_err(mcp_board_frame_error)
}

pub(in crate::api::mcp_gateway) fn mcp_visible_pack_inventory(
    server: &SyncServer,
    actor: &McpResolvedActor,
) -> Result<Vec<(String, String)>, McpGatewayError> {
    let read = mcp_scoped_read(&server.vault, actor)?;
    let mut visible = Vec::new();
    for pack in server
        .vault
        .installed_packs()
        .map_err(|error| mcp_engine_error("pack inventory failed", error))?
    {
        if mcp_scope_admits_row(&server.vault, actor, &read, &pack.source_id)? {
            visible.push((pack.pack_name, pack.content_hash));
        }
    }
    Ok(visible)
}

pub(super) fn mcp_pack_sections(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<Vec<oneiron::context_board::BoardSection>, McpGatewayError> {
    use oneiron::context_board::{
        PluginSectionRegistry, PluginSectionRow, PluginSectionSnapshot, SectionId,
        render_pack_sections,
    };
    let registry = PluginSectionRegistry::rebuild(&server.vault, &McpPackSectionBindings).map_err(
        |error| McpGatewayError::new(-32603, "board_render_failed", format!("{error:?}")),
    )?;
    let read = mcp_scoped_read(&server.vault, actor)?;
    let mut snapshots = Vec::new();
    let mut visible = Vec::new();
    for entry in registry.pack_sections() {
        if !mcp_scope_admits_row(&server.vault, actor, &read, &entry.source_id)? {
            continue;
        }
        let mut rows = Vec::new();
        for id in server
            .vault
            .pack_section_claim_ids(&entry.pack_name, &entry.section.section_id)
            .map_err(|error| mcp_engine_error("pack section claim inventory failed", error))?
        {
            if !mcp_scope_admits_row(&server.vault, actor, &read, &id.to_hex())? {
                continue;
            }
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

/// True when the registered scope covers the row this board id names.
///
/// A row whose id is not an entity id cannot be proven in scope, so a narrowed
/// credential does not see it: this fails closed.
pub(in crate::api::mcp_gateway) fn mcp_scope_admits_row(
    vault: &oneiron::Vault,
    actor: &McpResolvedActor,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    row_id: &str,
) -> Result<bool, McpGatewayError> {
    let Ok(id) = oneiron::EntityId::from_hex(row_id) else {
        return Ok(false);
    };
    let readable = mcp_credential_reads(vault, actor, &id)
        .map_err(|error| mcp_engine_error("mcp board row admission failed", error))?;
    Ok(readable && mcp_scope_covers_entity(scoped_read, &actor.scope, &id)?)
}
