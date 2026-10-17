//! Board state, setup grammar, and page preflight.

use super::device_release::{mcp_carrier_releases, mcp_release_result, mcp_snapshot_releases};
use super::stream_reads::{mcp_live_task_lines, mcp_own_task_lines};
use super::{
    McpCallContext, McpGatewayError, mcp_actor_result, mcp_credential_reads, mcp_engine_error,
    mcp_facade_error, mcp_scope_covers_entity, mcp_scoped_read, mcp_scoped_tasks_section,
    mcp_text_content,
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

/// The most WORLDS rows one keyframe renders, as the HTTP board's.
const MCP_BOARD_WORLDS_CAP: usize = 16;

/// How one result relates to this connector's queued STREAM state.
#[derive(Debug)]
pub(super) enum McpCarrierPolicy {
    /// An ordinary result: drain AT MOST ONE pending frame beside it.
    Drain,
    /// The response's capability channel, never retained as session state.
    DrainWithCapabilities(Vec<oneiron::context_board::CapabilityHit>),
    /// This result carries its OWN freshly minted keyframe. `Some` is a frame
    /// the producer has not enqueued yet (setup mints one outside the
    /// registry); `None` is one the producer already enqueued (the engine's own
    /// `self.focus.refresh` does). Either way the queue behind it is EXPLICITLY
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
pub(super) async fn mcp_endpoint_result(
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
    pub(super) changes: oneiron::context_board::ChangedLine,
    /// Every row the sections and the changed line were derived from: what a
    /// retained page of this board is judged by again at release.
    pub(super) rows: Vec<oneiron::EntityId>,
    /// TASKS rows the credential's REQUESTED SCOPE withheld inside its own
    /// world and facet (`mcp_scoped_tasks_section`).
    scope_omitted: usize,
    /// TASKS rows the engine's own render row cap truncated away. A page
    /// WINDOW fact, kept apart from the scope fact above (ONE-1704 repair).
    window_truncated: usize,
    /// False when the producer's own TASK scan stopped at its cap, so the
    /// truncation count above is a lower bound rather than a census.
    source_exhausted: bool,
    /// The hook blocks this board carries, spent only when it goes out.
    pub(super) hooks: McpBoardHooks,
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
/// RETAINS that snapshot, so a later `describe`/`self.focus.refresh` fences
/// against the exact snapshot setup returned.
pub(super) async fn mcp_current_board(
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

/// The hook blocks one rendered board carries (ARCH-0080 §11, OF-579): the
/// blocks whose rows it shows, and the receipt its pinned MEMORIES rows owe.
/// A board rendered for its epoch alone spends neither. Setup's page one, a
/// `self.focus.refresh` and a keyed `describe` record the receipt before
/// their result goes out and spend the blocks once it has; a code-mode
/// board read, and a pumped run's own board row, do both as the answer
/// returns to the run.
#[derive(Default)]
pub(crate) struct McpBoardHooks {
    /// The blocks naming a TASKS row the board shows.
    blocks: std::collections::BTreeSet<oneiron::EntityId>,
    receipt: Option<crate::api::context_board::PinsReceipt>,
    /// Each MEMORIES section the board shows, by its name: its pinned rows
    /// and the blocks naming them.
    memories: std::collections::BTreeMap<String, oneiron::context_board::HookShare>,
}

impl McpBoardHooks {
    /// The share of these hooks a keyed `describe` of section `key` shows:
    /// the TASKS blocks for TASKS, that one world's blocks and the receipt
    /// for its rows for a MEMORIES section, and none for any other.
    pub(super) fn shown_by(mut self, key: &str) -> Self {
        match key.split_once(' ').map_or(key, |(name, _)| name) {
            "TASKS" => Self {
                blocks: self.blocks,
                ..Self::default()
            },
            "MEMORIES" => match self.memories.remove(key) {
                Some(share) => Self {
                    receipt: self.receipt.map(|receipt| receipt.only(&share.rows)),
                    memories: std::iter::once((key.to_owned(), share)).collect(),
                    ..Self::default()
                },
                None => Self::default(),
            },
            _ => Self::default(),
        }
    }

    /// The owner's receipt for what the hook rows disclose under a contact's
    /// standing clearance, recorded before the board goes out, as the HTTP
    /// board records it. A receipt that fails refuses the result.
    pub(super) async fn record_receipt(
        &mut self,
        server: &SyncServer,
    ) -> Result<(), McpGatewayError> {
        match self.receipt.take() {
            Some(receipt) => receipt
                .record(&server.vault)
                .await
                .map_err(super::mcp_api_error),
            None => Ok(()),
        }
    }

    /// Spends one delivery of each block a board that went out carried. A
    /// failed record leaves the block to show again, never to vanish unseen.
    pub(super) fn spend(&self, server: &SyncServer) {
        let mut blocks = self.blocks.clone();
        for share in self.memories.values() {
            blocks.extend(share.blocks.iter().copied());
        }
        if let Err(error) = server.vault.record_board_hook_deliveries(&blocks) {
            tracing::warn!(kind = ?error.kind(), "mcp board hook delivery record failed");
        }
    }
}

/// The session a connector's board names to its hook blocks: the one its
/// request names (`x-oneiron-session`), or none, which reaches only blocks
/// addressed to no session. A connection names no branch.
fn mcp_hook_recipient(actor: &McpCallContext) -> &str {
    actor.off_record_session.as_deref().unwrap_or_default()
}

/// The hook blocks that reach this connector's board, each kept to the refs
/// its registered scope admits, so a narrowed connector's board pins nothing
/// outside its world and facet.
fn mcp_hook_pins(
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
/// credential, with no room. The credential's read is not narrowed to its
/// world or facet, so a narrowed or record-restricted connector reads no
/// manifest pin, and only the hook rows [`mcp_hook_pins`] kept. `None` when no
/// pin reaches a row.
fn mcp_pinned_memories(
    server: &SyncServer,
    actor: &McpResolvedActor,
    hook_pins: &[oneiron::context_board::HookPin],
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
    crate::api::context_board::board_pins_projection(&server.vault, auth, read, None, &pins)
        .map_err(super::mcp_api_error)
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
/// TASKS comes from the rows of the engine's own gated `describe` facade,
/// NARROWED to this credential's world/facet ceiling before they ever reach
/// the renderer, so a board a narrow connector reads is never the actor-wide
/// board. The pinned VERBS section restates the generated grammar
/// as board state. `pins` tag the TASKS rows they name and pin their other
/// rows into MEMORIES, beside the policy manifest's pins.
fn mcp_board_sections(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
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
    let rows = crate::api::credential_memory(
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
        oneiron::context_board::People::load(&server.vault, now, &mut |person| {
            read.is_entity_readable(&person)
        })
        .map_err(|error| mcp_engine_error("board people failed", error))?
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
    let tasks_section = oneiron::context_board::assemble_tasks_section(&tasks, Vec::new())
        .map_err(mcp_board_frame_error)?;
    let mut sections = vec![verb_section, worlds_section];
    if let Some(memories) = mcp_pinned_memories(server, actor, pins)? {
        hooks.memories = memories.section.hook_shares(pins);
        served.extend_from_slice(memories.receipt.delivered());
        sections.extend(
            oneiron::context_board::assemble_memories_sections(&memories.section)
                .map_err(mcp_board_frame_error)?,
        );
        hooks.receipt = Some(memories.receipt);
    }
    sections.push(tasks_section);
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

/// A connector's READERS: its agent's own reader list, which is actor-wide
/// as its children are, so a world/facet-narrowed or record-restricted
/// connector reads none of it.
fn mcp_readers_section(
    server: &SyncServer,
    actor: &McpResolvedActor,
    people: &oneiron::context_board::PeopleView<'_>,
) -> Option<oneiron::context_board::BoardSection> {
    if actor.scope.is_narrow() || !actor.has_unrestricted_record_scope() {
        return None;
    }
    let memory = crate::api::credential_memory(
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
fn agent_readers_section(
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
fn mcp_worlds_section(
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

/// Only the implemented, read-only claim family can enter this host's board.
/// Other typed pack recipes stay installed as source, not invented board data.
struct McpPackSectionBindings;
impl oneiron::context_board::SectionBindingResolver for McpPackSectionBindings {
    fn state_family_exists(&self, family: &oneiron::context_board::StateFamilyRef) -> bool {
        family.family == "claim" && family.version == 1
    }
    fn authority_lane_exists(&self, authority: &oneiron::context_board::AuthorityLaneRef) -> bool {
        authority.0 == "read"
    }
    fn budget_policy_exists(&self, budget: &oneiron::context_board::BudgetPolicyRef) -> bool {
        budget.0 == oneiron::context_board::PLUGIN_SECTION_BUDGET_POLICY_REF
    }
}

pub(super) fn mcp_visible_pack_inventory(
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

fn mcp_pack_sections(
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
pub(super) fn mcp_scope_admits_row(
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

/// What a caller can actually DO next on this endpoint.
///
/// Execution help follows the server's verified host binding, not a static
/// release-wide assumption that no interpreter exists.
fn mcp_setup_help(server: &SyncServer) -> Vec<String> {
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
    if !mcp_snapshot_releases(server, actor, snapshot)? {
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
            rows: board.rows.clone(),
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
    let result = mcp_release_result(server, actor, &snapshot.rows, continued, result);
    // Page one went out: each hook block it carried spends a delivery. A
    // continuation restates that keyframe and spends nothing again.
    if result.is_ok()
        && let Some(hooks) = &hooks
    {
        hooks.spend(server);
    }
    result
}

/// A pumped run's CURRENT board (OF-533): [`mcp_current_board`] for the run's
/// agent, which holds no MCP credential. Its rows are read under the agent's
/// own lane on this device, its epoch and STREAM state are keyed on the
/// run's own connection, and nothing is narrowed: the agent reads its board
/// as a vault-wide connector of its own would. Its hook rows are those of
/// the blocks [`run_hook_pins`] keeps.
pub(crate) async fn run_current_board(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
) -> Result<McpBoardState, McpGatewayError> {
    let read = run_lane(server, actor)?;
    let packs = run_visible_pack_inventory(server, &read)?;
    let (observations, changes, board) =
        super::board_observations::run_state(server, actor, connection, &read, &packs).await?;
    let mut rows = Vec::new();
    let pins = run_hook_pins(server, &read)?;
    let (mut sections, omissions, hooks) =
        run_board_sections(server, actor, &read, &packs, &pins, &mut rows)?;
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
    let epoch = {
        let mut registry = server.mcp_registry.lock().await;
        registry.attach_run_board(connection, &actor.entity_ref().to_hex());
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
fn run_hook_pins(
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
fn run_lane(
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
fn run_visible_pack_inventory(
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
fn run_lane_reads(
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
/// MEMORIES its hook `pins` reach, TASKS with its people and children, PACKS
/// and the packs' own sections. `pins` tag the TASKS rows they name and pin
/// their other rows into MEMORIES, as on a connector's board.
fn run_board_sections(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    read: &oneiron::claim::ScopedRead<'_>,
    packs: &[(String, String)],
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
        oneiron::context_board::People::load(&server.vault, now, &mut |person| {
            read.is_entity_readable(&person)
        })
        .map_err(|error| mcp_engine_error("board people failed", error))?
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
    let tasks_section = oneiron::context_board::assemble_tasks_section(&tasks, Vec::new())
        .map_err(mcp_board_frame_error)?;
    let mut sections = vec![verb_section, worlds_section];
    if let Some(memories) = crate::api::context_board::lane_hook_pins_projection(read, pins)
        .map_err(super::mcp_api_error)?
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

/// [`mcp_pack_sections`] under the agent's own lane.
fn run_pack_sections(
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
