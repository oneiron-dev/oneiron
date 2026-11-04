//! The one board frame a hydration renders (ARCH-0067 §1): WORLDS, MEMORIES,
//! TASKS, SKILLS, ROOM and INBOX, each from its engine producer, in canon
//! order, under one budget. Every row is read under the caller's own read,
//! and every person is named by handle (PEOPLE ruling).

use super::super::core_engine_error;
use super::super::parse_entity_id_param;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::context_board::BoardFrameError;
use oneiron::context_board::BoardSection;
use oneiron::context_board::CapabilityHit;
use oneiron::context_board::PeopleView;
use oneiron::context_board::SessionReadSet;
use oneiron::context_board::quoted_leaf;
use oneiron::memory::MemoryError;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use utoipa::ToSchema;

/// WORLDS rows past this many collapse into the section's additive overflow.
const BOARD_WORLDS_CAP: usize = 16;
/// Most INBOX rows one board renders; the lens orders them by impact.
const BOARD_INBOX_CAP: usize = 16;

/// Names the room whose ROOM section this board renders.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ContextBoardRoomControls {
    /// Hex Channel Conversation id the caller sits in.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    conversation_id: String,
    /// The `room_page.next_cursor` a previous board answered, to render the
    /// room's next page of members and rules; absent for its first page.
    #[serde(default)]
    cursor: Option<String>,
}

/// Where the ROOM rows this board rendered sit in the room's whole stream
/// (FIX 9746, 9747): its members by actor id, then its rules by claim id.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardRoomPage {
    /// Members on the room's whole roster.
    roster_total: u64,
    /// Rules the caller reads in the room, on every page together.
    rules_total: u64,
    /// Pass as `room.cursor` for the room's next page; absent once `end`.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    /// No member or rule of the room is past this page.
    end: bool,
}

/// Names the project whose view rides TASKS.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ContextBoardProjectControls {
    /// Hex PROJECT entity id the caller can read.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    project_id: String,
}

/// How the board's render budget settled, so a shed is legible.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardRenderBudget {
    /// The cap the board rendered under: the caller's limit, never above the
    /// harness default.
    budget_tok: usize,
    /// Tokens the rendered board holds.
    rendered_tok: usize,
    /// True when the never-shed floor alone exceeds the cap.
    floor_exceeds_cap: bool,
    /// The shed ranks applied, in order.
    applied_shed: Vec<String>,
}

impl ContextBoardRenderBudget {
    pub(super) fn of(render: &oneiron::context_board::BoardRender) -> Self {
        Self {
            budget_tok: render.metadata.budget_tok,
            rendered_tok: render.metadata.rendered_tok,
            floor_exceeds_cap: render.metadata.floor_exceeds_cap,
            applied_shed: render
                .shed
                .applied
                .iter()
                .map(|rank| rank.as_str().to_owned())
                .collect(),
        }
    }
}

/// The room a board renders and where it was named.
struct RoomTarget {
    id: EntityId,
    /// Named in `room`: a room the caller does not sit in is refused. A room
    /// that only rides the retrieval request renders when the caller sits
    /// in it, and is otherwise the retrieval's audience alone.
    explicit: bool,
    /// Where in the room's stream the page starts.
    cursor: Option<String>,
}

/// What a hydration asks of its board beyond retrieval, checked before any
/// work runs.
pub(super) struct BoardTargets {
    actor: Option<(EntityId, oneiron::EdgeActorClass)>,
    room: Option<RoomTarget>,
    /// The SESSION whose present participants ROOM reads its host among,
    /// when the board's session id names one.
    session: Option<EntityId>,
    project: Option<EntityId>,
}

impl BoardTargets {
    pub(super) fn actor(&self) -> Option<EntityId> {
        self.actor.map(|(actor, _)| actor)
    }

    /// The room the board renders, wherever it was named.
    pub(super) fn room_id(&self) -> Option<EntityId> {
        self.room.as_ref().map(|room| room.id)
    }
}

/// The caller's entity principal and declared class, when it has both.
fn board_actor(auth: &CoreAuth) -> Option<(EntityId, oneiron::EdgeActorClass)> {
    let actor = EntityId::from_hex(auth.principal_ref()?).ok()?;
    let class = match auth.actor_class()? {
        "human" => oneiron::EdgeActorClass::Human,
        "agent" => oneiron::EdgeActorClass::Agent,
        "system" => oneiron::EdgeActorClass::System,
        _ => return None,
    };
    Some((actor, class))
}

pub(super) fn board_targets(
    auth: &CoreAuth,
    room: Option<&ContextBoardRoomControls>,
    retrieval_room: Option<&str>,
    session: Option<&str>,
    project: Option<&ContextBoardProjectControls>,
) -> Result<BoardTargets, ApiError> {
    let actor = board_actor(auth);
    let room = match room {
        Some(room) => {
            let id = parse_entity_id_param(&room.conversation_id, "room.conversation_id")?;
            if actor.is_none() {
                return Err(ApiError::bad_request(
                    "ROOM needs an entity principal with a declared actor class",
                    Some("room"),
                ));
            }
            Some(RoomTarget {
                id,
                explicit: true,
                cursor: room.cursor.clone(),
            })
        }
        None => retrieval_room
            .filter(|_| actor.is_some())
            .and_then(|id| EntityId::from_hex(id).ok())
            .map(|id| RoomTarget {
                id,
                explicit: false,
                cursor: None,
            }),
    };
    let project = project
        .map(|project| parse_entity_id_param(&project.project_id, "project.project_id"))
        .transpose()?;
    Ok(BoardTargets {
        actor,
        room,
        session: session.and_then(|session| EntityId::from_hex(session).ok()),
        project,
    })
}

/// One assembled board: its sections in canon order, the typed rows the
/// response carries beside the render, and the ids it delivered.
pub(super) struct BoardParts {
    pub(super) authority: oneiron::pipeline::ResolvedWorldAuthority,
    pub(super) scope: String,
    pub(super) sections: Vec<BoardSection>,
    /// The caller's `you:` forks line, rendered under the legend.
    pub(super) you: Option<String>,
    pub(super) worlds: Vec<String>,
    pub(super) tasks: Vec<String>,
    pub(super) room: Option<Vec<String>>,
    /// Where the ROOM rows sit in the room's whole stream.
    pub(super) room_page: Option<ContextBoardRoomPage>,
    pub(super) skills: Vec<String>,
    /// The task intents, worlds, room, room rules and project the board
    /// named: rows a keyed replay re-admits.
    pub(super) named: Vec<EntityId>,
    /// The hook blocks whose task rows TASKS tagged.
    pub(super) hook_blocks: std::collections::BTreeSet<EntityId>,
    /// The rows each INBOX row kept rests on (FIX 8145): every identity of
    /// the caller's that admitted it, and each row it names that the read
    /// read. A keyed replay re-admits each; none is a board document.
    pub(super) inbox: Vec<EntityId>,
}

/// Assembles every section the board renders for this caller.
pub(super) fn board_parts(
    server: &SyncServer,
    auth: &CoreAuth,
    read: &oneiron::claim::ScopedRead<'_>,
    targets: &BoardTargets,
    memories: Option<&oneiron::MemoriesSection>,
    hits: &[CapabilityHit],
    reads: &SessionReadSet,
    people: &PeopleView<'_>,
    hook_pins: &[oneiron::context_board::HookPin],
) -> Result<BoardParts, ApiError> {
    let vault: &oneiron::Vault = &server.vault;
    let mut named = Vec::new();

    // WORLDS: the tiers the caller's planner reads, over the WORLD bodies
    // its read admits.
    let mut authority = vault
        .board_world_authority(targets.actor(), None)
        .map_err(|error| core_engine_error("board world authority failed", error))?;
    // A room board actually reads inside its members' met world set
    // (ARCH-0067 §8), the ceiling the pack's audience applies: the active
    // tier the board renders and records is that met set, never the
    // caller's wider one. A room that only rides the retrieval request
    // and does not resolve bounds nothing here, as its ROOM section does.
    if let Some(room) = &targets.room {
        let met = vault
            .room_audience_members_under(read, room.id, targets.actor())
            .and_then(|members| vault.room_world_set(&members));
        match met {
            Ok(Some(room_worlds)) => {
                authority.active_set = authority.active_set.meet(&room_worlds);
            }
            Ok(None) => {}
            Err(error) if room.explicit => {
                return Err(core_engine_error("board room worlds failed", error));
            }
            Err(_) => {}
        }
    }
    let allowed: Vec<EntityId> = authority.allowed_set.worlds().iter().copied().collect();
    let presences = oneiron::context_board::WorldPresence::read_admitted(read, &allowed)
        .map_err(|error| core_engine_error("board worlds failed", error))?;
    named.extend(presences.iter().map(|world| world.id));
    let worlds =
        oneiron::context_board::WorldsSection::project(&presences, &authority, BOARD_WORLDS_CAP)
            .board_section()
            .map_err(board_frame_error)?;
    let scope = oneiron::context_board::world_set_scope(&authority.active_set);

    let memory = targets.actor.map(|(actor, class)| {
        crate::api::credential_memory(vault, Some(auth), actor, class).at(auth.locality())
    });

    // ROOM, read fresh through the caller's own facade handle, with its host
    // among the board session's present participants: one page of the
    // room's rows, its next page behind `room_page.next_cursor`.
    let room = match (&targets.room, &memory) {
        (Some(target), Some(memory)) => {
            match memory.rooms_render_page_hosted(
                target.id,
                targets.session,
                target.cursor.as_deref(),
            ) {
                Ok(room) => Some(room),
                Err(error) if !target.explicit && caller_fault(&error) => None,
                Err(error) => {
                    return Err(board_memory_error(
                        "board room failed",
                        "room.conversation_id",
                        error,
                    ));
                }
            }
        }
        _ => None,
    };
    let room_section = room
        .as_ref()
        .map(|room| room.board_section(people))
        .transpose()
        .map_err(board_frame_error)?;
    let room_page = room.as_ref().map(|page| ContextBoardRoomPage {
        roster_total: page.roster_total,
        rules_total: page.rules_total,
        next_cursor: page.next_cursor.clone(),
        end: page.end,
    });
    let room = room.map(|page| page.section);
    if let Some(room) = &room {
        named.push(room.room);
        named.extend(
            room.claims
                .iter()
                .filter_map(|claim| EntityId::from_hex(&claim.claim_ref).ok()),
        );
    }

    // TASKS: each task's `who` and `fits:` by handle, the caller's live
    // children on the task they realize, and the project view as its first
    // detail row. The `you:` line rides the frame, under the legend.
    let (mut tasks, you) = match &memory {
        Some(memory) => {
            let mut rows = readable_task_rows(auth, read, memory)?;
            let (children, forks) = match targets.actor() {
                Some(actor) => (
                    oneiron::context_board::child_states_for_actor(vault, actor)
                        .map_err(|error| core_engine_error("board children failed", error))?,
                    oneiron::context_board::fork_states_for_actor(vault, actor)
                        .map_err(|error| core_engine_error("board forks failed", error))?,
                ),
                None => (Vec::new(), Vec::new()),
            };
            // A child joins only under the reader and destination its TASK
            // rows passed (FIX 9755): one whose TASK they withheld never
            // renders as a bare row. A child with no TASK is an attempt no
            // entity read proves, kept exactly where the bare jobs are.
            rows.attach_people_admitted(people, &children, |child| {
                match child.task_ref.as_deref().map(EntityId::from_hex) {
                    Some(Ok(task)) => {
                        oneiron::context_board::TasksSectionRows::task_admitted(memory, read, task)
                    }
                    _ => Ok(auth.verified_slip().is_none()),
                }
            })
            .map_err(|error| core_engine_error("board children failed", error))?;
            let you = oneiron::context_board::render_you_line(&forks, &rows.intents);
            let mut tasks = rows.render();
            tasks.pin_hook_tasks(&rows.intents, hook_pins);
            (tasks, you)
        }
        None => (
            oneiron::context_board::TasksSection {
                rows: Vec::new(),
                overflow: None,
            },
            None,
        ),
    };
    let hook_blocks = tasks.tag_hook_pins(hook_pins);
    named.extend(
        tasks
            .rows
            .iter()
            .filter(|row| row.is_intent)
            .filter_map(|row| EntityId::from_hex(&row.id).ok()),
    );
    let project =
        match (targets.project, &room) {
            (Some(project), _) => Some(project_row(server, read, project)?.ok_or_else(|| {
                ApiError::bad_request("unknown project", Some("project.project_id"))
            })?),
            // An ordinary room's body is not a project room's and reads as an
            // error here: it names no project.
            (None, Some(room)) => match vault
                .project_room(room.room)
                .ok()
                .flatten()
                .and_then(|room| EntityId::from_hex(&room.project_id).ok())
            {
                Some(project) => project_row(server, read, project)?,
                None => None,
            },
            (None, None) => None,
        };
    let mut lead = Vec::new();
    if let Some((project, row)) = project {
        named.push(project);
        lead.push(row);
    }
    // The fan-out launches that wait on an approver (OF-393): the reader's
    // own, those whose bound lead or board role it holds, or every one for
    // the owner. They are actor-wide, so a narrowed or record-restricted
    // credential reads none; this mirrors board_setup.rs `mcp_fanout_rows`.
    if let Some(memory) = memory
        .as_ref()
        .filter(|_| auth.require_unrestricted_record_scope().is_ok())
    {
        let launches = memory
            .pending_task_fanout_launches()
            .map_err(|error| board_memory_error("board fan-outs failed", "tasks", error))?;
        lead.extend(oneiron::context_board::fanout_action_rows(&launches));
    }
    let tasks_section =
        oneiron::context_board::assemble_tasks_section(&tasks, lead).map_err(board_frame_error)?;

    // SKILLS, with the learning view on each found skill row and the agent
    // definitions the capability channel found.
    let skills = oneiron::context_board::SkillsSection::project_with_learning(
        hits,
        reads,
        vault,
        targets.actor(),
    )
    .map_err(|error| core_engine_error("board skills failed", error))?;
    let skills_section = skills.board_section().map_err(board_frame_error)?;

    // INBOX: the caller's own slice of the inbox lens, kept to rows that
    // reach it through an identity its read admits. Hidden when empty.
    let mut inbox_sources = Vec::new();
    let inbox = match targets.actor() {
        Some(actor) => {
            let mut rows = Vec::new();
            let slice = vault
                .agent_inbox_board_slice(actor, BOARD_INBOX_CAP, vault.now_recorded_at())
                .map_err(|error| core_engine_error("board inbox failed", error))?;
            let later = slice.later;
            for (mut item, state) in slice.rows {
                let mut admitting = Vec::new();
                for participant in item
                    .participants
                    .iter()
                    .filter(|row| row.actor_ref == actor)
                {
                    // A row no identity carries (a digest, a comm widen ask)
                    // is admitted by the record it names (FIX 1261, 3901).
                    let Some(source) = participant.identity_ref.or_else(|| {
                        item.payload_ref
                            .as_deref()
                            .and_then(|record| EntityId::from_hex(record).ok())
                    }) else {
                        continue;
                    };
                    if read
                        .is_ref_readable(&source)
                        .map_err(|error| core_engine_error("board inbox failed", error))?
                    {
                        admitting.push(source);
                    }
                }
                if !admitting.is_empty() {
                    // FIX 9745: the sender renders only while the caller's
                    // read reads it; otherwise the row names no sender.
                    if let Some(sender) = item.sender {
                        if read
                            .is_ref_readable(&sender)
                            .map_err(|error| core_engine_error("board inbox failed", error))?
                        {
                            inbox_sources.push(sender);
                        } else {
                            item.sender = None;
                        }
                    }
                    inbox_sources.extend(admitting);
                    inbox_sources.extend(inbox_named_sources(read, &item, actor)?);
                    rows.push((item, state));
                }
            }
            oneiron::context_board::assemble_inbox_section(actor, &rows, later, people)
                .map_err(board_frame_error)?
        }
        None => None,
    };

    let mut sections = vec![worlds.clone()];
    if let Some(memories) = memories {
        sections.extend(
            oneiron::context_board::assemble_memories_sections(memories)
                .map_err(board_frame_error)?,
        );
    }
    sections.push(tasks_section.clone());
    sections.push(skills_section);
    sections.extend(room_section.clone());
    sections.extend(inbox);
    Ok(BoardParts {
        authority,
        scope,
        sections,
        you,
        worlds: worlds.detail_rows().to_vec(),
        tasks: tasks_section.detail_rows().to_vec(),
        room: room_section.map(|room| room.pinned_rows().to_vec()),
        room_page,
        skills: std::iter::once(skills.loaded).chain(skills.found).collect(),
        named,
        hook_blocks,
        inbox: inbox_sources,
    })
}

/// The rows INBOX row `item` names beside the identity that admitted it,
/// each kept only while `read` reads it, in one snapshot: its concern's
/// subject, its review's reader and every other participant (FIX 8145). A
/// keyed replay of the board re-admits each, so a row one of them no longer
/// reaches is not released again.
fn inbox_named_sources(
    read: &oneiron::claim::ScopedRead<'_>,
    item: &oneiron::agent_inbox_lens::AgentInboxLensItem,
    actor: EntityId,
) -> Result<Vec<EntityId>, ApiError> {
    let mut named: Vec<EntityId> = item
        .concern
        .iter()
        .map(|concern| concern.subject)
        .chain(item.diary_review.iter().map(|review| review.reader))
        .chain(
            item.participants
                .iter()
                .map(|participant| participant.actor_ref)
                .filter(|other| *other != actor),
        )
        .collect();
    named.sort_unstable();
    named.dedup();
    let sets: Vec<_> = named.iter().map(|id| vec![*id]).collect();
    let readable = read
        .refs_readable_each(&sets)
        .map_err(|error| core_engine_error("board inbox failed", error))?;
    Ok(named
        .into_iter()
        .zip(readable)
        .filter_map(|(id, readable)| readable.then_some(id))
        .collect())
}

/// The caller's TASKS rows, kept as its read reads them: an intent row only
/// while the caller's read reads its TASK, a bare job only for a caller with
/// no credential to narrow it (as the facade's `describe` does).
fn readable_task_rows(
    auth: &CoreAuth,
    read: &oneiron::claim::ScopedRead<'_>,
    memory: &oneiron::memory::Memory<'_>,
) -> Result<oneiron::context_board::TasksSectionRows, ApiError> {
    let mut rows = memory
        .describe_rows()
        .map_err(|error| board_memory_error("board tasks failed", "tasks", error))?;
    let mut intents = Vec::with_capacity(rows.intents.len());
    for intent in std::mem::take(&mut rows.intents) {
        let readable = match EntityId::from_hex(&intent.id) {
            Ok(id) => read
                .is_entity_readable(&id)
                .map_err(|error| core_engine_error("board tasks failed", error))?,
            Err(_) => auth.verified_slip().is_none(),
        };
        if readable {
            intents.push(intent);
        }
    }
    rows.intents = intents;
    if auth.verified_slip().is_some() {
        rows.bare_jobs.clear();
    }
    Ok(rows)
}

/// The vault's people as the caller's read admits them, and the persons the
/// caller's cached prefix roster holds: those an agent run's emitted prefix
/// made resident, or, before a run's prefix emits, those its epoch-boundary
/// selection will. A caller with no run reads every name inline.
pub(super) async fn board_people(
    server: &SyncServer,
    auth: &CoreAuth,
    read: &oneiron::claim::ScopedRead<'_>,
    session_id: Option<&str>,
) -> Result<(oneiron::context_board::People, BTreeSet<EntityId>), ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let mut people = oneiron::context_board::People::load(&server.vault, now, &mut |person| {
        read.is_entity_readable(&person)
    })
    .map_err(|error| core_engine_error("board people failed", error))?;
    // Each `about` is the stored line of the highest band the reader reads.
    let applied = read
        .read_receipt(None, 0)
        .map_err(|error| core_engine_error("board people failed", error))?
        .applied;
    let ceiling = (!applied.deny_all).then_some(applied.max_sensitivity_band);
    people
        .set_about(&mut |person| server.vault.person_about(person, ceiling))
        .map_err(|error| core_engine_error("board people failed", error))?;
    people
        .disclose_names(&server.vault, read.actor_key())
        .map_err(|error| core_engine_error("board people disclosure failed", error))?;
    let run_key = auth
        .principal_ref()
        .filter(|_| auth.actor_class() == Some("agent"))
        .and_then(|actor| EntityId::from_hex(actor).ok())
        .zip(session_id.map(str::to_owned));
    let resident = match run_key {
        Some(key) => match server.self_brief_sessions.lock().await.get(&key) {
            Some(run) if run.emitted_epoch == Some(run.epoch) => {
                run.render.resident_people().clone()
            }
            Some(run) => {
                let mut pinned = vec![run.state.self_ref, run.state.principal];
                pinned.extend(run.state.cast.iter().copied());
                people.residence(&pinned).resident
            }
            None => BTreeSet::new(),
        },
        None => BTreeSet::new(),
    };
    Ok((people, resident))
}

/// The project view row, when the caller's read reads the project and its
/// fold shows it. Goal and why come from the project's intake goal when it
/// has one, else from the project row; every authored value is a quoted leaf.
fn project_row(
    server: &SyncServer,
    read: &oneiron::claim::ScopedRead<'_>,
    project: EntityId,
) -> Result<Option<(EntityId, String)>, ApiError> {
    if !read
        .is_entity_readable(&project)
        .map_err(|error| core_engine_error("board project failed", error))?
    {
        return Ok(None);
    }
    let Some(record) = server
        .vault
        .project(project)
        .map_err(|error| core_engine_error("board project failed", error))?
    else {
        return Ok(None);
    };
    let (goal, why) = match server
        .vault
        .project_intake_goal(project)
        .map_err(|error| core_engine_error("board project failed", error))?
    {
        Some(intake) => (Some(intake.goal), Some(intake.why)),
        None => (record.goal, record.why),
    };
    let leader = EntityId::from_hex(&record.leader)
        .map_or_else(|_| quoted_leaf(&record.leader), |leader| leader.to_hex());
    let mut row = format!("project {} leader={leader}", project.to_hex());
    if let Some(goal) = goal.filter(|goal| !goal.is_empty()) {
        row.push_str(&format!(" goal={}", quoted_leaf(&goal)));
    }
    if let Some(why) = why.filter(|why| !why.is_empty()) {
        row.push_str(&format!(" why={}", quoted_leaf(&why)));
    }
    Ok(Some((project, row)))
}

/// A refusal the caller's own request earned: a room it does not sit in, an
/// unknown id, a wrong root.
fn caller_fault(error: &MemoryError) -> bool {
    matches!(
        error.code.as_str(),
        oneiron::memory::MEMORY_CODE_BAD_REQUEST
            | oneiron::memory::MEMORY_CODE_NOT_FOUND
            | oneiron::memory::MEMORY_CODE_WRONG_ROOT
    )
}

fn board_memory_error(context: &'static str, field: &str, error: MemoryError) -> ApiError {
    if caller_fault(&error) {
        return ApiError::bad_request(error.message, Some(field));
    }
    tracing::error!(code = %error.code, error = %error.message, "{context}");
    ApiError::internal_server_error(context)
}

pub(super) fn board_frame_error(error: BoardFrameError) -> ApiError {
    ApiError::bad_request(
        format!("context board render failed: {error}"),
        Some("board"),
    )
}

/// What one rendered board section was read from (DESIGN-V2 R2): its
/// rendered name, the fence it renders behind, and the memory rows (at the
/// revision each was served at, where the read pinned one) and skills (at
/// the version the session loaded, where it did) it shows. It rides beside
/// the board's text and never changes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoardSectionSource {
    pub(crate) name: String,
    pub(crate) fence: oneiron::llm::TrustFence,
    pub(crate) dependencies: Vec<oneiron::llm::SegmentLocator>,
}

/// The rendered board's sections, in the order the frame renders them:
/// every first-party section in frame order inside the authoritative
/// wrapper, then each foreign world's MEMORIES section after it, as guest
/// evidence. A section's dependencies are its own rows; the SKILLS section
/// names every skill the session loaded and every capability hit.
pub(super) fn section_sources(
    sections: &[BoardSection],
    memories: Option<&oneiron::MemoriesSection>,
    hits: &[CapabilityHit],
    reads: &SessionReadSet,
) -> Vec<BoardSectionSource> {
    use oneiron::llm::{SegmentLocator, SourceRevision, TrustFence};
    let mut first_party = Vec::new();
    let mut guest = Vec::new();
    for section in sections {
        let name = section.name().to_owned();
        let world = name.strip_prefix("MEMORIES world=");
        let foreign = world
            .and_then(|world| EntityId::from_hex(world).ok())
            .is_some_and(oneiron::entity_id::is_foreign_world_id_range);
        let mut dependencies = Vec::new();
        if let (Some(world), Some(memories)) = (world, memories) {
            dependencies.extend(
                memories
                    .rows
                    .iter()
                    .filter(|row| row.world.as_deref().unwrap_or("unscoped") == world)
                    .filter_map(|row| {
                        Some(SegmentLocator::Memory {
                            id: EntityId::from_hex(&row.id).ok()?,
                            revision: row
                                .source_revision
                                .map(|revision| SourceRevision(revision.0)),
                        })
                    }),
            );
        }
        if name == "SKILLS" {
            let loaded: Vec<(EntityId, String)> = reads
                .loaded_skills()
                .filter_map(|(id, version)| {
                    Some((EntityId::from_hex(id).ok()?, version.to_owned()))
                })
                .collect();
            dependencies.extend(loaded.iter().map(|(id, version)| SegmentLocator::Skill {
                id: *id,
                version: Some(version.clone()),
            }));
            dependencies.extend(
                hits.iter()
                    .filter(|hit| !loaded.iter().any(|(id, _)| *id == hit.id))
                    .map(|hit| SegmentLocator::Skill {
                        id: hit.id,
                        version: None,
                    }),
            );
        }
        let source = BoardSectionSource {
            name,
            fence: if foreign {
                TrustFence::Guest
            } else {
                TrustFence::Authoritative
            },
            dependencies,
        };
        if foreign {
            guest.push(source);
        } else {
            first_party.push(source);
        }
    }
    first_party.extend(guest);
    first_party
}
