//! A live chat turn's board in two parts (I1 = C, ARCH-0067 turn order:
//! committed history, state-only board, new user message, recalled
//! memories and found skills, opener). The state part holds every section
//! that reads no new message: WORLDS, TASKS, the session's loaded skills,
//! ROOM, INBOX, an agent run's SCRATCHPAD and an agent's READERS, beside
//! the `you:` and changed lines. The query part holds what the message
//! read: every MEMORIES section and the skills its capability channel
//! found. One hydration, one budget and one shed ladder serve both; the
//! public board and `ai.reply` render the one frame as before.
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardLegend, BoardPart, BoardSection,
    CapabilityHit, ChangedLine, SessionReadSet, SplitBoardRender, render_split_board_block,
    split_skills_section,
};
use oneiron::llm::SegmentLocator;

use super::board::{BoardSectionSource, board_frame_error, section_sources};
use crate::error::ApiError;

/// The section names the query part holds whole.
const MEMORIES_SECTION_PREFIX: &str = "MEMORIES world=";
/// The section split between the two parts.
const SKILLS_SECTION: &str = "SKILLS";

/// One chat turn's board as its two parts, and what each part's sections
/// were read from, in the order each part renders them.
#[derive(Debug)]
pub(crate) struct ChatSplit {
    pub(super) render: SplitBoardRender,
    pub(super) state_sources: Vec<BoardSectionSource>,
    pub(super) query_sources: Vec<BoardSectionSource>,
}

/// What one board frame holds, for its split render.
pub(super) struct SplitFrame<'a> {
    pub(super) header: &'a BoardBlockHeader,
    pub(super) sections: &'a [BoardSection],
    pub(super) you: Option<&'a str>,
    pub(super) changes: &'a ChangedLine,
    pub(super) budget: BoardBudgetRequest,
}

/// What the board's sections were read from.
pub(super) struct SplitInputs<'a> {
    pub(super) memories: Option<&'a oneiron::MemoriesSection>,
    pub(super) hits: &'a [CapabilityHit],
    pub(super) reads: &'a SessionReadSet,
}

/// `frame` rendered as its two parts, each section in the part it reads
/// for, in frame order.
pub(super) fn split_board(
    frame: &SplitFrame<'_>,
    inputs: &SplitInputs<'_>,
) -> Result<ChatSplit, ApiError> {
    let mut sections = Vec::with_capacity(frame.sections.len() + 1);
    let mut parts = Vec::with_capacity(frame.sections.len() + 1);
    for section in frame.sections {
        if section.name() == SKILLS_SECTION {
            let (loaded, found) = split_skills_section(section).map_err(board_frame_error)?;
            sections.push(loaded);
            parts.push(BoardPart::State);
            if let Some(found) = found {
                sections.push(found);
                parts.push(BoardPart::Query);
            }
        } else {
            sections.push(section.clone());
            parts.push(if section.name().starts_with(MEMORIES_SECTION_PREFIX) {
                BoardPart::Query
            } else {
                BoardPart::State
            });
        }
    }
    let render = render_split_board_block(
        &BoardFrame {
            header: frame.header,
            legend: &BoardLegend::canonical(),
            sections: &sections,
            you: frame.you,
            changes: Some(frame.changes),
        },
        &parts,
        frame.budget,
    );
    let of_part = |part: BoardPart| {
        let held: Vec<BoardSection> = sections
            .iter()
            .zip(&parts)
            .filter(|(_, rides)| **rides == part)
            .map(|(section, _)| section.clone())
            .collect();
        part_sources(&held, part, inputs)
    };
    Ok(ChatSplit {
        state_sources: of_part(BoardPart::State),
        query_sources: of_part(BoardPart::Query),
        render,
    })
}

/// What each of one part's `sections` was read from, in the order the part
/// renders them: as [`section_sources`] names them, its SKILLS section
/// naming only what that part shows. The state part's loaded line names
/// each skill the session loaded, at its version; the query part's found
/// rows name each capability hit the session has not loaded.
fn part_sources(
    sections: &[BoardSection],
    part: BoardPart,
    inputs: &SplitInputs<'_>,
) -> Vec<BoardSectionSource> {
    let mut sources = section_sources(sections, inputs.memories, inputs.hits, inputs.reads);
    for source in sources
        .iter_mut()
        .filter(|source| source.name == SKILLS_SECTION)
    {
        source.dependencies.retain(|locator| match locator {
            SegmentLocator::Skill { version, .. } => {
                version.is_some() == (part == BoardPart::State)
            }
            _ => true,
        });
    }
    sources
}

/// The state part a live chat turn of `auth` in `conversation` would render
/// now (I1 = C): the read the turn's own board makes
/// ([`super::chat_turn_board`]) less its retrieval, and less everything a
/// served board records: no cursor moves, no changed line is acknowledged,
/// no hook block is delivered, no row is observed. A candidate for the next
/// turn's prepared tail, never served as a board; the turn renders its own,
/// and only an identical beginning of its tokens reuses this one. `None`
/// when the read is refused or fails.
pub(crate) async fn next_state_part(
    server: &std::sync::Arc<crate::server::SyncServer>,
    auth: &crate::auth::CoreAuth,
    conversation: Option<oneiron::EntityId>,
) -> Option<String> {
    use oneiron::context_board::PeopleView;
    auth.require(crate::auth::CoreScope::Read).ok()?;
    auth.require_unrestricted_record_scope().ok()?;
    let room = conversation.map(|id| id.to_hex());
    let targets = super::board::board_targets(auth, None, room.as_deref(), None, None).ok()?;
    let (standing, _) = super::standing::standing_prefix(server, auth, None, targets.room_id())
        .await
        .ok()?;
    let caller = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let read = super::super::scoped_read_for_core_auth(&server.vault, auth).ok()?;
    let hook_pins = server.vault.board_hook_pins("", None).ok()?;
    let mut installed_packs: Vec<(String, String)> = Vec::new();
    for row in server.vault.installed_packs().ok()? {
        let Ok(source) = oneiron::EntityId::from_hex(&row.source_id) else {
            continue;
        };
        if read.is_entity_readable(&source).ok()? {
            installed_packs.push((row.pack_name, row.content_hash));
        }
    }
    let session_id = super::resolved_session_id(server, caller, None)
        .await
        .ok()?;
    let own = auth
        .principal_ref()
        .and_then(|reference| oneiron::EntityId::from_hex(reference).ok());
    // The changed line as the next board would read it, from a copy of the
    // session's read set: the copy is never acknowledged or observed.
    let reads = super::session_read_set(server, caller, session_id.as_deref())
        .await
        .ok()?
        .as_deref()
        .cloned()
        .unwrap_or_default();
    let mut changed = reads.refresh(&read, 16).ok()?;
    let installs = reads.pack_changes(
        &installed_packs,
        16_usize.saturating_sub(changed.rows.len()),
    );
    changed.rows.extend(installs.rows);
    changed.overflow += installs.overflow;
    reads
        .fold_own_changes(&read, own, auth.locality(), &mut changed, 16)
        .ok()?;
    let (people, resident) = super::board::board_people(server, auth, &read, None)
        .await
        .ok()?;
    let mut parts = super::board::board_parts(
        server,
        auth,
        &read,
        &targets,
        None,
        &[],
        &reads,
        &PeopleView::new(&people, &resident),
        &hook_pins,
    )
    .ok()?;
    if let Some((section, _)) =
        super::served_readers(server, auth, &PeopleView::new(&people, &resident))
    {
        parts.sections.push(section);
    }
    let split = split_board(
        &SplitFrame {
            header: &BoardBlockHeader {
                // The epoch rides the query part alone.
                epoch: 0,
                scope: parts.scope.clone(),
            },
            sections: &parts.sections,
            you: parts.you.as_deref(),
            changes: &changed,
            budget: BoardBudgetRequest {
                harness_default_tok: standing
                    .as_ref()
                    .map_or(crate::mcp::MCP_BOARD_BUDGET_TOK, |prefix| {
                        prefix.other_context_tokens
                    }),
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        },
        &SplitInputs {
            memories: None,
            hits: &[],
            reads: &reads,
        },
    )
    .ok()?;
    Some(split.render.state)
}
