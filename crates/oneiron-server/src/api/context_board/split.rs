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
