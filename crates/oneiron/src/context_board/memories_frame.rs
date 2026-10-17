//! Connects typed MEMORIES projections to the shared board frame and shed ladder.
use super::frame::{BoardFrameError, BoardSection, MAX_BOARD_ROW_BYTES, SectionPolicy, ShedRank};
use super::memories::{MemoriesSection, MemoryRow, MemoryTier};
use std::collections::BTreeMap;

/// One MEMORIES row as the board renders it. A foreign row shows no snippet.
/// A hook block's row carries its hook's tag, as a quoted leaf.
pub(super) fn memory_row_text(row: &MemoryRow, foreign: bool) -> String {
    let mut text = memory_row_head(row, foreign);
    if !foreign && let Some(snippet) = &row.snippet {
        text.push(' ');
        text.push_str(snippet);
    }
    text
}

/// The bytes a split row's `(part n/m)` tag may take, with its spaces.
const PART_TAG_BYTES: usize = " (part /) ".len() + 2 * 20;

/// [`memory_row_text`] as the board rows it renders in. A row over
/// [`MAX_BOARD_ROW_BYTES`] carries its snippet across numbered rows, the
/// first led by the row's head and each later one by its reference, cut only
/// at character boundaries: a pinned text is never truncated (Rule 5).
fn memory_board_rows(row: &MemoryRow, foreign: bool) -> Vec<String> {
    let text = memory_row_text(row, foreign);
    let snippet = match &row.snippet {
        Some(snippet) if !foreign && text.len() > MAX_BOARD_ROW_BYTES => snippet.as_str(),
        _ => return vec![text],
    };
    let head = memory_row_head(row, foreign);
    let reference = format!("{}:{}", row.short_id, row.content_hash);
    let room = MAX_BOARD_ROW_BYTES
        .saturating_sub(head.len() + PART_TAG_BYTES)
        .max(4);
    let mut parts = Vec::new();
    let mut rest = snippet;
    while !rest.is_empty() {
        let cut = rest.floor_char_boundary(room);
        parts.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    let total = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            let lead = if index == 0 { &head } else { &reference };
            format!("{lead} (part {}/{total}) {part}", index + 1)
        })
        .collect()
}

/// A MEMORIES row's reference, trust, tier and hook tag, before its snippet.
fn memory_row_head(row: &MemoryRow, foreign: bool) -> String {
    let label = row
        .claim_source
        .map_or("unknown", crate::claim::ClaimSource::as_str);
    let tier = match row.tier {
        MemoryTier::Pinned => "PINNED",
        MemoryTier::Snippet if !foreign => "snippet",
        _ => "index-only",
    };
    let mut text = format!(
        "{}:{} trust={} tier={}",
        row.short_id, row.content_hash, label, tier
    );
    if let Some(hook) = &row.hook {
        text.push_str(" hook=");
        text.push_str(&super::quoted_leaf(hook));
    }
    text
}

/// The board section a MEMORIES row in `world` renders in, one per world;
/// a row with no world renders in `unscoped`.
pub(super) fn memories_section_name(world: Option<&str>) -> String {
    format!("MEMORIES world={}", world.unwrap_or("unscoped"))
}

pub fn assemble_memories_sections(
    section: &MemoriesSection,
) -> Result<Vec<BoardSection>, BoardFrameError> {
    let mut worlds: BTreeMap<Option<&str>, Vec<_>> = BTreeMap::new();
    for row in &section.rows {
        worlds.entry(row.world.as_deref()).or_default().push(row);
    }
    let mut sections = Vec::new();
    for (world, rows) in worlds {
        let foreign = world
            .and_then(|id| crate::EntityId::from_hex(id).ok())
            .is_some_and(crate::entity_id::is_foreign_world_id_range);
        let mut pinned = Vec::new();
        let mut details = Vec::new();
        for row in &rows {
            let texts = memory_board_rows(row, foreign);
            if row.tier == MemoryTier::Pinned {
                pinned.extend(texts);
            } else {
                details.extend(texts);
            }
        }
        let mut board = BoardSection::new(
            memories_section_name(world),
            pinned,
            details,
            vec![format!("count: {}", rows.len())],
            SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::MemoriesSnippets),
            },
        )?;
        if foreign {
            board = board.with_foreign_host(world.unwrap_or("unknown"));
        }
        sections.push(board);
    }
    Ok(sections)
}

impl MemoriesSection {
    /// Uses the same cross-section budget and structural fence as the board.
    pub fn render_board(
        &self,
        header: &super::frame::BoardBlockHeader,
        budget: super::frame::BoardBudgetRequest,
    ) -> Result<super::frame::BoardRender, BoardFrameError> {
        let sections = assemble_memories_sections(self)?;
        super::frame::render_board_block(
            &super::frame::BoardFrame {
                header,
                legend: &super::frame::BoardLegend::canonical(),
                sections: &sections,
                you: None,
                changes: None,
            },
            budget,
        )
    }
}
