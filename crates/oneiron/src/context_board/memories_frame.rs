//! Connects typed MEMORIES projections to the shared board frame and shed ladder.
use super::frame::{BoardFrameError, BoardSection, SectionPolicy, ShedRank};
use super::memories::{MemoriesSection, MemoryRow, MemoryTier};
use std::collections::BTreeMap;

/// One MEMORIES row as the board renders it. A foreign row shows no snippet.
/// A hook block's row carries its hook's tag, as a quoted leaf.
pub(super) fn memory_row_text(row: &MemoryRow, foreign: bool) -> String {
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
    if !foreign && let Some(snippet) = &row.snippet {
        text.push(' ');
        text.push_str(snippet);
    }
    text
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
            let text = memory_row_text(row, foreign);
            if row.tier == MemoryTier::Pinned {
                pinned.push(text);
            } else {
                details.push(text);
            }
        }
        let mut board = BoardSection::new(
            format!("MEMORIES world={}", world.unwrap_or("unscoped")),
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
