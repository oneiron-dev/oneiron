//! Connects typed MEMORIES projections to the shared board frame and shed ladder.
use super::frame::{BoardFrameError, BoardSection, SectionPolicy, ShedRank};
use super::memories::{MemoriesSection, MemoryTier};
use std::collections::BTreeMap;

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
            if !foreign && let Some(snippet) = &row.snippet {
                text.push(' ');
                text.push_str(snippet);
            }
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
                changes: None,
            },
            budget,
        )
    }
}
