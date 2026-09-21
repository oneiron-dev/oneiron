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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::ClaimSource;
    use crate::context_board::memories::{MemoriesBudget, MemoryRow, MemorySlot, MemorySource};
    use crate::context_board::{BoardBlockHeader, BoardBudgetRequest};
    use proptest::prelude::*;

    fn row(seed: u8, source: ClaimSource, world: Option<String>, snippet: String) -> MemoryRow {
        MemoryRow {
            row_index: 0,
            slot: MemorySlot::Claims,
            source: MemorySource::Result,
            id: crate::test_util::entity(seed).to_hex(),
            short_id: format!("cl{seed}"),
            content_hash: "ab".into(),
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            asset_ref: None,
            score: 1.0,
            claim_source: Some(source),
            world,
            tier: MemoryTier::Snippet,
            snippet: Some(snippet),
        }
    }
    fn section(rows: Vec<MemoryRow>) -> MemoriesSection {
        MemoriesSection {
            version: "v4".into(),
            budget: MemoriesBudget::default(),
            rows,
            companion: None,
            disclosure: None,
        }
    }
    fn render(section: &MemoriesSection) -> String {
        section
            .render_board(
                &BoardBlockHeader {
                    epoch: 1,
                    scope: "all".into(),
                },
                BoardBudgetRequest {
                    harness_default_tok: 4096,
                    caller_limit_tok: None,
                    explicit_override_tok: None,
                },
            )
            .unwrap()
            .text
    }

    #[test]
    fn labels_and_foreign_fence_are_engine_owned() {
        let guest = crate::test_util::entity(0xF1).to_hex();
        let text = render(&section(vec![
            row(1, ClaimSource::UserStated, None, "home".into()),
            row(2, ClaimSource::Generated, None, "guess".into()),
            row(
                3,
                ClaimSource::ToolOutput,
                Some(guest.clone()),
                "never a guest snippet".into(),
            ),
        ]));
        assert!(text.contains("cl1:ab trust=user_stated tier=snippet home"));
        assert!(text.contains("cl2:ab trust=generated tier=snippet guess"));
        assert!(text.contains("cl3:ab trust=tool_output tier=index-only"));
        assert!(!text.contains("never a guest snippet"));
        assert!(text.contains(&format!(
            "</memory>\n<evidence role=\"guest\" host=\"{guest}\" consolidatable=\"false\">"
        )));
        let labels = [
            ClaimSource::UserStated,
            ClaimSource::Observed,
            ClaimSource::Inferred,
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ]
        .map(ClaimSource::as_str);
        assert_eq!(
            labels,
            [
                "user_stated",
                "observed",
                "inferred",
                "imported",
                "tool_output",
                "generated"
            ]
        );
    }

    proptest! {
        #[test]
        fn no_claim_value_changes_board_structure(value in ".{0,300}") {
            let text = render(&section(vec![row(1, ClaimSource::Imported, None, value)]));
            prop_assert_eq!(text.lines().count(), 5);
            prop_assert_eq!(text.matches("<memory ").count(), 1);
            prop_assert_eq!(text.matches("</memory>").count(), 1);
            prop_assert_eq!(text.matches("<evidence ").count(), 0);
        }
    }
}
