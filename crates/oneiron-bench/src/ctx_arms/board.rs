//! The engine-board render: the harness, not the strategy, turns typed state
//! into the dynamic tail through the engine's own renderer
//! (`oneiron::context_board::render_board_block`). A strategy hands over
//! typed state only, so no strategy-written text can ride the board.

use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardFrameError, BoardLegend, BoardSection,
    BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF, SectionPolicy, render_board_block,
    section_policy_for_budget_ref,
};

use super::arms::{Grid, snapshot_lines};
use super::window::RefMeta;

/// The render cap for the dynamic tail (the harness default in
/// `BoardBudgetRequest`).
pub(crate) const BOARD_TOK: usize = 2048;

/// Renders a SKETCHPAD section (pinned, never shed) from the typed grid and
/// an OFFLOAD section (plugin policy, sheds to a count) from the reference
/// store's typed index. The epoch is the number of compactions so far.
pub(crate) fn render(
    sketch: Option<(&Grid, u32)>,
    refs: &[RefMeta],
) -> Result<String, BoardFrameError> {
    let header = BoardBlockHeader {
        epoch: refs.len() as u64,
        scope: "ctx-arms".to_owned(),
    };
    let legend = BoardLegend::canonical();
    let mut sections = Vec::new();
    if let Some((grid, version)) = sketch {
        let pinned = SectionPolicy {
            pinned: true,
            shed_rank: None,
        };
        sections.push(BoardSection::new(
            "SKETCHPAD",
            snapshot_lines(grid, version),
            Vec::new(),
            Vec::new(),
            pinned,
        )?);
    }
    let plugin = section_policy_for_budget_ref(&BudgetPolicyRef(
        PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned(),
    ))?;
    sections.push(BoardSection::new(
        "OFFLOAD",
        Vec::new(),
        refs.iter().map(RefMeta::row).collect(),
        vec![format!("refs={}", refs.len())],
        plugin,
    )?);
    let frame = BoardFrame {
        header: &header,
        legend: &legend,
        sections: &sections,
        changes: None,
    };
    let request = BoardBudgetRequest {
        harness_default_tok: BOARD_TOK,
        caller_limit_tok: None,
        explicit_override_tok: None,
    };
    Ok(render_board_block(&frame, request)?.text)
}
