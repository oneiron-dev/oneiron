//! The engine-board render: the harness, not the strategy, turns typed state
//! into the dynamic tail through the engine's own renderer
//! (`oneiron::context_board::render_board_block`). A strategy hands over
//! typed state only, so no strategy-written text can ride the board.

use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardFrameError, BoardLegend, BoardSection,
    BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF, SectionPolicy, ServedLifecycle,
    SessionReadSet, SkillsSection, render_board_block, section_policy_for_budget_ref,
};

use super::arms::{Grid, snapshot_lines};
use super::window::{Link, RefMeta};

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

/// Where a resource's current body sits right now, as the board shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// Resident on the prefix inventory at its current version.
    Prefix,
    /// Live in the log at its current version.
    Log,
    /// Inside a reference.
    Ref(u32),
    /// Nowhere in the session: only a `get` gives it.
    Get,
}

/// One typed resource row: the version the session knows is current, the
/// newest version whose body it was served, and where the current body is.
#[derive(Clone, Debug)]
pub(crate) struct ResRow {
    pub(crate) name: String,
    pub(crate) current: u32,
    pub(crate) served: u32,
    pub(crate) held: Held,
}

/// The canon board's typed state. Every field is typed; the renderer, not
/// the strategy, writes the text.
pub(crate) struct CanonBoard<'a> {
    /// Compactions so far.
    pub(crate) epoch: u64,
    /// The turn clock: the stand-in for the board's per-turn rows (tasks
    /// running for N minutes, this turn's found skills).
    pub(crate) turn: usize,
    pub(crate) sketch: Option<(&'a Grid, u32)>,
    pub(crate) resources: &'a [ResRow],
    /// The engine's session read set: served rows and loaded skill bodies.
    pub(crate) read_set: &'a SessionReadSet,
}

/// Renders the canon dynamic tail through `render_board_block`: NOW (the
/// turn clock), SKETCHPAD (the typed grid), RESOURCES (the live index), the
/// engine's SKILLS section (its `loaded` line from the read set) and the
/// engine's changed line (served rows whose current version moved on).
pub(crate) fn render_canon(state: &CanonBoard<'_>) -> Result<String, BoardFrameError> {
    let header = BoardBlockHeader {
        epoch: state.epoch,
        scope: "ctx-arms".to_owned(),
    };
    let legend = BoardLegend::canonical();
    let pinned = SectionPolicy {
        pinned: true,
        shed_rank: None,
    };
    let mut sections = vec![BoardSection::new(
        "NOW",
        vec![format!("turn: {}", state.turn)],
        Vec::new(),
        Vec::new(),
        pinned,
    )?];
    if let Some((grid, version)) = state.sketch {
        sections.push(BoardSection::new(
            "SKETCHPAD",
            snapshot_lines(grid, version),
            Vec::new(),
            Vec::new(),
            pinned,
        )?);
    }
    if !state.resources.is_empty() {
        let mut rows = vec![format!("resources[{}:]{{v,at}}:", state.resources.len())];
        rows.extend(state.resources.iter().map(|r| {
            let at = match r.held {
                Held::Prefix => "prefix".to_owned(),
                Held::Log => "log".to_owned(),
                Held::Ref(id) => format!("r{id}"),
                Held::Get => "get".to_owned(),
            };
            format!("{}: v{},{at}", r.name, r.current)
        }));
        sections.push(BoardSection::new(
            "RESOURCES",
            rows,
            Vec::new(),
            Vec::new(),
            pinned,
        )?);
    }
    let skills = SkillsSection::project(&[], state.read_set);
    if state.read_set.loaded_skills().next().is_some() {
        sections.push(skills.board_section()?);
    }
    let changes = state.read_set.changed(8, |id| {
        state.resources.iter().find(|r| r.name == id).map(|r| {
            if r.current > r.served {
                ServedLifecycle::Superseded(format!("v{}", r.current))
            } else {
                ServedLifecycle::Active
            }
        })
    });
    let has_changes = !changes.rows.is_empty() || changes.overflow > 0;
    let frame = BoardFrame {
        header: &header,
        legend: &legend,
        sections: &sections,
        changes: has_changes.then_some(&changes),
    };
    let request = BoardBudgetRequest {
        harness_default_tok: BOARD_TOK,
        caller_limit_tok: None,
        explicit_override_tok: None,
    };
    Ok(render_board_block(&frame, request)?.text)
}

/// The epoch keyframe (bench-local render of the canon shape: no engine
/// renderer for the cached-prefix keyframe is public). One row per
/// reference: the epoch that minted it and its typed index. A projection
/// of the reference store: it changes only when an epoch closes.
pub(crate) fn render_keyframe(epoch: u64, rows: &[(RefMeta, u64)]) -> String {
    let mut lines = vec![format!(
        "<memory surface=\"prefix\" block=\"epoch\" epoch=\"{epoch}\">"
    )];
    lines.push(format!("refs[{}:]{{epoch,turns,spans,tok}}:", rows.len()));
    for (meta, e) in rows {
        let turns = meta
            .turns
            .map_or_else(|| "-".to_owned(), |(a, b)| format!("{a}-{b}"));
        lines.push(format!(
            "  r{}: e{e},{turns},{},{}",
            meta.id, meta.spans, meta.tok
        ));
    }
    lines.push("</memory>".to_owned());
    lines.join("\n")
}

/// The prefix inventory: the resident set (bodies as the environment
/// serves them) and one link row per non-resident resource.
pub(crate) fn render_inventory(
    held: &[(String, u32)],
    bodies: &[String],
    links: &[(String, u32, Link)],
) -> String {
    let mut lines = vec!["<memory surface=\"prefix\" block=\"working-set\">".to_owned()];
    lines.push(format!("resident[{}:]{{v}}:", held.len()));
    lines.extend(held.iter().map(|(name, v)| format!("  {name}: v{v}")));
    lines.extend(bodies.iter().filter(|b| !b.is_empty()).cloned());
    lines.push(format!("links[{}:]{{v,at}}:", links.len()));
    lines.extend(links.iter().map(|(name, v, at)| {
        let at = match at {
            Link::Ref(id) => format!("r{id}"),
            Link::Get => "get".to_owned(),
        };
        format!("  {name}: v{v},{at}")
    }));
    lines.push("</memory>".to_owned());
    lines.join("\n")
}
