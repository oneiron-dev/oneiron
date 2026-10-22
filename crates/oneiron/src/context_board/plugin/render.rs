//! Pure plugin renderers and the pending-proposal section.
use super::super::frame::{BoardSection, SectionPolicy, ShedRank, section_policy_for_budget_ref};
use super::super::one_line_token;
use super::admission::{PluginSectionRegistry, section_is_live};
use super::errors::{PluginResult, PluginSectionError};
use super::install::PluginInstallOrigin;
use super::manifest::{SectionId, SkillLifecycleSource};
use super::pages::{PluginProposalPage, PluginSectionSnapshotPage};
use crate::entity_id::EntityId;

// ---------------------------------------------------------------------------
// §5 — pure rendering
// ---------------------------------------------------------------------------
/// One engine-authored plugin row. `row_id` and every cell are DATA: they reach
/// the board through [`quoted_leaf`] and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSectionRow {
    pub row_id: String,
    pub cells: Vec<String>,
}

/// Typed state a provider hands the renderer. There is no text seam here — the
/// renderer never receives a pre-rendered line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSectionSnapshot {
    pub section_id: SectionId,
    pub rows: Vec<PluginSectionRow>,
}

/// The escaped, quoted leaf position — the ONLY place a caller-supplied string
/// reaches a rendered row.
///
/// `one_line_token` is the shared control-only physical-line fence, applied
/// first so a row is always one physical line; the quotes and the `\`/`"`
/// escapes are the leaf's own, so a value carrying a quote closes nothing.
/// XML/wrapper neutralization is NOT done here: ONE-1797's `xml_text_token`
/// performs it exactly once at the final frame boundary.
#[must_use]
pub fn quoted_leaf(value: &str) -> String {
    let collapsed = one_line_token(value);
    let mut out = String::with_capacity(collapsed.len() + 2);
    out.push('"');
    for character in collapsed.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(character),
        }
    }
    out.push('"');
    out
}

/// One row: engine-owned separators around quoted leaves. The structural
/// signature of a row (its quote count and its single physical line) is a
/// function of the row's SHAPE, never of any value's content.
#[must_use]
pub fn render_plugin_row(row: &PluginSectionRow) -> String {
    let mut out = quoted_leaf(&row.row_id);
    for cell in &row.cells {
        out.push(' ');
        out.push_str(&quoted_leaf(cell));
    }
    out
}

/// The count fallback row: the plain row count for a complete set, and the
/// truthful total, shown and remaining counts for one page of a longer one.
fn count_row(total: u64, shown: usize, remaining: u64) -> String {
    if remaining == 0 && u64::try_from(shown).is_ok_and(|shown| shown == total) {
        format!("count: {total}")
    } else {
        format!("count: {total} shown: {shown} remaining: {remaining}")
    }
}

/// Builds validated [`BoardSection`] values for every still-live admitted
/// plugin section.
///
/// Filters through the Active/version/hash re-read FIRST, so a Stale,
/// Quarantined, Superseded, missing, or hash-mismatched pack contributes
/// nothing to this render. Each surviving section carries no PINNED rows, a
/// non-empty deterministic count fallback, and the frame-owned plugin policy.
pub fn render_plugin_sections(
    registry: &PluginSectionRegistry,
    snapshots: &[PluginSectionSnapshot],
    skills: &dyn SkillLifecycleSource,
) -> PluginResult<Vec<BoardSection>> {
    render_live_sections(registry, skills, |section_id| {
        snapshots
            .iter()
            .find(|snapshot| snapshot.section_id == *section_id)
            .map(|snapshot| {
                let shown = u64::try_from(snapshot.rows.len()).unwrap_or(u64::MAX);
                (snapshot, shown, 0)
            })
    })
}

/// [`render_plugin_sections`] over paged snapshots: each section's count row
/// carries its page's truthful total and remaining counts.
pub fn render_plugin_section_pages(
    registry: &PluginSectionRegistry,
    pages: &[PluginSectionSnapshotPage],
    skills: &dyn SkillLifecycleSource,
) -> PluginResult<Vec<BoardSection>> {
    render_live_sections(registry, skills, |section_id| {
        pages
            .iter()
            .find(|page| page.snapshot.section_id == *section_id)
            .map(|page| (&page.snapshot, page.total, page.remaining))
    })
}

fn render_live_sections<'a>(
    registry: &PluginSectionRegistry,
    skills: &dyn SkillLifecycleSource,
    snapshot_for: impl Fn(&SectionId) -> Option<(&'a PluginSectionSnapshot, u64, u64)>,
) -> PluginResult<Vec<BoardSection>> {
    let mut sections = Vec::new();
    for admitted in registry.sections() {
        let manifest = &admitted.manifest;
        if !section_is_live(manifest, skills)? {
            continue;
        }
        let (snapshot, total, remaining) =
            snapshot_for(manifest.section_id()).ok_or_else(|| {
                PluginSectionError::MissingSnapshot {
                    section_id: manifest.section_id().0.clone(),
                }
            })?;

        let policy = section_policy_for_budget_ref(manifest.budget_policy())?;
        if policy
            != (SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::PluginSections),
            })
        {
            return Err(PluginSectionError::NonPluginSectionPolicy);
        }

        let detail_rows: Vec<String> = snapshot.rows.iter().map(render_plugin_row).collect();
        let count_rows = vec![count_row(total, snapshot.rows.len(), remaining)];
        // `BoardSection::new` applies the shared per-row byte clamp BEFORE
        // anything is tokenized, so an over-limit hostile row is rejected
        // deterministically and never reaches the shed loop's repeated
        // candidate renders.
        sections.push(BoardSection::new(
            manifest.name().to_owned(),
            Vec::new(),
            detail_rows,
            count_rows,
            policy,
        )?);
    }
    Ok(sections)
}

/// Pack-origin sections render from a fresh Active-pack projection, never from
/// a fabricated Approved section-install claim. Until a typed state provider
/// supplies rows, the honest visible section is an empty budgeted working set;
/// requested verbs and authority remain permissions, not installed grants.
pub fn render_pack_sections(
    registry: &PluginSectionRegistry,
    snapshots: &[PluginSectionSnapshot],
) -> PluginResult<Vec<BoardSection>> {
    registry
        .pack_sections()
        .map(|entry| {
            let policy = section_policy_for_budget_ref(&entry.section.budget_policy)?;
            let rows: Vec<String> = snapshots
                .iter()
                .find(|snapshot| snapshot.section_id.0 == entry.section.section_id)
                .map(|snapshot| snapshot.rows.iter().map(render_plugin_row).collect())
                .unwrap_or_default();
            BoardSection::new(
                entry.section.section_id.clone(),
                Vec::new(),
                rows.clone(),
                vec![format!("count: {}", rows.len())],
                policy,
            )
            .map_err(Into::into)
        })
        .collect()
}

/// Pending typed data for ONE-1707's PROPOSALS projection. It is NOT an
/// admitted section and NOT install authority: it can neither accept consent
/// nor register a section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginProposalRow {
    pub install_claim_id: EntityId,
    pub origin: PluginInstallOrigin,
    pub pack_id: String,
    pub section_id: SectionId,
    pub label: String,
    pub awaiting_owner_consent: bool,
}

/// The fixed, engine-owned name of the pending-proposal board section.
///
/// A CONSTANT, not a manifest-supplied string: `PROPOSALS` is a core frame
/// slot the engine owns, so no pack can name a section into it and no caller
/// can rename it. It is deliberately not in [`CORE_SECTION_IDS`](crate::context_board::CORE_SECTION_IDS) — that list
/// is the set of ids a plugin manifest may not CLAIM, and a plugin claiming
/// `proposals` as its own section id is already refused by the id grammar
/// plus the collision check on admitted ids.
pub const PLUGIN_PROPOSALS_SECTION_NAME: &str = "PROPOSALS";

/// Renders the fixed `PROPOSALS` section over the pending rows.
///
/// One detail row per pending proposal through the shared row fence and the
/// frame's per-row byte clamp, no PINNED rows, a deterministic non-empty
/// count fallback, and the plugin shed rank — so proposals shed before core
/// detail rather than crowding it out.
///
/// This is neither an admitted plugin section nor a self-consent verb: it is
/// the agent-visible carrier for questions already waiting on the owner.
///
/// # Errors
///
/// [`PluginSectionError::Frame`] when a row exceeds the shared byte clamp.
pub fn render_plugin_proposal_section(rows: &[PluginProposalRow]) -> PluginResult<BoardSection> {
    let shown = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    proposal_section(rows, shown, 0)
}

/// [`render_plugin_proposal_section`] over one proposal page: the count row
/// carries the complete matching total and how many remain past the page.
///
/// # Errors
///
/// [`PluginSectionError::Frame`] when a row exceeds the shared byte clamp.
pub fn render_plugin_proposal_page(page: &PluginProposalPage) -> PluginResult<BoardSection> {
    proposal_section(&page.rows, page.matching_total, page.remaining)
}

fn proposal_section(
    rows: &[PluginProposalRow],
    total: u64,
    remaining: u64,
) -> PluginResult<BoardSection> {
    let detail_rows: Vec<String> = rows.iter().map(render_plugin_proposal_row).collect();
    // Non-empty on purpose, including at zero: the shed ladder degrades a
    // section TO its count rows, and an empty fallback is rejected by
    // `BoardSection::new`.
    let count_rows = vec![count_row(total, rows.len(), remaining)];
    Ok(BoardSection::new(
        PLUGIN_PROPOSALS_SECTION_NAME,
        Vec::new(),
        detail_rows,
        count_rows,
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::PluginSections),
        },
    )?)
}

/// Renders one proposal row. Same law as every other row: engine-owned
/// structure, caller data only in escaped quoted leaves.
#[must_use]
pub fn render_plugin_proposal_row(row: &PluginProposalRow) -> String {
    format!(
        "proposal {} {} {} awaiting_consent={} origin={} claim={}",
        quoted_leaf(&row.pack_id),
        quoted_leaf(&row.section_id.0),
        quoted_leaf(&row.label),
        row.awaiting_owner_consent,
        row.origin.kind(),
        row.install_claim_id.to_hex(),
    )
}
