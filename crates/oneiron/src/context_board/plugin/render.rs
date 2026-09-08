//! Pure plugin renderers and the pending-proposal section.
use super::super::frame::{BoardSection, SectionPolicy, ShedRank, section_policy_for_budget_ref};
use super::super::one_line_token;
use super::admission::{PluginSectionRegistry, section_is_live};
use super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::errors::{PluginResult, PluginSectionError};
use super::install::PluginInstallOrigin;
use super::manifest::{SectionId, SkillLifecycleSource};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::vault::Vault;

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
    let mut sections = Vec::new();
    for admitted in registry.sections() {
        let manifest = &admitted.manifest;
        if !section_is_live(manifest, skills)? {
            continue;
        }
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.section_id == *manifest.section_id())
            .ok_or_else(|| PluginSectionError::MissingSnapshot {
                section_id: manifest.section_id().0.clone(),
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
        let count_rows = vec![format!("count: {}", snapshot.rows.len())];
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
/// can rename it. It is deliberately not in [`CORE_SECTION_IDS`] — that list
/// is the set of ids a plugin manifest may not CLAIM, and a plugin claiming
/// `proposals` as its own section id is already refused by the id grammar
/// plus the collision check on admitted ids.
pub const PLUGIN_PROPOSALS_SECTION_NAME: &str = "PROPOSALS";

/// Bound on the pending-consent scan the proposal projection performs.
const PLUGIN_PROPOSAL_SCAN_LIMIT: usize = 1_024;

/// Projects every STILL-PENDING plugin-section install as one typed row.
///
/// Reads the public pending-consent surface and filters to
/// [`PREDICATE_PLUGIN_SECTION_INSTALL`]. Both origins are returned:
/// `Conversation` and `DreamerSuggestion` alike. Origin decides provenance
/// and dedupe, never whether the agent may SEE an unresolved install — a
/// conversation-initiated install that vanished from the board would leave
/// the agent unable to explain a pending question it raised itself.
///
/// This is a projection over the gate's own pending rows. It mints nothing,
/// stores nothing, and is not install authority: a row here can neither
/// accept consent nor register a section.
///
/// Rows are ordered by claim id so a render is byte-stable across restarts.
/// `limit` caps the number of ROWS returned.
///
/// # Errors
///
/// Storage errors, and [`PluginSectionError::MalformedClaimPayload`] never:
/// a pending row whose payload or manifest does not strictly decode is
/// SKIPPED rather than failing the whole board, so one corrupt claim cannot
/// blank the section.
pub fn pending_plugin_proposal_rows(
    vault: &Vault,
    limit: usize,
) -> PluginResult<Vec<PluginProposalRow>> {
    let mut rows: Vec<PluginProposalRow> = Vec::new();
    for pending in vault.pending_gate_consents(PLUGIN_PROPOSAL_SCAN_LIMIT)? {
        let Ok(claim_id) = EntityId::from_bytes(pending.claim_id) else {
            continue;
        };
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL {
            continue;
        }
        // A pending row survives only while the claim is genuinely awaiting
        // an owner: an approved, retracted, or superseded body has already
        // been decided and must not keep asking.
        if body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
        {
            continue;
        }
        let Ok(payload) = PluginInstallClaimPayload::from_value(&body.value) else {
            continue;
        };
        let Ok(envelope) = payload.manifest() else {
            continue;
        };
        rows.push(PluginProposalRow {
            install_claim_id: claim_id,
            origin: payload.origin,
            pack_id: envelope.manifest.provenance.pack_id,
            section_id: payload.section_id,
            label: envelope.manifest.name,
            awaiting_owner_consent: true,
        });
    }
    rows.sort_by_key(|row| *row.install_claim_id.as_bytes());
    rows.truncate(limit);
    Ok(rows)
}

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
    let detail_rows: Vec<String> = rows.iter().map(render_plugin_proposal_row).collect();
    // Non-empty on purpose, including at zero: the shed ladder degrades a
    // section TO its count rows, and an empty fallback is rejected by
    // `BoardSection::new`.
    let count_rows = vec![format!("count: {}", rows.len())];
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
