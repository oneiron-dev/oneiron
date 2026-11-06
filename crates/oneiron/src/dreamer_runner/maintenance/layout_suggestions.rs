//! Board layout suggestions per agent type (FIX 12572, layout half; owner
//! 2026-11-03 20:31, ledger engine-20261103-board-layout-addons item 5):
//! the Coach notices how agents of one type lay out their context boards
//! and suggests a default layout for that type. A suggestion only: it lands
//! Proposed in the owner's run tray, and no board reads it back. No model is
//! called.
//!
//! A board layout is kept per agent (FIX 12570), so one agent definition
//! holds one layout. Agent type here is the wake role an agent definition
//! carries (companion, leader, worker, or none set): the agents of one role
//! are compared with each other.
//!
//! For each section, the suggested default takes what at least two thirds
//! of the role's laid-out agents share: the section folded, its median share
//! of the cap, and the status filter most of them set. The suggestion is a
//! whole board layout that passes the engine's layout check: shares that
//! would sum past the cap are scaled down to fit it, and past the section
//! limit only the sections most of the agents name are kept. A suggestion is filed
//! again only when what it suggests changes: its claim id is made from its
//! content, and the agents behind it are its evidence.

use std::collections::BTreeMap;

use super::coach::{COACH_LAYOUT_DEFAULT_PREDICATE, COACH_LAYOUT_SUGGESTIONS_FACET};
use super::proposals;
use crate::context_board::{
    BOARD_LAYOUT_SECTIONS_MAX, BoardLayout, SectionFilter, SectionFold, SectionLayout,
    board_layouts_in_txn,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::store::agent_record::AgentWakeCadence;
use crate::{EntityId, Result, Vault};

/// The fewest laid-out agents of one role before the Coach suggests a
/// default layout for it. Canon names no number: three, as for folds.
const LAYOUT_SUGGESTION_MIN_AGENTS: usize = 3;

/// The role an agent definition wakes as, by its own cadence dial.
fn role_name(cadence: Option<AgentWakeCadence>) -> &'static str {
    match cadence {
        Some(AgentWakeCadence::Companion { .. }) => "companion",
        Some(AgentWakeCadence::Leader { .. }) => "leader",
        Some(AgentWakeCadence::Worker) => "worker",
        None => "unset",
    }
}

/// Whether `count` of `of` is at least two thirds.
fn most(count: usize, of: usize) -> bool {
    of > 0 && count.saturating_mul(3) >= of.saturating_mul(2)
}

/// The upper median, or `None` for no values.
fn median(values: &mut [u8]) -> Option<u8> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

/// One pass over every agent's live board layout. A role whose suggestion
/// cannot land is left for the next night; the others still run.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    vault.require_coach_attempt(attempt, COACH_LAYOUT_SUGGESTIONS_FACET)?;
    let layouts = {
        let txn = vault.store.env.read_txn()?;
        board_layouts_in_txn(vault, &txn)?
    };
    let mut roles: BTreeMap<&'static str, Vec<(EntityId, BoardLayout)>> = BTreeMap::new();
    for (actor, layout) in layouts {
        if layout.sections.is_empty() {
            continue;
        }
        // Only an agent definition has an agent type; any other actor's
        // board is not compared.
        let Ok(Some(definition)) = vault.get_agent_definition(&actor) else {
            continue;
        };
        roles
            .entry(role_name(definition.wake_cadence))
            .or_default()
            .push((actor, layout));
    }
    let envelope = proposals::run_tray_envelope(
        vault,
        COACH_LAYOUT_SUGGESTIONS_FACET,
        attempt.status.attempt.id,
    )?;
    let subject = envelope.actor().entity_ref();
    for (role, agents) in &roles {
        if agents.len() < LAYOUT_SUGGESTION_MIN_AGENTS {
            continue;
        }
        let layout = suggested_layout(agents);
        if layout.sections.is_empty() {
            continue;
        }
        // The suggestion is a layout the owner can put in force as it is:
        // one the engine's own check refuses is not filed.
        if let Err(error) = layout.validate() {
            tracing::warn!(
                ?error,
                "a board layout suggestion did not pass the layout check"
            );
            continue;
        }
        let value = serde_json::json!({ "role": role, "layout": layout });
        let evidence: Vec<EntityId> = agents.iter().map(|(actor, _)| *actor).collect();
        if let Err(error) = vault.with_write_txn_grouped(|txn| {
            proposals::emit_in_txn(
                vault,
                txn,
                subject,
                COACH_LAYOUT_DEFAULT_PREDICATE,
                &value,
                &evidence,
                &envelope,
                now,
            )
        }) {
            tracing::warn!(kind = ?error.kind(), "a board layout suggestion did not land");
        }
    }
    Ok(())
}

/// What most of `agents` share, section by section (a section folded, a
/// share of the cap, a status filter), as one board layout within the
/// engine's limits.
fn suggested_layout(agents: &[(EntityId, BoardLayout)]) -> BoardLayout {
    let total = agents.len();
    // How many agents name each section: the sections most agents name are
    // the ones kept past the section limit.
    let mut support: BTreeMap<&String, usize> = BTreeMap::new();
    for (_, layout) in agents {
        for key in layout.sections.keys() {
            *support.entry(key).or_default() += 1;
        }
    }
    let mut suggested: Vec<(usize, String, SectionLayout)> = Vec::new();
    for (key, named) in support {
        let sections: Vec<&SectionLayout> = agents
            .iter()
            .filter_map(|(_, layout)| layout.sections.get(key))
            .collect();
        let mut section = SectionLayout::default();
        if most(
            sections
                .iter()
                .filter(|section| section.fold.is_some())
                .count(),
            total,
        ) {
            section.fold = Some(SectionFold::default());
        }
        let mut shares: Vec<u8> = sections
            .iter()
            .filter_map(|section| section.share_pct)
            .collect();
        if most(shares.len(), total) {
            section.share_pct = median(&mut shares);
        }
        let mut filters: BTreeMap<Vec<String>, usize> = BTreeMap::new();
        for section in &sections {
            if let Some(filter) = &section.filter
                && !filter.status.is_empty()
            {
                let mut status = filter.status.clone();
                status.sort_unstable();
                *filters.entry(status).or_default() += 1;
            }
        }
        if let Some((status, _)) = filters
            .into_iter()
            .filter(|(_, count)| most(*count, total))
            .max_by_key(|(_, count)| *count)
        {
            section.filter = Some(SectionFilter { who: None, status });
        }
        if section != SectionLayout::default() {
            suggested.push((named, key.clone(), section));
        }
    }
    // Most-named first, then by key, so the cut is the same on every pass.
    suggested.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    suggested.truncate(BOARD_LAYOUT_SECTIONS_MAX);
    let mut layout = BoardLayout {
        sections: suggested
            .into_iter()
            .map(|(_, key, section)| (key, section))
            .collect(),
    };
    fit_shares_to_cap(&mut layout);
    layout
}

/// Section shares are shares of one cap and never sum past it (owner
/// 2026-11-03 20:31). Medians taken section by section can: then each
/// suggested share is scaled down in proportion, rounding down.
fn fit_shares_to_cap(layout: &mut BoardLayout) {
    let total: u32 = layout
        .sections
        .values()
        .filter_map(|section| section.share_pct)
        .map(u32::from)
        .sum();
    if total <= 100 {
        return;
    }
    for section in layout.sections.values_mut() {
        if let Some(pct) = section.share_pct {
            section.share_pct = u8::try_from(u32::from(pct) * 100 / total).ok();
        }
    }
}
