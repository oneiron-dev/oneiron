//! The actor's own board layout on the HTTP, chat and MCP boards
//! (BOARD-LAYOUT = A, owner 2026-11-03 20:25).
//!
//! The layout's doors are the generated `self.board.*` verbs. This module
//! selects the layout one hydration renders under, and resolves a section
//! filter for one board. A hydration with a TURN (or a native chat answer)
//! projects the actor's pending batch and the SAME accepted commit
//! activates it; a hydration without a TURN reads the live layout only.

use super::super::core_engine_error;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::context_board::{
    BoardActorClass, BoardLayout, BoardLayoutCandidate, BoardSection, BoardWhoFilter, MemoryTier,
    PeopleView, PersonKind, SectionFilter, TasksSectionRows,
};
use std::collections::{BTreeMap, BTreeSet};

/// The layout one board renders under, the actor it belongs to, and the
/// candidate the board's turn activates.
#[derive(Debug, Clone, Default)]
pub(crate) struct BoardLayoutSelection {
    pub(crate) actor: Option<EntityId>,
    pub(crate) layout: BoardLayout,
    pub(crate) candidate: Option<BoardLayoutCandidate>,
}

/// Selects the layout a hydration renders under. `chat_layout_actor`
/// carries a native chat turn's answering agent: when `Some`, it selects
/// exactly that actor with a turn; when `None`, the authenticated caller
/// with `has_turn` as the request states it. A caller with no entity
/// principal and declared class renders under the default layout.
pub(crate) fn hydrate_layout_selection(
    server: &SyncServer,
    auth: &CoreAuth,
    has_turn: bool,
    chat_layout_actor: Option<EntityId>,
) -> Result<BoardLayoutSelection, ApiError> {
    let (actor, has_turn) = match chat_layout_actor {
        Some(actor) => (Some(actor), true),
        None => (layout_actor(auth), has_turn),
    };
    let Some(actor) = actor else {
        return Ok(BoardLayoutSelection::default());
    };
    let (layout, candidate) = server
        .vault
        .select_board_layout(actor, has_turn)
        .map_err(|error| core_engine_error("board layout selection failed", error))?;
    Ok(BoardLayoutSelection {
        actor: Some(actor),
        layout,
        candidate,
    })
}

/// The board cap a harness renders under: the owner's cap
/// (`/v1/owner/settings/board-layout`), else `harness_tok`. Settings that
/// fail to read keep the harness default.
pub(crate) fn board_cap_tok(vault: &oneiron::Vault, harness_tok: usize) -> usize {
    match vault.board_layout_settings() {
        Ok(settings) => settings.cap_or(harness_tok),
        Err(error) => {
            tracing::warn!(%error, "board layout settings did not read; the harness cap applies");
            harness_tok
        }
    }
}

/// The caller's entity principal as its layout owner: a declared actor
/// class plus a hex principal.
fn layout_actor(auth: &CoreAuth) -> Option<EntityId> {
    match auth.actor_class()? {
        "human" | "agent" | "system" => (),
        _ => return None,
    }
    EntityId::from_hex(auth.principal_ref()?).ok()
}

/// The class a board filter gives a person row.
pub(crate) fn person_class(kind: PersonKind) -> BoardActorClass {
    match kind {
        PersonKind::Human => BoardActorClass::Human,
        PersonKind::Agent => BoardActorClass::Agent,
    }
}

/// `rows` narrowed by one TASKS `filter` on `actor`'s board. A group filter
/// reads its project's roster only while `read` reads the project; an
/// unreadable or unknown group keeps no row. The filter narrows rows `read`
/// already admitted, never widens them.
pub(crate) fn filter_task_rows(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    people: &PeopleView<'_>,
    actor: Option<EntityId>,
    filter: &SectionFilter,
    rows: &TasksSectionRows,
) -> Result<TasksSectionRows, oneiron::Error> {
    let members = match filter.who.as_ref().and_then(|who| who.group()) {
        Some(group) if read.is_entity_readable(&group)? => {
            vault.board_filter_group_members(group)?
        }
        _ => BTreeSet::new(),
    };
    Ok(rows.filtered(filter, |who| {
        filter.who.as_ref().is_none_or(|filter| {
            filter.matches(who, actor, &members, |id| people.kind(id).map(person_class))
        })
    }))
}

/// The MEMORIES `sections` of `actor`'s board narrowed by its layout's
/// MEMORIES `who` filter (BOARD-LAYOUT add-on 2): a detail row stays while
/// the actor who wrote it matches, or while the fold keeps it open by id.
/// The writer is the row's stamped maker ([`oneiron::Vault::memory_row_writers`]),
/// and, as an INBOX sender (FIX 9745), it counts only while `read` reads it
/// or it is `actor` itself; a row with no such writer matches no `who`.
/// Pinned rows and each section's count and fold summary stay. The filter
/// narrows the rendered board only: the typed MEMORIES section is unchanged.
/// Beside the sections it answers what the choice read: the writer of each
/// detail row it kept by its writer (other than `actor`) and the group it
/// resolved, which a keyed replay re-admits, so a replay never shows a row
/// chosen by a writer or roster the caller can no longer read.
pub(crate) fn filter_memories_sections(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    people: &PeopleView<'_>,
    actor: Option<EntityId>,
    layout: &BoardLayout,
    memories: &oneiron::MemoriesSection,
    sections: Vec<BoardSection>,
) -> Result<(Vec<BoardSection>, Vec<EntityId>), oneiron::Error> {
    let Some(who) = layout
        .filter("memories")
        .and_then(|filter| filter.who.as_ref())
    else {
        return Ok((sections, Vec::new()));
    };
    let keep = layout
        .fold("memories")
        .map(|fold| fold.keep.as_slice())
        .unwrap_or_default();
    let rows: Vec<EntityId> = memories
        .rows
        .iter()
        .filter_map(|row| EntityId::from_hex(&row.id).ok())
        .collect();
    let mut readable = BTreeMap::new();
    let mut writers = BTreeMap::new();
    for (row, writer) in vault.memory_row_writers(&rows)? {
        let shown = match readable.get(&writer) {
            Some(shown) => *shown,
            None => {
                let shown = Some(writer) == actor || read.is_entity_readable(&writer)?;
                readable.insert(writer, shown);
                shown
            }
        };
        if shown {
            writers.insert(row, writer);
        }
    }
    let members = match who.group() {
        Some(group) if read.is_entity_readable(&group)? => {
            vault.board_filter_group_members(group)?
        }
        _ => BTreeSet::new(),
    };
    let detail: BTreeSet<EntityId> = memories
        .rows
        .iter()
        .filter(|row| row.tier != MemoryTier::Pinned)
        .filter_map(|row| EntityId::from_hex(&row.id).ok())
        .collect();
    let matched: BTreeSet<EntityId> = writers
        .iter()
        .filter(|(_, writer)| {
            who.matches(Some(**writer), actor, &members, |id| {
                people.kind(id).map(person_class)
            })
        })
        .map(|(row, _)| *row)
        .collect();
    // What each detail row the filter alone keeps rests on: its writer
    // (other than `actor`), the PERSON a class match read the writer's class
    // from, and the group whose roster matched it. A pinned or fold-kept row
    // rests on none of them.
    let mut read_sources: Vec<EntityId> = Vec::new();
    for row in matched
        .iter()
        .filter(|row| detail.contains(*row) && !keep.contains(*row))
    {
        let Some(writer) = writers.get(row).copied() else {
            continue;
        };
        let mut rests_on = vec![writer];
        match who {
            BoardWhoFilter::Class { .. } => {
                rests_on.extend(people.people.get(writer).map(|person| person.person));
            }
            BoardWhoFilter::Group { group } => rests_on.push(*group),
            BoardWhoFilter::Mine | BoardWhoFilter::Actor { .. } => {}
        }
        for source in rests_on {
            if Some(source) != actor && !read_sources.contains(&source) {
                read_sources.push(source);
            }
        }
    }
    let sections = sections
        .into_iter()
        .map(|section| section.narrowed(|row| keep.contains(&row) || matched.contains(&row)))
        .collect();
    Ok((sections, read_sources))
}
