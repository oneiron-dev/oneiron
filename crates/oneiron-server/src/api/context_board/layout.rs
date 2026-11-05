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
    BoardActorClass, BoardLayout, BoardLayoutCandidate, PeopleView, PersonKind, SectionFilter,
    TasksSectionRows,
};
use std::collections::BTreeSet;

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
