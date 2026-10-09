//! Stateless ROOM projection and the one roster-to-Scope function.

use super::{BoardFrameError, BoardSection, SectionPolicy, one_line_token};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::pipeline::WorldAuthoritySet;
use crate::{EntityId, Result};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

/// One roster entry. The engine builds every entry from the Conversation's
/// `memberIds` and each member's own grants; no request supplies one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPresence {
    pub actor: EntityId,
    /// The bound caller's class. Other members carry none, so a peer read
    /// matches only class-agnostic grants.
    pub actor_class: Option<crate::EdgeActorClass>,
    pub label: String,
    pub present: bool,
    /// The worlds this member reads by default (ARCH-0022).
    pub active_worlds: WorldAuthoritySet,
}

/// ARCH-0067 §8: the only function from a roster to a Scope. It meets the
/// present members' world sets into the ordinary Scope; every other axis
/// stays open here and each member's own grants still bind at the read door.
/// A member who joins can only narrow the result.
pub fn room_scope(roster: &[RoomPresence]) -> Result<Scope> {
    let mut present = roster.iter().filter(|member| member.present);
    let Some(first) = present.next() else {
        return Ok(Scope::default());
    };
    let mut base = first.active_worlds.include_base();
    let mut worlds = first.active_worlds.worlds().clone();
    for member in present {
        base &= member.active_worlds.include_base();
        worlds.retain(|id| member.active_worlds.worlds().contains(id));
    }
    // Keep the world-set bound at this door too.
    let meet = WorldAuthoritySet::new(base, worlds)?;
    // Base has its own boolean. A world id equal to the reserved base id
    // cannot stand in for it.
    let mut ids: BTreeSet<_> = meet
        .worlds()
        .iter()
        .filter(|id| **id != crate::claim::base_world_id())
        .map(|id| ScopeId(*id))
        .collect();
    if meet.include_base() {
        ids.insert(ScopeId(crate::claim::base_world_id()));
    }
    let mut scope = Scope::top();
    scope.worlds = ids.into_iter().collect();
    Ok(scope)
}

/// The world axis of a room Scope as a retrieval world set, or `None` when
/// the axis is open.
pub(crate) fn scope_worlds(scope: &Scope) -> Result<Option<WorldAuthoritySet>> {
    let base = ScopeId(crate::claim::base_world_id());
    match &scope.worlds {
        ScopeAxis::All => Ok(None),
        ScopeAxis::Bottom => WorldAuthoritySet::new(false, []).map(Some),
        ScopeAxis::Some(ids) => WorldAuthoritySet::new(
            ids.contains(&base),
            ids.iter().filter(|id| **id != base).map(|id| id.0),
        )
        .map(Some),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RoomMode {
    #[default]
    Chime,
    AskedOnly,
    Silent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RoomBar {
    Low,
    #[default]
    Med,
    High,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoomPosture {
    pub mode: RoomMode,
    pub bar: RoomBar,
}
impl RoomPosture {
    pub fn compose(self, other: Self) -> Self {
        Self {
            mode: self.mode.max(other.mode),
            bar: self.bar.max(other.bar),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoomSection {
    pub room: EntityId,
    pub roster: Vec<RoomPresence>,
    pub scope: Scope,
    pub posture: RoomPosture,
    pub claims: Vec<crate::memory::ClaimView>,
    /// The caller's read of the room's rules. Rules the caller could read but
    /// a present peer could not are counted as withheld rows.
    pub receipt: crate::claim::ScopedReadReceipt,
}

impl RoomSection {
    /// Roster, scope, posture and rules only. Values are escaped again by the
    /// board frame; flattening here only prevents row/control-character tricks.
    pub fn board_section(&self) -> std::result::Result<BoardSection, BoardFrameError> {
        let mut rows = vec![format!("room: {}", self.room.to_hex())];
        rows.extend(self.roster.iter().map(|member| {
            format!(
                "{} {} {}",
                member.actor.to_hex(),
                if member.present { "present" } else { "away" },
                one_line_token(&member.label)
            )
        }));
        let base = ScopeId(crate::claim::base_world_id());
        rows.push(format!(
            "scope: base={} worlds={}",
            self.scope.worlds.contains(&base),
            match &self.scope.worlds {
                ScopeAxis::All => "all".to_owned(),
                ScopeAxis::Bottom => String::new(),
                ScopeAxis::Some(ids) => ids
                    .iter()
                    .filter(|id| **id != base)
                    .map(|id| id.0.to_hex())
                    .collect::<Vec<_>>()
                    .join(","),
            }
        ));
        let mode = match self.posture.mode {
            RoomMode::Chime => "chime",
            RoomMode::AskedOnly => "asked-only",
            RoomMode::Silent => "silent",
        };
        let bar = match self.posture.bar {
            RoomBar::Low => "low",
            RoomBar::Med => "med",
            RoomBar::High => "high",
        };
        rows.push(if self.posture.mode == RoomMode::Chime {
            format!("posture: {mode} bar={bar}")
        } else {
            format!("posture: {mode}")
        });
        rows.extend(self.claims.iter().map(|claim| {
            format!(
                "{}: {} {}",
                claim.claim_ref,
                one_line_token(&claim.predicate),
                one_line_token(&claim.value.to_string())
            )
        }));
        BoardSection::new(
            "ROOM",
            rows,
            Vec::new(),
            Vec::new(),
            SectionPolicy {
                pinned: true,
                shed_rank: None,
            },
        )
    }
}
