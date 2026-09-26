//! Stateless ROOM projection and ordinary world-scope intersection.

use super::{BoardFrameError, BoardSection, SectionPolicy, one_line_token};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::pipeline::WorldAuthoritySet;
use crate::{EntityId, Result};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

/// Host-resolved presence; authority comes from the normal turn resolver.
#[derive(Debug, Clone)]
pub struct RoomPresence {
    pub actor: EntityId,
    /// Class authenticated by the host; validated against the actor entity on each read.
    pub actor_class: Option<crate::EdgeActorClass>,
    pub label: String,
    pub present: bool,
    pub active_worlds: WorldAuthoritySet,
}

/// Meet the already narrowed per-turn world sets into the ordinary Scope.
/// The other axes remain unchanged; the ordinary read grants for each present
/// participant are checked separately at the read door. Joining cannot widen.
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
    // Keep the world-set bound and canonical normalization at this door too.
    let intersection = WorldAuthoritySet::new(base, worlds)?;
    let mut ids: BTreeSet<_> = intersection
        .worlds()
        .iter()
        .copied()
        // Base has its own boolean authority. A caller-supplied world ID
        // cannot smuggle that reserved Scope member into the intersection.
        .filter(|id| *id != crate::claim::base_world_id())
        .map(ScopeId)
        .collect();
    if intersection.include_base() {
        ids.insert(ScopeId(crate::claim::base_world_id()));
    }
    let mut scope = Scope::top();
    scope.worlds = if ids.is_empty() {
        ScopeAxis::Bottom
    } else {
        ScopeAxis::Some(ids)
    };
    Ok(scope)
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
        rows.push(format!(
            "scope: base={} worlds={}",
            self.scope
                .worlds
                .contains(&ScopeId(crate::claim::base_world_id())),
            match &self.scope.worlds {
                ScopeAxis::Some(ids) => ids
                    .iter()
                    .filter(|id| id.0 != crate::claim::base_world_id())
                    .map(|id| id.0.to_hex())
                    .collect::<Vec<_>>()
                    .join(","),
                _ => String::new(),
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
