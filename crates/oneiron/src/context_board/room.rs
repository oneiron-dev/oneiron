//! Stateless ROOM projection and the one roster-to-Scope function.

use super::people::{PeopleView, PersonKind, PersonRow};
use super::{BoardFrameError, BoardSection, SectionPolicy, one_line_token};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::pipeline::WorldAuthoritySet;
use crate::{EntityId, Result};

#[cfg(test)]
mod tests;

/// Most persons the ROOM `invite?:` line names; the rest are counted.
const ROOM_INVITE_CAP: usize = 5;

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
    /// The member's contact clearance (ILDF2). `None` for the vault owner
    /// and the vault's own agents, which add no clearance term; bottom for a
    /// member with no contact or an unknown, revoked or undecodable one.
    pub clearance: Option<Scope>,
}

/// One party to the roster-to-Scope meet: a room member, or a resolved
/// interlocutor, whose only term is its clearance (`Option<Scope>`).
pub trait RosterParty {
    /// Whether the party is in the meet.
    fn present(&self) -> bool;
    /// The worlds the party reads by default, if it brings a world term.
    fn worlds(&self) -> Option<&WorldAuthoritySet>;
    /// The party's clearance term; `None` adds none.
    fn clearance(&self) -> Option<&Scope>;
}

impl RosterParty for RoomPresence {
    fn present(&self) -> bool {
        self.present
    }
    fn worlds(&self) -> Option<&WorldAuthoritySet> {
        Some(&self.active_worlds)
    }
    fn clearance(&self) -> Option<&Scope> {
        self.clearance.as_ref()
    }
}

impl RosterParty for WorldAuthoritySet {
    fn present(&self) -> bool {
        true
    }
    fn worlds(&self) -> Option<&WorldAuthoritySet> {
        Some(self)
    }
    fn clearance(&self) -> Option<&Scope> {
        None
    }
}

impl RosterParty for Option<Scope> {
    fn present(&self) -> bool {
        true
    }
    fn worlds(&self) -> Option<&WorldAuthoritySet> {
        None
    }
    fn clearance(&self) -> Option<&Scope> {
        self.as_ref()
    }
}

/// ARCH-0067 §8 and ILDF2 R17: the only function from a roster to a Scope,
/// also exported as `disclosure::disclosable_set`. It meets the present
/// parties' world sets into the room's world ceiling, then meets in every
/// present party's clearance. The owner and the vault's own agents add no
/// clearance term, so with no other party present the clearance half is the
/// top (P1). A record is disclosed under the result iff it is positively
/// public or sits under it (P7). No party present gives bottom, and a party
/// who joins can only narrow the result.
pub fn room_scope<P: RosterParty>(roster: &[P]) -> Result<Scope> {
    let worlds = room_worlds(roster)?;
    Ok(match room_clearance(roster) {
        Some(clearance) => worlds.meet(&clearance),
        None => worlds,
    })
}

/// The clearance half of [`room_scope`]: the meet of the present parties'
/// clearances, `None` while no present party brings one.
pub(crate) fn room_clearance<P: RosterParty>(roster: &[P]) -> Option<Scope> {
    roster
        .iter()
        .filter(|party| party.present())
        .filter_map(RosterParty::clearance)
        .fold(None, |met, term| {
            crate::claim::meet_clearance(met.as_ref(), Some(term))
        })
}

/// The world ceiling of [`room_scope`]: the meet of the present parties'
/// world sets, every other axis open. Every row a room reads lies in it,
/// public or not; a clearance narrows only what may be disclosed.
pub(crate) fn room_worlds<P: RosterParty>(roster: &[P]) -> Result<Scope> {
    let mut present = roster.iter().filter(|party| party.present()).peekable();
    if present.peek().is_none() {
        return Ok(Scope::default());
    }
    // Each party's world set is a worlds axis with base an ordinary member
    // (R13); the room's axis is their meet, open while no party brings one.
    let mut scope = Scope::top();
    for set in present.filter_map(RosterParty::worlds) {
        scope.worlds = scope.worlds.meet(&set.scope_axis());
    }
    Ok(scope)
}

/// The world axis of a room Scope as a retrieval world set, or `None` when
/// the axis is open.
pub(crate) fn scope_worlds(scope: &Scope) -> Result<Option<WorldAuthoritySet>> {
    WorldAuthoritySet::from_scope_axis(&scope.worlds)
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
    /// The room's own open offer cards (OF-530 ruling A), read fresh: each
    /// stays listed while it is open.
    pub offers: Vec<crate::workspace_roster::OfferCard>,
    /// The caller's read of the room's rules. Rules the caller could read but
    /// a present peer could not are counted as withheld rows.
    pub receipt: crate::claim::ScopedReadReceipt,
    /// Who holds the room's speaking duty among a named session's present
    /// participants (ARCH-0067 §8). `None` when no session was read, so the
    /// section renders no host line rather than guessing who is present.
    pub host: Option<crate::workspace_roster::RoomHosting>,
    /// The PERSONs the reader may bring into the room by a roster write it
    /// could sign (FIX 1163): the only ones `invite?:` suggests.
    pub invitable: std::collections::BTreeSet<EntityId>,
}

impl RoomSection {
    /// Roster, invitees, scope, posture, host, rules and open offers only.
    /// Invitees are the reader's people it may invite ([`Self::invitable`]).
    /// Values are escaped again by the board frame; flattening here only
    /// prevents row/control-character tricks. An undecided host renders as
    /// no host with its candidates. Persons are named by handle (PEOPLE,
    /// ARCH-0067), with their name inline when the reader's cached roster
    /// lacks them.
    pub fn board_section(
        &self,
        people: &PeopleView<'_>,
    ) -> std::result::Result<BoardSection, BoardFrameError> {
        let mut rows = vec![format!("room: {}", self.room.to_hex())];
        rows.extend(self.roster.iter().map(|member| {
            let kind = people
                .kind(member.actor)
                .or(match member.actor_class {
                    Some(crate::EdgeActorClass::Human) => Some(PersonKind::Human),
                    Some(crate::EdgeActorClass::Agent) => Some(PersonKind::Agent),
                    _ => None,
                })
                .map_or("agent", PersonKind::as_str);
            let state = if member.present { "present" } else { "away" };
            match people.mention(member.actor) {
                Some(mention) => format!("{mention} {state} {kind}"),
                None => format!(
                    "{} {state} {kind} {}",
                    member.actor.to_hex(),
                    one_line_token(&member.label)
                ),
            }
        }));
        let members: std::collections::BTreeSet<EntityId> = self
            .roster
            .iter()
            .filter_map(|member| people.people.get(member.actor).map(|row| row.person))
            .collect();
        let invitees: Vec<&PersonRow> = people
            .people
            .rows()
            .iter()
            .filter(|row| !members.contains(&row.person) && self.invitable.contains(&row.person))
            .collect();
        if !invitees.is_empty() {
            let mut line = format!(
                "invite?: {}",
                invitees
                    .iter()
                    .take(ROOM_INVITE_CAP)
                    .map(|row| people.label(row.person))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            if invitees.len() > ROOM_INVITE_CAP {
                line.push_str(&format!(" +{}", invitees.len() - ROOM_INVITE_CAP));
            }
            rows.push(line);
        }
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
        if let Some(hosting) = &self.host {
            rows.push(match hosting.host {
                Some(host) => format!("host: {}", people.label(host)),
                None => format!(
                    "host: none candidates={}",
                    hosting
                        .candidates
                        .iter()
                        .map(|candidate| people.label(*candidate))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            });
        }
        rows.extend(self.claims.iter().map(|claim| {
            format!(
                "{}: {} {}",
                claim.claim_ref,
                one_line_token(&claim.predicate),
                one_line_token(&claim.value.to_string())
            )
        }));
        // Each open room-wide card, with the moment it ends unless engaged
        // again and the verbs that vote on and answer it.
        rows.extend(self.offers.iter().map(|card| {
            let cost = card.lease_cap.as_ref().map_or_else(
                || "none".to_owned(),
                |cap| format!("{} {}", cap.units, cap.unit.as_str()),
            );
            let ends = card.until.unwrap_or_else(|| {
                card.last_engaged_at
                    .saturating_add(crate::workspace_roster::ROOM_OFFER_IDLE_SECS)
            });
            format!(
                "offer: {} agent={} what={} artifact={} cost={} until={} vote=vault.rooms.offer.vote answer=vault.rooms.offer.answer",
                card.offer_id,
                people.label(card.agent),
                one_line_token(&card.what),
                one_line_token(card.artifact_ref.as_deref().unwrap_or("-")),
                one_line_token(&cost),
                ends,
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
