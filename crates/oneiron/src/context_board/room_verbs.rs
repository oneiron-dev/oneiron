//! The rooms.* facade family delegates to existing reads, witness and claim gates.

use super::room::{RoomPresence, room_clearance, room_worlds};
use crate::claim::{PointRead, RoomTerms, RoomTurnCeiling};
use crate::federation::Scope;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

mod ceiling;
mod live_audience;
mod projection;
mod thread_readers;
mod upkeep_posture;

pub(crate) use ceiling::room_facets_axis_in;
pub use projection::RoomSectionPage;
pub(crate) use thread_readers::{
    off_room_reader_clearance_in, public_thread_live_speakers_in, thread_ceiling_in,
    thread_reader_in,
};

impl Memory<'_> {
    /// The room's roster (ARCH-0067 §8): the channel Conversation's members,
    /// each with the worlds that member reads by default. The engine reads
    /// all of it from the room's owning record; no request supplies any part.
    /// Runtime presence is writable by any authenticated writer, so it never
    /// takes a member out of the meet: every member counts as present.
    /// Membership alone reads nothing: the caller's own grants must admit the
    /// room's record as well.
    pub fn room_roster(&self, room: EntityId) -> MemoryResult<Vec<RoomPresence>> {
        let roster = self.roster_of(room)?;
        if !self.room_record_readable(room)? {
            return Err(unknown_room());
        }
        Ok(roster)
    }

    /// The roster the room's own record holds, for a caller that reads it
    /// ([`room_reader_in`]): a member, or an agent on a Ready join. Deriving
    /// the room's Scope from it shows the caller nothing.
    fn roster_of(&self, room: EntityId) -> MemoryResult<Vec<RoomPresence>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let members = room_members_in(vault, &txn, room)?.ok_or_else(unknown_room)?;
        if !room_reader_in(vault, &txn, room, &members, self.actor())? {
            return Err(unknown_room());
        }
        let worlds = reading_defaults_in(vault, &txn, &members)?;
        let clearances = clearances_in(vault, &txn, &members)?;
        drop(txn);
        let mut roster = members
            .into_iter()
            .zip(worlds.into_iter().zip(clearances))
            .map(|(member, (active_worlds, clearance))| RoomPresence {
                actor: member,
                actor_class: (member == self.actor()).then(|| self.actor_class()),
                label: member.to_hex(),
                present: true,
                active_worlds,
                clearance,
            })
            .collect::<Vec<_>>();
        roster.sort_by_key(|member| member.actor);
        Ok(roster)
    }

    /// Whether the caller's own grants admit the room's record, which holds
    /// its roster and origin. It decides a room read beside membership and
    /// never serves the row. Through a turn the record must also sit in the
    /// facets the turn holds, which only narrow.
    pub(crate) fn room_record_readable(&self, room: EntityId) -> MemoryResult<bool> {
        let read = self
            .own_read_lane(crate::claim::ClaimReadStatus::Recorded)?
            .read(&[PointRead::id(room)], None)?;
        Ok(read.value.into_iter().flatten().next().is_some()
            && (self.room_turn().is_none()
                || self
                    .read_lane(crate::claim::ClaimReadStatus::Recorded)?
                    .facets_allow_id(&room)?))
    }

    /// Refuses a turn in a room whose own row sits outside the facets this
    /// caller's credential reads, as it refuses an unknown room (owner ruling
    /// FACET-READ): the turn would confirm the room and report its Scope.
    pub(crate) fn require_room_in_facets(&self, room: EntityId) -> MemoryResult<()> {
        if self
            .own_read_lane(crate::claim::ClaimReadStatus::Recorded)?
            .facets_allow_id(&room)?
        {
            Ok(())
        } else {
            Err(unknown_room())
        }
    }

    /// P7 for one rule `room` renders under `terms`, judged in the snapshot
    /// that reads the rule: the clearance `terms` captured with `roster`
    /// meets the room's clearance in this snapshot, so a clearance narrowed
    /// since never renders the rule; through a turn, that meets into the
    /// turn and the turn decides. A member who joined since, whose own read
    /// the render never checked, keeps the rule out. See
    /// [`crate::disclosure::discloses_raw`].
    pub(super) fn room_discloses(
        &self,
        room: EntityId,
        terms: &RoomTerms,
        roster: &[EntityId],
        id: EntityId,
    ) -> MemoryResult<bool> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let Some(now) = room_roster_in(vault, &txn, room)? else {
            return Ok(false);
        };
        if now
            .iter()
            .any(|member| roster.binary_search(member).is_err())
        {
            return Ok(false);
        }
        let fresh = if terms.p7 {
            room_clearance_in(vault, &txn, &now)?
        } else {
            None
        };
        // Through a turn, the turn's own terms decide: they hold the
        // captured ones and every narrowing a read has met since.
        let effective = match self.room_turn() {
            Some(turn) => {
                turn.terms.meet_clearance(fresh.as_ref());
                turn.terms.get()
            }
            None => RoomTerms {
                clearance: crate::claim::meet_clearance(terms.clearance.as_ref(), fresh.as_ref()),
                ..terms.clone()
            },
        };
        if effective.clearance.is_none() {
            return Ok(true);
        }
        let Some(record) = vault.store.port_entity_record(&txn, &id)? else {
            return Ok(false);
        };
        Ok(crate::disclosure::discloses_raw(
            vault,
            &txn,
            &effective.room_scope(),
            id,
            &record.encode(),
        )?)
    }

    /// The ARCH-0022 reading default of each actor under one authority
    /// snapshot: a grant row the authority fold quarantines never counts.
    pub(crate) fn reading_defaults(
        &self,
        actors: &[EntityId],
    ) -> MemoryResult<Vec<crate::pipeline::WorldAuthoritySet>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        Ok(reading_defaults_in(vault, &txn, actors)?)
    }

    /// The Scope every read of `room` runs inside. A handle bound to this
    /// room's turn keeps the Scope the turn opened with, met with the current
    /// roster: a grant added mid-turn cannot widen it, and a removal narrows it.
    pub fn room_read_scope(&self, room: EntityId) -> MemoryResult<Scope> {
        self.refuse_other_room(room)?;
        Ok(self
            .turn_terms_now(room, &self.roster_of(room)?)?
            .room_scope())
    }

    /// The world ceiling of [`Self::room_read_scope`], the same way: every
    /// row `room` reads lies in it, public or not.
    pub(crate) fn room_read_worlds(&self, room: EntityId) -> MemoryResult<Scope> {
        self.refuse_other_room(room)?;
        Ok(self.turn_terms_now(room, &self.roster_of(room)?)?.worlds)
    }

    /// A turn bound to one room reads no other room, and says nothing about it.
    fn refuse_other_room(&self, room: EntityId) -> MemoryResult<()> {
        match self.room_turn() {
            Some(turn) if turn.room != room => Err(MemoryError::bad_request_with(
                "room differs from the bound room turn",
                &[],
            )),
            _ => Ok(()),
        }
    }

    /// The terms `roster` gives `room`, met into the turn this handle is
    /// bound to, if any: the turn keeps what it held and narrows with the
    /// roster now. A turn bound to another room refuses.
    fn turn_terms_now(&self, room: EntityId, roster: &[RoomPresence]) -> MemoryResult<RoomTerms> {
        self.refuse_other_room(room)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let now = RoomTerms {
            worlds: room_worlds(roster)?,
            facets: room_facets_axis_in(vault, &txn, room)?,
            clearance: room_clearance(roster),
            p7: true,
        };
        Ok(match self.room_turn() {
            Some(turn) => turn.terms.meet(&now),
            None => now,
        })
    }

    /// The ceiling `room` puts on this caller's reads now, from one snapshot.
    pub(crate) fn room_ceiling(&self, room: EntityId) -> MemoryResult<RoomTurnCeiling> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        room_ceiling_in(vault, &txn, room, self.actor())?.ok_or_else(unknown_room)
    }

    /// The ceiling thread `thread` of `room` puts on this caller's reads now
    /// ([`thread_ceiling_in`]), met into the turn this handle is bound to,
    /// as [`Self::room_turn_now`] meets the room's. A turn bound to another
    /// room refuses.
    pub(crate) fn thread_ceiling(
        &self,
        room: EntityId,
        thread: EntityId,
    ) -> MemoryResult<RoomTurnCeiling> {
        self.refuse_other_room(room)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let now =
            thread_ceiling_in(vault, &txn, room, thread, self.actor())?.ok_or_else(unknown_room)?;
        // A held room turn discloses to its whole roster: it moves into a
        // private thread (FIX 2951) only when that roster is its audience.
        if !self.reads_thread_audience_in(&txn, room, thread)? {
            return Err(unknown_room());
        }
        drop(txn);
        // The thread stays personal or held as the bound turn is.
        Ok(match self.room_turn() {
            Some(turn) => {
                turn.terms.meet(&now.terms.get());
                RoomTurnCeiling {
                    terms: turn.terms.clone(),
                    personal: turn.personal,
                    ..now
                }
            }
            None => now,
        })
    }

    /// The world ceiling of [`Self::thread_ceiling`], as
    /// [`Self::room_read_worlds`] gives the room's: every row the thread
    /// reads lies in it.
    pub(crate) fn thread_read_worlds(
        &self,
        room: EntityId,
        thread: EntityId,
    ) -> MemoryResult<Scope> {
        Ok(self.thread_ceiling(room, thread)?.terms.get().worlds)
    }

    /// The ceiling a bound handle reads under now: the room's current terms
    /// met into the turn's, and the current roster as the audience, the same
    /// membership the room's own history reads check. A change mid-turn can
    /// only narrow the turn, and the turn keeps the narrowing for its later
    /// reads. Each row is checked again against the room as its own snapshot
    /// reads it. A turn bound to one thread rebuilds through that thread's
    /// ceiling ([`thread_ceiling_in`]), so a thread-only reader keeps reading
    /// it; a room turn reads as before. It stays personal or held as the
    /// turn is.
    pub(crate) fn room_turn_now(&self) -> MemoryResult<Option<RoomTurnCeiling>> {
        let Some(turn) = self.room_turn() else {
            return Ok(None);
        };
        let now = match turn.branch {
            Some(thread) => {
                let vault = self.vault();
                let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
                thread_ceiling_in(vault, &txn, turn.room, thread, self.actor())?
                    .ok_or_else(unknown_room)?
            }
            None => self.room_ceiling(turn.room)?,
        };
        turn.terms.meet(&now.terms.get());
        Ok(Some(RoomTurnCeiling {
            terms: turn.terms.clone(),
            personal: turn.personal,
            ..now
        }))
    }

    /// One read key per other member; see [`peer_read_keys_in`].
    pub(crate) fn peer_read_keys(
        &self,
        members: &[EntityId],
    ) -> MemoryResult<Vec<crate::claim::ScopedReadActorKey>> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        Ok(peer_read_keys_in(
            self.vault(),
            &txn,
            self.actor(),
            members,
        )?)
    }
}

impl Vault {
    /// The world set a room of `members` reads inside (ARCH-0067 §8): the
    /// meet of their ARCH-0022 reading defaults in one snapshot, the world
    /// ceiling of `room_scope`. A host bounds a room assembly by it. A room
    /// of no members reads no world; `None` bounds none.
    pub fn room_world_set(
        &self,
        members: &[EntityId],
    ) -> crate::Result<Option<crate::pipeline::WorldAuthoritySet>> {
        let txn = self.store.env.read_txn()?;
        let defaults = reading_defaults_in(self, &txn, members)?;
        super::scope_worlds(&room_worlds(&defaults)?)
    }
}

/// The one refusal for a room the caller cannot read: missing, deleted, not
/// a Conversation, or not the caller's. Nothing about the record leaks first.
fn unknown_room() -> MemoryError {
    MemoryError::bad_request_with("unknown room", &[])
}

/// A room's members from its owning record in `txn`: a project home room's
/// validated roster, or an ordinary Conversation's membership ledger, of any
/// kind (channel, direct, group, agent or mirror: one room substrate). A
/// body's unchecked extension fields never stand in for either. `None` is a
/// room that is missing, deleted, not a valid Conversation, or holds no valid
/// roster.
fn room_members_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> crate::Result<Option<Vec<EntityId>>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live() {
        return Ok(None);
    }
    let conversation = vault
        .store
        .port_entity_record(txn, &room)?
        .filter(|record| record.entity_type == crate::registry::ENTITY_TYPE_CONVERSATION)
        .is_some_and(|record| {
            crate::conversation::ConversationBody::from_bytes(&record.body).is_ok()
        });
    if !conversation {
        return Ok(None);
    }
    // The owning writer bounds the membership; the Scope reads all of it.
    Ok(vault.room_audience_members_in_txn(txn, room).ok())
}

/// The ARCH-0022 reading default of each actor in `txn`'s authority
/// snapshot: a grant row the authority fold quarantines never counts.
fn reading_defaults_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actors: &[EntityId],
) -> crate::Result<Vec<crate::pipeline::WorldAuthoritySet>> {
    let grants = crate::pipeline::WorldGrantIndex::read(&vault.store, txn)?;
    // Folded once, and only when some member is under world-access law.
    let fold = std::cell::OnceCell::new();
    let admit = |id: &EntityId, body: &crate::claim::ClaimBody| -> crate::Result<bool> {
        if fold.get().is_none() {
            let _ = fold.set(vault.authority_fold_readonly_in_txn(txn)?);
        }
        let fold = fold.get().expect("authority fold was just set");
        crate::authority::claim_causal_admitted(&vault.store, txn, fold, id, body)
    };
    let now = crate::unix_seconds_now();
    actors
        .iter()
        .map(|actor| {
            crate::pipeline::reading_default(&vault.store, txn, &grants, &admit, *actor, now)
        })
        .collect()
}

/// Each member's clearance term in `txn` (ILDF2): none for the vault owner
/// and the vault's own agents, else the member's contact clearance, bottom
/// when there is none.
fn clearances_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    members: &[EntityId],
) -> crate::Result<Vec<Option<Scope>>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    members
        .iter()
        .map(|member| {
            crate::disclosure::room_party_in(vault, txn, &fold, *member)?.clearance_in(vault, txn)
        })
        .collect()
}

/// The met clearance of `members` as `txn` reads it: [`room_clearance`]
/// over [`clearances_in`]. Cheap enough for every row a turn serves.
pub(crate) fn room_clearance_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    members: &[EntityId],
) -> crate::Result<Option<Scope>> {
    Ok(room_clearance(&clearances_in(vault, txn, members)?))
}

/// One read key per member other than `caller`. A member positively known
/// as the vault owner reads with the owner's key. Any other member names no
/// class, so only class-agnostic grants admit it, and its access grants
/// apply.
fn peer_read_keys_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: EntityId,
    members: &[EntityId],
) -> crate::Result<Vec<crate::claim::ScopedReadActorKey>> {
    let embedded_owner = crate::vault::embedded_owner_actor_id()?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    members
        .iter()
        .filter(|member| **member != caller)
        .map(|member| {
            if crate::disclosure::is_vault_owner(&fold, embedded_owner, member) {
                return Ok(crate::claim::ScopedReadActorKey::vault_owner(*member));
            }
            // The same positive and private-access gates the member's own
            // reads pass.
            crate::claim::ScopedReadActorKey::new(member.to_hex())
                .map(|key| key.require_access_grants(Some(*member)))
                .ok_or_else(|| crate::Error::InvalidConfig("invalid room actor".into()))
        })
        .collect()
}

/// The room's members as `txn` reads them, sorted and unique; `None` as for
/// [`room_members_in`]. A few point reads, cheap enough for every row.
pub(crate) fn room_roster_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> crate::Result<Option<Vec<EntityId>>> {
    Ok(room_members_in(vault, txn, room)?.map(|mut members| {
        members.sort_unstable();
        members.dedup();
        members
    }))
}

/// Whether `caller` reads `room` as `txn` reads it: a member of the room's
/// `members`; a person or an agent standing on a live OF-531 Ready join for
/// the room itself, a person's through its own pen
/// ([`crate::workspace_roster::room_join_audience_in`], OF-417); one of the
/// two actors a leader chat binds, while both still lead their projects
/// ([`crate::workspace_roster::leader_chat_reader_in`], FIX 3121); or the
/// room's host, its owner or a delegate (OF-530). A join, leader or host
/// standing opens the room's reads and takes no seat: the roster, and with
/// it the audience every disclosure meets, stays the members alone, and the
/// caller's own grants still bound each read.
pub(crate) fn room_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    members: &[EntityId],
    caller: EntityId,
) -> crate::Result<bool> {
    if members.contains(&caller)
        || crate::workspace_roster::room_join_audience_in(vault, txn, room, caller)?
        || crate::workspace_roster::leader_chat_reader_in(vault, txn, room, caller)?
    {
        return Ok(true);
    }
    let host = crate::WriteActor::new(caller, crate::EdgeActorClass::Human);
    Ok(crate::conversation::room_host_in_txn(vault, txn, room, host)?.is_some())
}

/// The ceiling `room` puts on `caller`'s reads as `txn` reads the room
/// (ARCH-0067 §8): `room_scope` over the roster in this snapshot, as its
/// world ceiling and its clearance, that roster as the audience, and every
/// other member's read key. The room's live speakers (FIX 1388/1389) join
/// the audience by their entry refs and meet an unknown's clearance; they
/// add no world, peer read or standing, and an incomplete live call holds
/// the build. One snapshot builds all of it, the same one that serves the
/// row it is checked against. `None` when `caller` does not read the room
/// here ([`room_reader_in`]); an agent on a Ready join reads it without
/// joining the roster. It is a held ceiling: only a personal read marks its
/// own (FIX 5545).
pub(crate) fn room_ceiling_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: EntityId,
) -> crate::Result<Option<RoomTurnCeiling>> {
    let Some(members) = room_roster_in(vault, txn, room)? else {
        return Ok(None);
    };
    if !room_reader_in(vault, txn, room, &members, caller)? {
        return Ok(None);
    }
    let live = vault.room_live_speaker_entries_in(txn, room)?;
    let speakers = vault.live_speaker_clearance_in(txn, &live)?;
    let mut ceiling =
        ceiling::room_turn_ceiling_in(vault, txn, room, caller, &members, speakers.as_ref())?;
    ceiling.roster = live_audience::with_entries(members, &live);
    Ok(Some(ceiling))
}
