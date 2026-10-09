//! The rooms.* facade family delegates to existing reads, witness and claim gates.

use super::room::{RoomBar, RoomMode, RoomPosture, RoomPresence, RoomSection, room_scope};
use crate::claim::{PointRead, RoomTurnCeiling};
use crate::federation::Scope;
use crate::memory::{ClaimListFilter, Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

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

    /// The roster the room's own record holds, for a caller that belongs to
    /// it. Deriving the room's Scope from it shows the caller nothing.
    fn roster_of(&self, room: EntityId) -> MemoryResult<Vec<RoomPresence>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let members = room_members_in(vault, &txn, room)?
            .filter(|members| members.contains(&self.actor()))
            .ok_or_else(unknown_room)?;
        let worlds = reading_defaults_in(vault, &txn, &members)?;
        drop(txn);
        let mut roster = members
            .into_iter()
            .zip(worlds)
            .map(|(member, active_worlds)| RoomPresence {
                actor: member,
                actor_class: (member == self.actor()).then(|| self.actor_class()),
                label: member.to_hex(),
                present: true,
                active_worlds,
            })
            .collect::<Vec<_>>();
        roster.sort_by_key(|member| member.actor);
        Ok(roster)
    }

    /// Whether the caller's own grants admit the room's record, which holds
    /// its roster and origin. It decides a room read beside membership and
    /// never serves the row.
    pub(crate) fn room_record_readable(&self, room: EntityId) -> MemoryResult<bool> {
        let read = self
            .own_read_lane(crate::claim::ClaimReadStatus::Recorded)?
            .read(&[PointRead::id(room)], None)?;
        Ok(read.value.into_iter().flatten().next().is_some())
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
        self.within_room_turn(room, room_scope(&self.roster_of(room)?)?)
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

    /// Meets `current` with the turn this handle is bound to, if any. A turn
    /// bound to another room refuses.
    pub(crate) fn within_room_turn(&self, room: EntityId, current: Scope) -> MemoryResult<Scope> {
        self.refuse_other_room(room)?;
        Ok(match self.room_turn() {
            Some(turn) => turn.scope.meet(&current),
            None => current,
        })
    }

    /// The ceiling `room` puts on this caller's reads now, from one snapshot.
    pub(crate) fn room_ceiling(&self, room: EntityId) -> MemoryResult<RoomTurnCeiling> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        room_ceiling_in(vault, &txn, room, self.actor())?.ok_or_else(unknown_room)
    }

    /// The ceiling a bound handle reads under now: the Scope the turn opened
    /// with, met with the room's current roster, and the current roster as
    /// the audience, the same membership the room's own history reads check.
    /// A change mid-turn can only narrow the Scope. Each row is checked again
    /// against the room as its own snapshot reads it.
    pub(crate) fn room_turn_now(&self) -> MemoryResult<Option<RoomTurnCeiling>> {
        let Some(turn) = self.room_turn() else {
            return Ok(None);
        };
        let now = self.room_ceiling(turn.room)?;
        Ok(Some(RoomTurnCeiling {
            scope: turn.scope.meet(&now.scope),
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

    /// Roster, scope, posture and rules, all read fresh. No copy of the board
    /// or of posture is stored anywhere.
    pub fn rooms_render(&self, room: EntityId) -> MemoryResult<RoomSection> {
        let roster = self.room_roster(room)?;
        // One rendered row per member: the board section keeps its own bound.
        if roster.len() > 1000 {
            return Err(MemoryError::bad_request_with(
                "room roster exceeds bound",
                &[],
            ));
        }
        let scope = self.within_room_turn(room, room_scope(&roster)?)?;
        let read = self.read_lane(crate::claim::ClaimReadStatus::Surfaceable)?;
        // Each rule must also pass every present peer's ordinary read.
        let present: Vec<_> = roster
            .iter()
            .filter(|member| member.present)
            .map(|member| member.actor)
            .collect();
        let peers: Vec<_> = self
            .peer_read_keys(&present)?
            .into_iter()
            .map(|key| self.vault().scoped_read(key))
            .collect();
        let crate::claim::ScopedReadResult {
            value: listed,
            mut receipt,
        } = self.claim_list(&ClaimListFilter {
            subject_ref: Some(room.to_hex()),
            predicate: None,
            lifecycle: Some("active".into()),
            // The native subject scan fails closed at its work bound. Room
            // output spends its own cap only after all visibility predicates.
            limit: crate::vault::MAX_EDGE_QUERY_RESULTS,
        })?;
        let reads = listed
            .iter()
            .map(|claim| EntityId::from_hex(&claim.claim_ref).map(PointRead::id))
            .collect::<crate::Result<Vec<_>>>()?;
        let own = read.read(&reads, None)?;
        receipt.restrict_with(&own.receipt);
        let peer_rows = peers
            .iter()
            .map(|peer| Ok(peer.read(&reads, None)?.value))
            .collect::<MemoryResult<Vec<_>>>()?;
        let mut claims = Vec::new();
        let mut posture = RoomPosture::default();
        let mut has_bar = false;
        for (index, claim) in listed.into_iter().enumerate() {
            let world = claim
                .world_ref
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?
                .unwrap_or_else(crate::claim::base_world_id);
            if own.value[index].is_none()
                || !scope.worlds.contains(&crate::federation::ScopeId(world))
            {
                continue;
            }
            if peer_rows.iter().any(|rows| rows[index].is_none()) {
                receipt.add_suppressed(1);
                continue;
            }
            if claims.len() == 1000 {
                return Err(crate::Error::IndexOverflow("visible room claims").into());
            }
            match (claim.predicate.as_str(), claim.value.as_str()) {
                ("room.posture.mode", Some(mode)) => {
                    posture.mode = posture.mode.max(match mode {
                        "chime" => RoomMode::Chime,
                        "asked_only" => RoomMode::AskedOnly,
                        "silent" => RoomMode::Silent,
                        _ => {
                            return Err(MemoryError::bad_request_with(
                                "invalid room posture mode",
                                &[],
                            ));
                        }
                    });
                }
                ("room.posture.bar", Some(bar)) => {
                    let bar = match bar {
                        "low" => RoomBar::Low,
                        "med" => RoomBar::Med,
                        "high" => RoomBar::High,
                        _ => {
                            return Err(MemoryError::bad_request_with(
                                "invalid room posture bar",
                                &[],
                            ));
                        }
                    };
                    posture.bar = if has_bar { posture.bar.max(bar) } else { bar };
                    has_bar = true;
                }
                _ => {}
            }
            claims.push(claim);
        }
        claims.sort_by(|a, b| a.claim_ref.cmp(&b.claim_ref));
        Ok(RoomSection {
            room,
            roster,
            scope,
            posture,
            claims,
            receipt,
        })
    }
}

/// The one refusal for a room the caller cannot read: missing, deleted, not
/// a channel, or not the caller's. Nothing about the record leaks first.
fn unknown_room() -> MemoryError {
    MemoryError::bad_request_with("unknown room", &[])
}

/// A channel's members from its owning record in `txn`: a project home
/// room's validated roster, or an ordinary channel's membership ledger. A
/// body's unchecked extension fields never stand in for either. `None` is a
/// room that is missing, deleted, not a channel, or holds no valid roster.
fn room_members_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> crate::Result<Option<Vec<EntityId>>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live() {
        return Ok(None);
    }
    let channel = vault
        .store
        .port_entity_record(txn, &room)?
        .filter(|record| record.entity_type == crate::registry::ENTITY_TYPE_CONVERSATION)
        .and_then(|record| crate::conversation::ConversationBody::from_bytes(&record.body).ok())
        .is_some_and(|body| body.kind == crate::conversation::ConversationKind::Channel);
    if !channel {
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

/// One read key per member other than `caller`. A member positively known
/// as the vault owner (the embedded owner, or a live human owner binding in
/// a rooted vault) reads with the owner's key. Any other member names no
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
            let owner = *member == embedded_owner
                || (fold.vault_id.is_some()
                    && crate::authority::actor_binding_is_active(&fold, member, "human"));
            if owner {
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

/// The ceiling `room` puts on `caller`'s reads as `txn` reads the room
/// (ARCH-0067 §8): `room_scope` over the roster in this snapshot, that roster
/// as the audience, and every other member's read key. One snapshot builds
/// all of it, the same one that serves the row it is checked against.
/// `None` when the room is not one `caller` belongs to here.
pub(crate) fn room_ceiling_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: EntityId,
) -> crate::Result<Option<RoomTurnCeiling>> {
    let Some(members) = room_roster_in(vault, txn, room)? else {
        return Ok(None);
    };
    if members.binary_search(&caller).is_err() {
        return Ok(None);
    }
    let worlds = reading_defaults_in(vault, txn, &members)?;
    let roster: Vec<_> = members
        .iter()
        .zip(worlds)
        .map(|(member, active_worlds)| RoomPresence {
            actor: *member,
            actor_class: None,
            label: String::new(),
            present: true,
            active_worlds,
        })
        .collect();
    Ok(Some(RoomTurnCeiling {
        room,
        caller,
        scope: room_scope(&roster)?,
        peers: peer_read_keys_in(vault, txn, caller, &members)?,
        roster: members,
    }))
}
