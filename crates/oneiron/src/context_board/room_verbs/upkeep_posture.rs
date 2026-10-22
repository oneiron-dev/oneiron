//! The posture a room host's upkeep voice speaks under (ARCH-0067 §8,
//! OF-417): the mode [`Memory::rooms_render`] composes, read in the
//! caller's own snapshot so the voice's write rechecks it where it lands.
//! The same rules count: active `room.posture.mode` claims about the room
//! that the caller's lane reads, in the room's worlds, that every other
//! member reads too and that P7 lets the room see. Stricter wins. Only the
//! mode is read; the bar stays the host's own judgment.
use super::*;
use crate::claim::ScopedRead;
use crate::context_board::room::RoomMode;

impl Memory<'_> {
    /// `room`'s composed posture mode as `txn` reads it, under `lane`, the
    /// caller's Surfaceable lane taken before the snapshot. `None` when the
    /// caller does not read the room, or acts in another room's turn. Every
    /// rule about the room is read, however many (rule 5). A mode value the
    /// render would refuse holds the room as silent.
    pub(crate) fn room_upkeep_mode_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lane: &ScopedRead<'_>,
        room: EntityId,
    ) -> MemoryResult<Option<RoomMode>> {
        let vault = self.vault();
        if self.room_turn().is_some_and(|turn| turn.room != room) {
            return Ok(None);
        }
        let Some(members) = room_members_in(vault, txn, room)? else {
            return Ok(None);
        };
        if !room_reader_in(vault, txn, room, &members, self.actor())? {
            return Ok(None);
        }
        let worlds = reading_defaults_in(vault, txn, &members)?;
        let clearances = clearances_in(vault, txn, &members)?;
        let mut roster = members
            .into_iter()
            .zip(worlds.into_iter().zip(clearances))
            .map(|(member, (active_worlds, clearance))| RoomPresence {
                actor: member,
                actor_class: None,
                label: String::new(),
                present: true,
                active_worlds,
                clearance,
            })
            .collect::<Vec<_>>();
        roster.sort_by_key(|member| member.actor);
        let now = RoomTerms {
            worlds: room_worlds(&roster)?,
            facets: room_facets_axis_in(vault, txn, room)?,
            clearance: room_clearance(&roster),
            p7: true,
        };
        let terms = match self.room_turn() {
            Some(turn) => turn.terms.meet(&now),
            None => now,
        };
        let present: Vec<EntityId> = roster.iter().map(|member| member.actor).collect();
        let peers: Vec<_> = peer_read_keys_in(vault, txn, self.actor(), &present)?
            .into_iter()
            .map(|key| vault.scoped_read(key))
            .collect();
        let mut mode = RoomMode::default();
        for edge in crate::ports::EdgeStoreRead::port_edges(
            &vault.store,
            txn,
            &room,
            crate::ports::EdgeDirection::In,
            Some(crate::EdgeKind::ClaimOf),
            None,
        )? {
            let id = edge?.target;
            let Some((entity_type, _, body)) = lane
                .get_entities_parts_in_txn(txn, &[id])?
                .into_iter()
                .next()
                .flatten()
            else {
                continue;
            };
            if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let claim = crate::claim::decode_claim_body(&body, true)?;
            if claim.predicate != "room.posture.mode"
                || claim.lifecycle != crate::claim::ClaimLifecycleStatus::Active
            {
                continue;
            }
            let world = claim.world.unwrap_or_else(crate::claim::base_world_id);
            if !terms
                .worlds
                .worlds
                .contains(&crate::federation::ScopeId(world))
            {
                continue;
            }
            let mut peers_read = true;
            for peer in &peers {
                peers_read = peers_read
                    && peer
                        .entities_readable_in_txn(txn, &[id])?
                        .into_iter()
                        .all(|readable| readable);
            }
            if !peers_read || !self.upkeep_discloses_in(txn, room, &terms, &present, id)? {
                continue;
            }
            mode = mode.max(match claim.value.as_str() {
                Some("chime") => RoomMode::Chime,
                Some("asked_only") => RoomMode::AskedOnly,
                _ => RoomMode::Silent,
            });
        }
        Ok(Some(mode))
    }

    /// [`Self::room_discloses`] in the caller's snapshot `txn`.
    fn upkeep_discloses_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        terms: &RoomTerms,
        roster: &[EntityId],
        id: EntityId,
    ) -> MemoryResult<bool> {
        let vault = self.vault();
        let Some(now) = room_roster_in(vault, txn, room)? else {
            return Ok(false);
        };
        if now
            .iter()
            .any(|member| roster.binary_search(member).is_err())
        {
            return Ok(false);
        }
        let fresh = if terms.p7 {
            room_clearance_in(vault, txn, &now)?
        } else {
            None
        };
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
        let Some(record) =
            crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &id)?
        else {
            return Ok(false);
        };
        Ok(crate::disclosure::discloses_raw(
            vault,
            txn,
            &effective.room_scope(),
            id,
            &record.encode(),
        )?)
    }
}
