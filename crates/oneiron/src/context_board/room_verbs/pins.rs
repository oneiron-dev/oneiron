//! A room's shared pins as one reader sees them (ROOM-SCOPED-PINS P2;
//! Engine TASK 00:05 rule 4, ruling THREADTASK-PINS-SHAPE 00:51).
//!
//! The stored list is never served. A reader gets a pin only when all of
//! these admit it:
//! - its standing in the room, as the ROOM section reads it
//!   ([`Memory::room_roster`]): a member, a Ready join, a leader chat or the
//!   host, with the room's record in the caller's own grants. An outsider or
//!   a former member is refused as for an unknown room.
//! - the target, read as itself through the caller's room read
//!   ([`Memory::for_room_projection`]): a person's own read of the room, an
//!   agent's held one. A private thread, history a late joiner was not given,
//!   a revoked grant or a deleted target withholds it.
//! - the room's P7 disclosure, as each room rule meets it, and the board's
//!   disclosure clamp when the caller passes one.
//!
//! A withheld target leaves nothing: no row, reference, record or count. Its
//! read's receipt is dropped, so no suppression total counts it either.
//! Pinning grants no read, and who may pin (P1's writer rule and its
//! Managers policy) is no read rule.

use super::super::memories::{MemoriesSection, MemoryRow};
use super::super::memory_pins::pinned_row;
use super::super::room::RoomPresence;
use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead, RoomTerms};
use crate::conversation::RoomPin;
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// Puts the shared pins of `room` the caller sees into `section`'s PINNED
    /// tier, each row carrying its pin record, and returns those records in
    /// the room's stored order. Each target is read through the caller's room
    /// read, the room's P7 and `disclosure`, as the module says; a withheld
    /// one adds no row, record, receipt or count. A target the section holds
    /// already renders once: the room's row takes its place with the full
    /// admitted text and keeps a hook's tag. PINNED rows are never cut for
    /// budget, so every admitted pin rides the board.
    ///
    /// # Errors
    ///
    /// A caller that does not read `room` is refused as for an unknown room.
    pub fn include_room_pins(
        &self,
        room: EntityId,
        section: &mut MemoriesSection,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> MemoryResult<Vec<RoomPin>> {
        let roster = self.room_roster(room)?;
        let terms = self.turn_terms_now(room, &roster)?;
        let admitted = self.admitted_room_pins(room, &roster, &terms, disclosure)?;
        let mut records = Vec::with_capacity(admitted.len());
        for (pin, mut row) in admitted {
            if let Some(old) = section.rows.iter().find(|old| old.id == row.id) {
                row.hook = old.hook.clone();
            }
            section.rows.retain(|old| old.id != row.id);
            section.rows.push(row);
            records.push(pin);
        }
        section.refinish();
        Ok(records)
    }

    /// The shared pins of `room` the caller sees under `terms`, the terms its
    /// `roster` gives the room now, each with its target's PINNED row and the
    /// row's FICTION mark, in the room's stored order. The caller has proven
    /// its standing ([`Memory::room_roster`]).
    pub(super) fn admitted_room_pins(
        &self,
        room: EntityId,
        roster: &[RoomPresence],
        terms: &RoomTerms,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> MemoryResult<Vec<(RoomPin, MemoryRow)>> {
        let stored = {
            let vault = self.vault();
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            crate::workspace_roster::stored_room_pins_in(vault, &txn, room)?
        };
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let turn = self.for_room_projection(room)?;
        let read = turn.memory().read_lane(ClaimReadStatus::Surfaceable)?;
        let mut present: Vec<EntityId> = roster
            .iter()
            .filter(|member| member.present)
            .map(|member| member.actor)
            .collect();
        present.sort_unstable();
        let mut pins = Vec::with_capacity(stored.len());
        let mut fenced = MemoriesSection::pins_only(None);
        for pin in stored {
            // The receipt is dropped: a withheld target is counted nowhere.
            let (_, row) = pinned_row(&read, PointRead::id(pin.target), None, disclosure)?;
            let Some(mut row) = row else {
                continue;
            };
            if !self.room_discloses(room, terms, &present, pin.target)? {
                continue;
            }
            row.room_pin = Some(pin.clone());
            fenced.rows.push(row);
            pins.push(pin);
        }
        // The FICTION marks of these rows alone, under the read that admitted
        // them: a section's other rows keep the marks their own reads set.
        fenced.fence_fiction_worlds(&read)?;
        Ok(pins.into_iter().zip(fenced.rows).collect())
    }
}
