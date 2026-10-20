//! What the vault's Owner or an Admin learns of a room's private threads
//! (FIX 5545): that they exist, by root id, never what they say. Adding
//! itself to one's audience is what lets it read one. One the room's Scope
//! refuses finds those it is in the audience of alone (FIX 6210), and,
//! inside a turn bound to one thread, leaves out a root whose audience that
//! turn's held disclosure does not meet (FIX 6339). The list of every
//! private thread, by its five facts, is [`super::private_threads`].

use super::audience::{privileged_private_thread_reader_in, thread_binding};
use super::audience_doors::vault_owner_or_admin_in;
use super::*;
use crate::registry::ENTITY_TYPE_TURN;
use crate::scan_check::{EngineScan, ScanCount};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The private threads of a room shown to the vault's Owner or an Admin.
pub(super) struct OwnerRoots {
    /// Whether the reader also reads the room itself, whose threads it then
    /// finds as any reader does.
    pub(super) reads_room: bool,
    /// The roots of the room's private threads, ids alone.
    pub(super) roots: Vec<EntityId>,
}

impl Memory<'_> {
    /// For the vault's Owner or an Admin, the roots of `room`'s private
    /// threads, found by the room's history rows and each root's birth
    /// binding, with no turn's content read. `None` for any other reader,
    /// whose find is the room's read alone. None is listed when the room's
    /// Scope reads no turns. One the room's Scope refuses
    /// ([`Self::owner_off_room`]) is proved the Owner or an Admin before that
    /// Scope is asked for, and finds the roots it reads off the room alone,
    /// each when its own thread's Scope reads turns (FIX 6210).
    pub(super) fn owner_private_roots(&self, room: EntityId) -> MemoryResult<Option<OwnerRoots>> {
        if self.owner_off_room(room)? {
            let mut roots = Vec::new();
            for root in self.privileged_private_roots(room)? {
                if turns_readable(&self.thread_read_worlds(room, root)?) {
                    roots.push(root);
                }
            }
            return Ok(Some(OwnerRoots {
                reads_room: false,
                roots,
            }));
        }
        let worlds = self.room_read_worlds(room)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if !vault_owner_or_admin_in(vault, &txn, self.actor())? {
            return Ok(None);
        }
        room_in(vault, &txn, room)?;
        let reads_room = match require_reader(vault, &txn, room, self.actor()) {
            Ok(_) => true,
            Err(Error::InvalidConfig(_)) => false,
            Err(error) => return Err(error.into()),
        };
        let roots = if turns_readable(&worlds) {
            self.private_roots_in(txn, room, false)?
        } else {
            Vec::new()
        };
        Ok(Some(OwnerRoots { reads_room, roots }))
    }

    /// The roots of `room`'s private threads this reader reads with no
    /// standing in the room ([`privileged_private_thread_reader_in`]), ids
    /// alone, in the room's history order. A root whose audience the turn
    /// this handle is bound to does not disclose to is left out, as that
    /// thread's own ceiling would refuse it (FIX 6339); an error reading it
    /// still refuses.
    pub(super) fn privileged_private_roots(&self, room: EntityId) -> MemoryResult<Vec<EntityId>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        self.private_roots_in(txn, room, true)
    }

    /// The roots of `room`'s private threads as `txn` reads them, by the
    /// room's history rows and each root's birth binding; with `privileged`,
    /// only those this reader reads off the room, whose held audience check
    /// ([`Memory::reads_thread_audience_in`]) admits it. Every row is read,
    /// however many (rule 5); past the threshold row the owner's check is
    /// raised for the room.
    fn private_roots_in(
        &self,
        txn: heed::RoTxn<'_>,
        room: EntityId,
        privileged: bool,
    ) -> MemoryResult<Vec<EntityId>> {
        let vault = self.vault();
        let mut count = ScanCount::start(
            &vault.store,
            &txn,
            EngineScan::RoomHistoryRows,
            room.as_bytes(),
        )?;
        let mut roots = Vec::new();
        for row in HISTORY.iter_from(&vault.store, &txn, room.as_bytes())? {
            count.row();
            let (_, turn) = row?;
            if let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } = live_entity_row_in_txn(&vault.store, &txn, &turn)?
                && thread_binding(&body)?.is_some_and(|binding| {
                    binding.root == turn && binding.room == room && binding.audience.is_some()
                })
                && (!privileged
                    || (privileged_private_thread_reader_in(
                        vault,
                        &txn,
                        room,
                        turn,
                        self.actor(),
                    )? && self.reads_thread_audience_in(&txn, room, turn)?))
            {
                roots.push(turn);
            }
        }
        drop(txn);
        count.finish(vault);
        Ok(roots)
    }

    /// Whether this reader is the vault's Owner or an Admin whose read of
    /// `room` the room's Scope refuses: a room its project vouches for, which
    /// no turn this handle is bound to places elsewhere, and that this reader
    /// holds no seat in and reads on no other standing
    /// ([`crate::context_board::room_reader_in`]). Such a reader finds and
    /// reads the room's private threads it is in the audience of alone (FIX
    /// 6209, 6210); any other reads the room as before.
    pub(super) fn owner_off_room(&self, room: EntityId) -> MemoryResult<bool> {
        if self.room_turn().is_some_and(|turn| turn.room != room) {
            return Ok(false);
        }
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(members) = crate::context_board::room_roster_in(vault, &txn, room)? else {
            return Ok(false);
        };
        if crate::context_board::room_reader_in(vault, &txn, room, &members, self.actor())?
            || room_in(vault, &txn, room).is_err()
        {
            return Ok(false);
        }
        Ok(vault_owner_or_admin_in(vault, &txn, self.actor())?)
    }
}
