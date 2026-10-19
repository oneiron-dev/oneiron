//! What the vault's Owner or an Admin learns of a room's private threads
//! (FIX 5545): that they exist, by root id, never what they say. Adding
//! itself to one's audience is what lets it read one.

use super::audience::thread_binding;
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
    /// Scope reads no turns.
    pub(super) fn owner_private_roots(&self, room: EntityId) -> MemoryResult<Option<OwnerRoots>> {
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
        let mut roots = Vec::new();
        if turns_readable(&worlds) {
            // Every row is read, however many (rule 5); past the threshold
            // row the owner's check is raised for the room.
            let mut count = ScanCount::start(
                &vault.store,
                &txn,
                EngineScan::RoomHistoryRows,
                room.as_bytes(),
            )?;
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
                {
                    roots.push(turn);
                }
            }
            drop(txn);
            count.finish(vault);
        }
        Ok(Some(OwnerRoots { reads_room, roots }))
    }
}
