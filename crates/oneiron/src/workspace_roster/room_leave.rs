//! The room leave door (FIX 3968).
//!
//! `rooms.leave` ends one person's live membership of a room as the bound
//! caller, through the same membership ledger as the HTTP member write's
//! `leave` action. A leave ends the person's current window and roles; the
//! participation it ended stays ended. Saving that rode on the live
//! participation stops with it, and a later `rooms.join` opens a new
//! membership rather than reviving the old one (ARCH-0052 #d5-save-grant,
//! #d5-bound-run).

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// Ends `person`'s current membership of `room`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomLeaveRequest {
    pub room: EntityId,
    pub person: EntityId,
}

/// The room's members once the leave committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomLeaveOutcome {
    pub member_ids: Vec<EntityId>,
}

impl Memory<'_> {
    /// Ends a person's current membership of a room for the bound actor, at
    /// the vault's recorded time, and returns the room's members after it.
    pub fn rooms_leave(&self, request: &RoomLeaveRequest) -> MemoryResult<RoomLeaveOutcome> {
        let vault = self.vault();
        let caller = self.write_actor();
        let member_ids = vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            vault.leave_member_in_txn(txn, request.room, request.person, caller, now)?;
            Ok::<_, MemoryError>(vault.members_in_txn(txn, request.room)?)
        })?;
        Ok(RoomLeaveOutcome { member_ids })
    }
}
