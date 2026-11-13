//! The room role door (FIX [ROOM-ROLE-SET]; the lead 14 Nov 00:2x, under the
//! owner's 13 Nov 22:44 grant).
//!
//! `vault.rooms.members.role.set` sets a current member's role in an ordinary
//! room through [`crate::Vault::set_room_role`], under the authority that call
//! already holds: the caller is a PERSON whose own role in the room is one the
//! room policy lets delegate (`RoomAction::Delegate`). The
//! role and its host-local grant commit together. The reply is the act's
//! receipt: who set which role for whom, at the engine's recorded time of the
//! write; on the wire it also carries the call receipt every reply carries
//! (OF-538). An agent is no PERSON, so it never sets a role.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::conversation::RoomRole;
use crate::memory::{Memory, MemoryResult};

/// `vault.rooms.members.role.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomMemberRoleSet {
    /// The room.
    pub room: EntityId,
    /// The current member whose role changes.
    pub person: EntityId,
    /// The role the member holds once the act commits.
    pub role: RoomRole,
}

/// `vault.rooms.members.role.set`'s reply: the act's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomMemberRoleReceipt {
    pub room: EntityId,
    pub person: EntityId,
    pub role: RoomRole,
    /// The caller whose standing in the room delegated the role.
    pub set_by: EntityId,
    /// The engine's recorded time of the write.
    pub set_at: u64,
}

impl Memory<'_> {
    /// `vault.rooms.members.role.set`: sets `input.person`'s role in
    /// `input.room` as the bound caller ([`crate::Vault::set_room_role`]), and
    /// returns the act's receipt.
    pub fn rooms_members_role_set(
        &self,
        input: &RoomMemberRoleSet,
    ) -> MemoryResult<RoomMemberRoleReceipt> {
        let vault = self.vault();
        let caller = self.write_actor();
        let set_at = vault.set_room_role_recorded(input.room, input.person, input.role, caller)?;
        #[cfg(feature = "sync")]
        vault.refresh_room_cell_in_live_window(input.room, None);
        Ok(RoomMemberRoleReceipt {
            room: input.room,
            person: input.person,
            role: input.role,
            set_by: caller.entity_ref(),
            set_at,
        })
    }
}
