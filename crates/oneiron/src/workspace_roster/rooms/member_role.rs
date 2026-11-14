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
//! (OF-538). A person sets a role, never an agent: a caller bound as an
//! agent is refused before the role read, even a PERSON acting as an agent in
//! a room it created, as the pins policy door refuses one (review round 1 of
//! #7700).

use serde::{Deserialize, Serialize};

use crate::conversation::RoomRole;
use crate::error::{ClaimError, Error};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

const ROLE_BY_PERSON: &str = "a person sets a member's room role, never an agent";

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
    /// returns the act's receipt. A caller bound as anything but a human is
    /// refused.
    pub fn rooms_members_role_set(
        &self,
        input: &RoomMemberRoleSet,
    ) -> MemoryResult<RoomMemberRoleReceipt> {
        let vault = self.vault();
        let caller = self.write_actor();
        if caller.actor_class() != EdgeActorClass::Human {
            return Err(MemoryError::from(Error::Claim(
                ClaimError::ActorLacksClaimAuthority {
                    reason: ROLE_BY_PERSON,
                },
            )));
        }
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
