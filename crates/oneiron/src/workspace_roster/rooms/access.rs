//! One access path for every room (THREAD-TASK-EVERY-ROOM): a project's
//! home room, a project's extra room and a vault's ordinary room are read,
//! spoken in, bound and projected through the same roster.
//!
//! Entry: [`room_access_in`].

use super::*;
use crate::vault::live_entity_row_in_txn;

/// A live room as every room path reads it: its roster and, for a
/// project's home room, the record its project vouches for. Standing,
/// private audience and the read ceiling stay with their own checks; the
/// roster grants no memory scope.
#[derive(Debug, Clone)]
pub(in crate::workspace_roster) struct RoomAccess {
    /// The room's roster, as hex ids: a home room's effective project
    /// seats, any other room's membership ledger.
    pub(in crate::workspace_roster) member_ids: Vec<String>,
    /// The home room's record, `None` for every other room. Linking a room
    /// to a project as an extra room groups it and puts nothing here.
    pub(in crate::workspace_roster) home: Option<ProjectRoom>,
}

/// `room` as every room path reads it, in `txn`: a home room through its
/// project's signed history ([`room_in`]), any other live Conversation
/// through its own membership ledger. A room that is missing, deleted or
/// no Conversation is refused as an invalid room operation.
pub(in crate::workspace_roster) fn room_access_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<RoomAccess> {
    if !live_entity_row_in_txn(&vault.store, txn, &room)?.is_live() {
        return Err(invalid());
    }
    if let Some(record) = project_room_of(vault, txn, room)? {
        return Ok(RoomAccess {
            member_ids: record.member_ids.clone(),
            home: Some(record),
        });
    }
    Ok(RoomAccess {
        member_ids: vault
            .members_in_txn(txn, room)?
            .iter()
            .map(EntityId::to_hex)
            .collect(),
        home: None,
    })
}
