//! The marker the room closed-setting door sets while it rewrites whether a
//! room is closed (ARCH-0082 #closed-room). The all-writer guard
//! ([`super::validate_put_in_txn`]) refuses any other change to it.
use super::*;
use crate::side_table::{self, Raw, SideTable};

/// `[1]` while the room closed-setting door rewrites a room body, keyed by
/// room.
pub(crate) const CLOSED_UPDATES: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_CLOSED_UPDATE);
