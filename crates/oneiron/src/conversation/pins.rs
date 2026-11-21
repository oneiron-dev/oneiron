//! The marker the room pin doors set while they rewrite a room body's shared
//! pins or pin policy (ROOM-SCOPED-PINS). The all-writer guard
//! ([`super::validate_put_in_txn`]) refuses any other change to them.
use super::*;
use crate::side_table::{self, Raw, SideTable};

/// `[1]` while a room pin door rewrites a room body, keyed by room.
pub(crate) const PIN_UPDATES: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_PIN_UPDATE);

/// A room body as a reader is served it: without its shared pins, which a
/// reader gets only through the room's own admitted projection, target by
/// target (ROOM-SCOPED-PINS; Engine ruling THREADTASK-PINS-SHAPE Q4 = A),
/// and without the records its unpins removed, which name pinners and
/// targets as the pins do (ROOM-PINS-LWW-MERGE). `None` when the bytes carry
/// neither key, so a room never pinned in is served byte for byte as stored.
pub(crate) fn served_room_body(body: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(mut entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    if !cursor.is_empty() {
        return Ok(None);
    }
    let before = entries.len();
    entries.retain(|(key, _)| !matches!(key.as_str(), Some("pins" | "unpinned")));
    if entries.len() == before {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries))
        .map_err(|_| crate::store::conversation_body::invalid("body encode"))?;
    Ok(Some(out))
}

/// A stored body of `entity_type` as it leaves this vault for a reader that
/// is not the owner's own copy: a room body without its shared pins, as
/// [`served_room_body`] serves it, its `pin_policy` kept (Engine ruling
/// EXPORTDOORS Q2 = A; FIX ROOM-PINS-WHOLE-BLOB-TRANSPORT). `None` for any
/// other kind, and for a room body with neither a `pins` nor an `unpinned`
/// key, which leaves as stored.
pub(crate) fn body_without_room_pins(entity_type: u8, body: &[u8]) -> Result<Option<Vec<u8>>> {
    if entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
        return Ok(None);
    }
    served_room_body(body)
}
