//! The extra-room index: from an extra room to the project that groups it, rebuilt from the room
//! body's `project_group` key at every CONVERSATION put.

use crate::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::conversation_body::{ROOM_PROJECT_GROUP_KEY, invalid};
use heed::RwTxn;

/// Rebuild the extra-room index row for room `id` from its CONVERSATION body `data`, read as a
/// raw rmpv map (never decoded as `ConversationBody`, so a ProjectRoom-shaped home-room body also
/// passes): a canonical 32-hex `project_group` puts the room-to-project row; an absent key or an
/// empty body deletes it; a malformed value is refused.
pub(crate) fn index_extra_room(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<()> {
    if data.is_empty() {
        super::EXTRA_ROOM_PROJECT.delete(store, txn, &id)?;
        return Ok(());
    }
    let mut cursor = std::io::Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("body decode"))?;
    let rmpv::Value::Map(entries) = value else {
        return Err(invalid("body must be a map"));
    };
    for (key, val) in &entries {
        if key.as_str() != Some(ROOM_PROJECT_GROUP_KEY) {
            continue;
        }
        let Some(link) = val.as_str() else {
            return Err(invalid("invalid project_group"));
        };
        let project = EntityId::from_hex(link).map_err(|_| invalid("invalid project_group"))?;
        if project.to_hex() != link {
            return Err(invalid("invalid project_group"));
        }
        super::EXTRA_ROOM_PROJECT.put(store, txn, &id, &project)?;
        return Ok(());
    }
    super::EXTRA_ROOM_PROJECT.delete(store, txn, &id)?;
    Ok(())
}
