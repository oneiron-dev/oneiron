//! Delete the derived home room at the common entity deindex door.
use super::*;
use crate::store::Store;

pub(crate) fn deindex_project_room(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, Vec<EntityId>)> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok((false, false, Vec::new()));
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok((false, false, Vec::new()));
    };
    if !is_project_type(store, header.entity_type) {
        return Ok((false, false, Vec::new()));
    }
    let room_id = home_room_id(*id);
    let room_key = [ROOM_PROJECT, room_id.as_bytes()].concat();
    let owner = store.vault_meta.get(txn, &room_key)?;
    if owner.as_deref().is_some_and(|owner| owner != id.as_bytes()) {
        return Err(Error::CorruptedIndex("project room owner"));
    }
    if let Some(room) = record::<ProjectRoom>(store, txn, room_id, ENTITY_TYPE_CONVERSATION)? {
        if room.project_id != id.to_hex() {
            return Err(Error::CorruptedIndex("project room collision"));
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &room_id)?;
        store.vault_meta.delete(txn, &room_key)?;
        return Ok((vector, graph, neighbors));
    }
    store.vault_meta.delete(txn, &room_key)?;
    Ok((false, false, Vec::new()))
}
