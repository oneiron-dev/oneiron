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
    if ROOT.get(store, txn, &())? == Some(*id) {
        return Err(
            crate::error::RecordError::InvalidProjectBody("cannot delete root project").into(),
        );
    }
    for row in store.type_index.prefix_iter(txn, &[header.entity_type])? {
        let (key, _) = row?;
        let child_id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project type index"))?,
        )?;
        if let Some(child) = record::<ProjectRecord>(store, txn, child_id, header.entity_type)?
            && child.parent.as_deref() == Some(id.to_hex().as_str())
        {
            return Err(
                crate::error::RecordError::InvalidProjectBody("project has live children").into(),
            );
        }
    }
    let room_id = home_room_id(*id);
    super::super::rooms::delete_room_metadata(store, txn, room_id)?;
    let owner = ROOM_PROJECT.get(store, txn, &room_id)?;
    if owner.is_some_and(|owner| owner != *id) {
        return Err(Error::CorruptedIndex("project room owner"));
    }
    if let Some(room) = record::<ProjectRoom>(store, txn, room_id, ENTITY_TYPE_CONVERSATION)? {
        if room.project_id != id.to_hex() {
            return Err(Error::CorruptedIndex("project room collision"));
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &room_id)?;
        ROOM_PROJECT.delete(store, txn, &room_id)?;
        return Ok((vector, graph, neighbors));
    }
    ROOM_PROJECT.delete(store, txn, &room_id)?;
    Ok((false, false, Vec::new()))
}
