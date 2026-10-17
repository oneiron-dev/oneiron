//! Delete the derived home room at the common entity deindex door.
use super::*;
use crate::store::Store;

pub(crate) fn deindex_project_room(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<(bool, bool, Vec<EntityId>)> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
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
    {
        // Each child names its parents as its signed history folds them; a
        // child whose history serves no authority keeps its stored claim.
        let reader = super::read::ProjectReader::new(store, txn, store.privacy_posture)?;
        for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            store,
            txn,
            header.entity_type,
            None,
        )? {
            let child_id = row?;
            if child_id == *id {
                continue;
            }
            let effective = match &reader {
                Some(reader) => reader.effective(child_id)?,
                None => None,
            };
            let parents = match effective {
                Some(view) => view.parents,
                None => match record::<ProjectRecord>(store, txn, child_id, header.entity_type)? {
                    Some(child) => child.parents,
                    None => continue,
                },
            };
            if parents.contains(&id.to_hex()) {
                return Err(crate::error::RecordError::InvalidProjectBody(
                    "project has live children",
                )
                .into());
            }
        }
    }
    origin::deindex_origin(store, txn, *id)?;
    let room_id = home_room_id(*id)?;
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
