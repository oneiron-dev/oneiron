//! Delete the derived home room at the common entity deindex door.
use super::*;
use crate::store::Store;

/// Refuses a delete of the vault's root project, the one structural row
/// every vault carries (ARCH-0067: the vault itself is the root project).
/// The delete rail, its preflight and the delete preview call it before any
/// writer, and the deindex door again, so every door refuses it alike.
pub(crate) fn reject_root_project_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if ROOT.get(store, txn, &())? == Some(*id) {
        return Err(
            crate::error::RecordError::InvalidProjectBody("cannot delete root project").into(),
        );
    }
    Ok(())
}

/// Refuses a delete of a project another live project names as its parent;
/// any other id passes. The deindex door refuses it, and a hard delete's
/// rail, its preflight and its publication writer refuse it too, before the
/// publication commits the read fence of a purge that would then refuse.
pub(crate) fn reject_project_with_live_children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(());
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(());
    };
    if !is_project_type(store, header.entity_type) {
        return Ok(());
    }
    reject_live_children_of(store, txn, id, header.entity_type)
}

fn reject_live_children_of(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Result<()> {
    // Each child names its parents as its signed history folds them; a
    // child whose history serves no authority keeps its stored claim.
    let reader = super::read::ProjectReader::new(store, txn, store.privacy_posture)?;
    for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(store, txn, kind, None)? {
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
            None => match record::<ProjectRecord>(store, txn, child_id, kind)? {
                Some(child) => child.parents,
                None => continue,
            },
        };
        if parents.contains(&id.to_hex()) {
            return Err(
                crate::error::RecordError::InvalidProjectBody("project has live children").into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn deindex_project_room(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    deindex: &dyn Fn(&mut heed::RwTxn<'_>, &EntityId) -> Result<(bool, bool, bool, Vec<EntityId>)>,
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
    reject_root_project_delete(store, txn, id)?;
    reject_live_children_of(store, txn, id, header.entity_type)?;
    // The owner's mint row (its name) goes with the project.
    // The deleted project's extra-room links go with it: every index row naming it is removed.
    // The rooms stay, their bodies untouched; a stale body key reads as unlinked.
    let linked: Vec<EntityId> = EXTRA_ROOM_PROJECT
        .scan(store, txn)?
        .into_iter()
        .filter_map(|(room, project)| (project == *id).then_some(room))
        .collect();
    for room in linked {
        EXTRA_ROOM_PROJECT.delete(store, txn, &room)?;
    }
    origin::deindex_origin(store, txn, *id)?;
    let room_id = home_room_id(*id)?;
    // The room's rows stop naming it below; a standing answer on one may
    // sit in a facet only the room placed it in.
    super::room_narrowing::queue_unbound_room_in(store, txn, room_id)?;
    super::super::rooms::delete_room_metadata(store, txn, room_id)?;
    let owner = ROOM_PROJECT.get(store, txn, &room_id)?;
    if owner.is_some_and(|owner| owner != *id) {
        return Err(Error::CorruptedIndex("project room owner"));
    }
    if let Some(room) = record::<ProjectRoom>(store, txn, room_id, ENTITY_TYPE_CONVERSATION)? {
        if room.project_id != id.to_hex() {
            return Err(Error::CorruptedIndex("project room collision"));
        }
        let (_, vector, graph, neighbors) = deindex(txn, &room_id)?;
        ROOM_PROJECT.delete(store, txn, &room_id)?;
        return Ok((vector, graph, neighbors));
    }
    ROOM_PROJECT.delete(store, txn, &room_id)?;
    Ok((false, false, Vec::new()))
}
