//! Archived rooms this vault cannot seat (fix list rows
//! ARCHIVE-IMPORT-ACTORLESS-SEATED-ROOM-REFUSED and
//! ARCHIVE-IMPORT-ROOM-PINS-OR-CLOSED-REFUSED; Engine ANSWER
//! ARCHIVE-IMPORT-ACTORLESS-SEATED-ROOM = B, 20 Nov 11:39).
//!
//! A room's members, shared pins, pin policy, closed bit and leader chat
//! binding change only through their room doors, which mark their write
//! transaction (`conversation::validate_put_in_txn`). Every whole-vault
//! import door but the owner's restore writes no such mark, so an archived
//! room this vault does not hold, whose body the room guard would refuse
//! here, stays archive data ([`omit_rooms_not_seated_here`]), named under
//! `RoomNotSeatedHere`, and the import goes on: one archived row never
//! aborts the import.
//!
//! A room the import keeps out keeps its speech out with it
//! ([`omit_speech_of_omitted_rooms`]): each TURN that is its child and each
//! MESSAGE that belongs to it or is part of such a TURN, so no TURN or
//! MESSAGE lands outside the room whose members alone read it. That holds
//! for a project's home room kept out with its project too
//! (`withhold_unborn_projects`, `map_project_root`), whose speech stays out
//! unnamed, as the room does.

use std::io::{Read, Seek};

use super::super::archive_index::{IndexedArchive, Tag};
use super::super::{ExportImportOmission, ImportOmissionReason};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// Keeps out each archived room this vault does not hold whose body the room
/// guard would refuse as a first put no room door marks
/// (`conversation::new_room_needs_a_door_in_txn`), read in `txn`, and
/// returns one omission for each, under `RoomNotSeatedHere`. Runs on every
/// door but the owner's restore, before the entity pass.
pub(super) fn omit_rooms_not_seated_here<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<Vec<ExportImportOmission>> {
    let mut omissions = Vec::new();
    let mut after = None;
    while let Some(room) = archive.next_of_type(ENTITY_TYPE_CONVERSATION, after.as_ref())? {
        after = Some(room);
        if archive.index.contains(Tag::Omitted, room.as_bytes())?
            || crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &room)?.is_some()
        {
            continue;
        }
        let (_, row) = archive
            .entity(&room)?
            .ok_or(Error::InvariantViolation("archive index lost a room"))?;
        if crate::conversation::new_room_needs_a_door_in_txn(
            &vault.store,
            txn,
            room,
            &row.body.to_bytes()?,
        )? {
            archive.index.put(Tag::Omitted, room.as_bytes(), &[])?;
            archive
                .index
                .put(Tag::RoomNotSeatedHere, room.as_bytes(), &[])?;
            omissions.push(room_not_seated_here(room));
        }
    }
    Ok(omissions)
}

/// Keeps out each archived TURN that is a child of a room the import keeps
/// out, then each archived MESSAGE that belongs to such a room or is part of
/// a TURN kept out, and returns one omission, under `RoomNotSeatedHere`, for
/// each kept out with a room [`omit_rooms_not_seated_here`] kept out. Runs
/// once every pass that keeps a room or a TURN out has run, before the
/// entity pass.
pub(super) fn omit_speech_of_omitted_rooms<R: Read + Seek>(
    archive: &mut IndexedArchive<'_, R>,
) -> Result<Vec<ExportImportOmission>> {
    let mut omissions = Vec::new();
    let mut after = None;
    while let Some(turn) = archive.next_of_type(ENTITY_TYPE_TURN, after.as_ref())? {
        after = Some(turn);
        if archive.index.contains(Tag::Omitted, turn.as_bytes())? {
            continue;
        }
        if let Some(not_seated) =
            omitted_container(archive, &turn, EdgeKind::ChildOf, ENTITY_TYPE_CONVERSATION)?
        {
            archive.index.put(Tag::Omitted, turn.as_bytes(), &[])?;
            if not_seated {
                archive
                    .index
                    .put(Tag::RoomNotSeatedHere, turn.as_bytes(), &[])?;
                omissions.push(room_not_seated_here(turn));
            }
        }
    }
    let mut after = None;
    while let Some(message) = archive.next_of_type(ENTITY_TYPE_MESSAGE, after.as_ref())? {
        after = Some(message);
        if archive.index.contains(Tag::Omitted, message.as_bytes())? {
            continue;
        }
        let room = omitted_container(
            archive,
            &message,
            EdgeKind::BelongsTo,
            ENTITY_TYPE_CONVERSATION,
        )?;
        let turn = omitted_container(archive, &message, EdgeKind::PartOf, ENTITY_TYPE_TURN)?;
        if room.is_some() || turn.is_some() {
            archive.index.put(Tag::Omitted, message.as_bytes(), &[])?;
            if room == Some(true) || turn == Some(true) {
                omissions.push(room_not_seated_here(message));
            }
        }
    }
    Ok(omissions)
}

/// Whether archived row `id` has a `kind` edge to a row archived as
/// `container_type` that the import keeps out: `None` when it has none, else
/// whether one of them was kept out as a room this vault cannot seat, or
/// with one.
fn omitted_container<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
    kind: EdgeKind,
    container_type: u8,
) -> Result<Option<bool>> {
    let mut kept_out = None;
    for target in super::super::evidence_import::archived_targets(&archive.index, id, kind)? {
        if archive.index.contains(Tag::Omitted, target.as_bytes())?
            && archive
                .entity_at(&target)?
                .is_some_and(|at| at.entity_type == container_type)
        {
            let not_seated = archive
                .index
                .contains(Tag::RoomNotSeatedHere, target.as_bytes())?;
            kept_out = Some(kept_out.unwrap_or(false) || not_seated);
        }
    }
    Ok(kept_out)
}

fn room_not_seated_here(id: EntityId) -> ExportImportOmission {
    ExportImportOmission {
        entity_id: id.to_hex(),
        reason: ImportOmissionReason::RoomNotSeatedHere,
    }
}
