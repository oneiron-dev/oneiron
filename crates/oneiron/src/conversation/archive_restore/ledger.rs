//! Atomic, byte-preserving landing of a whole room membership ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use super::*;
use crate::batch::export::archive_retained_side_rows::visit_retained_side_rows;
use crate::batch::export::{IndexedArchive, Tag};
use crate::conversation::SpeakerHandoffBoundary;
use crate::conversation::body::ConversationBody;
use crate::conversation::membership::{
    self, MEMBERSHIP_ROWS, MEMBERSHIP_SEQ, MembershipAction, MembershipRow,
};
use crate::conversation::membership_index;
use crate::serialize::ExportSecrets;
use crate::side_table::{self, SideKey};

/// Whether `name` is a room membership ledger table: its rows or its revision.
pub(crate) fn is_ledger_table(name: &str) -> bool {
    name == side_table::CONVERSATION_MEMBERSHIP_ROW.name
        || name == side_table::CONVERSATION_MEMBERSHIP_SEQ.name
}

type RoomEnvelopes<'a> = Vec<(usize, &'a ArchiveRetainedSideRow)>;

fn room_of(row: &ArchiveRetainedSideRow) -> Option<EntityId> {
    <EntityId as SideKey>::decode_key(row.source_key.get(..16)?)
}

struct WholeLedger<'a> {
    rows: Vec<MembershipRow>,
    envelopes: BTreeMap<u64, &'a ArchiveRetainedSideRow>,
    sequence: &'a ArchiveRetainedSideRow,
}

/// Encoding checks precede the shared ledger and per-person window checks.
fn decode_ledger<'a>(
    room: EntityId,
    envelopes: &[(usize, &'a ArchiveRetainedSideRow)],
) -> std::result::Result<WholeLedger<'a>, RetainedSideHeldBackReason> {
    use RetainedSideHeldBackReason::{InvalidValue, MissingCompanion};
    let mut ordered = BTreeMap::new();
    let mut sequences = Vec::new();
    let mut duplicate = false;
    for (_, envelope) in envelopes {
        if envelope.source_table == side_table::CONVERSATION_MEMBERSHIP_ROW.name {
            let ((key_room, ordinal), row) = decode_archived_row(&MEMBERSHIP_ROWS, envelope)?;
            if key_room != room {
                return Err(InvalidValue);
            }
            duplicate |= ordered.insert(ordinal, (*envelope, row)).is_some();
        } else {
            let (key_room, count) = decode_archived_row(&MEMBERSHIP_SEQ, envelope)?;
            if key_room != room || count == 0 {
                return Err(InvalidValue);
            }
            sequences.push((*envelope, count));
        }
    }
    let rows: Vec<_> = ordered.values().map(|(_, row)| row.clone()).collect();
    membership::check_row_order(&rows).map_err(|_| InvalidValue)?;
    if sequences.len() != 1 || duplicate {
        return Err(MissingCompanion);
    }
    let (sequence, count) = sequences[0];
    if count != rows.len() as u64 || ordered.keys().copied().ne(0..count) {
        return Err(MissingCompanion);
    }
    let mut windows = BTreeMap::new();
    for row in &rows {
        // The stored read never re-checks where a Join's window opens, so the archive does
        // (REVIEW-9446 P1-4, round 2 P1-4).
        if matches!(row.action, MembershipAction::Join) && !join_window_admitted(room, row) {
            return Err(InvalidValue);
        }
        membership::apply_window_row(windows.entry(row.person).or_default(), row)
            .map_err(|_| InvalidValue)?;
    }
    Ok(WholeLedger {
        rows,
        envelopes: ordered
            .into_iter()
            .map(|(ordinal, (row, _))| (ordinal, row))
            .collect(),
        sequence,
    })
}

/// Whether archived Join `row` of room `room` opens its window where a membership door opens
/// one. A plain Join opens it at the room's origin or at its join time. A speaker handoff's
/// Join opens it where its own receipt, for this room, this PERSON and this join time, says:
/// at the join time, or, for the entry's cut, at the latest at the join time. Any other
/// boundary is a history cut no door wrote (REVIEW-9446 round 2 P1-4).
fn join_window_admitted(room: EntityId, row: &MembershipRow) -> bool {
    let Some(from) = row.visible_from else {
        return false;
    };
    match &row.handoff {
        None => from == 0 || from == row.at,
        Some(receipt) => {
            receipt.container == room
                && receipt.person == row.person
                && receipt.joined_at == row.at
                && receipt.visible_from == from
                && match receipt.boundary {
                    SpeakerHandoffBoundary::JoinTime => from == row.at,
                    SpeakerHandoffBoundary::EntryEnteredAt => from <= row.at,
                }
        }
    }
}

/// Only an empty destination can install; even a partial destination is kept intact.
fn land_ledger_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    room: EntityId,
    ledger: &WholeLedger<'_>,
    prelanded: bool,
    require_companions: bool,
) -> Result<ArchivedSideRowOutcome> {
    let live_rows: Vec<_> = MEMBERSHIP_ROWS
        .iter_raw_from(vault, txn, room.as_bytes())?
        .collect::<Result<_>>()?;
    let sequence = MEMBERSHIP_SEQ.get_bytes(vault, txn, &room)?;
    let same = sequence.as_deref() == Some(ledger.sequence.source_value.as_slice())
        && live_rows.len() == ledger.envelopes.len()
        && live_rows
            .iter()
            .zip(ledger.envelopes.values())
            .all(|((key, value), row)| *key == row.source_key && *value == row.source_value);
    if same {
        // The pre-pass kept out every room whose seat would not stand
        // ([`rooms_owner_restore_cannot_seat`]), so a prelanded room counts as installed only
        // while it, each member and its roster stand live here (REVIEW-9446 P1-2). An
        // identical destination ledger counts as unchanged only beside the same live
        // companions; without them it is held back and kept as it is (round 2 P1-3).
        if require_companions
            && let Some(reason) = ledger_companion_holdback(vault, txn, room, &ledger.rows)?
        {
            if prelanded {
                return Err(Error::InvariantViolation(
                    "a prelanded room ledger lost a live companion",
                ));
            }
            return Ok(ArchivedSideRowOutcome::HeldBack(reason));
        }
        return Ok(if prelanded {
            ArchivedSideRowOutcome::Installed
        } else {
            ArchivedSideRowOutcome::Unchanged
        });
    }
    if sequence.is_some() || !live_rows.is_empty() {
        return Ok(ArchivedSideRowOutcome::KeptLive);
    }
    if require_companions
        && let Some(reason) = ledger_companion_holdback(vault, txn, room, &ledger.rows)?
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(reason));
    }
    // All bytes were checked before writing any part of the room's ledger.
    for (&ordinal, envelope) in &ledger.envelopes {
        let outcome = install_archived_row(
            &MEMBERSHIP_ROWS,
            vault,
            txn,
            permit,
            &(room, ordinal),
            envelope,
        )?;
        if !matches!(outcome, ArchivedSideRowOutcome::Installed) {
            return Err(Error::InvariantViolation(
                "validated absent membership row did not install",
            ));
        }
    }
    let outcome =
        install_archived_row(&MEMBERSHIP_SEQ, vault, txn, permit, &room, ledger.sequence)?;
    if !matches!(outcome, ArchivedSideRowOutcome::Installed) {
        return Err(Error::InvariantViolation(
            "validated absent membership sequence did not install",
        ));
    }
    membership_index::rebuild_room_in(&vault.store, txn, room, &ledger.rows)?;
    Ok(ArchivedSideRowOutcome::Installed)
}

fn ledger_companion_holdback(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    rows: &[MembershipRow],
) -> Result<Option<RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{InconsistentCompanion, MissingLiveEntity, WrongEntityKind};
    match live_entity_row_in_txn(&vault.store, txn, &room)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION => {}
        LiveEntityRow::Live { .. } => return Ok(Some(WrongEntityKind)),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => return Ok(Some(MissingLiveEntity)),
    }
    let members = membership::members_at_rows(rows, u64::MAX);
    for person in &members {
        match live_entity_row_in_txn(&vault.store, txn, person)? {
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => {}
            LiveEntityRow::Live { .. } => return Ok(Some(WrongEntityKind)),
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                return Ok(Some(MissingLiveEntity));
            }
        }
    }
    if body::body_in(vault, txn, room)?
        .member_ids
        .into_iter()
        .collect::<BTreeSet<_>>()
        != members
    {
        return Ok(Some(InconsistentCompanion));
    }
    Ok(None)
}

pub(super) fn land_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
    prelanded_rooms: &BTreeSet<EntityId>,
) -> Result<BTreeMap<usize, ArchivedSideRowOutcome>> {
    let mut rooms: BTreeMap<EntityId, RoomEnvelopes<'_>> = BTreeMap::new();
    let mut outcomes = BTreeMap::new();
    for (index, row) in rows
        .iter()
        .enumerate()
        .filter(|(_, row)| is_ledger_table(&row.source_table))
    {
        if let Some(room) = room_of(row) {
            rooms.entry(room).or_default().push((index, row));
        } else {
            outcomes.insert(
                index,
                ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
            );
        }
    }
    for (room, envelopes) in rooms {
        let outcome = match decode_ledger(room, &envelopes) {
            Ok(ledger) => land_ledger_in_txn(
                vault,
                txn,
                permit,
                room,
                &ledger,
                prelanded_rooms.contains(&room),
                true,
            )?,
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
        };
        for (index, _) in envelopes {
            // Each envelope has the same all-or-none room outcome.
            let per_envelope = match &outcome {
                ArchivedSideRowOutcome::Installed => ArchivedSideRowOutcome::Installed,
                ArchivedSideRowOutcome::Unchanged => ArchivedSideRowOutcome::Unchanged,
                ArchivedSideRowOutcome::KeptLive => ArchivedSideRowOutcome::KeptLive,
                ArchivedSideRowOutcome::HeldBack(reason) => {
                    ArchivedSideRowOutcome::HeldBack(*reason)
                }
            };
            outcomes.insert(index, per_envelope);
        }
    }
    Ok(outcomes)
}

/// The live ledger envelopes the archive carries, by room.
fn archived_live_ledgers<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
) -> Result<BTreeMap<EntityId, Vec<ArchiveRetainedSideRow>>> {
    let mut rooms: BTreeMap<EntityId, Vec<ArchiveRetainedSideRow>> = BTreeMap::new();
    visit_retained_side_rows(archive, |_, row| {
        if row.source_live
            && is_ledger_table(&row.source_table)
            && let Some(room) = room_of(&row)
        {
            rooms.entry(room).or_default().push(row);
        }
        Ok(())
    })?;
    Ok(rooms)
}

/// The archived rooms the owner's restore cannot seat (REVIEW-9446 P1-2, P1-3): each archived
/// room this vault does not hold, kept in by every earlier pass, whose body carries a leader
/// chat binding this vault's project door did not make (round 2 P1-5), or whose roster names
/// a member and whose seat would not stand here. A seat stands when the room's archived ledger
/// lands whole and its current members are the roster (or this vault already holds a ledger whose
/// current members are), and each member is a live PERSON here or an archived PERSON the
/// import puts, which then lands live or aborts the import. Read in `txn` before the entity
/// pass, so the caller keeps each such room out with its speech, and the late pass counts its
/// ledger as held back.
pub(crate) fn rooms_owner_restore_cannot_seat<R: Read + Seek>(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    secrets: ExportSecrets,
) -> Result<Vec<EntityId>> {
    let ledgers = archived_live_ledgers(archive)?;
    let mut unseated = Vec::new();
    let mut after = None;
    while let Some(room) = archive.next_of_type(ENTITY_TYPE_CONVERSATION, after.as_ref())? {
        after = Some(room);
        if archive.index.contains(Tag::Omitted, room.as_bytes())?
            || !matches!(
                live_entity_row_in_txn(&vault.store, txn, &room)?,
                LiveEntityRow::Absent
            )
        {
            continue;
        }
        let Some((_, record)) = archive.entity(&room)? else {
            continue;
        };
        // A body that does not read as a room fails its own put, as before.
        let bytes = record.body.to_bytes_in_with(&archive.files, secrets)?;
        let Ok(body) = ConversationBody::from_bytes(&bytes) else {
            continue;
        };
        // The room guard refuses a binding the project door did not make here, and no
        // owner door restores one, so the room stays archive data with its speech.
        if body::leader_chat_binding_unbound_in_txn(&vault.store, txn, room, &body)? {
            unseated.push(room);
            continue;
        }
        let roster: BTreeSet<EntityId> = body.member_ids.into_iter().collect();
        if !roster.is_empty() && !seat_stands(vault, txn, archive, room, &roster, &ledgers)? {
            unseated.push(room);
        }
    }
    Ok(unseated)
}

/// Whether absent room `room`'s nonempty `roster` would stand here after the prelanding:
/// see [`rooms_owner_restore_cannot_seat`].
fn seat_stands<R: Read + Seek>(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    room: EntityId,
    roster: &BTreeSet<EntityId>,
    ledgers: &BTreeMap<EntityId, Vec<ArchiveRetainedSideRow>>,
) -> Result<bool> {
    let held_here = MEMBERSHIP_SEQ.get_bytes(vault, txn, &room)?.is_some()
        || MEMBERSHIP_ROWS
            .iter_raw_from(vault, txn, room.as_bytes())?
            .next()
            .is_some();
    let members = if held_here {
        // The prelanding keeps a destination ledger; the room guard reads it.
        membership::current_members_in(&vault.store, txn, room)?
    } else {
        let Some(envelopes) = ledgers.get(&room) else {
            return Ok(false);
        };
        let indexed: Vec<_> = envelopes.iter().enumerate().collect();
        match decode_ledger(room, &indexed) {
            Ok(ledger) => membership::members_at_rows(&ledger.rows, u64::MAX),
            Err(_) => return Ok(false),
        }
    };
    if members != *roster {
        return Ok(false);
    }
    for person in roster {
        let lands_live = match live_entity_row_in_txn(&vault.store, txn, person)? {
            LiveEntityRow::Live { entity_type, .. } => entity_type == ENTITY_TYPE_PERSON,
            LiveEntityRow::Absent => {
                archive
                    .entity_at(person)?
                    .is_some_and(|at| at.entity_type == ENTITY_TYPE_PERSON)
                    && !archive.index.contains(Tag::Omitted, person.as_bytes())?
            }
            LiveEntityRow::DeletedShell => false,
        };
        if !lands_live {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Owner-only preparation for the unchanged body guard; accounting stays in the late pass.
/// Each room [`rooms_owner_restore_cannot_seat`] named is omitted by then and skipped here.
pub(crate) fn preland_room_ledgers_in_txn<R: Read + Seek>(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    archive: &IndexedArchive<'_, R>,
    secrets: ExportSecrets,
) -> Result<BTreeSet<EntityId>> {
    let rooms = archived_live_ledgers(archive)?;
    let mut prelanded = BTreeSet::new();
    for (room, envelopes) in rooms {
        if !matches!(
            live_entity_row_in_txn(&vault.store, txn, &room)?,
            LiveEntityRow::Absent
        ) || archive.index.contains(Tag::Omitted, room.as_bytes())?
        {
            continue;
        }
        let Some((_, record)) = archive.entity(&room)? else {
            continue;
        };
        if record.entity_type != ENTITY_TYPE_CONVERSATION {
            continue;
        }
        let bytes = record.body.to_bytes_in_with(&archive.files, secrets)?;
        let Ok(body) = ConversationBody::from_bytes(&bytes) else {
            continue;
        };
        let indexed: Vec<_> = envelopes.iter().enumerate().collect();
        let Ok(ledger) = decode_ledger(room, &indexed) else {
            continue;
        };
        if body.member_ids.into_iter().collect::<BTreeSet<_>>()
            != membership::members_at_rows(&ledger.rows, u64::MAX)
        {
            continue;
        }
        if matches!(
            land_ledger_in_txn(vault, txn, permit, room, &ledger, false, false)?,
            ArchivedSideRowOutcome::Installed
        ) {
            prelanded.insert(room);
        }
    }
    Ok(prelanded)
}

/// No canonical or derived membership survives an omitted prelanded room record.
pub(crate) fn remove_orphaned_prelanded_rooms_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    prelanded: &mut BTreeSet<EntityId>,
) -> Result<()> {
    let mut orphaned = Vec::new();
    for &room in prelanded.iter() {
        if !matches!(live_entity_row_in_txn(&vault.store, txn, &room)?,
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION)
        {
            MEMBERSHIP_ROWS.delete_from(vault, txn, room.as_bytes())?;
            MEMBERSHIP_SEQ.delete(vault, txn, &room)?;
            membership_index::rebuild_room_in(&vault.store, txn, room, &[])?;
            orphaned.push(room);
        }
    }
    for room in orphaned {
        prelanded.remove(&room);
    }
    Ok(())
}

/// Raw ledger edits for tests/archive_import_owner_installs_room_membership.rs: a source room
/// ledger the membership door never writes, so its whole-vault archive carries one. Not API.
#[cfg(oneiron_test_support)]
pub(crate) mod test_support {
    use super::*;

    /// Deletes room `room`'s ledger revision row and keeps its rows.
    pub(crate) fn drop_sequence(vault: &crate::Vault, room: EntityId) -> Result<()> {
        let mut txn = vault.store.env.write_txn()?;
        MEMBERSHIP_SEQ.delete(vault, &mut txn, &room)?;
        txn.commit()?;
        Ok(())
    }

    /// Copies room `room`'s ledger rows and revision row from `from` into `to`, with no room
    /// record beside them.
    pub(crate) fn copy_ledger(
        from: &crate::Vault,
        to: &crate::Vault,
        room: EntityId,
    ) -> Result<()> {
        let rtxn = from.store.env.read_txn()?;
        let rows = MEMBERSHIP_ROWS.scan_from(from, &rtxn, room.as_bytes())?;
        let sequence = MEMBERSHIP_SEQ.get(from, &rtxn, &room)?;
        drop(rtxn);
        let mut txn = to.store.env.write_txn()?;
        for (key, row) in &rows {
            MEMBERSHIP_ROWS.put(to, &mut txn, key, row)?;
        }
        if let Some(count) = sequence {
            MEMBERSHIP_SEQ.put(to, &mut txn, &room, &count)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Rewrites row `ordinal` of room `room`'s ledger with `visible_from`.
    pub(crate) fn set_row_visible_from(
        vault: &crate::Vault,
        room: EntityId,
        ordinal: u64,
        visible_from: Option<u64>,
    ) -> Result<()> {
        let mut txn = vault.store.env.write_txn()?;
        let mut row = MEMBERSHIP_ROWS
            .get(vault, &txn, &(room, ordinal))?
            .ok_or(Error::InvariantViolation("no such membership row"))?;
        row.visible_from = visible_from;
        MEMBERSHIP_ROWS.put(vault, &mut txn, &(room, ordinal), &row)?;
        txn.commit()?;
        Ok(())
    }
}
