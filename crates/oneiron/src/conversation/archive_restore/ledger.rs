//! Atomic, byte-preserving landing of a whole room membership ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use super::*;
use crate::batch::export::archive_retained_side_rows::visit_retained_side_rows;
use crate::batch::export::{IndexedArchive, Tag};
use crate::conversation::body::ConversationBody;
use crate::conversation::membership::{self, MEMBERSHIP_ROWS, MEMBERSHIP_SEQ, MembershipRow};
use crate::conversation::membership_index;
use crate::serialize::ExportSecrets;
use crate::side_table::{self, SideKey};

pub(super) fn is_ledger_table(name: &str) -> bool {
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

/// Owner-only preparation for the unchanged body guard; accounting stays in the late pass.
pub(crate) fn preland_room_ledgers_in_txn<R: Read + Seek>(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    archive: &IndexedArchive<'_, R>,
    secrets: ExportSecrets,
) -> Result<BTreeSet<EntityId>> {
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
