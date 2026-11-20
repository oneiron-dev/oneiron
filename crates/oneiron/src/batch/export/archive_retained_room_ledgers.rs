//! The room ledgers a whole-vault export carries whole or withholds whole: a room's membership
//! ledger rows and its revision row go together, live and inert, since a restore needs its one
//! revision and every row (REVIEW-9446 round 2 P1-2), and a malformed inert copy never takes a
//! room's live ledger out of the backup (REVIEW-9739 P1-2).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::archive_retained_side_rows::ArchiveRetainedSideRow;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;

/// The room a room-keyed retained row belongs to: the membership ledger, its revision and the
/// room role grants are keyed by their room first.
pub(super) fn retained_row_room(source_table: &str, source_key: &[u8]) -> Option<EntityId> {
    use crate::side_table::{
        CONVERSATION_MEMBERSHIP_ROW, CONVERSATION_MEMBERSHIP_SEQ, CONVERSATION_ROLE_GRANT,
    };
    if [
        &CONVERSATION_MEMBERSHIP_ROW,
        &CONVERSATION_MEMBERSHIP_SEQ,
        &CONVERSATION_ROLE_GRANT,
    ]
    .iter()
    .any(|decl| decl.name == source_table)
    {
        <EntityId as SideKey>::decode_key(source_key.get(..16)?)
    } else {
        None
    }
}

/// Withholds the whole ledger of the room a withheld live ledger envelope belongs to, when its
/// key still names one: the ledger goes whole or not at all ([`note_ledger_envelope`]), so a live
/// row the export withholds, one its rule cannot read among them, takes its room's other rows
/// and revision along. A withheld inert copy is withheld alone: an imported copy is archive data
/// that never installs, so it never takes the room's live ledger out of the backup, whatever its
/// bytes say (REVIEW-9739 P1-2, round 2 P1-1).
pub(super) fn withhold_room_ledger(
    envelope: &ArchiveRetainedSideRow,
    withheld_ledgers: &mut BTreeSet<EntityId>,
) {
    if envelope.source_live
        && crate::conversation::archive_restore::is_ledger_table(&envelope.source_table)
        && let Some(room) = retained_row_room(&envelope.source_table, &envelope.source_key)
    {
        withheld_ledgers.insert(room);
    }
}

/// Notes room ledger envelope `envelope`'s room under its identity, so a withheld live ledger
/// takes its inert copies along too. A live ledger row that does not read as one, or that names
/// an entity the export keeps out, withholds its room's whole ledger (REVIEW-9446 round 2 P1-2):
/// a restore needs its one revision and every row, and each envelope's bytes are its identity,
/// so no row is trimmed or rewritten. Such an inert copy is withheld alone, as
/// [`withhold_room_ledger`] withholds one (REVIEW-9739 round 2 P1-1). Returns whether the export
/// carries the envelope.
pub(super) fn note_ledger_envelope(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    envelope: &ArchiveRetainedSideRow,
    identity: [u8; 32],
    ledger_rooms: &mut BTreeMap<[u8; 32], EntityId>,
    withheld_ledgers: &mut BTreeSet<EntityId>,
) -> Result<bool> {
    if !crate::conversation::archive_restore::is_ledger_table(&envelope.source_table) {
        return Ok(true);
    }
    let Some(room) = retained_row_room(&envelope.source_table, &envelope.source_key) else {
        return Ok(true);
    };
    if envelope.source_table == crate::side_table::CONVERSATION_MEMBERSHIP_ROW.name
        && !(envelope.source_live && withheld_ledgers.contains(&room))
        && membership_row_withheld(vault, rtxn, &envelope.source_value)?
    {
        if !envelope.source_live {
            return Ok(false);
        }
        withheld_ledgers.insert(room);
    }
    ledger_rooms.insert(identity, room);
    Ok(true)
}

/// Whether the export withholds a membership ledger row with value bytes `value`, read in
/// `rtxn`: its bytes read as no ledger row, or it names an entity the export keeps out.
fn membership_row_withheld(vault: &Vault, rtxn: &RoTxn<'_>, value: &[u8]) -> Result<bool> {
    let Some(named) = crate::conversation::membership_row_named_entities(value) else {
        return Ok(true);
    };
    for id in &named {
        if super::export_egress::whole_vault_export_excludes_entity_in_txn(vault, rtxn, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}
