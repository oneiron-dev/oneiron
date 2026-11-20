//! The room ledgers a whole-vault export carries whole or withholds whole: a room's membership
//! ledger rows and its revision row go together, live and inert, since a restore needs its one
//! revision and every row (REVIEW-9446 round 2 P1-2), and a malformed inert copy never takes a
//! room's live ledger out of the backup (REVIEW-9739 P1-2).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::archive_retained_side_rows::ArchiveRetainedSideRow;
use super::archive_retained_subjects::RetainedSubjectRule;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::Store;

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

/// Withholds the whole ledger of the room a withheld ledger envelope belongs to, when its key
/// still names one: the ledger goes whole or not at all ([`note_ledger_envelope`]), so a row the
/// export withholds takes its room's other rows and revision along. A live row does so even
/// when `rule` cannot read it. An inert copy `rule` cannot read is withheld alone: an imported
/// copy is archive data, and a malformed one never takes the room's live ledger out of the
/// backup (REVIEW-9739 P1-2).
pub(super) fn withhold_room_ledger(
    rule: Option<RetainedSubjectRule>,
    envelope: &ArchiveRetainedSideRow,
    withheld_ledgers: &mut BTreeSet<EntityId>,
) {
    if !crate::conversation::archive_restore::is_ledger_table(&envelope.source_table) {
        return;
    }
    if !envelope.source_live
        && rule
            .and_then(|rule| rule.records(&envelope.source_key, &envelope.source_value))
            .is_none()
    {
        return;
    }
    if let Some(room) = retained_row_room(&envelope.source_table, &envelope.source_key) {
        withheld_ledgers.insert(room);
    }
}

/// Notes room ledger envelope `envelope`'s room under its identity, and withholds that room's
/// whole ledger when the envelope is a ledger row that names an entity the export keeps out, or
/// a live row that does not read as a ledger row (REVIEW-9446 round 2 P1-2). The ledger goes
/// whole or not at all: a restore needs its one revision and every row, and each envelope's
/// bytes are its identity, so no row is trimmed or rewritten. An inert copy that does not read
/// as a ledger row is withheld alone, as [`withhold_room_ledger`] withholds one whose key does
/// not read (REVIEW-9739 P1-2). Returns whether the export carries the envelope.
pub(super) fn note_ledger_envelope(
    store: &Store,
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
    if envelope.source_table != crate::side_table::CONVERSATION_MEMBERSHIP_ROW.name {
        ledger_rooms.insert(identity, room);
        return Ok(true);
    }
    let Some(named) = crate::conversation::membership_row_named_entities(&envelope.source_value)
    else {
        if !envelope.source_live {
            return Ok(false);
        }
        ledger_rooms.insert(identity, room);
        withheld_ledgers.insert(room);
        return Ok(true);
    };
    ledger_rooms.insert(identity, room);
    if withheld_ledgers.contains(&room) {
        return Ok(true);
    }
    for id in &named {
        if super::export_egress::whole_vault_export_excludes_entity_in_txn(store, rtxn, id)? {
            withheld_ledgers.insert(room);
            break;
        }
    }
    Ok(true)
}
