//! Owner restore of archived room membership ledgers and role grants.
//!
//! Whole ledgers land byte for byte before fresh room records, whose unchanged
//! guard checks the restored roster. Existing ledgers are never overwritten.
//!
//! Each archived `CONVERSATION_ROLE_GRANT` row lands only when its room is a
//! live room record and its person a live PERSON on this vault, the person is
//! a current member, and the room body's twin `roles` entry already holds the
//! same grant. The twin check is the anti-stale-re-grant mechanism: a Leave
//! deletes the grant row and drops the twin together, so a grant without its
//! twin is never installed alone. Installed rows need no refresh: no sync
//! live-window cell derives from the ledger or from role grants.

mod ledger;

pub(crate) use ledger::{preland_room_ledgers_in_txn, remove_orphaned_prelanded_rooms_in_txn};

use std::collections::BTreeSet;

use super::body::{self, RoomRole};
use super::membership;
use super::roles::ROLE_GRANTS;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Lands room ledgers first, then role grants backed by membership and body roles.
pub(crate) fn land_archived_conversation_role_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
    prelanded_rooms: &BTreeSet<EntityId>,
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut ledger_outcomes = ledger::land_rows_in_txn(vault, txn, permit, rows, prelanded_rooms)?;
    let mut outcomes = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        if ledger::is_ledger_table(&row.source_table) {
            outcomes.push(
                ledger_outcomes
                    .remove(&index)
                    .ok_or(Error::InvariantViolation(
                        "a ledger envelope must have a landing outcome",
                    ))?,
            );
            continue;
        }
        let outcome = match decode_archived_row(&ROLE_GRANTS, row) {
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
            Ok(((room, person), grant)) => {
                match companion_holdback_in_txn(vault, &*txn, room, person, &grant)? {
                    Some(reason) => ArchivedSideRowOutcome::HeldBack(reason),
                    None => install_archived_row(
                        &ROLE_GRANTS,
                        vault,
                        txn,
                        permit,
                        &(room, person),
                        row,
                    )?,
                }
            }
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// The holdback reason for one decoded grant row, or `None` when its room,
/// person, membership and twin entry all stand on this vault.
fn companion_holdback_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
    grant: &RoomRole,
) -> Result<Option<RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{
        InconsistentCompanion, MissingCompanion, MissingLiveEntity, WrongEntityKind,
    };
    match live_entity_row_in_txn(&vault.store, txn, &room)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION => {}
        LiveEntityRow::Live { .. } => return Ok(Some(WrongEntityKind)),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(Some(MissingLiveEntity));
        }
    }
    match live_entity_row_in_txn(&vault.store, txn, &person)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => {}
        LiveEntityRow::Live { .. } => return Ok(Some(WrongEntityKind)),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(Some(MissingLiveEntity));
        }
    }
    let members =
        membership::members_at_rows(&membership::rows_in(&vault.store, txn, room)?, u64::MAX);
    if !members.contains(&person) {
        return Ok(Some(MissingCompanion));
    }
    if body::body_in(vault, txn, room)?.roles.get(&person.to_hex()) != Some(grant) {
        return Ok(Some(InconsistentCompanion));
    }
    Ok(None)
}
