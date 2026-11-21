//! Doors to the booking rows a home move carries (FIX
//! [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE], FIX
//! [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE]), for the booking home-move
//! tests: a machine that holds none of the old home's node-local booking
//! rows, a move of the booking sections from one vault to another as the
//! carrier runs it, the old home's writer once the new home acknowledged that
//! move, and a read of whether a node-local booking row holds some bytes. A
//! machine also holds none of the old home's outbound send ledger (FIX
//! [BK-EMERGENCY-UNCERTAIN-SEND-NOT-SHOWN-TO-OWNER]), and a read of the note
//! a held deposit's row carries (FIX [BK-REPLAY-NOTE-NOT-CARRIED-TO-NEW-HOME]).

use crate::side_table::{self, SideTableDbs, SideTableDecl};
use crate::sync::home_handoff::{
    acknowledge_home_move_for_doors, carry_section_for_doors, freeze_home_state_for_doors,
    registers_section_for_doors,
};
use crate::{EntityId, Result, Vault};

/// The node-local booking declarations: the tokens, leases, deposits,
/// provider events and emergency picks; the holds; the receipts; the
/// emergency instructions, plans and checkpoints, the three lookups those
/// rows rebuild and the checkpoints' uncertain-send marks (no section of
/// their own).
const BOOKING_ROWS: [&SideTableDecl; 10] = [
    &side_table::BOOKING_TOKEN,
    &side_table::BOOKING_HOLD,
    &side_table::BOOKING_LIFECYCLE_RECEIPT,
    &side_table::EMERGENCY_INSTRUCTION,
    &side_table::EMERGENCY_PLAN,
    &side_table::EMERGENCY_ITEM,
    &side_table::EMERGENCY_REQUEST_PLAN_INDEX,
    &side_table::EMERGENCY_PENDING_EVENT_LOOKUP,
    &side_table::EMERGENCY_EFFECT_LOOKUP,
    &side_table::EMERGENCY_UNCERTAIN_SEND,
];

/// The node-local outbound send state: the intent ledger with its attempt
/// index, accounting, parties, settlements and remote tasks, and the dispatch
/// chokepoint's dedupe rows. No move and no sync carries it: each node's
/// ledger names only the sends that node made. The attempt format marker
/// stays, as on any node.
const OUTBOUND_ROWS: [&SideTableDecl; 13] = [
    &side_table::OUTBOUND_INTENT_ACCOUNTING,
    &side_table::OUTBOUND_INTENT_ATTEMPT_INDEX,
    &side_table::OUTBOUND_INTENT_LATE_RECIPIENT,
    &side_table::OUTBOUND_INTENT_LEDGER_RECORD,
    &side_table::OUTBOUND_INTENT_PARTY,
    &side_table::OUTBOUND_INTENT_PARTY_OF,
    &side_table::OUTBOUND_INTENT_SETTLEMENT,
    &side_table::OUTBOUND_INTENT_UNAVAILABLE,
    &side_table::OUTBOUND_REMOTE_TASK_INPUT,
    &side_table::OUTBOUND_REMOTE_TASK_POLL,
    &side_table::OUTBOUND_REMOTE_TASK_SESSION_END,
    &side_table::OUTBOUND_DEDUPE_RESERVATION,
    &side_table::OUTBOUND_DEDUPE_INTENT,
];

/// Deletes every row of the node-local booking declarations in `vault`: a
/// machine that never held another machine's booking rows, while the
/// bookings' EVENTs and claims reached it by sync (a test makes two machines
/// from copies of one vault).
///
/// # Errors
///
/// Store errors.
pub fn drop_node_local_booking_rows(vault: &Vault) -> Result<()> {
    drop_rows(vault, &BOOKING_ROWS)
}

/// Deletes every row of the node-local outbound send state in `vault`: a
/// machine that never made another machine's sends, so a send the old home
/// made is not one the new home already recorded.
///
/// # Errors
///
/// Store errors.
pub fn drop_node_local_outbound_rows(vault: &Vault) -> Result<()> {
    drop_rows(vault, &OUTBOUND_ROWS)
}

/// Deletes every row of `decls` in `vault`, in one writer.
fn drop_rows(vault: &Vault, decls: &[&'static SideTableDecl]) -> Result<()> {
    vault.with_write_txn(|txn| {
        for decl in decls {
            let suffixes = decl
                .iter_raw(vault, txn)?
                .map(|row| row.map(|(suffix, _)| suffix))
                .collect::<Result<Vec<_>>>()?;
            for suffix in suffixes {
                let mut key = decl.prefix.to_vec();
                key.extend_from_slice(&suffix);
                vault.side_vault_meta().delete(txn, &key)?;
            }
        }
        Ok(())
    })
}

/// Moves the booking rows from `old_home` to `new_home` as a home move does:
/// freezes the old home's state (from then on its rows are history and the
/// home-move fence refuses their writes there), then carries each booking
/// section this build registers through the section's own export, wire
/// encoding and adopt, withholding the actor parts of `withheld`. A build that
/// registers no booking section carries nothing. Whether every carried
/// section applied.
///
/// # Errors
///
/// Store errors; a section's own export, decode and adopt errors.
pub fn move_booking_home(
    old_home: &Vault,
    new_home: &Vault,
    withheld: &[EntityId],
) -> Result<bool> {
    freeze_home_state_for_doors(old_home)?;
    let mut applied = true;
    for decl in BOOKING_ROWS {
        if registers_section_for_doors(decl.name) {
            applied &= carry_section_for_doors(old_home, new_home, decl.name, withheld)?;
        }
    }
    Ok(applied)
}

/// Runs on `old_home` what its writer runs once the new home acknowledged the
/// move `old_home` froze its rows for: every carried table's scrub of what
/// must not outlast the move (the emergency checkpoints' raw action tokens).
///
/// # Errors
///
/// Store errors; a table's own scrub errors.
pub fn acknowledge_booking_home_move(old_home: &Vault) -> Result<()> {
    acknowledge_home_move_for_doors(old_home)
}

/// Whether any stored row of the node-local booking declarations in `vault`
/// holds `needle` among its value's bytes.
///
/// # Errors
///
/// Store errors.
pub fn booking_rows_hold(vault: &Vault, needle: &[u8]) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for decl in BOOKING_ROWS {
        for row in decl.iter_raw(vault, &txn)? {
            let (_, value) = row?;
            if value.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The version the INBOX read state keeps for the booking row `item_id` in
/// `vault` (`booking::lifecycle::booking_inbox_row_version_in_txn`): for a
/// held deposit's row, `unattributed_cancel:<SEQUENCE>` once a cancel
/// Oneiron cannot attribute is noted on its deposit there, else `None`.
///
/// # Errors
///
/// Store errors.
pub fn booking_inbox_row_version(vault: &Vault, item_id: &str) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    crate::booking::lifecycle::booking_inbox_row_version_in_txn(vault, &txn, item_id)
}
