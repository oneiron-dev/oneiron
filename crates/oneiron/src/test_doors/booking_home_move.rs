//! Doors to the booking rows a home move carries (FIX
//! [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE], FIX
//! [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE]), for the booking home-move
//! tests: a machine that holds none of the old home's node-local booking
//! rows, a move of the booking sections from one vault to another as the
//! carrier runs it, the old home's writer once the new home acknowledged that
//! move, and a read of whether a node-local booking row holds some bytes.

use crate::side_table::{self, SideTableDbs, SideTableDecl};
use crate::sync::home_handoff::{
    acknowledge_home_move_for_doors, carry_section_for_doors, freeze_home_state_for_doors,
    registers_section_for_doors,
};
use crate::{EntityId, Result, Vault};

/// The node-local booking declarations: the tokens, leases, deposits,
/// provider events and emergency picks; the holds; the receipts; the
/// emergency instructions, plans and checkpoints, and the three lookups those
/// rows rebuild (no section of their own).
const BOOKING_ROWS: [&SideTableDecl; 9] = [
    &side_table::BOOKING_TOKEN,
    &side_table::BOOKING_HOLD,
    &side_table::BOOKING_LIFECYCLE_RECEIPT,
    &side_table::EMERGENCY_INSTRUCTION,
    &side_table::EMERGENCY_PLAN,
    &side_table::EMERGENCY_ITEM,
    &side_table::EMERGENCY_REQUEST_PLAN_INDEX,
    &side_table::EMERGENCY_PENDING_EVENT_LOOKUP,
    &side_table::EMERGENCY_EFFECT_LOOKUP,
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
    vault.with_write_txn(|txn| {
        for decl in BOOKING_ROWS {
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
