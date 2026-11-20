//! Doors to the booking rows a home move carries (FIX
//! [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]), for the booking home-move
//! test: a machine that holds none of the old home's node-local booking rows,
//! and a move of the booking sections from one vault to another as the
//! carrier runs it.

use crate::side_table::{self, SideTableDbs, SideTableDecl};
use crate::sync::home_handoff::{
    carry_section_for_doors, freeze_home_state_for_doors, registers_section_for_doors,
};
use crate::{EntityId, Result, Vault};

/// The node-local booking declarations: the tokens, leases, deposits,
/// provider events and emergency picks; the holds; the receipts.
const BOOKING_ROWS: [&SideTableDecl; 3] = [
    &side_table::BOOKING_TOKEN,
    &side_table::BOOKING_HOLD,
    &side_table::BOOKING_LIFECYCLE_RECEIPT,
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
