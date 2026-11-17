//! Canonical capture owner witnesses, carried under each key owner's compartment.

use super::blocked_capture_witness_owner;
use crate::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, Join, PlacedTable, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, Captured, OwnerRef, RowLocator, TypedRow, Unresolved,
};

const WITNESSES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE_OWNER);

/// Every witness, keyed by its owner under that owner's tree. A restored
/// part must be an empty witness whose key names the compartment's owner.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[&PlacedTable {
        table: WITNESSES,
        place: place_witness,
    }],
    capture: Capture::ByTable,
    check: Check::Own(check_witness),
    row_owner: Some(witness_owner),
    join: Join::NoSplit,
    restore: Restore::Parts,
};

/// Files one witness under the owner its key names; a key that names none,
/// or a value that is not empty, is undecodable.
fn place_witness(out: &mut Captured, row: TypedRow<Vec<u8>, Vec<u8>>) -> Result<()> {
    let Some(owner) = blocked_capture_witness_owner(&row.at.key) else {
        out.unclassified(row.at, None, Unresolved::Undecodable);
        return Ok(());
    };
    if !row.bytes.is_empty() {
        out.unclassified(
            row.at,
            Some(OwnerRef::entity(&owner)),
            Unresolved::Undecodable,
        );
        return Ok(());
    }
    rows::actor_keyed(
        out,
        OwnerRef::entity(&owner),
        owner,
        &row.at,
        WITNESSES.decl().prefix,
        &row.bytes,
    )
}

/// A witness is a row of its table with an empty value.
fn check_witness(at: &RowLocator, value: &[u8]) -> Result<()> {
    if !at.in_table(WITNESSES.decl()) || !value.is_empty() {
        return Err(rows::bad_part());
    }
    Ok(())
}

/// The owner a witness's key names.
fn witness_owner(at: &RowLocator) -> Option<OwnerRef> {
    blocked_capture_witness_owner(&at.key).map(|owner| OwnerRef::entity(&owner))
}
