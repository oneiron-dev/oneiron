//! Canonical step-capture owner witnesses, carried under each key owner's compartment.

use heed::{RoTxn, RwTxn};

use super::blocked_capture_witness_owner;
use crate::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

const WITNESSES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE_OWNER);

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, WITNESSES, &mut out)? {
        let Some(owner) = blocked_capture_witness_owner(&row.at.key) else {
            out.unclassified(row.at, None, Unresolved::Undecodable);
            continue;
        };
        if !row.bytes.is_empty() {
            out.unclassified(
                row.at,
                Some(OwnerRef::entity(&owner)),
                Unresolved::Undecodable,
            );
            continue;
        }
        rows::actor_keyed(
            &mut out,
            OwnerRef::entity(&owner),
            owner,
            &row.at,
            WITNESSES.decl().prefix,
            &row.bytes,
        )?;
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(WITNESSES.decl())
}

pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    let expected_owner32 = opened.owner32;
    let expected_subtype = opened.subtype;
    rows::restore_parts(
        dbs,
        txn,
        &opened,
        |at, value| {
            if !owns(at) || !value.is_empty() {
                return Err(rows::bad_part());
            }
            let owner = blocked_capture_witness_owner(&at.key).ok_or_else(rows::bad_part)?;
            let owner = OwnerRef::entity(&owner);
            if owner.owner32 != expected_owner32 || owner.subtype != expected_subtype {
                return Err(rows::bad_part());
            }
            Ok(())
        },
        rows::no_join,
    )
}
