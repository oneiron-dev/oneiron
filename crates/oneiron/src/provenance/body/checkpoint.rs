//! The checkpoint getter of body descriptors (KS7-2): each descriptor and
//! each digest holder row under its attachment occurrence (the owning
//! record, then the occurrence), never under the digest, so two occurrences
//! of the same bytes are two owners. Each holds only while its owning
//! record's tree does. The descriptor is metadata: the bytes it names are
//! KS-2's to seal wherever their family keeps them, and nothing here seals
//! them twice. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::{BODY, BODY_DIGEST};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

/// Files a row under `owner`'s `occurrence`, holding while `owner` does.
fn occurrence_row(
    out: &mut Captured,
    owner: &EntityId,
    occurrence: &EntityId,
    at: RowLocator,
    value: Vec<u8>,
) {
    let compartment = OwnerRef::occurrence(owner, occurrence);
    out.owner(compartment).occurrence_hint = Some(*occurrence.as_bytes());
    out.depends(compartment, &at, OwnerRef::entity(owner));
    out.exact(compartment, at, value);
}

/// Every body descriptor and digest holder row in `txn`, by occurrence.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, BODY, &mut out)? {
        let (owner, occurrence) = row.key;
        if row.value.owner != owner || row.value.occurrence != occurrence {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        occurrence_row(&mut out, &owner, &occurrence, row.at, row.bytes);
    }
    // A holder row is keyed by the digest; its owner is its value.
    for row in rows::typed_rows(dbs, txn, BODY_DIGEST, &mut out)? {
        let occurrence = row.key.1;
        occurrence_row(&mut out, &row.value, &occurrence, row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(BODY.decl()) || at.in_table(BODY_DIGEST.decl())
}

/// The bundle framing of `rows`' descriptor parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(BODY.decl()) {
        rows::check_row(BODY, at, value)
    } else {
        rows::check_row(BODY_DIGEST, at, value)
    }
}

/// Puts `opened`'s descriptor rows back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
