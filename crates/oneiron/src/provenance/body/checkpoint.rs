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

use heed::RoTxn;

use super::{BODY, BODY_DIGEST};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, CapturedByAdapter, Check, Join, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, RowLocator, RowPart, Unresolved,
};

/// Every body descriptor and digest holder row, by occurrence, restored
/// exactly.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[&CapturedByAdapter(BODY), &CapturedByAdapter(BODY_DIGEST)],
    capture: Capture::Own(capture),
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
    restore: Restore::Parts,
};

/// Files a row under `owner`'s `occurrence`, holding while `owner` does.
fn occurrence_row(
    out: &mut Captured,
    owner: &EntityId,
    occurrence: &EntityId,
    sources: &[EntityId],
    at: RowLocator,
    value: Vec<u8>,
) {
    let compartment = OwnerRef::occurrence(owner, occurrence);
    out.owner(compartment).occurrence_hint = Some(*occurrence.as_bytes());
    out.depends(compartment, &at, OwnerRef::entity(owner));
    for source in sources {
        out.depends(compartment, &at, OwnerRef::entity(source));
    }
    out.exact(compartment, at, value);
}

/// Every body descriptor and digest holder row in `txn`, by occurrence.
fn capture(store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    let dependencies =
        crate::agent_dispatch::workflow_tool_checkpoint::body_dependencies(store, txn)?;
    for row in rows::typed_rows(store, txn, BODY, out)? {
        let (owner, occurrence) = row.key;
        if row.value.owner != owner || row.value.occurrence != occurrence {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        occurrence_row(
            out,
            &owner,
            &occurrence,
            dependencies
                .get(&owner)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            row.at,
            row.bytes,
        );
    }
    // A holder row is keyed by the digest; its owner is its value.
    for row in rows::typed_rows(store, txn, BODY_DIGEST, out)? {
        let occurrence = row.key.1;
        occurrence_row(
            out,
            &row.value,
            &occurrence,
            dependencies
                .get(&row.value)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            row.at,
            row.bytes,
        );
    }
    Ok(())
}

/// The rows of `opened` a restore puts among the image's `vault_meta` rows
/// as the compartment opens, before any reference pass reads them there
/// (the retired-body prune, KS-2A; a step start's replay landing, FIX 9180):
/// each exact whole-row part that no owner that did not open holds up,
/// checked by the getter's codecs. The getter frames no other form.
///
/// # Errors
///
/// A part that is not an exact whole descriptor or holder row, or one the
/// codecs refuse.
pub(crate) fn image_rows(opened: &OpenedOwnerRows) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let held = opened.held_up();
    let mut out = Vec::with_capacity(opened.rows.len());
    for part in &opened.rows {
        let RowPart::Exact { at, value } = part else {
            return Err(rows::bad_part());
        };
        if held.contains(at) {
            continue;
        }
        if !at.path.is_empty() {
            return Err(rows::bad_part());
        }
        ADAPTER.check(at, value)?;
        out.push((at.key.clone(), value.clone()));
    }
    Ok(out)
}
