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

/// Restores the getter's rows, then applies only this restore's admitted
/// body retirements to the actual joined rows in the same writer.
pub(crate) fn restore_pruned_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
    retired_digests: &std::collections::BTreeSet<[u8; 32]>,
) -> Result<Restored> {
    if retired_digests.is_empty() {
        return restore_in_txn(dbs, txn, opened);
    }
    let written = std::cell::RefCell::new(Vec::new());
    let mut restored = rows::restore_parts(
        dbs,
        txn,
        &opened,
        |at, value| {
            check(at, value)?;
            written.borrow_mut().push(at.clone());
            Ok(())
        },
        rows::no_join,
    )?;
    // The check runs on final joined locators, not actor-part placeholders.
    let mut before = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for at in written.into_inner() {
        if !seen.insert(at.clone()) {
            continue;
        }
        let value = dbs
            .vault_meta()
            .get(txn, &at.key)?
            .ok_or(crate::Error::CorruptedIndex(
                "restored body descriptor row missing",
            ))?;
        before.push((at, value.to_vec()));
    }
    let mut after: Vec<_> = before
        .iter()
        .map(|(at, value)| (at.key.clone(), value.clone()))
        .collect();
    for digest in retired_digests {
        crate::store::owned_body::prune_digest_in_rows(&mut after, digest)?;
    }
    let after: std::collections::BTreeMap<_, _> = after.into_iter().collect();
    for (at, value) in before {
        match after.get(&at.key) {
            Some(updated) if updated != &value => {
                dbs.vault_meta().put(txn, &at.key, updated)?;
            }
            None => {
                dbs.vault_meta().delete(txn, &at.key)?;
                restored.written -= 1;
                restored.dropped.push(at);
            }
            _ => {}
        }
    }
    Ok(restored)
}
