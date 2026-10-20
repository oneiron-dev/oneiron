//! The checkpoint getter of row births (KS7-2): each birth envelope under its
//! born row's entity tree, and each born-from index row under the born row,
//! holding while its trigger does. A birth names its process's actor: the
//! compartment keeps the birth with the born row in that place, and the actor
//! is an actor part. A birth is immutable and has no erased form, so a
//! restore writes it back only when its actor opens; otherwise the row reads
//! as having no stamped birth, never a stand-in. Nothing calls this until
//! KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::{BIRTH_BY_TRIGGER, ROW_BIRTH};
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";

/// Every birth and born-from index row in `txn`, by born row.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, ROW_BIRTH, &mut out)? {
        let born = row.key;
        rows::split_actors(&mut out, OwnerRef::entity(&born), ROW_BIRTH, row, |birth| {
            let actor = std::mem::replace(&mut birth.made_by.process.actor, born);
            vec![(PROCESS.to_owned(), actor)]
        })?;
    }
    for row in rows::typed_rows(dbs, txn, BIRTH_BY_TRIGGER, &mut out)? {
        let (trigger, born) = row.key;
        let owner = OwnerRef::entity(&born);
        out.depends(owner, &row.at, OwnerRef::entity(&trigger));
        out.exact(owner, row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(ROW_BIRTH.decl()) || at.in_table(BIRTH_BY_TRIGGER.decl())
}

/// The bundle framing of `rows`' birth parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(ROW_BIRTH.decl()) {
        rows::check_row(ROW_BIRTH, at, value)
    } else if at.in_table(BIRTH_BY_TRIGGER.decl()) {
        rows::check_row(BIRTH_BY_TRIGGER, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A birth with its actor back; `None` when the actor did not open.
fn join(
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if !at.in_table(ROW_BIRTH.decl()) {
        return Err(rows::bad_part());
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let birth = rows::join_actors(ROW_BIRTH, value, parts, |birth, field, actor| {
        if field != PROCESS {
            return Err(rows::bad_part());
        }
        birth.made_by.process.actor = actor;
        Ok(())
    })?;
    ROW_BIRTH.encode_value(&birth).map(Some)
}

/// Puts `opened`'s birth rows back: each born-from index row exactly, and
/// each birth whose actor opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
