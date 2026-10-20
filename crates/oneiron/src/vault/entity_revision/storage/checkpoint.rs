//! The checkpoint getter of the revision ledger (KS7-2): each entity's
//! revision state, retained frontiers, frontier identities, vector refill
//! marker, staged index inputs and staged phonetic codes, under its own
//! entity tree, each row exact.
//!
//! The retained revision document is not compartmented: it holds the whole
//! raw entity bytes of every revision, and no split takes an actor those
//! bytes name out of that history. It stays under the vault-wide seal,
//! named with its entity. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::super::vector_refill::REFILL;
use super::super::{pending_index, phonetic};
use super::{DOC, FRONTIER, IDENTITY, STATE};
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

/// The carrier a revision document is: the raw entity bytes of each
/// revision, actors and all.
const REVISION_DOC_ACTORS: &str = "revision document holds raw entity bytes";

/// Every revision-ledger row in `txn`, by entity.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, STATE, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, DOC, &mut out)? {
        let owner = OwnerRef::entity(&row.key);
        out.unclassified(
            row.at,
            Some(owner),
            Unresolved::ActorSplit(REVISION_DOC_ACTORS),
        );
    }
    for row in rows::typed_rows(dbs, txn, FRONTIER, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.0), row.at, row.bytes);
    }
    // A reverse row belongs to the entity its value names, never to its
    // key's revision hash.
    for row in rows::typed_rows(dbs, txn, IDENTITY, &mut out)? {
        out.exact(OwnerRef::entity(&row.value), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, REFILL, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    pending_index::checkpoint::capture(dbs, txn, &mut out)?;
    phonetic::checkpoint::capture(dbs, txn, &mut out)?;
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [
        STATE.decl(),
        FRONTIER.decl(),
        IDENTITY.decl(),
        REFILL.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
        || pending_index::checkpoint::owns(at)
        || phonetic::checkpoint::owns(at)
}

/// The bundle framing of `rows`' revision-ledger parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(STATE.decl()) {
        rows::check_row(STATE, at, value)
    } else if at.in_table(FRONTIER.decl()) {
        rows::check_row(FRONTIER, at, value)
    } else if at.in_table(IDENTITY.decl()) {
        rows::check_row(IDENTITY, at, value)
    } else if at.in_table(REFILL.decl()) {
        rows::check_row(REFILL, at, value)
    } else if pending_index::checkpoint::owns(at) {
        pending_index::checkpoint::check(at, value)
    } else if phonetic::checkpoint::owns(at) {
        phonetic::checkpoint::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// Puts `opened`'s revision-ledger rows back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
