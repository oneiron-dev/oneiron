//! The checkpoint getter of the revision ledger (KS7-2): each entity's
//! revision state, retained frontiers, frontier identities, vector refill
//! marker, staged index inputs and staged phonetic codes, under its own
//! entity tree, each row exact.
//!
//! The retained revision document holds the whole raw entity row of every
//! revision. It splits through its own codec ([`document`], FIX 6072) when
//! its history is a fixed NOTE core's or a strict MODEL body's and no
//! binding the capture view holds for it would change under an erase: no
//! public revision ref changes (lead pick (b)). Any other stays under the
//! vault-wide seal, named with its entity. A restore checks that document's
//! bindings whole, once every row of this getter is in. Nothing calls this
//! until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod document;

use heed::{RoTxn, RwTxn};

use super::super::vector_refill::REFILL;
use super::super::{pending_index, phonetic};
use super::{DOC, FRONTIER, IDENTITY, STATE};
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// Every revision-ledger row in `txn`, by entity.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    let states = rows::typed_rows(dbs, txn, STATE, &mut out)?;
    let docs = rows::typed_rows(dbs, txn, DOC, &mut out)?;
    let frontiers = rows::typed_rows(dbs, txn, FRONTIER, &mut out)?;
    let identities = rows::typed_rows(dbs, txn, IDENTITY, &mut out)?;
    let bindings = document::Bindings::index(&docs, &states, &frontiers, &identities);
    for row in states {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in docs {
        document::capture(dbs, txn, &mut out, &bindings, row)?;
    }
    for row in frontiers {
        out.exact(OwnerRef::entity(&row.key.0), row.at, row.bytes);
    }
    // A reverse row belongs to the entity its value names, never to its
    // key's revision hash.
    for row in identities {
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
        DOC.decl(),
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
    } else if at.in_table(DOC.decl()) {
        document::check(at, value)
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

/// Puts `opened`'s revision-ledger rows back: each exact row as it stands,
/// and a revision document as its join gives it back. That document's
/// bindings are checked whole: their collisions before any row is written,
/// and what was written once every row is in, before this returns, so no
/// later row of this getter writes one of them again.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    let staged = document::preflight(dbs, txn, &opened)?;
    let restored = rows::restore_parts(dbs, txn, &opened, check, document::join)?;
    if let Some(staged) = staged {
        document::finish_restore_in_txn(dbs, txn, &staged)?;
    }
    Ok(restored)
}
