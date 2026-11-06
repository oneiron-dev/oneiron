//! The checkpoint getter of the revision ledger (KS7-2): each entity's
//! revision state, retained frontiers, frontier identities, vector refill
//! marker, staged index inputs and staged phonetic codes, under its own
//! entity tree, each row exact. An identity-topology author carrier's
//! state, retained frontiers and reverse rows hash the carrier's raw row,
//! its actor included, and its revision document (one a pin made) holds that
//! row: each is that actor's actor-keyed row under the carrier's tree, as the
//! carrier row is (FIX 17143), so an erase of the actor leaves neither the
//! row nor a hash of it in an image. Its document's bindings are not checked
//! on restore: no split of it is restored, only the whole document.
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

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::super::vector_refill::REFILL;
use super::super::{pending_index, phonetic};
use super::{DOC, FRONTIER, IDENTITY, STATE};
use crate::entity_id::EntityId;
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
    let mut carriers = BTreeMap::new();
    for row in states {
        let owner = OwnerRef::entity(&row.key);
        match carrier_actor(dbs, txn, &row.key)? {
            Some(actor) => {
                carriers.insert(row.key, actor);
                let table = STATE.decl().prefix;
                rows::actor_keyed(&mut out, owner, actor, &row.at, table, &row.bytes)?;
            }
            None => out.exact(owner, row.at, row.bytes),
        }
    }
    for row in docs {
        match carriers.get(&row.key) {
            Some(actor) => {
                let owner = OwnerRef::entity(&row.key);
                let table = DOC.decl().prefix;
                rows::actor_keyed(&mut out, owner, *actor, &row.at, table, &row.bytes)?;
            }
            None => document::capture(dbs, txn, &mut out, &bindings, row)?,
        }
    }
    for row in frontiers {
        let owner = OwnerRef::entity(&row.key.0);
        match carriers.get(&row.key.0) {
            Some(actor) => {
                let table = FRONTIER.decl().prefix;
                rows::actor_keyed(&mut out, owner, *actor, &row.at, table, &row.bytes)?;
            }
            None => out.exact(owner, row.at, row.bytes),
        }
    }
    // A reverse row belongs to the entity its value names, never to its
    // key's revision hash.
    for row in identities {
        let owner = OwnerRef::entity(&row.value);
        match carriers.get(&row.value) {
            Some(actor) => {
                let table = IDENTITY.decl().prefix;
                rows::actor_keyed(&mut out, owner, *actor, &row.at, table, &row.bytes)?;
            }
            None => out.exact(owner, row.at, row.bytes),
        }
    }
    for row in rows::typed_rows(dbs, txn, REFILL, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    pending_index::checkpoint::capture(dbs, txn, &mut out)?;
    phonetic::checkpoint::capture(dbs, txn, &mut out)?;
    Ok(out)
}

/// The actor `id`'s entity row attributes, when it is an author carrier.
fn carrier_actor(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let row = dbs.entities().get(txn, id.as_bytes())?;
    Ok(row
        .as_deref()
        .and_then(crate::identity_topology::author_carrier_actor))
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
        document::check(at, value).or_else(|_| document::check_carrier(at, value))
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
/// and a revision document as its join gives it back (an author carrier's
/// comes back whole, out of its actor's part, with no binding staged). A
/// joined document's bindings are checked whole: their collisions before any row is written,
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
