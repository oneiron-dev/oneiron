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
mod native;

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::super::vector_refill::REFILL;
use super::super::{pending_index, phonetic};
use super::{DOC, FRONTIER, IDENTITY, STATE};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, CapturedByAdapter, Check, Join, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, Restored, RowLocator,
};
use crate::store::{ManifestDbs, Store};

/// Every revision-ledger row by entity. The capture is the adapter's own: a
/// revision document splits only by the bindings its state, frontiers and
/// identities give, and an author carrier's rows go under its actor. So is
/// the restore: a joined document's bindings are checked around the parts.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &CapturedByAdapter(STATE),
        &CapturedByAdapter(DOC),
        &CapturedByAdapter(FRONTIER),
        &CapturedByAdapter(IDENTITY),
        &CapturedByAdapter(REFILL),
        pending_index::checkpoint::TABLE,
        phonetic::checkpoint::TABLE,
    ],
    capture: Capture::Own(capture),
    check: Check::Own(check),
    row_owner: None,
    join: Join::Row(document::join),
    restore: Restore::Own(restore),
};

/// Every revision-ledger row in `txn`, by entity.
fn capture(store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    let states = rows::typed_rows(store, txn, STATE, out)?;
    let docs = rows::typed_rows(store, txn, DOC, out)?;
    let frontiers = rows::typed_rows(store, txn, FRONTIER, out)?;
    let identities = rows::typed_rows(store, txn, IDENTITY, out)?;
    let bindings = document::Bindings::index(&docs, &states, &frontiers, &identities);
    bindings.check_native_without_doc(store, txn)?;
    let mut carriers = BTreeMap::new();
    for row in states {
        let owner = OwnerRef::entity(&row.key);
        match carrier_actor(store, txn, &row.key)? {
            Some(actor) => {
                carriers.insert(row.key, actor);
                let table = STATE.decl().prefix;
                rows::actor_keyed(out, owner, actor, &row.at, table, &row.bytes)?;
            }
            None => out.exact(owner, row.at, row.bytes),
        }
    }
    for row in docs {
        match carriers.get(&row.key) {
            Some(actor) => {
                let owner = OwnerRef::entity(&row.key);
                let table = DOC.decl().prefix;
                rows::actor_keyed(out, owner, *actor, &row.at, table, &row.bytes)?;
            }
            None => document::capture(store, txn, out, &bindings, row)?,
        }
    }
    for row in frontiers {
        let owner = OwnerRef::entity(&row.key.0);
        match carriers.get(&row.key.0) {
            Some(actor) => {
                let table = FRONTIER.decl().prefix;
                rows::actor_keyed(out, owner, *actor, &row.at, table, &row.bytes)?;
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
                rows::actor_keyed(out, owner, *actor, &row.at, table, &row.bytes)?;
            }
            None => out.exact(owner, row.at, row.bytes),
        }
    }
    for row in rows::typed_rows(store, txn, REFILL, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    pending_index::checkpoint::capture(store, txn, out)?;
    phonetic::checkpoint::capture(store, txn, out)
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

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(STATE.decl()) {
        rows::check_row(STATE, at, value)
    } else if at.in_table(DOC.decl()) {
        document::check(at, value).or_else(|_| document::check_carrier(at, value))
    } else if at.in_table(FRONTIER.decl()) {
        rows::check_row(FRONTIER, at, value)?;
        super::frontier::FrontierEntry::decode(value)
            .map(|_| ())
            .map_err(|_| rows::bad_part())
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
fn restore(store: &Store, txn: &mut RwTxn<'_>, opened: OpenedOwnerRows) -> Result<Restored> {
    let staged = document::preflight(store, txn, &opened)?;
    let restored = ADAPTER.restore_parts(store, txn, &opened)?;
    if let Some(staged) = staged {
        document::finish_restore_in_txn(store, txn, &staged)?;
    }
    Ok(restored)
}
