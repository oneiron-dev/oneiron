//! The checkpoint getter of entity documents (KS7-2): each entity's head,
//! citation floors, forks, pins, purge and settlement receipts under its own
//! entity tree, and each proposal bundle split by its forks' entities
//! ([`proposal`]). Every actor a row names is split out; a pending fork whose
//! opener stays erased goes on restore, as the erase deletes it.
//!
//! The document rows ([`documents`]) and fork snapshots are Loro bytes whose
//! birth and commit messages name their actors (FIX 6072): a full history
//! splits through the shared Loro projection (`loro`), its join writing the
//! same history back with every actor that did not open erased. A NOTE's
//! document rows split the same through NOTE's own codec. A shallow history
//! and a pending fork's snapshot stay under the vault-wide seal, named with
//! the owner they join. Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod documents;
mod loro;
mod message_receipts;
mod proposal;

// The entity document family's Loro split and join (FIX 9126): a group is
// its full snapshot, then its updates in replay order.
#[allow(
    unused_imports,
    reason = "L03's sync checkpoint adapter calls these once CHECKPOINT_PAYLOADS_ENABLED is on"
)]
pub(crate) use self::loro::{join as join_entity_doc_loro, split as split_entity_doc_loro};

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::citation_floor::ENTITY_DOC_CITATION_FLOOR;
use super::doc_actor::DocActor;
use super::forks::{
    ACTOR_ERASE_PENDING_ENTITY_DOC_FORK, ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT,
    ENTITY_DOC_PROPOSAL_BUNDLE, ENTITY_DOC_RECEIPT, ForkStatus, PendingDocForkErase,
};
use super::pins::{ENTITY_DOC_PIN, ENTITY_DOC_PURGE_RECEIPT};
use super::storage::ENTITY_DOC_HEAD;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
    Unresolved,
};

/// The field a row's one actor fills.
const ACTOR: &str = "actor";

/// An id in its one canonical spelling.
fn hex_id(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Moves a row's actor out, leaving no one.
fn take_actor(slot: &mut DocActor) -> Vec<(String, EntityId)> {
    match std::mem::replace(slot, DocActor::Erased) {
        DocActor::Actor(id) => vec![(ACTOR.to_owned(), id)],
        DocActor::Erased => Vec::new(),
    }
}

/// Puts an opened actor back where the split left no one.
fn fill(slot: &mut DocActor, actor: EntityId) -> Result<()> {
    if *slot != DocActor::Erased {
        return Err(rows::bad_part());
    }
    *slot = DocActor::Actor(actor);
    Ok(())
}

fn put_actor(slot: &mut DocActor, field: &str, actor: EntityId) -> Result<()> {
    if field != ACTOR {
        return Err(rows::bad_part());
    }
    fill(slot, actor)
}

/// Every entity-document row in `txn`, by owner.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    let mut slots = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_HEAD, &mut out)? {
        let entity = row.key.0;
        if row.value.entity != entity.to_hex() {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        slots.insert(row.value.document.clone(), entity);
        out.exact(OwnerRef::entity(&entity), row.at, row.bytes);
    }
    documents::capture(dbs, txn, slots, &mut out)?;
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_CITATION_FLOOR, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        out.depends(owner, &row.at, OwnerRef::entity(&row.key.1.0));
        out.exact(owner, row.at, row.bytes);
    }
    capture_forks(dbs, txn, &mut out)?;
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_PIN, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        out.depends(owner, &row.at, OwnerRef::entity(&row.key.1.0));
        rows::split_actors(&mut out, owner, ENTITY_DOC_PIN, row, |pin| {
            take_actor(&mut pin.actor)
        })?;
    }
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_PURGE_RECEIPT, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        rows::split_actors(&mut out, owner, ENTITY_DOC_PURGE_RECEIPT, row, |receipt| {
            take_actor(&mut receipt.actor)
        })?;
    }
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_RECEIPT, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        rows::split_actors(&mut out, owner, ENTITY_DOC_RECEIPT, row, |receipt| {
            take_actor(&mut receipt.actor)
        })?;
    }
    proposal::capture(dbs, txn, &mut out)?;
    Ok(out)
}

/// Each fork under the entity its record names, and each fork snapshot
/// under its fork's entity (`loro::capture_fork_snapshot`); a snapshot no
/// record names has no owner.
fn capture_forks(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    let mut forks = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_FORK, out)? {
        let Some(entity) = hex_id(&row.value.entity) else {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        };
        let fork = (entity, row.value.status, row.value.base.clone());
        forks.insert(row.key.clone(), fork);
        let owner = OwnerRef::entity(&entity);
        rows::split_actors(out, owner, ENTITY_DOC_FORK, row, |fork| {
            take_actor(&mut fork.actor)
        })?;
    }
    for row in rows::typed_rows(dbs, txn, ENTITY_DOC_FORK_SNAPSHOT, out)? {
        match forks.get(&row.key) {
            Some((entity, status, base)) => {
                loro::capture_fork_snapshot(out, *entity, *status, base, row);
            }
            None => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
    }
    Ok(())
}

fn owns(at: &RowLocator) -> bool {
    let decls = [
        ENTITY_DOC_HEAD.decl(),
        ENTITY_DOC_CITATION_FLOOR.decl(),
        ENTITY_DOC_FORK.decl(),
        ENTITY_DOC_FORK_SNAPSHOT.decl(),
        ENTITY_DOC_PIN.decl(),
        ENTITY_DOC_PURGE_RECEIPT.decl(),
        ENTITY_DOC_RECEIPT.decl(),
        ENTITY_DOC_PROPOSAL_BUNDLE.decl(),
    ];
    documents::owns(at) || decls.into_iter().any(|decl| at.in_table(decl))
}

/// The bundle framing of `rows`' entity-document parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(ENTITY_DOC_HEAD.decl()) {
        rows::check_row(ENTITY_DOC_HEAD, at, value)
    } else if at.in_table(ENTITY_DOC_CITATION_FLOOR.decl()) {
        rows::check_row(ENTITY_DOC_CITATION_FLOOR, at, value)
    } else if at.in_table(ENTITY_DOC_FORK.decl()) {
        rows::check_row(ENTITY_DOC_FORK, at, value)
    } else if at.in_table(ENTITY_DOC_PIN.decl()) {
        rows::check_row(ENTITY_DOC_PIN, at, value)
    } else if at.in_table(ENTITY_DOC_PURGE_RECEIPT.decl()) {
        rows::check_row(ENTITY_DOC_PURGE_RECEIPT, at, value)
    } else if at.in_table(ENTITY_DOC_RECEIPT.decl()) {
        rows::check_row(ENTITY_DOC_RECEIPT, at, value)
    } else if at.in_table(ENTITY_DOC_PROPOSAL_BUNDLE.decl()) {
        rows::check_row(ENTITY_DOC_PROPOSAL_BUNDLE, at, value)
    } else if at.in_table(ENTITY_DOC_FORK_SNAPSHOT.decl()) {
        rows::check_row(ENTITY_DOC_FORK_SNAPSHOT, at, value)?;
        loro::check_snapshot(value, None)
    } else if documents::owns(at) {
        documents::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A no-one-form row with its opened actors back. A pending fork whose
/// opener did not open goes, as the erase deletes it; every other row stays,
/// naming no one where its actor did not open. A fork snapshot's history is
/// rebuilt the same, its birth naming `opened`'s entity.
fn join(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    opened: &OpenedOwnerRows,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(ENTITY_DOC_FORK_SNAPSHOT.decl()) {
        let entity = tree_entity(opened)?;
        return loro::join_fork_snapshot(&entity, value, parts).map(Some);
    }
    if at.in_table(ENTITY_DOC_FORK.decl()) {
        let fork = rows::join_actors(ENTITY_DOC_FORK, value, parts, |fork, field, actor| {
            put_actor(&mut fork.actor, field, actor)
        })?;
        if fork.actor == DocActor::Erased
            && fork.status == ForkStatus::Pending
            && ACTOR_ERASE_PENDING_ENTITY_DOC_FORK == PendingDocForkErase::Delete
        {
            return Ok(None);
        }
        return ENTITY_DOC_FORK.encode_value(&fork).map(Some);
    }
    if at.in_table(ENTITY_DOC_PIN.decl()) {
        let pin = rows::join_actors(ENTITY_DOC_PIN, value, parts, |pin, field, actor| {
            put_actor(&mut pin.actor, field, actor)
        })?;
        return ENTITY_DOC_PIN.encode_value(&pin).map(Some);
    }
    if at.in_table(ENTITY_DOC_PURGE_RECEIPT.decl()) {
        let receipt = rows::join_actors(
            ENTITY_DOC_PURGE_RECEIPT,
            value,
            parts,
            |receipt, field, actor| put_actor(&mut receipt.actor, field, actor),
        )?;
        return ENTITY_DOC_PURGE_RECEIPT.encode_value(&receipt).map(Some);
    }
    if at.in_table(ENTITY_DOC_RECEIPT.decl()) {
        let receipt =
            rows::join_actors(ENTITY_DOC_RECEIPT, value, parts, |receipt, field, actor| {
                put_actor(&mut receipt.actor, field, actor)
            })?;
        return ENTITY_DOC_RECEIPT.encode_value(&receipt).map(Some);
    }
    if at.in_table(ENTITY_DOC_PROPOSAL_BUNDLE.decl()) {
        return proposal::join(dbs, view, at, value, parts);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s entity-document rows back: exact rows as they are, each
/// actor that opened back in its row, each document slot rebuilt as one
/// group before any row is written ([`documents::join`]), and each proposal
/// fragment merged into the bundle the owners restored so far hold.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    let rebuilt = documents::join(&opened)?;
    rows::restore_parts(dbs, txn, &opened, check, |view, at, value, parts| {
        if documents::owns(at) {
            let row = rebuilt.get(at).cloned();
            return row.map(Some).ok_or_else(rows::bad_part);
        }
        join(dbs, view, &opened, at, value, parts)
    })
}

/// The entity whose tree `opened` is.
fn tree_entity(opened: &OpenedOwnerRows) -> Result<EntityId> {
    let id = opened.owner32.first_chunk::<16>().copied();
    match (opened.subtype, id) {
        (Subtype::EntityTree, Some(id)) => EntityId::from_bytes(id),
        _ => Err(rows::bad_part()),
    }
}
