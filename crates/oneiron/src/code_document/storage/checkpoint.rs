//! The checkpoint getter of code documents (KS7-2): each document's head,
//! tested frontiers, path row and ingress receipts under the document's own
//! compartment, its canonical id, never a text hash or an op fold. An
//! operation's Loro stamp names no actor (FIX 3520), so heads and frontiers
//! keep their snapshots exact; each receipt's actor is an actor part, and a
//! restore leaves a receipt naming no one where its actor did not open, as
//! the erase does. The path row's key is a hash of the repo and path, and it
//! rides with the document it names. Nothing calls this until KS7-5, and only
//! once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::receipt_actor::ReceiptActor;
use super::{
    CODE_DOCUMENT_FRONTIER, CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS, CODE_DOCUMENT_PATH, HeadRow,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
    Unresolved,
};

/// The field a head receipt's actor fills, before the operation's id.
const RECEIPT: &str = "receipt ";

/// The field an ingress receipt's actor fills.
const ACTOR: &str = "actor";

/// A code document's compartment: its canonical 32-byte id.
fn document(id: &[u8; 32]) -> Result<OwnerRef> {
    let subtype = Subtype::CodeDocument;
    Ok(OwnerRef {
        subtype,
        owner32: subtype.owner(id)?,
    })
}

/// Moves a receipt's actor out, leaving no one.
fn take_actor(slot: &mut ReceiptActor) -> Option<EntityId> {
    std::mem::replace(slot, ReceiptActor::Erased).id()
}

/// Puts an opened actor back where the split left no one.
fn fill(slot: &mut ReceiptActor, actor: EntityId) -> Result<()> {
    if *slot != ReceiptActor::Erased {
        return Err(rows::bad_part());
    }
    *slot = ReceiptActor::Actor(actor);
    Ok(())
}

/// Moves every head receipt's actor out, each named by its operation.
fn take_head_actors(head: &mut HeadRow) -> Vec<(String, EntityId)> {
    let mut actors = Vec::new();
    for receipt in &mut head.receipts {
        if let Some(actor) = take_actor(&mut receipt.actor) {
            actors.push((format!("{RECEIPT}{}", receipt.operation), actor));
        }
    }
    actors
}

fn put_head_actor(head: &mut HeadRow, field: &str, actor: EntityId) -> Result<()> {
    let operation = field.strip_prefix(RECEIPT).ok_or_else(rows::bad_part)?;
    let receipt = head
        .receipts
        .iter_mut()
        .find(|receipt| receipt.operation == operation)
        .ok_or_else(rows::bad_part)?;
    fill(&mut receipt.actor, actor)
}

/// Every code-document row in `txn`, by document. A row whose own document
/// ids disagree has no one owner and is not compartmented.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, CODE_DOCUMENT_HEAD, &mut out)? {
        if row.value.state.frontier.document_id != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        let owner = document(&row.key)?;
        rows::split_actors(&mut out, owner, CODE_DOCUMENT_HEAD, row, take_head_actors)?;
    }
    for row in rows::typed_rows(dbs, txn, CODE_DOCUMENT_FRONTIER, &mut out)? {
        let (id, _) = row.key;
        if row.value.frontier.document_id != id {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        out.exact(document(&id)?, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, CODE_DOCUMENT_INGRESS, &mut out)? {
        let id = row.value.before.document_id;
        if row.value.after.document_id != id {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        rows::split_actors(
            &mut out,
            document(&id)?,
            CODE_DOCUMENT_INGRESS,
            row,
            |receipt| {
                take_actor(&mut receipt.actor)
                    .map(|actor| (ACTOR.to_owned(), actor))
                    .into_iter()
                    .collect()
            },
        )?;
    }
    for row in rows::typed_rows(dbs, txn, CODE_DOCUMENT_PATH, &mut out)? {
        out.exact(document(&row.value)?, row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [
        CODE_DOCUMENT_HEAD.decl(),
        CODE_DOCUMENT_FRONTIER.decl(),
        CODE_DOCUMENT_INGRESS.decl(),
        CODE_DOCUMENT_PATH.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
}

/// The bundle framing of `rows`' code-document parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(CODE_DOCUMENT_HEAD.decl()) {
        rows::check_row(CODE_DOCUMENT_HEAD, at, value)
    } else if at.in_table(CODE_DOCUMENT_FRONTIER.decl()) {
        rows::check_row(CODE_DOCUMENT_FRONTIER, at, value)
    } else if at.in_table(CODE_DOCUMENT_INGRESS.decl()) {
        rows::check_row(CODE_DOCUMENT_INGRESS, at, value)
    } else if at.in_table(CODE_DOCUMENT_PATH.decl()) {
        rows::check_row(CODE_DOCUMENT_PATH, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A head or ingress receipt with its opened actors back; a receipt whose
/// actor did not open names no one, as the erase leaves it.
fn join(
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(CODE_DOCUMENT_HEAD.decl()) {
        let head = rows::join_actors(CODE_DOCUMENT_HEAD, value, parts, put_head_actor)?;
        return CODE_DOCUMENT_HEAD.encode_value(&head).map(Some);
    }
    if at.in_table(CODE_DOCUMENT_INGRESS.decl()) {
        let receipt = rows::join_actors(
            CODE_DOCUMENT_INGRESS,
            value,
            parts,
            |receipt, field, actor| {
                if field != ACTOR {
                    return Err(rows::bad_part());
                }
                fill(&mut receipt.actor, actor)
            },
        )?;
        return CODE_DOCUMENT_INGRESS.encode_value(&receipt).map(Some);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s code-document rows back: snapshots and path rows as they
/// are, and each receipt with the actors that opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
