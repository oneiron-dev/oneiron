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

use heed::RoTxn;

use super::receipt_actor::ReceiptActor;
use super::{
    CODE_DOCUMENT_FRONTIER, CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS, CODE_DOCUMENT_PATH, HeadRow,
    ReceiptRow, SnapshotRow,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, Join, PlacedTable, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, TypedRow, Unresolved,
};

/// The field a head receipt's actor fills, before the operation's id.
const RECEIPT: &str = "receipt ";

/// The field an ingress receipt's actor fills.
const ACTOR: &str = "actor";

/// Every code-document row by document: snapshots and path rows exact, each
/// receipt's actor split out. A row whose own document ids disagree has no
/// one owner and is not compartmented.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &PlacedTable {
            table: CODE_DOCUMENT_HEAD,
            place: place_head,
        },
        &PlacedTable {
            table: CODE_DOCUMENT_FRONTIER,
            place: place_frontier,
        },
        &PlacedTable {
            table: CODE_DOCUMENT_INGRESS,
            place: place_ingress,
        },
        &PlacedTable {
            table: CODE_DOCUMENT_PATH,
            place: place_path,
        },
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::Row(join),
    restore: Restore::Parts,
};

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

/// A head under its document, each receipt's actor split out.
fn place_head(out: &mut Captured, row: TypedRow<[u8; 32], HeadRow>) -> Result<()> {
    if row.value.state.frontier.document_id != row.key {
        out.unclassified(row.at, None, Unresolved::NoOwner);
        return Ok(());
    }
    let owner = document(&row.key)?;
    rows::split_actors(out, owner, CODE_DOCUMENT_HEAD, row, take_head_actors)
}

/// A tested frontier under its document, exact.
fn place_frontier(
    out: &mut Captured,
    row: TypedRow<([u8; 32], [u8; 32]), SnapshotRow>,
) -> Result<()> {
    let (id, _) = row.key;
    if row.value.frontier.document_id != id {
        out.unclassified(row.at, None, Unresolved::NoOwner);
        return Ok(());
    }
    out.exact(document(&id)?, row.at, row.bytes);
    Ok(())
}

/// An ingress receipt under its document, its actor split out.
fn place_ingress(out: &mut Captured, row: TypedRow<EntityId, ReceiptRow>) -> Result<()> {
    let id = row.value.before.document_id;
    if row.value.after.document_id != id {
        out.unclassified(row.at, None, Unresolved::NoOwner);
        return Ok(());
    }
    rows::split_actors(out, document(&id)?, CODE_DOCUMENT_INGRESS, row, |receipt| {
        take_actor(&mut receipt.actor)
            .map(|actor| (ACTOR.to_owned(), actor))
            .into_iter()
            .collect()
    })
}

/// A path row under the document it names, exact.
fn place_path(out: &mut Captured, row: TypedRow<[u8; 32], [u8; 32]>) -> Result<()> {
    out.exact(document(&row.value)?, row.at, row.bytes);
    Ok(())
}

/// A head or ingress receipt with its opened actors back; a receipt whose
/// actor did not open names no one, as the erase leaves it.
fn join(
    _: &Store,
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
