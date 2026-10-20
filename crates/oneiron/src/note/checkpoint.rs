//! The checkpoint getter of NOTE rows (KS7-2): each NOTE's head, head
//! documents, overrides and seal under its own entity tree; each fork and
//! landing receipt under the NOTE its record names; each review bundle under
//! its members' NOTE ([`bundle`]); each pin index row under its citing
//! document ([`pins`]); each operation receipt under the NOTE its key leads
//! with; and each title row, its key split from its author
//! ([`super::title_index::checkpoint`]). Every actor a row names is split
//! out; a fork no one decided whose opener stays erased goes on restore, as
//! the erase deletes it.
//!
//! A proposal head's Loro snapshot splits through the shared Loro projection
//! under its NOTE ([`loro`], FIX 6072): its stamps' and authorship records'
//! actors out, and the join writing the same history back with every actor
//! that did not open erased. One whose fork no one decided, a shallow one and
//! one that is no value-only proposal stay under the vault-wide seal, named
//! with the NOTE. The live documents' rows are split by the entity-document
//! getter through the same NOTE codec, and a NOTE core's author by the
//! entity-row getter ([`body`]). Nothing calls this until KS7-5, and only
//! once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod body;
mod bundle;
mod loro;
mod pins;

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

pub(crate) use self::body::{CORE_RAW_REFS, join_core_row, reads_core_row, split_core_row};
pub(crate) use self::loro::{check_live_snapshot, frames_live, join_live, snapshot_note, split_live};

use super::documents::{NOTE_HEAD, NOTE_HEAD_DOC, NOTE_PROPOSAL_DOC};
use super::lifecycle::NOTE_SEAL;
use super::overrides::NOTE_OVERRIDE;
use super::proposals::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_RECEIPT, NoteActor,
    PendingNoteForkErase,
};
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_NC_E};
use super::title_index;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
    Unresolved,
};

/// The field a row's one actor fills.
const ACTOR: &str = "actor";

/// Moves a row's actor out, leaving no one.
fn take_actor(slot: &mut NoteActor) -> Vec<(String, EntityId)> {
    match std::mem::replace(slot, NoteActor::Erased) {
        NoteActor::Actor(id) => vec![(ACTOR.to_owned(), id)],
        NoteActor::Erased => Vec::new(),
    }
}

/// Puts an opened actor back where the split left no one.
fn fill(slot: &mut NoteActor, actor: EntityId) -> Result<()> {
    if *slot != NoteActor::Erased {
        return Err(rows::bad_part());
    }
    *slot = NoteActor::Actor(actor);
    Ok(())
}

fn put_actor(slot: &mut NoteActor, field: &str, actor: EntityId) -> Result<()> {
    if field != ACTOR {
        return Err(rows::bad_part());
    }
    fill(slot, actor)
}

/// The NOTE an operation receipt's key leads with: `hex32(note) ":" ...`.
fn leading_note(key: &[u8]) -> Option<EntityId> {
    let (hex, rest) = key.split_at_checked(32)?;
    rest.first().filter(|byte| **byte == b':')?;
    let hex = std::str::from_utf8(hex).ok()?;
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Every NOTE row in `txn`, by owner.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, NOTE_HEAD, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_HEAD_DOC, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.0), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_OVERRIDE, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_SEAL, &mut out)? {
        let owner = OwnerRef::entity(&row.key);
        rows::split_actors(&mut out, owner, NOTE_SEAL, row, |seal| {
            take_actor(&mut seal.sealed_by)
        })?;
    }
    // Each fork no one decided, by its NOTE and head: its proposal document
    // goes with it when its opener does not open.
    let mut undecided = BTreeSet::new();
    for row in rows::typed_rows(dbs, txn, NOTE_FORK, &mut out)? {
        if !row.value.decided {
            undecided.insert((row.value.note, row.value.fork));
        }
        let owner = OwnerRef::entity(&row.value.note);
        rows::split_actors(&mut out, owner, NOTE_FORK, row, |fork| {
            take_actor(&mut fork.actor)
        })?;
    }
    for row in rows::typed_rows(dbs, txn, NOTE_PROPOSAL_DOC, &mut out)? {
        let note = row.key.0.0;
        let pending = undecided.contains(&(note, row.key.1.0));
        loro::capture_proposal(&mut out, note, pending, row);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_RECEIPT, &mut out)? {
        let owner = OwnerRef::entity(&row.value.note);
        rows::split_actors(&mut out, owner, NOTE_RECEIPT, row, |receipt| {
            take_actor(&mut receipt.actor)
        })?;
    }
    bundle::capture(dbs, txn, &mut out)?;
    pins::capture(dbs, txn, &mut out)?;
    capture_operation_receipts(dbs, txn, &mut out)?;
    title_index::checkpoint::capture(dbs, txn, &mut out)?;
    Ok(out)
}

/// Each applied or rejected operation receipt and each command receipt,
/// under the NOTE its key leads with.
fn capture_operation_receipts(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    out: &mut Captured,
) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, SYNC_NC_E, out)? {
        match leading_note(&row.key) {
            Some(note) => out.exact(OwnerRef::entity(&note), row.at, row.bytes),
            None => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
    }
    for row in rows::typed_rows(dbs, txn, NOTE_RECEIPT_BY_REQUEST, out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        rows::split_actors(out, owner, NOTE_RECEIPT_BY_REQUEST, row, |receipt| {
            take_actor(&mut receipt.0)
        })?;
    }
    Ok(())
}

fn owns(at: &RowLocator) -> bool {
    [
        NOTE_HEAD.decl(),
        NOTE_HEAD_DOC.decl(),
        NOTE_OVERRIDE.decl(),
        NOTE_SEAL.decl(),
        NOTE_FORK.decl(),
        NOTE_RECEIPT.decl(),
        NOTE_PROPOSAL_BUNDLE.decl(),
        NOTE_PROPOSAL_DOC.decl(),
        SYNC_NC_E.decl(),
        NOTE_RECEIPT_BY_REQUEST.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
        || pins::owns(at)
        || title_index::checkpoint::owns(at)
}

/// The bundle framing of `rows`' NOTE parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(NOTE_HEAD.decl()) {
        rows::check_row(NOTE_HEAD, at, value)
    } else if at.in_table(NOTE_HEAD_DOC.decl()) {
        rows::check_row(NOTE_HEAD_DOC, at, value)
    } else if at.in_table(NOTE_OVERRIDE.decl()) {
        rows::check_row(NOTE_OVERRIDE, at, value)
    } else if at.in_table(NOTE_SEAL.decl()) {
        rows::check_row(NOTE_SEAL, at, value)
    } else if at.in_table(NOTE_FORK.decl()) {
        rows::check_row(NOTE_FORK, at, value)
    } else if at.in_table(NOTE_RECEIPT.decl()) {
        rows::check_row(NOTE_RECEIPT, at, value)
    } else if at.in_table(NOTE_PROPOSAL_BUNDLE.decl()) {
        rows::check_row(NOTE_PROPOSAL_BUNDLE, at, value)
    } else if at.in_table(NOTE_PROPOSAL_DOC.decl()) {
        rows::check_row(NOTE_PROPOSAL_DOC, at, value)?;
        loro::check_proposal(at, value)
    } else if at.in_table(SYNC_NC_E.decl()) {
        rows::check_row(SYNC_NC_E, at, value)
    } else if at.in_table(NOTE_RECEIPT_BY_REQUEST.decl()) {
        rows::check_row(NOTE_RECEIPT_BY_REQUEST, at, value)
    } else if pins::owns(at) {
        pins::check(at, value)
    } else if title_index::checkpoint::owns(at) {
        title_index::checkpoint::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A no-one-form row with its opened actors back. A fork no one decided
/// whose opener did not open goes, as the erase deletes it; every other row
/// stays, naming no one where its actor did not open. A proposal document's
/// history is rebuilt the same, a document of the NOTE its key leads with.
fn join(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(NOTE_FORK.decl()) {
        let fork = rows::join_actors(NOTE_FORK, value, parts, |fork, field, actor| {
            put_actor(&mut fork.actor, field, actor)
        })?;
        if fork.actor == NoteActor::Erased
            && !fork.decided
            && ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete
        {
            return Ok(None);
        }
        return NOTE_FORK.encode_value(&fork).map(Some);
    }
    if at.in_table(NOTE_SEAL.decl()) {
        let seal = rows::join_actors(NOTE_SEAL, value, parts, |seal, field, actor| {
            put_actor(&mut seal.sealed_by, field, actor)
        })?;
        return NOTE_SEAL.encode_value(&seal).map(Some);
    }
    if at.in_table(NOTE_RECEIPT.decl()) {
        let receipt = rows::join_actors(NOTE_RECEIPT, value, parts, |receipt, field, actor| {
            put_actor(&mut receipt.actor, field, actor)
        })?;
        return NOTE_RECEIPT.encode_value(&receipt).map(Some);
    }
    if at.in_table(NOTE_RECEIPT_BY_REQUEST.decl()) {
        let receipt = rows::join_actors(
            NOTE_RECEIPT_BY_REQUEST,
            value,
            parts,
            |receipt, field, actor| put_actor(&mut receipt.0, field, actor),
        )?;
        return NOTE_RECEIPT_BY_REQUEST.encode_value(&receipt).map(Some);
    }
    if at.in_table(NOTE_PROPOSAL_BUNDLE.decl()) {
        return bundle::join(dbs, view, at, value, parts);
    }
    if at.in_table(NOTE_PROPOSAL_DOC.decl()) {
        return loro::join_proposal(at, value, parts).map(Some);
    }
    Err(rows::bad_part())
}

/// A no-one-form row with its opened actors back, at the key it restores
/// to: a title row's key and value are spelled back from its NOTE half and
/// its author's part ([`title_index::checkpoint::join`]), and every other
/// row keeps its part's key ([`join`]).
fn join_row(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<(RowLocator, Vec<u8>)>> {
    if title_index::checkpoint::owns(at) {
        return title_index::checkpoint::join(at, value, parts);
    }
    Ok(join(dbs, view, at, value, parts)?.map(|value| (at.clone(), value)))
}

/// Puts `opened`'s NOTE rows back: exact rows as they are, each actor that
/// opened back in its row, each bundle fragment and explainer copy merged
/// into the bundle the owners restored so far hold, and each title row whose
/// author opened, its key spelled back.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts_keyed(dbs, txn, &opened, check, |view, at, value, parts| {
        join_row(dbs, view, at, value, parts)
    })
}
