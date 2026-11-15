//! The checkpoint getter of NOTE rows (KS7-2): each NOTE's head, head
//! documents, overrides and seal under its own entity tree; each fork and
//! landing receipt under the NOTE its record names; each review bundle under
//! its members' NOTE ([`bundle`]); each pin index row under its citing
//! document ([`pins`]); each operation receipt under the NOTE its key leads
//! with; and each title row, its key split from its author
//! ([`super::title_index::checkpoint`]). Every actor a row names is split
//! out; a fork no one decided whose opener stays erased goes on restore with
//! its proposal document, as the erase deletes both (FIX 3520, FIX 6523).
//!
//! A proposal head's Loro snapshot splits through the shared Loro projection
//! under its NOTE ([`loro`], FIX 6072): its stamps' and authorship records'
//! actors out, and the join writing the same history back with every actor
//! that did not open erased; its pins stay in it, and the restore's
//! citation erase takes out each one whose record went (FIX 18270). A
//! shallow one, and one whose fork no one decided and whose fork record did
//! not split beside it, stay under the vault-wide seal, named with the NOTE.
//! The live documents' rows are split by the entity-document getter through
//! the same NOTE codec, and a NOTE core's author by the entity-row getter
//! ([`body`]). Nothing calls this until KS7-5, and only
//! once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod body;
mod bundle;
mod loro;
mod pins;

use std::collections::BTreeMap;

use heed::RoTxn;

pub(crate) use self::body::{CORE_RAW_REFS, join_core_row, reads_core_row, split_core_row};
pub(crate) use self::loro::{
    check_live_snapshot, frames_live, join_live, snapshot_note, split_live,
};

use super::documents::{NOTE_HEAD, NOTE_HEAD_DOC, NOTE_PROPOSAL_DOC};
use super::lifecycle::NOTE_SEAL;
use super::overrides::NOTE_OVERRIDE;
use super::pin_index::{
    NOTE_PIN_CITING, NOTE_PIN_CLAIM, NOTE_PIN_REQUEST_CITING, NOTE_PIN_REQUEST_CLAIM,
    NOTE_PIN_REQUEST_SOURCE, NOTE_PIN_SOURCE,
};
use super::proposals::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_RECEIPT, NoteActor,
    NoteFork, PendingNoteForkErase,
};
use super::side_keys::HexPair;
use super::sync_rows::{NOTE_FORK_AUTHORITY, NOTE_RECEIPT_BY_REQUEST, SYNC_NC_E};
use super::title_index;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, CapturedByAdapter, Check, Join, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, Unresolved,
};
use crate::store::{ManifestDbs, Store};

/// Every NOTE row by owner, its actors split out. The capture is the
/// adapter's own: a proposal document splits only beside its fork record,
/// and a bundle by its members. So is the check (a proposal's history, a
/// title's spelling), and the join reads the whole compartment: a proposal
/// document goes with a fork record that joins as one the erase deletes,
/// and a title row's key is spelled back from its author's part.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &CapturedByAdapter(NOTE_HEAD),
        &CapturedByAdapter(NOTE_HEAD_DOC),
        &CapturedByAdapter(NOTE_OVERRIDE),
        &CapturedByAdapter(NOTE_SEAL),
        &CapturedByAdapter(NOTE_FORK),
        &CapturedByAdapter(NOTE_RECEIPT),
        &CapturedByAdapter(NOTE_PROPOSAL_BUNDLE),
        &CapturedByAdapter(NOTE_PROPOSAL_DOC),
        &CapturedByAdapter(SYNC_NC_E),
        &CapturedByAdapter(NOTE_RECEIPT_BY_REQUEST),
        &CapturedByAdapter(NOTE_FORK_AUTHORITY),
        &CapturedByAdapter(NOTE_PIN_SOURCE),
        &CapturedByAdapter(NOTE_PIN_CLAIM),
        &CapturedByAdapter(NOTE_PIN_CITING),
        &CapturedByAdapter(NOTE_PIN_REQUEST_CITING),
        &CapturedByAdapter(NOTE_PIN_REQUEST_CLAIM),
        &CapturedByAdapter(NOTE_PIN_REQUEST_SOURCE),
        title_index::checkpoint::RESERVATION_TABLE,
        title_index::checkpoint::BY_NOTE_TABLE,
    ],
    capture: Capture::Own(capture),
    check: Check::Own(check),
    row_owner: None,
    join: Join::Compartment(join_row),
    restore: Restore::Parts,
};

/// The field a row's one actor fills.
const ACTOR: &str = "actor";

/// Moves a row's local actor out, leaving no one. An imported author is
/// source provenance, never a local actor part: it stays in the row
/// (FIX 7777).
fn take_actor(slot: &mut NoteActor) -> Vec<(String, EntityId)> {
    match *slot {
        NoteActor::Actor(id) => {
            *slot = NoteActor::Erased;
            vec![(ACTOR.to_owned(), id)]
        }
        NoteActor::Erased | NoteActor::Imported(_) => Vec::new(),
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
fn capture(store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(store, txn, NOTE_HEAD, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(store, txn, NOTE_HEAD_DOC, out)? {
        out.exact(OwnerRef::entity(&row.key.0), row.at, row.bytes);
    }
    for row in rows::typed_rows(store, txn, NOTE_OVERRIDE, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(store, txn, NOTE_SEAL, out)? {
        let owner = OwnerRef::entity(&row.key);
        rows::split_actors(out, owner, NOTE_SEAL, row, |seal| {
            take_actor(&mut seal.sealed_by)
        })?;
    }
    // Each fork no one decided, by its NOTE and head, and whether its record
    // split under that NOTE: its proposal document goes with it when its
    // opener does not open, so the document splits only beside the record.
    let mut undecided = BTreeMap::new();
    for row in rows::typed_rows(store, txn, NOTE_FORK, out)? {
        let owner = OwnerRef::entity(&row.value.note);
        if !row.value.decided {
            // The split places the record under `owner` exactly when its
            // codec spells it back; otherwise it leaves it unclassified. Its
            // document's restore finds it by the head its key names.
            let beside = row.key == row.value.fork && rows::spells_back(NOTE_FORK, &row);
            undecided.insert((row.value.note, row.value.fork), beside);
        }
        rows::split_actors(out, owner, NOTE_FORK, row, |fork| {
            take_actor(&mut fork.actor)
        })?;
    }
    for row in rows::typed_rows(store, txn, NOTE_PROPOSAL_DOC, out)? {
        let note = row.key.0.0;
        let fork = undecided.get(&(note, row.key.1.0)).copied();
        loro::capture_proposal(out, note, fork, row);
    }
    for row in rows::typed_rows(store, txn, NOTE_RECEIPT, out)? {
        let owner = OwnerRef::entity(&row.value.note);
        rows::split_actors(out, owner, NOTE_RECEIPT, row, |receipt| {
            take_actor(&mut receipt.actor)
        })?;
    }
    bundle::capture(store, txn, out)?;
    pins::capture(store, txn, out)?;
    capture_operation_receipts(store, txn, out)?;
    title_index::checkpoint::capture(store, txn, out)
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
    // Each mark on a fork its authority sent, under the NOTE its key leads
    // with (FIX 12789).
    for row in rows::typed_rows(dbs, txn, NOTE_FORK_AUTHORITY, out)? {
        out.exact(OwnerRef::entity(&row.key.0.0), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_RECEIPT_BY_REQUEST, out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        rows::split_actors(out, owner, NOTE_RECEIPT_BY_REQUEST, row, |receipt| {
            take_actor(&mut receipt.0)
        })?;
    }
    Ok(())
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
    } else if at.in_table(NOTE_FORK_AUTHORITY.decl()) {
        rows::check_row(NOTE_FORK_AUTHORITY, at, value)
    } else if pins::owns(at) {
        pins::check(at, value)
    } else if title_index::checkpoint::owns(at) {
        title_index::checkpoint::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// Whether a joined fork record goes: one no one decided whose opener did
/// not open, as the erase deletes it (FIX 3520).
fn pending_fork_goes(fork: &NoteFork) -> bool {
    fork.actor == NoteActor::Erased
        && !fork.decided
        && ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete
}

/// Whether the proposal document at `at` goes with its fork on this restore
/// (FIX 6523): the fork record of its head in `opened` joins as one no one
/// decided whose opener did not open, which the erase deletes with its
/// document. An exact record restores as it is, and so does its document. A
/// document no record here names (a decided fork's is split exact or with
/// its own actors, as is an unforked one) stays.
fn proposal_goes(opened: &OpenedOwnerRows, at: &RowLocator) -> Result<bool> {
    let key = at.key.strip_prefix(NOTE_PROPOSAL_DOC.decl().prefix);
    let key = key
        .and_then(HexPair::decode_key)
        .ok_or_else(rows::bad_part)?;
    let record = RowLocator::row(RowDb::of(NOTE_FORK.decl()), NOTE_FORK.key_bytes(&key.1.0));
    let Some(part) = opened.rows.iter().find(|part| part.at() == &record) else {
        return Ok(false);
    };
    match part {
        RowPart::Exact { .. } => Ok(false),
        RowPart::NoActor { value, .. } => {
            let parts: Vec<&ActorPart> = opened
                .actor_parts
                .iter()
                .filter(|part| part.content_locator == record)
                .collect();
            let fork = rows::join_actors(NOTE_FORK, value, &parts, |fork, field, actor| {
                put_actor(&mut fork.actor, field, actor)
            })?;
            Ok(fork.note == key.0.0 && pending_fork_goes(&fork))
        }
        RowPart::ActorKeyed { .. } => Err(rows::bad_part()),
    }
}

/// A no-one-form row with its opened actors back. A fork no one decided
/// whose opener did not open goes with its proposal document, as the erase
/// deletes both; every other row stays, naming no one where its actor did
/// not open. A proposal document's history is rebuilt the same, a document
/// of the NOTE its key leads with.
fn join(
    dbs: &impl ManifestDbs,
    view: &RoTxn<'_>,
    opened: &OpenedOwnerRows,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(NOTE_FORK.decl()) {
        let fork = rows::join_actors(NOTE_FORK, value, parts, |fork, field, actor| {
            put_actor(&mut fork.actor, field, actor)
        })?;
        if pending_fork_goes(&fork) {
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
        if proposal_goes(opened, at)? {
            return Ok(None);
        }
        return loro::join_proposal(at, value, parts).map(Some);
    }
    Err(rows::bad_part())
}

/// A no-one-form row with its opened actors back, at the key it restores
/// to: a title row's key and value are spelled back from its NOTE half and
/// its author's part ([`title_index::checkpoint::join`]), and every other
/// row keeps its part's key ([`join`]). A restore puts exact rows back as
/// they are, and merges each bundle fragment and explainer copy into the
/// bundle the owners restored so far hold.
fn join_row(
    store: &Store,
    view: &RoTxn<'_>,
    opened: &OpenedOwnerRows,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<(RowLocator, Vec<u8>)>> {
    if title_index::checkpoint::owns(at) {
        return title_index::checkpoint::join(at, value, parts);
    }
    Ok(join(store, view, opened, at, value, parts)?.map(|value| (at.clone(), value)))
}
