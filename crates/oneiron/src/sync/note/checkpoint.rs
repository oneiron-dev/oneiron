//! The native NOTE carriers' values in a checkpoint (KS7-3a, KS7-3b), read
//! with the NOTE sync codecs: a proposal document and a head are their
//! NOTE's, and a landing receipt, a fork and a review bundle bind to the
//! NOTE (or each NOTE) they decode to, never to their own ids. A record's
//! actor is split out (FIX 9127) as the vault's own NOTE rows split theirs:
//! the copy names no one, and an actor that does not open leaves it so. An
//! undecided fork whose opener does not open goes, and so does a bundle's
//! waiting fork, taking the bundle's explainer with it, as the erase takes
//! them ([`ACTOR_ERASE_PENDING_NOTE_FORK`]).
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeSet;

use super::{FORMAT, FORMAT_KEY, id, pack, unpack};
use crate::EntityId;
use crate::error::Result;
use crate::note::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NoteActor, NoteFork, NoteLandingReceipt, NoteReviewBundle,
    PendingNoteForkErase,
};
use crate::recovery::{CanonicalHead, CanonicalHeadMove};
use crate::store::checkpoint_payload::rows::{OwnerRef, bad_part};
use crate::sync::checkpoint_payload::{Holder, KeyClass, Placement, SyncUnclassified, ValueSplit};

/// The field a record's one actor fills.
const ACTOR: &str = "actor";

/// The field a bundle's waiting fork's opener fills, then the fork's id.
const WAITING: &str = "waiting/";

/// The field a bundle's landing receipt's actor fills, then the receipt's
/// id.
const LANDED: &str = "landed/";

/// The explainer a bundle that lost a waiting fork keeps, as the erase
/// leaves it: it can quote what left.
const REDACTED: &str = "redacted";

/// Where the value under `key` in the NOTE map `map` goes.
pub(in crate::sync) fn entry(map: &str, key: &str, value: &[u8]) -> Placement {
    let read = match map {
        "documents" => document(key, value),
        "document_heads" => head(key, value),
        "head_move_receipts" => receipt(key, value),
        "note_forks" => fork(key, value),
        "note_proposals" => bundle(key, value),
        _ => None,
    };
    read.unwrap_or_else(|| Placement::unclassified(None, SyncUnclassified::Undecodable))
}

/// What the key `key` of the NOTE map `map` spells: ids, and the proposal
/// document map's schema names.
pub(in crate::sync) fn key_class(map: &str, key: &str) -> KeyClass {
    let opaque = match map {
        "documents" if key == FORMAT_KEY => true,
        "documents" => matches!(
            key.split(':').collect::<Vec<_>>().as_slice(),
            ["note_proposal_doc", "v1", note, fork] if id(note).is_ok() && id(fork).is_ok()
        ),
        _ => id(key).is_ok(),
    };
    if opaque {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}

/// A record of `note`, `no_one` once its actor is out.
fn workflow(note: EntityId, actor: Option<EntityId>, no_one: Option<Vec<u8>>) -> Option<Placement> {
    let holders = vec![Holder::new(OwnerRef::entity(&note), Vec::new())];
    let actors = actor
        .map(|actor| vec![(ACTOR.to_owned(), actor)])
        .unwrap_or_default();
    Some(Placement::split(
        holders,
        ValueSplit {
            no_one: no_one?,
            actors,
        },
    ))
}

/// Moves a record's actor out, leaving no one.
fn take_actor(slot: &mut NoteActor) -> Option<EntityId> {
    std::mem::replace(slot, NoteActor::Erased).id()
}

/// A proposal document's text, its NOTE's; the format marker is structure.
fn document(key: &str, value: &[u8]) -> Option<Placement> {
    if key == FORMAT_KEY {
        return (value == FORMAT).then(|| Placement::Structure {
            dependencies: Vec::new(),
        });
    }
    let parts: Vec<&str> = key.split(':').collect();
    let ["note_proposal_doc", "v1", note, fork] = parts.as_slice() else {
        return None;
    };
    let note = id(note).ok()?;
    id(fork).ok()?;
    unpack::<String>(value).ok()?;
    Some(Placement::owned(OwnerRef::entity(&note), Vec::new()))
}

/// A NOTE's head: ids only, its NOTE's.
fn head(key: &str, value: &[u8]) -> Option<Placement> {
    let row: CanonicalHead = unpack(value).ok()?;
    let note = EntityId::from_bytes(row.entity_id).ok()?;
    EntityId::from_bytes(row.head).ok()?;
    (id(key).ok()? == note).then(|| Placement::owned(OwnerRef::entity(&note), Vec::new()))
}

fn receipt(key: &str, value: &[u8]) -> Option<Placement> {
    let mut wrapper: CanonicalHeadMove = unpack(value).ok()?;
    let mut row: NoteLandingReceipt = unpack(&wrapper.receipt).ok()?;
    let filed = id(key).ok()? == row.id
        && wrapper.id == *row.id.as_bytes()
        && wrapper.entity_id == *row.note.as_bytes();
    if !filed {
        return None;
    }
    let actor = take_actor(&mut row.actor);
    wrapper.receipt = pack(&row).ok()?;
    workflow(row.note, actor, pack(&wrapper).ok())
}

fn fork(key: &str, value: &[u8]) -> Option<Placement> {
    let mut row: NoteFork = unpack(value).ok()?;
    if id(key).ok()? != row.fork {
        return None;
    }
    let actor = take_actor(&mut row.actor);
    workflow(row.note, actor, pack(&row).ok())
}

/// A review bundle: each NOTE whose forks or receipts it holds keeps its
/// own copy, with the explainer they share, and each member's actor is a
/// field of its own.
fn bundle(key: &str, value: &[u8]) -> Option<Placement> {
    let mut row: NoteReviewBundle = unpack(value).ok()?;
    if id(key).ok()? != row.id {
        return None;
    }
    let waiting = row.waiting.iter().map(|fork| fork.note);
    let notes: BTreeSet<EntityId> = waiting
        .chain(row.landed.iter().map(|receipt| receipt.note))
        .collect();
    if notes.is_empty() {
        return Some(Placement::unclassified(None, SyncUnclassified::NoOwner));
    }
    let holders = notes
        .iter()
        .map(|note| Holder::new(OwnerRef::entity(note), Vec::new()))
        .collect();
    let mut actors = Vec::new();
    for fork in &mut row.waiting {
        if let Some(actor) = take_actor(&mut fork.actor) {
            actors.push((format!("{WAITING}{}", fork.fork.to_hex()), actor));
        }
    }
    for receipt in &mut row.landed {
        if let Some(actor) = take_actor(&mut receipt.actor) {
            actors.push((format!("{LANDED}{}", receipt.id.to_hex()), actor));
        }
    }
    let no_one = pack(&row).ok()?;
    Some(Placement::split(holders, ValueSplit { no_one, actors }))
}

/// Puts `actor` back where a split left no one.
fn put(slot: &mut NoteActor, actor: EntityId) -> Result<()> {
    if *slot != NoteActor::Erased {
        return Err(bad_part());
    }
    *slot = NoteActor::Actor(actor);
    Ok(())
}

/// A record's one actor back, when it opened.
fn put_one(slot: &mut NoteActor, opened: &[(&str, EntityId)]) -> Result<()> {
    for (field, actor) in opened {
        if *field != ACTOR {
            return Err(bad_part());
        }
        put(slot, *actor)?;
    }
    Ok(())
}

/// Whether an undecided fork whose opener did not open goes.
fn fork_goes(fork: &NoteFork) -> bool {
    fork.actor == NoteActor::Erased
        && !fork.decided
        && ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete
}

/// The NOTE record `no_one` of the map `map` with each of `opened` back:
/// `None` for a fork that goes, or a bundle left with no member.
pub(in crate::sync) fn fill(
    map: &str,
    no_one: &[u8],
    opened: &[(&str, EntityId)],
) -> Result<Option<Vec<u8>>> {
    match map {
        "head_move_receipts" => {
            let mut wrapper: CanonicalHeadMove = unpack(no_one)?;
            let mut row: NoteLandingReceipt = unpack(&wrapper.receipt)?;
            put_one(&mut row.actor, opened)?;
            wrapper.receipt = pack(&row)?;
            pack(&wrapper).map(Some)
        }
        "note_forks" => {
            let mut row: NoteFork = unpack(no_one)?;
            put_one(&mut row.actor, opened)?;
            if fork_goes(&row) {
                return Ok(None);
            }
            pack(&row).map(Some)
        }
        "note_proposals" => {
            let mut row: NoteReviewBundle = unpack(no_one)?;
            for (field, actor) in opened {
                let slot = if let Some(fork) = field.strip_prefix(WAITING) {
                    row.waiting
                        .iter_mut()
                        .find(|waiting| waiting.fork.to_hex() == fork)
                        .map(|waiting| &mut waiting.actor)
                } else if let Some(receipt) = field.strip_prefix(LANDED) {
                    row.landed
                        .iter_mut()
                        .find(|landed| landed.id.to_hex() == receipt)
                        .map(|landed| &mut landed.actor)
                } else {
                    None
                };
                put(slot.ok_or_else(bad_part)?, *actor)?;
            }
            let waiting = row.waiting.len();
            if ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete {
                row.waiting.retain(|fork| fork.actor != NoteActor::Erased);
            }
            if row.waiting.len() != waiting {
                if row.waiting.is_empty() && row.landed.is_empty() {
                    return Ok(None);
                }
                REDACTED.clone_into(&mut row.explainer);
            }
            pack(&row).map(Some)
        }
        _ => Err(bad_part()),
    }
}
