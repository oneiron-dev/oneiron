//! The native NOTE carriers' values in a checkpoint (KS7-3a), read with the
//! NOTE sync codecs: a proposal document and a head are their NOTE's, and
//! a landing receipt, a fork and a review bundle bind to the NOTE (or each
//! NOTE) they decode to, never to their own ids. A record naming a live
//! actor stays unclassified: no split here takes it out. One whose actor
//! was erased names no one.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeSet;

use super::{FORMAT, FORMAT_KEY, id, unpack};
use crate::EntityId;
use crate::note::{NoteActor, NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::recovery::{CanonicalHead, CanonicalHeadMove};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified};

/// A NOTE workflow record that names its actor.
const WORKFLOW_ACTOR: &str = "a NOTE workflow record names its actor";

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

/// A record of `note` naming `actor`.
fn workflow(note: EntityId, actor: &NoteActor) -> Placement {
    let owner = OwnerRef::entity(&note);
    match actor {
        NoteActor::Erased => Placement::owned(owner, Vec::new()),
        NoteActor::Actor(_) => {
            Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(WORKFLOW_ACTOR))
        }
    }
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
    let wrapper: CanonicalHeadMove = unpack(value).ok()?;
    let row: NoteLandingReceipt = unpack(&wrapper.receipt).ok()?;
    let filed = id(key).ok()? == row.id
        && wrapper.id == *row.id.as_bytes()
        && wrapper.entity_id == *row.note.as_bytes();
    filed.then(|| workflow(row.note, &row.actor))
}

fn fork(key: &str, value: &[u8]) -> Option<Placement> {
    let row: NoteFork = unpack(value).ok()?;
    (id(key).ok()? == row.fork).then(|| workflow(row.note, &row.actor))
}

/// A review bundle: each NOTE whose forks or receipts it holds keeps its
/// own copy, with the explainer they share.
fn bundle(key: &str, value: &[u8]) -> Option<Placement> {
    let row: NoteReviewBundle = unpack(value).ok()?;
    if id(key).ok()? != row.id {
        return None;
    }
    let waiting = row.waiting.iter().map(|fork| (fork.note, &fork.actor));
    let landed = row
        .landed
        .iter()
        .map(|receipt| (receipt.note, &receipt.actor));
    let named: Vec<(EntityId, &NoteActor)> = waiting.chain(landed).collect();
    let notes: BTreeSet<EntityId> = named.iter().map(|(note, _)| *note).collect();
    let first = notes.first().map(OwnerRef::entity);
    if named
        .iter()
        .any(|(_, actor)| matches!(actor, NoteActor::Actor(_)))
    {
        return Some(Placement::unclassified(
            first,
            SyncUnclassified::ActorSplit(WORKFLOW_ACTOR),
        ));
    }
    if notes.is_empty() {
        return Some(Placement::unclassified(None, SyncUnclassified::NoOwner));
    }
    let holders = notes
        .iter()
        .map(|note| Holder::new(OwnerRef::entity(note), Vec::new()))
        .collect();
    Some(Placement::Owned(holders))
}
