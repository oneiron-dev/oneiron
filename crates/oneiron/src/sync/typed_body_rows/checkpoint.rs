//! A typed body's row in a checkpoint (KS7-3a), read with its family's codec
//! and filed under its own key. A commit receipt rides with its body's
//! entity. A live one names its actor and its MadeBy's process's actor, which
//! no split here takes out, so it stays unclassified, named with it; an
//! erased one names no one and is its entity's. A fork rides with its body's
//! entity too: one naming its opener, the actor that merged or discarded it,
//! or a schema owner's record stays unclassified, named with it; one naming
//! no one is its entity's, with the parts of its snapshot. A part is the
//! fork's that lists it.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{Row, decode_row, entity_of, snapshot_parts};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, KeyClass, Placement, SyncUnclassified};

/// A live receipt's actors.
const RECEIPT_ACTORS: &str = "a typed body receipt names its actor and its process's actor";

/// A fork's actors.
const FORK_ACTORS: &str =
    "a typed body fork names its opener and its settler, and its owner's record names its own";

/// Where the row under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    if is_part_key(key) {
        return Placement::Part;
    }
    match decode_row(key, value) {
        Ok(Row::Receipt(record)) => {
            let owner = OwnerRef::entity(&record.entity);
            if record.names_actor() {
                Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(RECEIPT_ACTORS))
            } else {
                Placement::owned(owner, Vec::new())
            }
        }
        Ok(Row::Fork(carried)) => {
            let owner = OwnerRef::entity(&carried.entity);
            if carried.names_actor() {
                return Placement::unclassified(
                    Some(owner),
                    SyncUnclassified::ActorSplit(FORK_ACTORS),
                );
            }
            match snapshot_parts(&carried) {
                Some(parts) => Placement::Manifest {
                    holders: vec![Holder::new(owner, Vec::new())],
                    parts: parts.clone(),
                    joined: None,
                },
                None => Placement::owned(owner, Vec::new()),
            }
        }
        Err(_) => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a typed body row map key spells: its body's id and its commit peer
/// or its fork's id, or a part's digest.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if is_part_key(key) {
        KeyClass::Digest
    } else if entity_of(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
