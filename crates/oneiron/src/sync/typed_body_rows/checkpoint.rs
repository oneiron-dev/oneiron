//! A typed body's row in a checkpoint (KS7-3a), read with its family's codec
//! and filed under its own key. A commit receipt rides with its body's
//! entity. A live one names its actor and its MadeBy's process's actor, which
//! no split here takes out, so it stays unclassified, named with it; an
//! erased one names no one and is its entity's.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{decode_receipt, receipt_key, receipt_of};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{KeyClass, Placement, SyncUnclassified};

/// A live receipt's actors.
const RECEIPT_ACTORS: &str = "a typed body receipt names its actor and its process's actor";

/// Where the row under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    match decode_receipt(value) {
        Ok(record) if receipt_key(&record) == key => {
            let owner = OwnerRef::entity(&record.entity);
            if record.names_actor() {
                Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(RECEIPT_ACTORS))
            } else {
                Placement::owned(owner, Vec::new())
            }
        }
        _ => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a typed body row map key spells: its body's id and its commit peer.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if receipt_of(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
