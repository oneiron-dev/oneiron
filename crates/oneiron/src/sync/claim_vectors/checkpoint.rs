//! A claim vector in a checkpoint (KS7-3a): one whole carrier filed under
//! its claim, held by that claim and naming no actor, so the value stands
//! as its own `no_one` split. The vector row inside is derived bytes; the
//! carrier is sealed beside them, never split further.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::decode;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{Holder, KeyClass, Placement, SyncUnclassified, ValueSplit};

/// Where the value under `key` in the claim vector map goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let claim = crate::EntityId::from_hex(key)
        .ok()
        .filter(|id| id.to_hex() == key);
    match (claim, decode(value)) {
        (Some(claim), Ok(_)) => Placement::split(
            vec![Holder::new(OwnerRef::entity(&claim), Vec::new())],
            ValueSplit {
                no_one: value.to_vec(),
                actors: Vec::new(),
            },
        ),
        _ => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a claim vector map key spells: its claim's id.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if crate::EntityId::from_hex(key).is_ok_and(|claim| claim.to_hex() == key) {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
