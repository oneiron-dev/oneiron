//! A repo manifest in a checkpoint (KS7-3a), read with the head codec and
//! filed under its portable id: the head names its CODE entity and is the
//! manifest of its body's parts. The joined manifest names ids, refs and
//! pointers, and no actor, so it seals whole under its CODE entity.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::decode;
use crate::origin::RepoPortableId;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, KeyClass, Placement, SyncUnclassified};

/// Where the value under `key` in the repo manifest map goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    if is_part_key(key) {
        return Placement::Part;
    }
    match (decode(value), RepoPortableId::from_hex(key)) {
        (Ok(carried), Some(_)) => Placement::Manifest {
            holders: vec![Holder::new(OwnerRef::entity(&carried.code), Vec::new())],
            parts: carried.body,
            joined: None,
        },
        _ => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// What a repo manifest map key spells: its portable id, or a part's digest.
pub(in crate::sync) fn key_class(key: &str) -> KeyClass {
    if is_part_key(key) {
        KeyClass::Digest
    } else if RepoPortableId::from_hex(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
