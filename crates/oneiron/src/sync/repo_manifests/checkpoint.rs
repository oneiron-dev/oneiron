//! A repo manifest in a checkpoint (KS7-3a), read with the head codec and
//! filed under its portable id: the head names its CODE entity and is the
//! manifest of its body's parts. The joined manifest names ids, refs and
//! pointers, and no actor, so it seals whole under its CODE entity.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use super::decode;
use crate::origin::{RepoManifest, RepoPortableId};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::{is_part_key, join_parts_from, part_key};
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

/// Checks joinable manifest heads against their portable-id keys and CODE
/// entities, using current and retained historical values from one capture.
/// Only content-addressed part values enter the lookup, so a malformed old
/// value cannot hide a correct part. Missing or memory-deferred joins keep
/// their current placement; a proved mismatch keeps the window whole under
/// the existing `Undecodable` fallback. Malformed heads remain `entry()`'s.
pub(in crate::sync) fn binding_refusal(
    entries: &[(&str, &[u8])],
) -> Option<(OwnerRef, SyncUnclassified)> {
    let mut parts: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for &(key, value) in entries {
        if part_key(blake3::hash(value).as_bytes()) == key {
            parts.insert(key, value);
        }
    }
    for &(key, value) in entries {
        let Some(portable) = RepoPortableId::from_hex(key) else {
            continue;
        };
        let Ok(head) = decode(value) else {
            continue;
        };
        let Some(joined) = join_parts_from(&head.body, |part| parts.get(part).copied()) else {
            continue;
        };
        let Some(manifest) = RepoManifest::decode(&joined) else {
            return Some((OwnerRef::entity(&head.code), SyncUnclassified::Undecodable));
        };
        if manifest.portable != portable || manifest.code != head.code {
            return Some((OwnerRef::entity(&head.code), SyncUnclassified::Undecodable));
        }
    }
    None
}
