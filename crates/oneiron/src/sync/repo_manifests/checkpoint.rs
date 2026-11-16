//! A repo manifest in a checkpoint (KS7-3a), read with the head codec and
//! filed under its portable id: the head names its CODE entity and is the
//! manifest of its body's parts. The joined manifest names ids, refs and
//! pointers, and no actor, so it seals whole under its CODE entity.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this (CHECKPOINT_PAYLOADS_ENABLED, on since KS7-6)"
)]

use super::decode;
use crate::origin::{RepoManifest, RepoPortableId};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::{is_part_key, join_parts_from};
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

/// Whether the repo head `value` under `key` is the manifest its key names,
/// its parts joined through `part` (UC-10 PR 1): `Some(true)` when the
/// joined manifest names the key's portable id and the head's CODE entity,
/// `Some(false)` when it is another manifest. `None` for a value that is no
/// head under a portable id, for a head whose parts do not all join, and
/// for joined bytes that read as no manifest: it proves no binding.
pub(in crate::sync) fn bound<B: AsRef<[u8]>>(
    key: &str,
    value: &[u8],
    part: impl FnMut(&str) -> Option<B>,
) -> Option<bool> {
    let portable = RepoPortableId::from_hex(key)?;
    let head = decode(value).ok()?;
    let joined = join_parts_from(&head.body, part)?;
    RepoManifest::decode(&joined)
        .map(|manifest| manifest.portable == portable && manifest.code == head.code)
}

/// The CODE entity of the repo head `value` under `key` when its parts do
/// not join through `part` to a manifest but it names one `part` holds: its
/// holder would still take that part, so the capture keeps the window whole
/// (FIX 10278), as it does when every part is held and the joined bytes
/// read as no manifest. `None` for a head that joins to a manifest, or
/// names no held part.
pub(in crate::sync) fn unjoined_holder<B: AsRef<[u8]>>(
    key: &str,
    value: &[u8],
    part: impl Fn(&str) -> Option<B>,
) -> Option<OwnerRef> {
    RepoPortableId::from_hex(key)?;
    let head = decode(value).ok()?;
    if join_parts_from(&head.body, &part)
        .and_then(|joined| RepoManifest::decode(&joined))
        .is_some()
    {
        return None;
    }
    head.body
        .keys()
        .any(|key| part(&key).is_some())
        .then(|| OwnerRef::entity(&head.code))
}
