//! FIX 12763: narrow helpers for one portable manifest carrier.
//!
//! The window door reviews and discards one exact carried manifest through
//! these two helpers alone: a bound read that joins and checks the head
//! under one portable id, and an exact deletion that drops that head plus
//! the parts no remaining valid head lists. No mirror, merge, scrub or copy
//! behavior is changed. The collection here is scoped to the removed head's
//! parts only, never a global unreferenced sweep.

use loro::LoroDoc;

use crate::error::Result;
use crate::origin::{RepoManifest, RepoPortableId};

/// The carried manifest filed under `portable` when it is present,
/// canonical, joined and bound: the head decodes in its one spelling with
/// well-formed parts, every part is present with matching digests and total
/// length, the joined bytes decode as a manifest, and the map key, the
/// head's CODE and the manifest's portable id and CODE all agree. `None`
/// for a missing, pending, malformed or unbound carrier.
pub(crate) fn carried_manifest_for_portable(
    doc: &LoroDoc,
    portable: &RepoPortableId,
) -> Option<RepoManifest> {
    if !super::holds_repo_manifest_map(doc) {
        return None;
    }
    let map = doc.get_map(super::REPO_MANIFESTS_MAP);
    let key = portable.to_hex();
    let bytes = crate::sync::loro_support::map_get_bytes(&map, &key)?;
    let carried = super::decode(&bytes).ok()?;
    let joined = crate::sync::carrier_parts::join_parts(&map, &carried.body)?;
    let manifest = RepoManifest::decode(&joined)?;
    if manifest.portable != *portable || manifest.code != carried.code {
        return None;
    }
    Some(manifest)
}

/// Deletes the head filed under `portable` plus the part rows it lists
/// that no remaining valid head lists, committing with the bridge origin.
/// Leaves every other head, every unrelated pending part and every local
/// manifest row untouched. `Ok(false)` when no decodable head is filed
/// under `portable`.
pub(crate) fn delete_carrier_for_portable(
    doc: &LoroDoc,
    portable: &RepoPortableId,
) -> Result<bool> {
    use std::collections::BTreeSet;

    if !super::holds_repo_manifest_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(super::REPO_MANIFESTS_MAP);
    let key = portable.to_hex();
    let Some(bytes) = crate::sync::loro_support::map_get_bytes(&map, &key) else {
        return Ok(false);
    };
    let Ok(carried) = super::decode(&bytes) else {
        return Ok(false);
    };
    let mut remaining = BTreeSet::new();
    for (_, other) in super::head_rows(&map, |other| other != key.as_str()) {
        if let Ok(head) = super::decode(&other) {
            remaining.extend(head.body.keys());
        }
    }
    crate::sync::loro_support::map_delete(&map, &key)?;
    for part in carried.body.keys() {
        if !remaining.contains(&part) && crate::sync::loro_support::map_contains_binary(&map, &part)
        {
            crate::sync::loro_support::map_delete(&map, &part)?;
        }
    }
    super::commit(doc);
    Ok(true)
}
