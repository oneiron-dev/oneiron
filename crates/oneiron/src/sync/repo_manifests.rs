//! FIX 6870 phase 1: a repo's portable manifest on the window plane.
//!
//! A [`RepoManifest`](crate::origin::RepoManifest) names its repo's CODE
//! entity and rides the window beside that CODE row, in the
//! `repo_manifests` root map: a head under the portable id's hex naming the
//! CODE entity, and the manifest's bytes in linked parts
//! (`carrier_parts`), the shape of the MESSAGE document carrier
//! (`message_docs`) with one difference. A message document is the owner's
//! machines' alone; a manifest discloses nothing its CODE row's grant does
//! not already allow, so it rides in every window its CODE row rides, base
//! and world alike, and the federated selector copies it beside a shipped
//! CODE row only (`copy_repo_manifest_heads`, called from the selector's
//! export and admission, which already judged the CODE row).
//!
//! - Admission refuses every insert that is not a whole head filed under a
//!   portable id or a part filed under its digest. The binding of key to
//!   manifest is judged where the parts join: a joined manifest that names
//!   another id or CODE entity than its head and key is logged and left in
//!   the window, never a refusal of the update.
//! - Reverse rematerialization mirrors the standing manifest of each CODE
//!   row the window carries, and the live mirror notes a manifest write by
//!   its CODE row. Forward rematerialization, Observer B and the live
//!   mirror merge a carried manifest here
//!   (`Vault::merge_carried_repo_manifest`): rule 7 order, one standing
//!   manifest per CODE entity, a copy whose CODE row has not landed waits
//!   in the window.
//! - Every export, and the erase sweep, drop the manifest of a CODE row
//!   this vault erased or the window does not carry, with every part no
//!   head lists.

pub(super) mod checkpoint;
pub(super) mod conflicts;

use std::collections::BTreeSet;

use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::bridge::BRIDGE_ORIGIN;
use super::carrier_parts::{
    Parts, admit_part, is_part_key, join_parts, part_key, split_parts, unreferenced_parts,
    write_parts,
};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::{RepoManifest, RepoManifestMerge, RepoPortableId};

/// The window root map that carries repo manifests beside their CODE rows.
pub(crate) const REPO_MANIFESTS_MAP: &str = "repo_manifests";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("repo manifest refused: {reason}"))
}

/// A repo manifest as a window carries it: the CODE entity it names, and
/// the parts of the manifest's bytes. The portable id is its map key, and
/// the joined manifest repeats it; the merge judges that they agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedHead {
    code: EntityId,
    body: Parts,
}

fn encode(carried: &CarriedHead) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(carried).map_err(|_| refused("does not encode"))
}

/// Decodes a carried head. A head has one spelling.
fn decode(bytes: &[u8]) -> Result<CarriedHead> {
    let carried: CarriedHead =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a manifest head"))?;
    if encode(&carried)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    if !carried.body.well_formed() {
        return Err(refused("not a manifest's parts"));
    }
    Ok(carried)
}

/// Admits one insert into a window's `repo_manifests` map: a whole head
/// filed under its portable id, or a part. Unlike a MESSAGE document, a
/// manifest rides in a world window too (module docs), so `key` judges
/// nothing here.
pub(crate) fn admit_repo_manifest_carrier(
    _key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if is_part_key(map_key) {
        return admit_part(map_key, value);
    }
    if RepoPortableId::from_hex(map_key).is_none() {
        return Err(refused("not filed under a portable id"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    decode(bytes).map(|_| ())
}

/// [`admit_repo_manifest_carrier`] over every row `map` holds.
pub(crate) fn admit_repo_manifest_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &rows {
        admit_repo_manifest_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` the standing manifest of each CODE row of `codes`
/// the reverse pass just mirrored there, where this vault's copy replaces
/// the window's: rule 7 order, read from the joined held copy. A held copy
/// still waiting for its parts, or deferred for memory, stays pending for
/// a later pass; only a complete carrier proved invalid is written over.
/// The head and each part commit on their own.
pub(crate) fn mirror_repo_manifests(
    vault: &Vault,
    doc: &LoroDoc,
    codes: &[EntityId],
) -> Result<()> {
    if codes.is_empty() {
        return Ok(());
    }
    let standing = vault.standing_repo_manifests(|code| codes.contains(code))?;
    if standing.is_empty() {
        return Ok(());
    }
    let map = doc.get_map(REPO_MANIFESTS_MAP);
    for manifest in standing {
        let key = manifest.portable.to_hex();
        let held = map_get_bytes(&map, &key).and_then(|bytes| decode(&bytes).ok());
        if let Some(held) = &held {
            let joined = join_parts(&map, &held.body);
            let held_manifest = joined.as_deref().and_then(RepoManifest::decode);
            if let Some(held_manifest) = held_manifest
                && (held.code != manifest.code
                    || held_manifest.portable != manifest.portable
                    || held_manifest.code != manifest.code
                    || !manifest.replaces(&held_manifest)?)
            {
                continue;
            }
            if joined.is_none() && !held_carrier_proved_invalid(&map, &held.body) {
                continue;
            }
        }
        let encoded = manifest.encode()?;
        let (parts, pieces) = split_parts(&encoded)?;
        let carried = CarriedHead {
            code: manifest.code,
            body: parts,
        };
        map_insert_bytes(&map, &key, &encode(&carried)?)?;
        commit(doc);
        write_parts(&map, &pieces, || commit(doc))?;
        if let Some(held) = held {
            let listed: BTreeSet<String> = carried.body.keys().collect();
            // Manifests share digest-keyed chunks across heads: a part this
            // head dropped stays while another head still lists it.
            let mut shared: BTreeSet<String> = BTreeSet::new();
            for (_, bytes) in head_rows(&map, |other| other != key) {
                if let Ok(other) = decode(&bytes) {
                    shared.extend(other.body.keys());
                }
            }
            for part in held.body.keys() {
                if !listed.contains(&part)
                    && !shared.contains(&part)
                    && map_contains_binary(&map, &part)
                {
                    map_delete(&map, &part)?;
                }
            }
            commit(doc);
        }
    }
    Ok(())
}

/// Whether the held head's carrier is complete but proved invalid:
/// every part present, yet a part's bytes do not match its digest or the
/// sizes do not add up. A head still waiting for a part is not invalid;
/// nor is one whose present, digest-clean parts fail only the join's
/// memory reserve. Both stay pending for a later pass.
fn held_carrier_proved_invalid(map: &LoroMap, body: &Parts) -> bool {
    let mut total = 0_usize;
    for digest in &body.parts {
        let Some(part) = map_get_bytes(map, &part_key(digest)) else {
            return false;
        };
        if blake3::hash(&part).as_bytes() != digest {
            return true;
        }
        total += part.len();
    }
    usize::try_from(body.len).is_ok_and(|len| total != len)
}

fn commit(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
}

/// Merges every manifest window `key`'s document carries, as a window open
/// does. A manifest that fails is logged and left; it never stops the open.
pub(crate) fn apply_repo_manifest_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if !holds_repo_manifest_map(doc) {
        return;
    }
    let map = doc.get_map(REPO_MANIFESTS_MAP);
    let heads = head_rows(&map, |_| true);
    merge_heads(vault, &map, key.as_str(), heads);
}

/// Observer B for the repo manifest map: each head an import brought, and
/// each head one of whose parts it brought, since a head waits for its
/// parts.
pub(crate) fn materialize_repo_manifests_from_delta(
    doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut updated = BTreeSet::new();
    let mut part_landed = false;
    for (key, value) in &delta.updated {
        if let Some(ValueOrContainer::Value(LoroValue::Binary(_))) = value {
            let key = key.to_string();
            part_landed |= is_part_key(&key);
            updated.insert(key);
        }
    }
    let map = doc.get_map(REPO_MANIFESTS_MAP);
    let mut heads = head_rows(&map, |_| true);
    heads.retain(|(map_key, bytes)| {
        updated.contains(map_key)
            || (part_landed
                && decode(bytes)
                    .is_ok_and(|carried| carried.body.keys().any(|part| updated.contains(&part))))
    });
    merge_heads(vault, &map, window_key, heads);
    Some(Vec::new())
}

/// Merges the manifests window `key`'s document carries for `rows`, just
/// committed here: a CODE row that lands after its manifest's head finds
/// it here. An authority log entry among `rows` (the owner's origin cut
/// among them, FIX 15740) merges every head, since any copy waiting for a
/// proven writer may be proven now.
pub(crate) fn merge_committed_repo_manifests(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    rows: &BTreeSet<EntityId>,
) {
    if !holds_repo_manifest_map(doc) {
        return;
    }
    let authority_moved = holds_authority_entry(vault, rows);
    let map = doc.get_map(REPO_MANIFESTS_MAP);
    let heads = head_rows(&map, |_| true)
        .into_iter()
        .filter(|(_, bytes)| {
            authority_moved || decode(bytes).is_ok_and(|carried| rows.contains(&carried.code))
        })
        .collect();
    merge_heads(vault, &map, key.as_str(), heads);
}

/// Whether `rows` holds an authority log entry, each read by its header in
/// place. A read fault reads as none: the next window open merges every
/// head anyway.
fn holds_authority_entry(vault: &Vault, rows: &BTreeSet<EntityId>) -> bool {
    let Ok(txn) = vault.store.env.read_txn() else {
        return false;
    };
    rows.iter().any(|id| {
        matches!(
            crate::batch::stored_entity_type(&vault.store, &txn, id),
            Ok(Some(crate::registry::ENTITY_TYPE_AUTHORITY_LOG))
        )
    })
}

/// Each head `map` holds whose key `keep` takes, with its value.
fn head_rows(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if !is_part_key(map_key)
            && keep(map_key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Whether `doc` holds a repo manifest map. Looking a root up by name
/// creates it: look first.
fn holds_repo_manifest_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(REPO_MANIFESTS_MAP))
}

/// Merges each carried head's manifest here. A head whose parts have not
/// landed waits for them; one whose joined manifest names another id or
/// CODE entity than its key and head, or does not decode, is logged and
/// left in the window (module docs): it never refuses the update that
/// brought it.
fn merge_heads(vault: &Vault, map: &LoroMap, window: &str, heads: Vec<(String, Vec<u8>)>) {
    let mut merged = 0_usize;
    for (map_key, bytes) in heads {
        let (carried, portable) = match (decode(&bytes), RepoPortableId::from_hex(&map_key)) {
            (Ok(carried), Some(portable)) => (carried, portable),
            _ => {
                tracing::warn!(window, key = %map_key, "repo manifest head malformed; left out");
                continue;
            }
        };
        let Some(joined) = join_parts(map, &carried.body) else {
            tracing::debug!(window, key = %map_key, "repo manifest waits for its parts");
            continue;
        };
        let Some(manifest) = RepoManifest::decode(&joined) else {
            tracing::warn!(window, key = %map_key, "repo manifest malformed; left out");
            continue;
        };
        if manifest.portable != portable || manifest.code != carried.code {
            tracing::warn!(
                window,
                key = %map_key,
                "repo manifest names another id or CODE entity than its head; left in the window"
            );
            continue;
        }
        match vault.merge_carried_repo_manifest(&manifest) {
            Ok(RepoManifestMerge::Adopted) => merged += 1,
            Ok(RepoManifestMerge::Held) => {}
            Ok(RepoManifestMerge::Waiting) => {
                tracing::debug!(window, key = %map_key, "repo manifest waits for its CODE row");
            }
            Ok(RepoManifestMerge::Unproven) => tracing::debug!(
                window,
                key = %map_key,
                "repo manifest waits for a proven refs writer; the one held here stands"
            ),
            Ok(RepoManifestMerge::Conflict) => tracing::warn!(
                window,
                key = %map_key,
                "repo manifest conflicts; the one held here stands and the other stays in the window"
            ),
            Err(error) => {
                tracing::warn!(window, key = %map_key, error = %error, "repo manifest not merged");
            }
        }
    }
    if merged > 0 {
        tracing::debug!(window, merged, "repo manifests merged");
    }
}

/// Drops from `doc` the manifest of each CODE row this vault erased or the
/// window no longer carries, with every part no remaining head lists:
/// erase wins over a manifest, and a manifest never rides where its CODE
/// row does not. `history_free` names the window pinned history-free
/// before any row goes, as `scrub_message_docs` does; the sweep passes
/// `None`. Returns whether a row went, committed.
pub(crate) fn scrub_repo_manifests(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_repo_manifest_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(REPO_MANIFESTS_MAP);
    let entities = doc.get_map("entities");
    let mut gone = Vec::new();
    let mut referenced = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, bytes) in head_rows(&map, |_| true) {
            let Ok(carried) = decode(&bytes) else {
                continue;
            };
            if !map_contains_binary(&entities, &carried.code.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &carried.code)?
            {
                gone.push(map_key);
            } else {
                referenced.extend(carried.body.keys());
            }
        }
    }
    gone.extend(unreferenced_parts(&map, &referenced));
    if gone.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &gone {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// Copies each manifest head `source` holds whose CODE entity `keep`
/// takes, with every part it lists, into `target`: the federated
/// selector's export and admission copies, run after the CODE rows they
/// judged are in `target`, so a head crosses only beside a CODE row that
/// crossed. A head missing a part in `source` stays behind whole. The
/// caller commits.
pub(crate) fn copy_repo_manifest_heads(
    source: &LoroDoc,
    target: &LoroDoc,
    keep: impl Fn(&EntityId) -> bool,
) -> Result<()> {
    if !holds_repo_manifest_map(source) {
        return Ok(());
    }
    let source_map = source.get_map(REPO_MANIFESTS_MAP);
    let target_entities = target.get_map("entities");
    let mut copies = Vec::new();
    for (map_key, bytes) in head_rows(&source_map, |key| RepoPortableId::from_hex(key).is_some()) {
        let Ok(carried) = decode(&bytes) else {
            continue;
        };
        if !keep(&carried.code) || !map_contains_binary(&target_entities, &carried.code.to_hex()) {
            continue;
        }
        let mut parts = Vec::new();
        let mut whole = true;
        for part in carried.body.keys() {
            match map_get_bytes(&source_map, &part) {
                Some(part_bytes) => parts.push((part, part_bytes)),
                None => whole = false,
            }
        }
        if whole {
            copies.push((map_key, bytes, parts));
        }
    }
    if copies.is_empty() {
        return Ok(());
    }
    let target_map = target.get_map(REPO_MANIFESTS_MAP);
    for (map_key, bytes, parts) in copies {
        map_insert_bytes(&target_map, &map_key, &bytes)?;
        for (part, part_bytes) in parts {
            map_insert_bytes(&target_map, &part, &part_bytes)?;
        }
    }
    Ok(())
}
