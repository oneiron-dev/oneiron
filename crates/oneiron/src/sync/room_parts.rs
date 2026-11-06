//! FIX 11790: a room row too large for one window value.
//!
//! A room turn row or side row whose encoding is past its map's whole-row
//! bound rides as linked parts (`carrier_parts`): the manifest that lists
//! them under the row's own key, and each part under `part/` and its digest
//! in the same map. A row within the bound rides whole under its key, byte
//! for byte as before, so a row has one spelling. Every reader takes a
//! manifest's row joined; one whose parts have not all landed waits in the
//! window, as a MESSAGE document does. Admission sees each part and the
//! manifest alone, so the row's own checks run on the joined row where it
//! merges.

use std::collections::{BTreeMap, BTreeSet};

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::carrier_parts::{
    Parts, admit_part, is_part_key, join_parts, split_parts, unreferenced_parts, write_parts,
};
use super::loro_bytes::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::offer_parts::{self, OfferManifest};
use crate::error::{Error, Result};

/// The largest room turn row a window carries whole; past it a row rides as
/// linked parts. Moved unchanged from `room_turns::MAX_ROW_BYTES` (FIX 12405).
pub(crate) const ROOM_TURN_MAX_ROW_BYTES: usize = 1 << 20;

/// The largest room side row a window carries whole; past it a row rides as
/// linked parts. Moved unchanged from `room_facts::MAX_ROW_BYTES` (FIX 12405).
pub(crate) const ROOM_FACT_MAX_ROW_BYTES: usize = 1 << 16;

/// What a manifest's value starts with. No row, a JSON object, starts with
/// a NUL byte.
const MANIFEST: &[u8] = b"\0parts\0";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("room row parts refused: {reason}"))
}

fn encode_manifest(parts: &Parts) -> Result<Vec<u8>> {
    let mut value = MANIFEST.to_vec();
    value.extend(rmp_serde::to_vec_named(parts).map_err(|_| refused("does not encode"))?);
    Ok(value)
}

/// The manifest `value` holds, in its one spelling. A checkpoint places a
/// manifest by the parts it lists.
pub(crate) fn manifest(value: &[u8]) -> Option<Parts> {
    if offer_parts::is_manifest(value) {
        return Some(OfferManifest::parse(value)?.parts());
    }
    generic_manifest(value)
}

/// The generic manifest `value` holds, in its one spelling, as [`write_row`]
/// writes a row past its bound that is no offer: never an offer's typed one.
/// A checkpoint re-parts a turn row it carries joined against it (FIX 12153).
pub(crate) fn generic_manifest(value: &[u8]) -> Option<Parts> {
    if offer_parts::is_manifest(value) {
        return None;
    }
    let parts: Parts = rmp_serde::from_slice(value.strip_prefix(MANIFEST)?).ok()?;
    (parts.well_formed() && encode_manifest(&parts).ok()? == value).then_some(parts)
}

/// The generic manifest value of `parts`, as [`write_row`] writes it.
pub(crate) fn generic_manifest_bytes(parts: &Parts) -> Result<Vec<u8>> {
    encode_manifest(parts)
}

/// The row `value`, a row key's value in `map`, carries: itself, or the join
/// of the parts its manifest lists; `None` while it waits for one.
fn joined(map: &LoroMap, value: Vec<u8>) -> Option<Vec<u8>> {
    if offer_parts::is_manifest(&value) {
        return OfferManifest::parse(&value)?.joined(map);
    }
    match manifest(&value) {
        Some(parts) => join_parts(map, &parts),
        None => Some(value),
    }
}

/// Admits one insert into a room row map that is a part, or the manifest of
/// a row past `max` (a typed Offer admits on its canonical parse alone):
/// `Ok(true)` once admitted, `Ok(false)` for a value the map's own row
/// admission judges.
pub(crate) fn admit(map_key: &str, value: &LoroValue, max: usize) -> Result<bool> {
    if is_part_key(map_key) {
        admit_part(map_key, value)?;
        return Ok(true);
    }
    let LoroValue::Binary(bytes) = value else {
        return Ok(false);
    };
    if offer_parts::is_manifest(bytes) {
        // A typed Offer admits on its canonical parse alone, with no length
        // gate: a native header erase may shrink its logical row below the
        // bound while its wording parts are still missing.
        manifest(bytes).ok_or_else(|| refused("not a manifest"))?;
        return Ok(true);
    }
    if !bytes.starts_with(MANIFEST) {
        return Ok(false);
    }
    let parts = manifest(bytes).ok_or_else(|| refused("not a manifest"))?;
    if usize::try_from(parts.len).is_ok_and(|len| len <= max) {
        return Err(refused("a row within its bound rides whole"));
    }
    Ok(true)
}

/// The row `map` holds under `key`, joined; `None` where it holds none or
/// the row waits for a part.
pub(crate) fn row_at(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    joined(map, map_get_bytes(map, key)?)
}

/// Whether the row `map` holds under `key` waits for a part to land.
pub(crate) fn waits(map: &LoroMap, key: &str) -> bool {
    map_get_bytes(map, key)
        .and_then(|value| manifest(&value))
        .is_some_and(|parts| parts.keys().any(|part| !map_contains_binary(map, &part)))
}

/// Each manifest `map` holds whose parts have not all landed, with its key
/// and parts. Whole rows and joined manifests are left out: the scrub drops
/// a waiting manifest with its present parts when its room is gone (FIX
/// 12127).
pub(crate) fn waiting_manifests(map: &LoroMap) -> Vec<(String, Parts)> {
    let mut manifests = Vec::new();
    map.for_each(|key, value| {
        if !is_part_key(key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && let Some(parts) = manifest(&bytes)
        {
            manifests.push((key.to_owned(), parts));
        }
    });
    manifests
        .into_iter()
        .filter(|(_, parts)| parts.keys().any(|part| !map_contains_binary(map, &part)))
        .collect()
}

/// Each row `map` holds under a key `keep` takes, joined, with its key. A
/// part, and a row that waits for one, are left out.
pub(crate) fn rows(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut values = Vec::new();
    map.for_each(|key, value| {
        if !is_part_key(key)
            && keep(key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            values.push((key.to_owned(), bytes.to_vec()));
        }
    });
    values
        .into_iter()
        .filter_map(|(key, value)| Some((key, joined(map, value)?)))
        .collect()
}

/// Each row of a room map for a canonical capture, from its raw binary
/// rows: a manifest with every part present as its one joined row, anything
/// else as the window holds it, parts included, so nothing is lost
/// (FIX 12126). Each manifest's assembled length is charged through
/// `charge` before any byte is copied: one part repeated names an assembly
/// far past the raw rows the budget already held. The join itself runs
/// through [`join_parts`], so its memory admission holds here as in the
/// window (FIX 8880).
pub(crate) fn capture_rows(
    raw: &BTreeMap<String, Vec<u8>>,
    charge: &mut impl FnMut(usize) -> Result<()>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let scratch = LoroDoc::new();
    let map = scratch.get_map("parts");
    for (key, value) in raw {
        if is_part_key(key) {
            map_insert_bytes(&map, key, value)?;
        }
    }
    let mut out = BTreeMap::new();
    let mut consumed = BTreeSet::new();
    for (key, value) in raw {
        if is_part_key(key) {
            continue;
        }
        match manifest(value) {
            Some(parts) => {
                let len = match OfferManifest::parse(value) {
                    Some(offer) => offer.logical_len().ok_or_else(|| refused("too long"))?,
                    None => parts.len,
                };
                charge(usize::try_from(len).map_err(|_| refused("too long"))?)?;
                match joined(&map, value.clone()) {
                    Some(row) => {
                        consumed.extend(parts.keys());
                        out.insert(key.clone(), row);
                    }
                    None => {
                        out.insert(key.clone(), value.clone());
                    }
                }
            }
            None => {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    for (key, value) in raw {
        if is_part_key(key) && !consumed.contains(key) {
            out.insert(key.clone(), value.clone());
        }
    }
    Ok(out)
}

/// The rows of `map` an import changed, joined, and each row key it cleared
/// as `None`: each row key `delta` updated, and each row a part it brought
/// completes, since a manifest waits for its parts.
pub(crate) fn changed_rows(map: &LoroMap, delta: &MapDelta<'_>) -> Vec<(String, Option<Vec<u8>>)> {
    let mut changed = BTreeMap::new();
    let mut landed = BTreeSet::new();
    for (key, value) in &delta.updated {
        let key = key.to_string();
        match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(_))) if is_part_key(&key) => {
                landed.insert(key);
            }
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                changed.insert(key, Some(bytes.to_vec()));
            }
            None if !is_part_key(&key) => {
                changed.insert(key, None);
            }
            _ => {}
        }
    }
    if !landed.is_empty() {
        map.for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && let Some(parts) = manifest(&bytes)
                && parts.keys().any(|part| landed.contains(&part))
            {
                changed
                    .entry(key.to_owned())
                    .or_insert_with(|| Some(bytes.to_vec()));
            }
        });
    }
    changed
        .into_iter()
        .filter_map(|(key, value)| match value {
            Some(value) => joined(map, value).map(|row| (key, Some(row))),
            None => Some((key, None)),
        })
        .collect()
}

/// Writes `row` into `map` under `key`: whole within `max` bytes, past it as
/// its manifest and its parts, all in the caller's commit. A part only the
/// old manifest under `key` listed goes.
pub(crate) fn write_row(map: &LoroMap, key: &str, row: &[u8], max: usize) -> Result<()> {
    let was_split = map_get_bytes(map, key).is_some_and(|value| manifest(&value).is_some());
    if row.len() > max {
        if !offer_parts::write_row(map, key, row, max)? {
            let (parts, pieces) = split_parts(row)?;
            map_insert_bytes(map, key, &encode_manifest(&parts)?)?;
            write_parts(map, &pieces, || {})?;
        }
    } else {
        map_insert_bytes(map, key, row)?;
    }
    if was_split {
        drop_unlisted_parts(map)?;
    }
    Ok(())
}

/// The key of each part `map` holds that no manifest in it lists.
pub(crate) fn unlisted_parts(map: &LoroMap) -> Vec<String> {
    let mut listed = BTreeSet::new();
    map.for_each(|key, value| {
        if !is_part_key(key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && let Some(parts) = manifest(&bytes)
        {
            listed.extend(parts.keys());
        }
    });
    unreferenced_parts(map, &listed)
}

/// Deletes each part `map` holds that no manifest in it lists, as a row that
/// went or shrank leaves them. Returns whether one went; the caller commits.
pub(crate) fn drop_unlisted_parts(map: &LoroMap) -> Result<bool> {
    let unlisted = unlisted_parts(map);
    for part in &unlisted {
        map_delete(map, part)?;
    }
    Ok(!unlisted.is_empty())
}
