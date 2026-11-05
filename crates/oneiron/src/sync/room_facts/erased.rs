//! The room side rows a carrier holds that name an actor this vault erased
//! (FIX 4227, 4228): each is rewritten naming no one under its own key, or
//! leaves, by every export and the erase sweep, and so in a recovery
//! artifact. The mirror takes such a copy to that form too, the window
//! pinned history-free first, so this machine's change to the row rides at
//! once (FIX 4872).
//!
//! Every erase reads a row the window holds, whatever its size (FIX 8882).
//! Eligible large Offers keep their actor fields inline (FIX 12406), so the
//! same erase decision can settle them before their wording parts land.
//! Other split rows still need their joined bytes (FIX 11790).

use std::collections::BTreeSet;

use loro::{LoroMap, LoroValue, ValueOrContainer};

use super::{encode, refused};
use crate::Vault;
use crate::error::Result;
use crate::recovery::CanonicalRoomFact;
use crate::room_codec::offer_parts::OfferManifest;
use crate::sync::loro_support::{map_delete, map_get_bytes};
use crate::sync::types::WindowKey;
use crate::workspace_roster::{RoomSideRow, erased_side_row_here};

/// Decodes a side row a window holds or this vault emitted, in its one
/// spelling and whatever its size (FIX 8882). Peer bytes pass the admission
/// bound first (`super::decode`).
pub(super) fn decode_held(bytes: &[u8]) -> Result<RoomSideRow> {
    let row = serde_json::from_slice(bytes).map_err(|_| refused("not a side row"))?;
    if encode(&row)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    Ok(row)
}

fn row_for_erasure(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    let raw = map_get_bytes(map, key)?;
    if OfferManifest::parse(&raw).is_some() {
        Some(raw)
    } else {
        crate::sync::room_parts::row_at(map, key)
    }
}

fn erased_form(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<Option<Option<Vec<u8>>>> {
    let inline = OfferManifest::parse(bytes);
    let row = match &inline {
        Some(manifest) => manifest.header.clone(),
        None => match decode_held(bytes) {
            Ok(row) => row,
            Err(_) => return Ok(None),
        },
    };
    match erased_side_row_here(vault, txn, &row)? {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(row)) => Ok(Some(Some(match inline {
            Some(manifest) => manifest.with_header(row)?,
            None => encode(&row)?,
        }))),
    }
}

/// Each row `map` holds that names an actor this vault erased, with what
/// takes its place: its bytes naming no one, or `None` when it leaves. A row
/// that does not decode is left to the other scrubs.
pub(super) fn erased_rows(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    map: &LoroMap,
) -> Result<Vec<(String, Option<Vec<u8>>)>> {
    let mut keys = Vec::new();
    map.for_each(|key, value| {
        if !crate::sync::carrier_parts::is_part_key(key)
            && matches!(value, ValueOrContainer::Value(LoroValue::Binary(_)))
        {
            keys.push(key.to_owned());
        }
    });
    let mut erased = Vec::new();
    for map_key in keys {
        if let Some(bytes) = row_for_erasure(map, &map_key)
            && let Some(form) = erased_form(vault, txn, &bytes)?
        {
            erased.push((map_key, form));
        }
    }
    Ok(erased)
}

/// Takes each copy `map` holds under one of `keys` that names an actor this
/// vault erased to the form the export scrub gives it: rewritten naming no
/// one, or gone (FIX 4872). `window`, whose history keeps the old copies, is
/// pinned history-free first. Returns whether it wrote; the caller commits.
pub(super) fn settle_erased_copies(
    vault: &Vault,
    map: &LoroMap,
    window: &WindowKey,
    keys: &[String],
) -> Result<bool> {
    let forms = {
        let rtxn = vault.store.env.read_txn()?;
        let mut forms = Vec::new();
        for map_key in keys.iter().collect::<BTreeSet<_>>() {
            if let Some(bytes) = row_for_erasure(map, map_key)
                && let Some(form) = erased_form(vault, &rtxn, &bytes)?
            {
                forms.push((map_key, form));
            }
        }
        forms
    };
    if forms.is_empty() {
        return Ok(false);
    }
    crate::sync::window::require_history_free_window(vault, window)?;
    for (map_key, form) in forms {
        match form {
            None => map_delete(map, map_key)?,
            Some(bytes) => {
                crate::sync::room_parts::write_row(map, map_key, &bytes, super::MAX_ROW_BYTES)?;
            }
        }
    }
    crate::sync::room_parts::drop_unlisted_parts(map)?;
    Ok(true)
}

/// A recovery artifact's room side rows, naming no one this vault erased
/// (FIX 4227): each such row rewritten under its own key, or left out.
pub(crate) fn erase_carried_actors(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &mut Vec<CanonicalRoomFact>,
) -> Result<()> {
    let mut kept = Vec::with_capacity(rows.len());
    let mut dropped_parts = BTreeSet::new();
    for mut fact in std::mem::take(rows) {
        match erased_form(vault, txn, &fact.row)? {
            None => kept.push(fact),
            Some(None) => {
                if let Some(manifest) = OfferManifest::parse(&fact.row) {
                    dropped_parts.extend(manifest.parts().keys());
                }
            }
            Some(Some(row)) => {
                fact.row = row;
                kept.push(fact);
            }
        }
    }
    if !dropped_parts.is_empty() {
        let listed = kept
            .iter()
            .filter_map(|fact| crate::sync::room_parts::manifest(&fact.row))
            .flat_map(|parts| parts.keys().collect::<Vec<_>>())
            .collect::<BTreeSet<_>>();
        kept.retain(|fact| !dropped_parts.contains(&fact.key) || listed.contains(&fact.key));
    }
    *rows = kept;
    Ok(())
}
