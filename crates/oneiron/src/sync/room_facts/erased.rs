//! The room side rows a carrier holds that name an actor this vault erased
//! (FIX 4227, 4228): each is rewritten naming no one under its own key, or
//! leaves, by every export and the erase sweep, and so in a recovery
//! artifact. The mirror takes such a copy to that form too, the window
//! pinned history-free first, so this machine's change to the row rides at
//! once (FIX 4872).
//!
//! Every erase reads a row the window already holds whole, whatever its
//! size (FIX 8882): the mirror writes rows past the admission bound, and an
//! erase that skipped them would leave a deleted room's bytes riding.

use std::collections::BTreeSet;

use loro::{LoroMap, LoroValue, ValueOrContainer};

use super::{encode, refused};
use crate::Vault;
use crate::error::Result;
use crate::recovery::CanonicalRoomFact;
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
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

/// Each row `map` holds that names an actor this vault erased, with what
/// takes its place: its bytes naming no one, or `None` when it leaves. A row
/// that does not decode is left to the other scrubs.
pub(super) fn erased_rows(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    map: &LoroMap,
) -> Result<Vec<(String, Option<Vec<u8>>)>> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    let mut erased = Vec::new();
    for (map_key, bytes) in rows {
        let Ok(row) = decode_held(&bytes) else {
            continue;
        };
        match erased_side_row_here(vault, txn, &row)? {
            None => {}
            Some(None) => erased.push((map_key, None)),
            Some(Some(row)) => erased.push((map_key, Some(encode(&row)?))),
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
            let Some(bytes) = map_get_bytes(map, map_key) else {
                continue;
            };
            let Ok(row) = decode_held(&bytes) else {
                continue;
            };
            if let Some(form) = erased_side_row_here(vault, &rtxn, &row)? {
                forms.push((map_key, form.map(|row| encode(&row)).transpose()?));
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
            Some(bytes) => map_insert_bytes(map, map_key, &bytes)?,
        }
    }
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
    for fact in std::mem::take(rows) {
        let Ok(row) = decode_held(&fact.row) else {
            kept.push(fact);
            continue;
        };
        match erased_side_row_here(vault, txn, &row)? {
            None => kept.push(fact),
            Some(None) => {}
            Some(Some(row)) => kept.push(CanonicalRoomFact {
                key: fact.key,
                row: encode(&row)?,
            }),
        }
    }
    *rows = kept;
    Ok(())
}
