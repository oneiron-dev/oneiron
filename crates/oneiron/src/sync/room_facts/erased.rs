//! The room side rows a carrier holds that name an actor this vault erased
//! (FIX 4227, 4228): each is rewritten naming no one under its own key, or
//! leaves, by every export and the erase sweep, and so in a recovery
//! artifact. The mirror leaves such a copy for that scrub, which pins the
//! window history-free before the copy changes.

use loro::{LoroMap, LoroValue, ValueOrContainer};

use super::{decode, encode};
use crate::Vault;
use crate::error::Result;
use crate::recovery::CanonicalRoomFact;
use crate::workspace_roster::erased_side_row_here;

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
        let Ok(row) = decode(&bytes) else {
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

/// Whether the copy `map` holds under `map_key` names an actor this vault
/// erased, so only the export scrub may change it.
pub(super) fn copy_names_erased(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    map: &LoroMap,
    map_key: &str,
) -> Result<bool> {
    let Some(bytes) = crate::sync::loro_support::map_get_bytes(map, map_key) else {
        return Ok(false);
    };
    let Ok(row) = decode(&bytes) else {
        return Ok(false);
    };
    Ok(erased_side_row_here(vault, txn, &row)?.is_some())
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
        let Ok(row) = decode(&fact.row) else {
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
