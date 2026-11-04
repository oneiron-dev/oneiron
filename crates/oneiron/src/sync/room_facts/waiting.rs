//! Waiting room-row manifests the scrub drops (FIX 12127).
//!
//! A manifest whose parts never all land leaves no joined row for the scrub
//! to read, so its key decides: a cell names its room, a claim or a response
//! names its turn, and any other row names the branch or room it rides with.
//! A manifest drops with its present parts when the scrub would drop the row
//! it stands for — its room deleted, or its branch erased. A row the key
//! does not place stays for its parts, as a row of an unknown room does.

use loro::LoroMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The waiting manifests of `map` the scrub drops: each one's key.
pub(super) fn doomed_manifests(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    map: &LoroMap,
) -> Result<Vec<String>> {
    let mut doomed = Vec::new();
    for (key, _) in crate::sync::room_parts::waiting_manifests(map) {
        if doomed_key(vault, txn, &key)? {
            doomed.push(key);
        }
    }
    Ok(doomed)
}

/// Whether the waiting manifest under `key` stands for a row the scrub
/// drops: its room deleted, or the branch it rides with erased. Anything
/// the key does not place stays for its parts.
fn doomed_key(vault: &Vault, txn: &heed::RoTxn<'_>, key: &str) -> Result<bool> {
    if let Some((room, _)) = super::cell_of(key) {
        return removed(vault, txn, &room);
    }
    if let Some((_, carrier, _)) = super::shared_of(key) {
        return carrier_removed(vault, txn, &carrier);
    }
    let Some((table, rest)) = key.split_once('/') else {
        return Ok(false);
    };
    match table {
        "claim" | "response" => {
            let Some(turn) = rest.split('/').next().and_then(super::named) else {
                return Ok(false);
            };
            turn_room_removed(vault, txn, &turn)
        }
        "fact" => {
            let Some(carrier) = rest.split('/').next().and_then(super::named) else {
                return Ok(false);
            };
            carrier_removed(vault, txn, &carrier)
        }
        _ => Ok(false),
    }
}

/// Whether the row riding with `carrier` — its branch or room — drops: the
/// carrier erased, or the room of the thread it roots deleted.
fn carrier_removed(vault: &Vault, txn: &heed::RoTxn<'_>, carrier: &EntityId) -> Result<bool> {
    if removed(vault, txn, carrier)? {
        return Ok(true);
    }
    turn_room_removed(vault, txn, carrier)
}

/// Whether the room of turn `turn` is deleted; a turn this vault holds no
/// row for places nothing, and stays.
fn turn_room_removed(vault: &Vault, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<bool> {
    let Some(row) = crate::workspace_roster::replicated_turn_in(vault, txn, *turn)? else {
        return Ok(false);
    };
    let Ok(room) = EntityId::from_hex(&row.room_id) else {
        return Ok(false);
    };
    removed(vault, txn, &room)
}

fn removed(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    crate::ports::removed_in_txn(&vault.store, txn, id)
}
