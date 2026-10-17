//! OF-522: a room's turn rows on the window plane.
//!
//! A room, its turns and its messages replicate as entities, but the room's
//! turn rows (who spoke, whom they addressed, which thread a turn sits in,
//! the tasks bound to a thread and the project it became) are this vault's
//! rows beside them. Without them another machine of the owner's holds the
//! messages but no thread, no binding and no history to convert from.
//!
//! - A turn row rides the base window's `room_turns` map under its turn's id,
//!   in the window its TURN entity rides.
//! - Admission refuses every insert into the map that is not a whole turn row
//!   filed under its own id, in the latest state, at a snapshot's root and in
//!   every retained operation.
//! - Reverse rematerialization mirrors the row of each TURN it mirrors, and a
//!   door that changes a row mirrors it into the live window after commit.
//! - Forward rematerialization and Observer B merge each row into this
//!   vault's as the witness door's append does (the room's own row merge),
//!   which indexes the room's history from it.

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::workspace_roster::{
    RoomTurn, TurnMerge, merge_replicated_turn_in_txn, replicated_turn_in,
};

/// The base window root map that carries room turn rows.
pub(crate) const ROOM_TURNS_MAP: &str = "room_turns";

/// The largest turn row a window carries.
const MAX_ROW_BYTES: usize = 1 << 20;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("room turn row refused: {reason}"))
}

fn encode(turn: &RoomTurn) -> Result<Vec<u8>> {
    serde_json::to_vec(turn).map_err(|_| refused("does not encode"))
}

fn decode(bytes: &[u8]) -> Result<RoomTurn> {
    if bytes.len() > MAX_ROW_BYTES {
        return Err(refused("too large"));
    }
    serde_json::from_slice(bytes).map_err(|_| refused("not a turn row"))
}

/// Admits one insert into a window's `room_turns` map: a whole turn row of a
/// base window, filed under its own turn's id, naming its room by id.
pub(crate) fn admit_room_turn_carrier(
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if key.is_some_and(|key| key.world().is_some()) {
        return Err(refused("in a world window"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let turn = decode(bytes)?;
    let id = EntityId::from_hex(&turn.turn_id)?;
    if id.to_hex() != map_key || turn.turn_id != map_key {
        return Err(refused("filed under another id"));
    }
    if EntityId::from_hex(&turn.room_id)?.to_hex() != turn.room_id {
        return Err(refused("names no room"));
    }
    Ok(())
}

/// [`admit_room_turn_carrier`] over every row `map` holds.
pub(crate) fn admit_room_turn_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
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
        admit_room_turn_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` the turn row this vault holds for TURN `id`, unless the
/// window holds it already. A row the window holds with messages or tasks
/// this vault's row lacks is written over with the merge of the two, so
/// neither machine's binding is lost. Returns whether it wrote; the caller
/// commits.
pub(crate) fn mirror_room_turn(vault: &Vault, doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        replicated_turn_in(vault, &rtxn, *id)?
    };
    let Some(mut turn) = held else {
        return Ok(false);
    };
    let map = doc.get_map(ROOM_TURNS_MAP);
    let hex = id.to_hex();
    if let Some(held) = map_get_bytes(&map, &hex).and_then(|held| decode(&held).ok()) {
        if held == turn {
            return Ok(false);
        }
        // The window's row may carry what this machine has not merged yet.
        for message in held.message_ids {
            if !turn.message_ids.contains(&message) {
                turn.message_ids.push(message);
            }
        }
        for task in held.task_ids {
            if !turn.task_ids.contains(&task) {
                turn.task_ids.push(task);
            }
        }
        if turn.converted_project.is_none() {
            turn.converted_project = held.converted_project;
        }
    }
    let bytes = encode(&turn)?;
    if map_get_bytes(&map, &hex).as_deref() == Some(bytes.as_slice()) {
        return Ok(false);
    }
    map_insert_bytes(&map, &hex, &bytes)?;
    Ok(true)
}

/// Merges every turn row window `key`'s document holds into this vault's, as
/// a window open does. A row that fails is logged and left; it never stops
/// the open.
pub(crate) fn apply_room_turn_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_room_turn_map(doc) {
        return;
    }
    let mut rows = Vec::new();
    doc.get_map(ROOM_TURNS_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    merge_rows(vault, key.as_str(), rows);
}

/// Observer B for the room turn map: each row an import changed.
pub(crate) fn materialize_room_turns_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let rows = delta
        .updated
        .iter()
        .filter_map(|(key, value)| match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                Some((key.to_string(), bytes.to_vec()))
            }
            _ => None,
        })
        .collect();
    merge_rows(vault, window_key, rows);
    Some(Vec::new())
}

/// Whether `doc` holds a room turn map. Looking a root up by name creates
/// it: look first.
fn holds_room_turn_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(ROOM_TURNS_MAP))
}

/// Merges each carried row into this vault's turn rows in one write.
fn merge_rows(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let turns: Vec<RoomTurn> = rows
        .into_iter()
        .filter_map(|(map_key, bytes)| match decode(&bytes) {
            Ok(turn) if turn.turn_id == map_key => Some(turn),
            _ => {
                tracing::warn!(window, key = %map_key, "room turn row malformed; left out");
                None
            }
        })
        .collect();
    if turns.is_empty() {
        return;
    }
    let outcome = vault.with_write_txn_grouped(|wtxn| {
        let mut merged = 0;
        for turn in turns {
            let id = turn.turn_id.clone();
            match merge_replicated_turn_in_txn(vault, wtxn, turn)? {
                TurnMerge::Written => merged += 1,
                TurnMerge::Held => {}
                TurnMerge::Refused => {
                    tracing::warn!(window, key = %id, "room turn row does not merge here; left out");
                }
            }
        }
        Ok(merged)
    });
    match outcome {
        Ok(merged) if merged > 0 => tracing::debug!(window, merged, "room turn rows merged"),
        Ok(_) => {}
        Err(error) => tracing::warn!(window, error = %error, "room turn rows not merged"),
    }
}
