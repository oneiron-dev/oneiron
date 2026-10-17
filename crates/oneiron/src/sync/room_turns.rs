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

use super::loro_support::{
    map_contains_binary, map_delete, map_for_each_bytes, map_get_bytes, map_insert_bytes,
};
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
/// window's row already carries every message and bound task of it and its
/// conversion. A row the window holds is extended, never replaced, so another
/// machine's binding is not lost and two machines settle on one row. Returns
/// whether it wrote; the caller commits.
pub(crate) fn mirror_room_turn(vault: &Vault, doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        replicated_turn_in(vault, &rtxn, *id)?
    };
    let Some(turn) = held else {
        return Ok(false);
    };
    let map = doc.get_map(ROOM_TURNS_MAP);
    let hex = id.to_hex();
    let row = match map_get_bytes(&map, &hex).and_then(|carried| decode(&carried).ok()) {
        Some(mut carried) => {
            let mut grew = false;
            for message in turn.message_ids {
                if !carried.message_ids.contains(&message) {
                    carried.message_ids.push(message);
                    grew = true;
                }
            }
            for task in turn.task_ids {
                if !carried.task_ids.contains(&task) {
                    carried.task_ids.push(task);
                    grew = true;
                }
            }
            if carried.converted_project.is_none() && turn.converted_project.is_some() {
                carried.converted_project = turn.converted_project;
                grew = true;
            }
            if !grew {
                return Ok(false);
            }
            carried
        }
        None => turn,
    };
    map_insert_bytes(&map, &hex, &encode(&row)?)?;
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

/// Deletes from `doc`'s room turn map each row whose room this vault deleted,
/// as the merge refuses one (OF-522). A row whose room this vault holds no
/// record of stays: a first sync can bring a turn row before its room. A live
/// doc keeps the old rows in its history, so `pin` names the window pinned
/// history-free before any row goes; the sweep, whose shallow cut drops that
/// history, passes `None`. Returns whether a row went, committed.
pub(crate) fn scrub_deleted_room_turns(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_room_turn_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(ROOM_TURNS_MAP);
    let mut rows = Vec::new();
    map_for_each_bytes(&map, |map_key, bytes| {
        if let Ok(turn) = decode(bytes)
            && let Ok(room) = EntityId::from_hex(&turn.room_id)
        {
            rows.push((map_key.to_owned(), room));
        }
    });
    let mut doomed = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, room) in rows {
            if crate::ports::removed_in_txn(&vault.store, &rtxn, &room)? {
                doomed.push(map_key);
            }
        }
    }
    if doomed.is_empty() {
        return Ok(false);
    }
    // Pin before touching the live map, as the egress scrubs do.
    if let Some(key) = pin {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &doomed {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN));
    Ok(true)
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
                TurnMerge::Refused(reason) => {
                    tracing::warn!(window, key = %id, ?reason, "room turn row does not merge here; left out");
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

impl Vault {
    /// Mirrors TURN `turn`'s room row into the live window that carries the
    /// TURN, after a door changed the row: a thread-task binding or a
    /// conversion (OF-522), and the side rows the door wrote with it (FIX
    /// 1794). Best effort: a window opened later mirrors it as it opens.
    pub(crate) fn refresh_room_turn_in_live_window(&self, turn: &EntityId) {
        let hex = turn.to_hex();
        for window in self.live_windows() {
            if window.key.world().is_some()
                || !map_contains_binary(&window.doc.get_map("entities"), &hex)
            {
                continue;
            }
            match mirror_room_turn(self, &window.doc, turn) {
                Ok(true) => {
                    window.doc.commit_with(
                        loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN),
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "room turn row not mirrored");
                }
            }
        }
        self.refresh_room_turn_facts_in_live_windows(*turn);
    }
}
