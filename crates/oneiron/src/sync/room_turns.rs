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
//!   every retained operation. A row past `MAX_ROW_BYTES` rides as parts
//!   (`room_parts`, FIX 11790), its checks run on the joined row as it merges.
//! - Reverse rematerialization mirrors the row of each TURN it mirrors, and a
//!   door that changes a row mirrors it into the live window after commit.
//! - Forward rematerialization and Observer B merge each row into this
//!   vault's as the witness door's append does (the room's own row merge),
//!   which indexes the room's history from it.

pub(super) mod checkpoint;

use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_contains_binary, map_delete};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ERASED_CALL_IDENTITY;
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
    decode_held(bytes)
}

/// Decodes a turn row a window holds or this vault emitted, whatever its
/// size (FIX 8882): a row past [`MAX_ROW_BYTES`] rides as parts (FIX 11790),
/// and the mirror's extension, the merge and every erase read it joined. A
/// whole value from a peer passes the bound first ([`decode`]).
fn decode_held(bytes: &[u8]) -> Result<RoomTurn> {
    serde_json::from_slice(bytes).map_err(|_| refused("not a turn row"))
}

/// Admits one insert into a window's `room_turns` map: a whole turn row of a
/// base window that passes `admit_turn`, or a part or the manifest of a row
/// past `MAX_ROW_BYTES` (FIX 11790).
pub(crate) fn admit_room_turn_carrier(
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if key.is_some_and(|key| key.world().is_some()) {
        return Err(refused("in a world window"));
    }
    if super::room_parts::admit(map_key, value, MAX_ROW_BYTES)? {
        return Ok(());
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    admit_turn(map_key, &decode(bytes)?)
}

/// The checks a turn row passes, whole or joined from its parts: filed under
/// its own turn's id, naming its room by id, each of its quotes kept against
/// a message it names (FIX 2028).
fn admit_turn(map_key: &str, turn: &RoomTurn) -> Result<()> {
    let id = EntityId::from_hex(&turn.turn_id)?;
    if id.to_hex() != map_key || turn.turn_id != map_key {
        return Err(refused("filed under another id"));
    }
    if EntityId::from_hex(&turn.room_id)?.to_hex() != turn.room_id {
        return Err(refused("names no room"));
    }
    if turn
        .quotes
        .keys()
        .any(|citer| !turn.message_ids.contains(citer))
    {
        return Err(refused("quotes for a message it does not name"));
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

/// Writes into `doc`, window `key`'s, the turn row this vault holds for TURN
/// `id`, unless the window's row already carries every message, message
/// quote and bound task of it and its conversion. A row the window holds is
/// extended, never replaced, so another machine's binding is not lost and two
/// machines settle on one row; a window row keeping another quote for one of
/// its messages is refused (FIX 2028). A window row still naming the actor
/// this vault's row names as erased (FIX 6543) takes the erased form as it is
/// extended (FIX 6639): `key` is pinned history-free first, as the egress
/// scrub pins it ([`scrub_deleted_room_turns`]), since the doc keeps the old
/// actor in its history, and that actor is never filed again. Returns whether
/// it wrote; the caller commits.
pub(crate) fn mirror_room_turn(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    id: &EntityId,
) -> Result<bool> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        replicated_turn_in(vault, &rtxn, *id)?
    };
    let Some(turn) = held else {
        return Ok(false);
    };
    let map = doc.get_map(ROOM_TURNS_MAP);
    let hex = id.to_hex();
    // FIX 11790: a carried row still missing a part waits for it, so another
    // machine's binding is not lost.
    if super::room_parts::waits(&map, &hex) {
        return Ok(false);
    }
    let carried = super::room_parts::row_at(&map, &hex)
        .and_then(|carried| decode_held(&carried).ok())
        .filter(|carried| admit_turn(&hex, carried).is_ok());
    let row = match carried {
        Some(mut carried) => {
            let mut grew = false;
            if turn.actor == ERASED_CALL_IDENTITY && carried.actor != turn.actor {
                // Pin before the actor changes, as the egress scrub does.
                super::window::require_history_free_window(vault, key)?;
                carried.actor = ERASED_CALL_IDENTITY.to_owned();
                grew = true;
            }
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
            for (citer, quote) in turn.quotes {
                match carried.quotes.get(&citer) {
                    Some(kept) if *kept != quote => return Err(refused("conflicting quote")),
                    Some(_) => {}
                    None => {
                        carried.quotes.insert(citer, quote);
                        grew = true;
                    }
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
    super::room_parts::write_row(&map, &hex, &encode(&row)?, MAX_ROW_BYTES)?;
    Ok(true)
}

/// Merges every turn row window `key`'s document holds into this vault's, as
/// a window open does. A row that fails is logged and left; it never stops
/// the open.
pub(crate) fn apply_room_turn_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_room_turn_map(doc) {
        return;
    }
    let rows = super::room_parts::rows(&doc.get_map(ROOM_TURNS_MAP), |_| true);
    merge_rows(vault, key.as_str(), rows);
}

/// Observer B for the room turn map: each row an import changed, and each
/// one a part it brought completes.
pub(crate) fn materialize_room_turns_from_delta(
    doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let rows = super::room_parts::changed_rows(&doc.get_map(ROOM_TURNS_MAP), delta)
        .into_iter()
        .filter_map(|(key, row)| Some((key, row?)))
        .collect();
    merge_rows(vault, window_key, rows);
    Some(Vec::new())
}

/// Deletes from `doc`'s room turn map each row whose room this vault deleted,
/// as the merge refuses one (OF-522), and rewrites in the erased form each
/// row that names an actor this vault names as no one (FIX 6543): the turn,
/// its links and its messages ride on, its actor's id does not. A row whose
/// room this vault holds no record of stays: a first sync can bring a turn
/// row before its room. A live doc keeps the old rows in its history, so
/// `pin` names the window pinned history-free before any row goes or
/// changes; the sweep, whose shallow cut drops that history, passes `None`.
/// Returns whether a row went or changed, committed.
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
    for (map_key, bytes) in super::room_parts::rows(&map, |_| true) {
        if let Ok(turn) = decode_held(&bytes)
            && let Ok(room) = EntityId::from_hex(&turn.room_id)
        {
            rows.push((map_key, room, turn));
        }
    }
    let mut doomed = Vec::new();
    let mut erased = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, room, mut turn) in rows {
            if crate::ports::removed_in_txn(&vault.store, &rtxn, &room)? {
                doomed.push(map_key);
            } else if actor_erased_here(vault, &rtxn, &turn)? {
                turn.actor = ERASED_CALL_IDENTITY.to_owned();
                erased.push((map_key, encode(&turn)?));
            }
        }
        // FIX 12127: a manifest whose parts never all land drops with the
        // row it stands for, its room read from this vault's turn for it.
        for (key, _) in super::room_parts::waiting_manifests(&map) {
            let Ok(id) = EntityId::from_hex(&key) else {
                continue;
            };
            let Some(turn) = replicated_turn_in(vault, &rtxn, id)? else {
                continue;
            };
            let Ok(room) = EntityId::from_hex(&turn.room_id) else {
                continue;
            };
            if crate::ports::removed_in_txn(&vault.store, &rtxn, &room)? {
                doomed.push(key);
            }
        }
    }
    if doomed.is_empty() && erased.is_empty() && super::room_parts::unlisted_parts(&map).is_empty()
    {
        return Ok(false);
    }
    // Pin before touching the live map, as the egress scrubs do.
    if let Some(key) = pin {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &doomed {
        map_delete(&map, map_key)?;
    }
    for (map_key, row) in &erased {
        super::room_parts::write_row(&map, map_key, row, MAX_ROW_BYTES)?;
    }
    // A row that went takes its parts with it.
    super::room_parts::drop_unlisted_parts(&map)?;
    doc.commit_with(loro::CommitOptions::new().origin(super::bridge::BRIDGE_ORIGIN));
    Ok(true)
}

/// Whether the window row `turn` names as its actor someone this vault names
/// as no one (FIX 6543): an actor its own marker erased, as every carrier
/// reads one ([`crate::deletion::ACTOR_ERASE_CARRIER_SOURCE`]), or the one
/// its own row for the turn already names in the erased form.
fn actor_erased_here(vault: &Vault, rtxn: &heed::RoTxn<'_>, turn: &RoomTurn) -> Result<bool> {
    let (Ok(actor), Ok(id)) = (
        EntityId::from_hex(&turn.actor),
        EntityId::from_hex(&turn.turn_id),
    ) else {
        return Ok(false);
    };
    Ok(vault.carrier_actor_erased_in_txn(rtxn, &actor)?
        || replicated_turn_in(vault, rtxn, id)?
            .is_some_and(|held| held.actor == ERASED_CALL_IDENTITY))
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
        .filter_map(|(map_key, bytes)| match decode_held(&bytes) {
            Ok(turn) if admit_turn(&map_key, &turn).is_ok() => Some(turn),
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
            match mirror_room_turn(self, &window.doc, &window.key, turn) {
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
