//! FIX 1794 (OF-522): a room's side rows on the window plane.
//!
//! A room's turn rows ride `room_turns` (`super::room_turns`). Its other
//! rows ride the base window's `room_facts` map, as L09 ruled each table
//! travels between the owner's machines. Only those machines take the map:
//! a federated or guest window copies none of it.
//!
//! - A room's host pin, its platform handles and its room-wide participation
//!   facts ride the window its room rides. A turn's claim and response ride
//!   the window the turn rides, and a thread's facts the window of the turn
//!   that roots it.
//! - A host pin rides under its room, and a handle under its room and
//!   handle. Each is a cell: the latest carrier write by Loro order stands,
//!   and a cleared pin is the cell's delete, so an older pin never returns.
//! - A claim, a response and a participation fact are written once. Each
//!   rides under its own digest, so two machines' rows both ride, and every
//!   machine settles on the same one and logs the other.
//! - Admission refuses every insert into the map that is not a whole side
//!   row filed under its own key, in the latest state, at a snapshot's root
//!   and in every retained operation.
//! - Reverse rematerialization mirrors each row beside its carrier, and a
//!   door that changes a row mirrors it into the live window after commit. A
//!   cell changed while no open window carried its room is marked, and
//!   mirrored as that window opens.
//! - Forward rematerialization and Observer B merge each row into this
//!   vault's (`workspace_roster::rooms::replica`).
//! - Every export, and the erase sweep, drops each row of a room this vault
//!   deleted or of a thread it erased.

use std::collections::{BTreeMap, BTreeSet};

use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::side_table::{self, Raw, SideTable};
use crate::workspace_roster::{
    RoomSideRow, SideMerge, clear_replicated_side_cell_in_txn, merge_replicated_responses_in_txn,
    merge_replicated_side_row_in_txn, replicated_side_carriers_in, replicated_side_rows_in,
};

/// The base window root map that carries a room's side rows.
pub(crate) const ROOM_FACTS_MAP: &str = "room_facts";

/// The largest side row a window carries.
const MAX_ROW_BYTES: usize = 1 << 16;

/// The key prefix of a room's host pin cell.
const PIN: &str = "pin/";
/// The key prefix of a room's platform handle cells.
const HANDLE: &str = "handle/";
/// The key prefix of a turn's responses.
const RESPONSE: &str = "response/";

/// The cells this machine changed while no open window carried their room.
const DIRTY: SideTable<String, (), Raw> = SideTable::new(&side_table::SYNC_ROOM_FACT_DIRTY);

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("room side row refused: {reason}"))
}

fn encode(row: &RoomSideRow) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| refused("does not encode"))
}

/// Decodes a carried row. A row has one spelling, so equal rows ride under
/// one key.
fn decode(bytes: &[u8]) -> Result<RoomSideRow> {
    if bytes.len() > MAX_ROW_BYTES {
        return Err(refused("too large"));
    }
    let row = serde_json::from_slice(bytes).map_err(|_| refused("not a side row"))?;
    if encode(&row)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    Ok(row)
}

/// The key `row`, encoded as `bytes`, rides under: a cell's room and handle,
/// or a written-once row's carrier and its own digest.
fn carrier_key(row: &RoomSideRow, bytes: &[u8]) -> String {
    let digest = || {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.room_facts.v1");
        hasher.update(bytes);
        bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
    };
    match row {
        RoomSideRow::HostPin { room, .. } => cell_key(*room, None),
        RoomSideRow::Handle { room, handle, .. } => cell_key(*room, Some(handle)),
        RoomSideRow::Claim { claim } => format!("claim/{}/{}", claim.turn_id, digest()),
        RoomSideRow::Response { parent, .. } => {
            format!("{RESPONSE}{}/{}", parent.to_hex(), digest())
        }
        RoomSideRow::Participation { room, branch, .. } => {
            format!("fact/{}/{}", branch.unwrap_or(*room).to_hex(), digest())
        }
    }
}

/// The key of room `room`'s host pin cell, or of its handle `handle`'s.
fn cell_key(room: EntityId, handle: Option<&str>) -> String {
    match handle {
        None => format!("{PIN}{}", room.to_hex()),
        Some(handle) => format!(
            "{HANDLE}{}/{}",
            room.to_hex(),
            bytes_to_hex_lower(handle.as_bytes())
        ),
    }
}

/// The room and handle a cell's key names, the handle `None` for a host
/// pin; `None` for any other key.
fn cell_of(map_key: &str) -> Option<(EntityId, Option<String>)> {
    if let Some(room) = map_key.strip_prefix(PIN) {
        return named(room).map(|room| (room, None));
    }
    let (room, handle) = map_key.strip_prefix(HANDLE)?.split_once('/')?;
    if handle.len() % 2 != 0 {
        return None;
    }
    let bytes = (0..handle.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(handle.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes_to_hex_lower(&bytes) != handle {
        return None;
    }
    Some((named(room)?, Some(String::from_utf8(bytes).ok()?)))
}

fn is_cell(map_key: &str) -> bool {
    map_key.starts_with(PIN) || map_key.starts_with(HANDLE)
}

/// `hex` as an id, when it is one's canonical spelling.
fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Admits one insert into a window's `room_facts` map: a whole side row of a
/// base window, filed under its own key.
pub(crate) fn admit_room_fact_carrier(
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
    let row = decode(bytes)?;
    if row.place().is_none() || !row.well_formed() {
        return Err(refused("names no room"));
    }
    if carrier_key(&row, bytes) != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

/// [`admit_room_fact_carrier`] over every row `map` holds.
pub(crate) fn admit_room_fact_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
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
        admit_room_fact_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` the side rows this vault holds that ride entity `id` of
/// type `entity_type`. A written-once row the window lacks is written. A
/// cell is written where the window never held it, or where this machine
/// changed it since: the `changed` cell a door just wrote, or a marked one.
/// A changed cell this vault no longer holds was cleared here, and leaves
/// the window. Every other cell stands as the window holds it. Returns
/// whether it wrote; the caller commits.
pub(crate) fn mirror_room_facts(
    vault: &Vault,
    doc: &LoroDoc,
    id: &EntityId,
    entity_type: u8,
    changed: Option<&str>,
) -> Result<bool> {
    let (rows, mut ours) = {
        let rtxn = vault.store.env.read_txn()?;
        let rows = replicated_side_rows_in(vault, &rtxn, *id, entity_type)?;
        let mut ours = Vec::new();
        if entity_type == ENTITY_TYPE_CONVERSATION {
            for prefix in [cell_key(*id, None), format!("{HANDLE}{}/", id.to_hex())] {
                ours.extend(DIRTY.scan_keys(&vault.store, &rtxn, prefix.as_bytes())?);
            }
            ours.extend(
                changed
                    .filter(|cell| cell_of(cell).is_some_and(|(room, _)| room == *id))
                    .map(str::to_owned),
            );
        }
        (rows, ours)
    };
    if rows.is_empty() && ours.is_empty() {
        return Ok(false);
    }
    let map = doc.get_map(ROOM_FACTS_MAP);
    let mut wrote = false;
    for row in &rows {
        let bytes = encode(row)?;
        let key = carrier_key(row, &bytes);
        let changed_here = ours.contains(&key);
        ours.retain(|cell| *cell != key);
        let held = map_get_bytes(&map, &key);
        if held.as_deref() == Some(bytes.as_slice())
            || (is_cell(&key) && !changed_here && map.get_last_editor(&key).is_some())
            || (!is_cell(&key) && held.is_some())
        {
            continue;
        }
        map_insert_bytes(&map, &key, &bytes)?;
        wrote = true;
    }
    for cleared in ours {
        if map_contains_binary(&map, &cleared) {
            map_delete(&map, &cleared)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Mirrors the side rows of each of `carriers` that `doc` carries, and
/// commits what it writes. Returns whether `doc` carries any of them.
pub(crate) fn mirror_carriers(
    vault: &Vault,
    doc: &LoroDoc,
    carriers: &[(EntityId, u8)],
    changed: Option<&str>,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut carried = false;
    let mut wrote = false;
    for (id, entity_type) in carriers {
        if !map_contains_binary(&entities, &id.to_hex()) {
            continue;
        }
        carried = true;
        wrote |= mirror_room_facts(vault, doc, id, *entity_type, changed)?;
    }
    if wrote {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(carried)
}

/// The carriers whose windows take the side rows the doors behind `rows`,
/// just committed here, wrote: each room turn's room, the turn, the turn it
/// answers and the root of its thread.
pub(crate) fn committed_carriers(vault: &Vault, rows: &BTreeSet<EntityId>) -> Vec<(EntityId, u8)> {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return Vec::new();
    };
    let mut carriers = BTreeSet::new();
    for id in rows {
        if let Ok(found) = replicated_side_carriers_in(vault, &rtxn, *id) {
            carriers.extend(found);
        }
    }
    carriers.into_iter().collect()
}

/// Merges every side row window `key`'s document holds into this vault's,
/// as a window open does. A row that fails is logged and left; it never
/// stops the open.
pub(crate) fn apply_room_fact_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_room_fact_map(doc) {
        return;
    }
    let mut rows = Vec::new();
    doc.get_map(ROOM_FACTS_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), Some(bytes.to_vec())));
        }
    });
    merge_rows(vault, doc, key.as_str(), rows);
}

/// Observer B for the room fact map: each row an import changed, and each
/// cell it dropped.
pub(crate) fn materialize_room_facts_from_delta(
    doc: &LoroDoc,
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
                Some((key.to_string(), Some(bytes.to_vec())))
            }
            None => Some((key.to_string(), None)),
            _ => None,
        })
        .collect();
    merge_rows(vault, doc, window_key, rows);
    Some(Vec::new())
}

/// Whether `doc` holds a room fact map. Looking a root up by name creates
/// it: look first.
fn holds_room_fact_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(ROOM_FACTS_MAP))
}

/// Every response `doc` carries for each of `parents`.
fn responses_for(doc: &LoroDoc, parents: &BTreeSet<EntityId>) -> Vec<(EntityId, Vec<RoomSideRow>)> {
    let mut found: BTreeMap<EntityId, Vec<RoomSideRow>> = BTreeMap::new();
    if parents.is_empty() {
        return Vec::new();
    }
    doc.get_map(ROOM_FACTS_MAP).for_each(|map_key, value| {
        if !map_key.starts_with(RESPONSE) {
            return;
        }
        let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
            return;
        };
        let Ok(row) = decode(&bytes) else {
            return;
        };
        if let RoomSideRow::Response { parent, .. } = &row
            && parents.contains(parent)
            && carrier_key(&row, &bytes) == map_key
        {
            found.entry(*parent).or_default().push(row);
        }
    });
    found.into_iter().collect()
}

/// Merges each carried row into this vault's in one write: dropped cells and
/// cells first, then claims and facts, then the responses of every claimed
/// turn the rows touch, each settled with every response the window
/// carries for it, since a response stands by the claim.
fn merge_rows(vault: &Vault, doc: &LoroDoc, window: &str, rows: Vec<(String, Option<Vec<u8>>)>) {
    let mut carried = Vec::new();
    let mut cleared = Vec::new();
    let mut parents = BTreeSet::new();
    for (map_key, bytes) in rows {
        let Some(bytes) = bytes else {
            if let Some(cell) = cell_of(&map_key) {
                cleared.push((map_key, cell));
            }
            continue;
        };
        match decode(&bytes) {
            Ok(row) if carrier_key(&row, &bytes) == map_key => match &row {
                RoomSideRow::Response { parent, .. } => {
                    parents.insert(*parent);
                }
                RoomSideRow::Claim { claim } => {
                    parents.extend(named(&claim.turn_id));
                    carried.push((map_key, row));
                }
                _ => carried.push((map_key, row)),
            },
            _ => tracing::warn!(window, key = %map_key, "room side row malformed; left out"),
        }
    }
    let responses = responses_for(doc, &parents);
    if carried.is_empty() && cleared.is_empty() && responses.is_empty() {
        return;
    }
    let outcome = vault.with_write_txn_grouped(|wtxn| {
        let mut merged = 0;
        for (map_key, (room, handle)) in &cleared {
            let merge = clear_replicated_side_cell_in_txn(vault, wtxn, *room, handle.as_deref())?;
            merged += usize::from(merge == SideMerge::Written);
            DIRTY.delete(&vault.store, wtxn, map_key)?;
        }
        for (map_key, row) in &carried {
            let merge = merge_replicated_side_row_in_txn(vault, wtxn, row)?;
            // The window's cell is this machine's now.
            if is_cell(map_key) && matches!(merge, SideMerge::Written | SideMerge::Held) {
                DIRTY.delete(&vault.store, wtxn, map_key)?;
            }
            merged += logged(window, map_key, merge);
        }
        for (parent, rows) in &responses {
            let merge = merge_replicated_responses_in_txn(vault, wtxn, *parent, rows)?;
            merged += logged(window, &parent.to_hex(), merge);
        }
        Ok(merged)
    });
    match outcome {
        Ok(merged) if merged > 0 => tracing::debug!(window, merged, "room side rows merged"),
        Ok(_) => {}
        Err(error) => tracing::warn!(window, error = %error, "room side rows not merged"),
    }
}

/// Logs a merge that did not simply stand, and counts one that wrote.
fn logged(window: &str, key: &str, merge: SideMerge) -> usize {
    match merge {
        SideMerge::Written => 1,
        SideMerge::Held => 0,
        SideMerge::Conflict => {
            tracing::warn!(
                window,
                key,
                "room side rows conflict; the one that stands is kept and the other stays in the window"
            );
            0
        }
        SideMerge::Refused(reason) => {
            tracing::warn!(
                window,
                key,
                ?reason,
                "room side row does not merge here; left out"
            );
            0
        }
    }
}

/// Drops from `doc` every side row of a room this vault deleted, or of a
/// thread it erased: erase wins over every side row, and an erased room's
/// rows stop riding its window. A row of a room this vault holds no record
/// of stays. A live doc keeps the old rows in its history, so `pin` names
/// the window pinned history-free before any row goes, as
/// `room_turns::scrub_deleted_room_turns` does; the sweep, whose shallow cut
/// drops that history, passes `None`. Returns whether a row went, committed.
pub(crate) fn scrub_room_facts(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_room_fact_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(ROOM_FACTS_MAP);
    let mut places = Vec::new();
    map.for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && let Some(place) = decode(&bytes).ok().and_then(|row| row.place())
        {
            places.push((map_key.to_owned(), place));
        }
    });
    let gone = {
        let rtxn = vault.store.env.read_txn()?;
        let mut removed = BTreeMap::new();
        let mut gone = Vec::new();
        for (map_key, (room, branch)) in places {
            let mut erased = false;
            for id in std::iter::once(room).chain(branch) {
                erased |= match removed.get(&id) {
                    Some(held) => *held,
                    None => {
                        let held = crate::ports::removed_in_txn(&vault.store, &rtxn, &id)?;
                        removed.insert(id, held);
                        held
                    }
                };
            }
            if erased {
                gone.push(map_key);
            }
        }
        gone
    };
    if gone.is_empty() {
        return Ok(false);
    }
    if let Some(key) = pin {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &gone {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

impl Vault {
    /// Mirrors room `room`'s host pin, or its platform handle `handle`, into
    /// the live window that carries the room, after a door changed it (FIX
    /// 1794). A cell no live window takes is marked, and mirrored as the
    /// room's window next opens.
    pub(crate) fn refresh_room_cell_in_live_window(&self, room: EntityId, handle: Option<&str>) {
        let cell = cell_key(room, handle);
        if self.mirror_carriers_in_live_windows(
            &[(room, ENTITY_TYPE_CONVERSATION)],
            Some(cell.as_str()),
        ) {
            return;
        }
        if let Err(error) =
            self.with_write_txn_grouped(|wtxn| DIRTY.put(&self.store, wtxn, &cell, &()))
        {
            tracing::warn!(room = %room, error = %error, "room side cell not marked");
        }
    }

    /// Mirrors the claim, response and participation facts a door wrote for
    /// room turn `turn` into the live windows that carry them: its room's,
    /// its own, its parent's and its thread root's (FIX 1794). Best effort: a
    /// window opened later mirrors them as it opens.
    pub(crate) fn refresh_room_turn_facts_in_live_windows(&self, turn: EntityId) {
        let carriers = self
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|rtxn| replicated_side_carriers_in(self, &rtxn, turn));
        match carriers {
            Ok(carriers) if !carriers.is_empty() => {
                self.mirror_carriers_in_live_windows(&carriers, None);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(turn = %turn, error = %error, "room side rows not mirrored");
            }
        }
    }

    /// Mirrors the side rows of each of `carriers` into the live base
    /// windows that carry it, under each window's materializer lock, so no
    /// import lands between the read and the write. Returns whether a live
    /// window carried one.
    fn mirror_carriers_in_live_windows(
        &self,
        carriers: &[(EntityId, u8)],
        changed: Option<&str>,
    ) -> bool {
        let mut carried = false;
        for window in self.live_windows() {
            if window.key.world().is_some() {
                continue;
            }
            let Some((window, materializer, _)) = self.live_window(&window.key) else {
                continue;
            };
            let _guard = materializer.lock();
            match mirror_carriers(self, &window.doc, carriers, changed) {
                Ok(held) => carried |= held,
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "room side rows not mirrored");
                }
            }
        }
        carried
    }
}
