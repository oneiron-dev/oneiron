//! FIX 5266: a vault's turn programs on the window plane (the Engine's
//! 10-20 ruling: replicate the arming as a synced row, with the elected home
//! as the single admitting machine). What rides, and what a carried row
//! does on this machine, is the program's own
//! (`dreamer_runner::turn_program_replica`); this carries the rows.
//!
//! - `turn_program_arms` rides base windows only: each arming in the window
//!   of its armed month and beside each riding wake in its TURN's window,
//!   each disarm in the window of its own month, under its registration.
//! - `turn_program_wakes` rides the base window of the wake's TURN, under
//!   the turn and the registration.
//! - Admission refuses every insert into either map, in a world window or
//!   that is not a whole row filed under its own key, at a snapshot's root,
//!   in its latest state and in every retained operation.
//! - Reverse rematerialization writes each window's rows from this vault's
//!   state, never over a carried arming that comes later in its
//!   registration's intent order nor over a decided wake, and a door that
//!   changed one mirrors it into the live windows after its commit. Forward
//!   rematerialization and Observer B merge each carried row into this
//!   vault's, so a replacement's later intent and decided wakes land here
//!   though no import delta names them.
//! - A row naming an actor this vault erased leaves the window at egress,
//!   pinned history-free first; a wake this vault admitted is written as
//!   decided (`Admitted`), which clears the machine that recorded it; an
//!   arming a later intent here ended leaves a live window.

use std::collections::BTreeMap;

use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::checkpoint_payload::{Placement, SyncUnclassified};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::dreamer_runner::turn_program_replica::{self as replica, RowMerge, RowPlacement};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::checkpoint_payload::rows::OwnerRef;

/// The base window root map that carries turn-program armings and disarms.
pub(crate) const TURN_PROGRAM_ARMS_MAP: &str = "turn_program_arms";

/// The base window root map that carries the wakes riding to the home.
pub(crate) const TURN_PROGRAM_WAKES_MAP: &str = "turn_program_wakes";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("turn program carrier refused: {reason}"))
}

/// Admits one insert into a window's `turn_program_arms` map: a whole arming
/// or disarm row of a base window, filed under its registration.
pub(crate) fn admit_turn_program_arm_carrier(
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
    replica::admit_arming_row(map_key, bytes)
}

/// Admits one insert into a window's `turn_program_wakes` map: a whole wake
/// row of a base window that rides, filed under its turn and registration.
pub(crate) fn admit_turn_program_wake_carrier(
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
    replica::admit_wake_row(map_key, bytes)
}

/// [`admit_turn_program_arm_carrier`] over every row `map` holds.
pub(crate) fn admit_turn_program_arm_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    admit_map(key, map, admit_turn_program_arm_carrier)
}

/// [`admit_turn_program_wake_carrier`] over every row `map` holds.
pub(crate) fn admit_turn_program_wake_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    admit_map(key, map, admit_turn_program_wake_carrier)
}

fn admit_map(
    key: Option<&WindowKey>,
    map: &LoroMap,
    admit: fn(Option<&WindowKey>, &str, &LoroValue) -> Result<()>,
) -> Result<()> {
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
        admit(key, map_key, value)?;
    }
    Ok(())
}

/// Whether `doc` holds the root map `root`. Looking a root up by name
/// creates it: look first.
fn holds_map(doc: &LoroDoc, root: &str) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(root))
}

/// Every row `map` holds, with its key.
fn rows_of(map: &LoroMap) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Each row an import changed, and each row key it cleared as `None`.
fn changed_rows(delta: &MapDelta<'_>) -> Vec<(String, Option<Vec<u8>>)> {
    delta
        .updated
        .iter()
        .filter_map(|(key, value)| match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                Some((key.to_string(), Some(bytes.to_vec())))
            }
            None => Some((key.to_string(), None)),
            Some(_) => None,
        })
        .collect()
}

/// Writes each of `rows` into `map` where the map does not hold its bytes
/// already. Returns whether it wrote; the caller commits.
fn write_rows(map: &LoroMap, rows: &[(String, Vec<u8>)]) -> Result<bool> {
    let mut wrote = false;
    for (map_key, row) in rows {
        if map_get_bytes(map, map_key).as_deref() != Some(row.as_slice()) {
            map_insert_bytes(map, map_key, row)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Writes into `doc`, base window `key`'s, the arming rows this vault holds
/// for its month, except where the window carries a row that comes no
/// earlier in that registration's intent order (the forward merge takes it),
/// and drops each carried arming row a later intent here ended. Returns
/// whether it wrote; the caller commits.
pub(crate) fn mirror_turn_program_armings(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<bool> {
    mirror_arming_rows(vault, doc, key, &[])
}

/// Mirrors the month's intents and the armings of wakes emitted beside them,
/// keeping the same intent order and cleanup in every base window.
fn mirror_arming_rows(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    wake_armings: &[(String, Vec<u8>)],
) -> Result<bool> {
    if key.world().is_some() {
        return Ok(false);
    }
    let carried: BTreeMap<String, Vec<u8>> = if holds_map(doc, TURN_PROGRAM_ARMS_MAP) {
        rows_of(&doc.get_map(TURN_PROGRAM_ARMS_MAP))
            .into_iter()
            .collect()
    } else {
        BTreeMap::new()
    };
    let (rows, ended) = {
        let rtxn = vault.store.env.read_txn()?;
        let rows: Vec<(String, Vec<u8>)> = replica::month_arming_rows_in_txn(vault, &rtxn, key)?
            .into_iter()
            .chain(wake_armings.iter().cloned())
            .filter(|(map_key, ours)| {
                carried
                    .get(map_key)
                    .is_none_or(|carried| !replica::arming_row_outranks(carried, ours))
            })
            .collect();
        let mut ended = Vec::new();
        for (map_key, bytes) in &carried {
            if !rows.iter().any(|(written, _)| written == map_key)
                && replica::arming_row_outranked_here_in_txn(vault, &rtxn, bytes)?
            {
                ended.push(map_key.clone());
            }
        }
        (rows, ended)
    };
    if rows.is_empty() && ended.is_empty() {
        return Ok(false);
    }
    // A carried arming row replaced or dropped here keeps its payload, its
    // arguments too, in the window's history: the window is pinned
    // history-free first, so no later export carries the obsolete operation,
    // whatever erase comes after (FIX 5266).
    if !ended.is_empty()
        || rows
            .iter()
            .any(|(map_key, ours)| carried.get(map_key).is_some_and(|held| held != ours))
    {
        super::window::require_history_free_window(vault, key)?;
    }
    let map = doc.get_map(TURN_PROGRAM_ARMS_MAP);
    let mut wrote = write_rows(&map, &rows)?;
    for map_key in &ended {
        map_delete(&map, map_key)?;
        wrote = true;
    }
    Ok(wrote)
}

/// Writes into `doc`, base window `key`'s, the wake rows this vault owes for
/// TURN `turn` that ride to the home, except over a carried row the home
/// decided, and writes as decided each carried wake of the turn this vault
/// admitted. Each emitted `Owed` row's arming is mirrored first into the same
/// window. Returns whether it wrote; the caller commits.
pub(crate) fn mirror_turn_program_wakes(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    turn: &EntityId,
) -> Result<bool> {
    if key.world().is_some() {
        return Ok(false);
    }
    let prefix = turn.to_hex();
    let carried: BTreeMap<String, Vec<u8>> = if holds_map(doc, TURN_PROGRAM_WAKES_MAP) {
        rows_of(&doc.get_map(TURN_PROGRAM_WAKES_MAP))
            .into_iter()
            .filter(|(map_key, _)| map_key.starts_with(&prefix))
            .collect()
    } else {
        BTreeMap::new()
    };
    let (rows, armings) = {
        let rtxn = vault.store.env.read_txn()?;
        let mut rows: Vec<(String, Vec<u8>)> = replica::turn_wake_rows_in_txn(vault, &rtxn, turn)?
            .into_iter()
            .filter(|(map_key, _)| {
                carried
                    .get(map_key)
                    .is_none_or(|carried| !replica::wake_row_decided(carried))
            })
            .collect();
        for (map_key, bytes) in &carried {
            if let Some(decided) = replica::admitted_row_in_txn(vault, &rtxn, bytes)? {
                rows.retain(|(written, _)| written != map_key);
                rows.push((map_key.clone(), decided));
            }
        }
        // Each decision this machine holds for the turn goes to the window,
        // with no carried `Owed` row too (FIX 5266).
        for (map_key, decided) in replica::turn_decided_rows_in_txn(vault, &rtxn, turn)? {
            if carried
                .get(&map_key)
                .is_some_and(|carried| replica::wake_row_decided(carried))
            {
                continue;
            }
            rows.retain(|(written, _)| *written != map_key);
            rows.push((map_key, decided));
        }
        let mut armings = Vec::new();
        for (map_key, bytes) in &rows {
            if !replica::wake_row_decided(bytes)
                && let Some(arming) = replica::owed_wake_arming_row_in_txn(vault, &rtxn, map_key)?
            {
                armings.push(arming);
            }
        }
        (rows, armings)
    };
    if rows.is_empty() {
        return Ok(false);
    }
    let wrote_armings = !armings.is_empty() && mirror_arming_rows(vault, doc, key, &armings)?;
    Ok(write_rows(&doc.get_map(TURN_PROGRAM_WAKES_MAP), &rows)? || wrote_armings)
}

/// Merges every row window `key`'s document holds into this vault's, as a
/// window open does: the armings first, so a wake finds its arming. A row
/// that fails is logged and left; it never stops the open.
pub(crate) fn apply_turn_program_maps(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() {
        return;
    }
    if holds_map(doc, TURN_PROGRAM_ARMS_MAP) {
        let rows = rows_of(&doc.get_map(TURN_PROGRAM_ARMS_MAP))
            .into_iter()
            .map(|(map_key, bytes)| (map_key, Some(bytes)))
            .collect();
        merge_armings(vault, key.as_str(), rows);
    }
    if holds_map(doc, TURN_PROGRAM_WAKES_MAP) {
        let rows = rows_of(&doc.get_map(TURN_PROGRAM_WAKES_MAP))
            .into_iter()
            .map(|(map_key, bytes)| (map_key, Some(bytes)))
            .collect();
        merge_wakes(vault, key.as_str(), rows);
    }
}

/// Observer B for the arming map: each row an import changed.
pub(crate) fn materialize_turn_program_arms_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    merge_armings(vault, window_key, changed_rows(delta));
    Some(Vec::new())
}

/// Observer B for the wake map: each row an import changed, and each it
/// cleared.
pub(crate) fn materialize_turn_program_wakes_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    merge_wakes(vault, window_key, changed_rows(delta));
    Some(Vec::new())
}

/// Merges each carried arming row in one write. A cleared row changes
/// nothing here: a disarm rides as a row of its own, an erase as its marker.
fn merge_armings(vault: &Vault, window: &str, rows: Vec<(String, Option<Vec<u8>>)>) {
    let rows: Vec<(String, Vec<u8>)> = rows
        .into_iter()
        .filter_map(|(map_key, bytes)| Some((map_key, bytes?)))
        .collect();
    if rows.is_empty() {
        return;
    }
    let outcome = vault.with_write_txn_grouped(|wtxn| {
        let mut merged = 0;
        for (map_key, bytes) in &rows {
            match replica::merge_arming_row_in_txn(vault, wtxn, map_key, bytes)? {
                RowMerge::Written => merged += 1,
                RowMerge::Held => {}
                RowMerge::Refused(reason) => {
                    tracing::warn!(window, key = %map_key, reason, "turn program arming row does not merge here; left out");
                }
            }
        }
        Ok(merged)
    });
    match outcome {
        Ok(merged) if merged > 0 => tracing::debug!(window, merged, "turn program armings merged"),
        Ok(_) => {}
        Err(error) => tracing::warn!(window, error = %error, "turn program armings not merged"),
    }
}

/// Merges each carried wake row in one write, on the home only, and drops
/// the riding wake this vault recorded for each row the window cleared.
fn merge_wakes(vault: &Vault, window: &str, rows: Vec<(String, Option<Vec<u8>>)>) {
    if rows.is_empty() {
        return;
    }
    let outcome = vault.with_write_txn_grouped(|wtxn| {
        let mut merged = 0;
        for (map_key, bytes) in &rows {
            let Some(bytes) = bytes else {
                if replica::drop_wake_row_in_txn(vault, wtxn, map_key)? {
                    merged += 1;
                }
                continue;
            };
            match replica::merge_wake_row_in_txn(vault, wtxn, map_key, bytes)? {
                RowMerge::Written => merged += 1,
                RowMerge::Held => {}
                RowMerge::Refused(reason) => {
                    tracing::warn!(window, key = %map_key, reason, "turn program wake row does not merge here; left out");
                }
            }
        }
        Ok(merged)
    });
    match outcome {
        Ok(merged) if merged > 0 => tracing::debug!(window, merged, "turn program wakes merged"),
        Ok(_) => {}
        Err(error) => tracing::warn!(window, error = %error, "turn program wakes not merged"),
    }
}

/// Deletes from `doc` each row of either map naming an actor this vault
/// erased, and writes as decided each wake row this vault admitted. A live doc keeps the old
/// rows in its history, so `pin` names the window pinned history-free before
/// an erased actor's row goes; the sweep, whose shallow cut drops that
/// history, passes `None`. Returns whether a row went, committed.
pub(crate) fn scrub_turn_programs(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    let arms = holds_map(doc, TURN_PROGRAM_ARMS_MAP);
    let wakes = holds_map(doc, TURN_PROGRAM_WAKES_MAP);
    if !arms && !wakes {
        return Ok(false);
    }
    let mut doomed: Vec<(&'static str, String)> = Vec::new();
    let mut decided: Vec<(String, Vec<u8>)> = Vec::new();
    let mut erased_any = false;
    {
        let rtxn = vault.store.env.read_txn()?;
        let erased = |actor: Option<EntityId>| -> Result<bool> {
            match actor {
                Some(actor) => vault.carrier_actor_erased_in_txn(&rtxn, &actor),
                None => Ok(false),
            }
        };
        if arms {
            for (map_key, bytes) in rows_of(&doc.get_map(TURN_PROGRAM_ARMS_MAP)) {
                if erased(replica::arming_row_actor(&bytes))? {
                    erased_any = true;
                    doomed.push((TURN_PROGRAM_ARMS_MAP, map_key));
                }
            }
        }
        if wakes {
            for (map_key, bytes) in rows_of(&doc.get_map(TURN_PROGRAM_WAKES_MAP)) {
                if erased(replica::wake_row_actor(&bytes))? {
                    erased_any = true;
                    doomed.push((TURN_PROGRAM_WAKES_MAP, map_key));
                } else if let Some(row) = replica::admitted_row_in_txn(vault, &rtxn, &bytes)? {
                    decided.push((map_key, row));
                }
            }
        }
    }
    if doomed.is_empty() && decided.is_empty() {
        return Ok(false);
    }
    // Pin before an erased actor's row leaves the live map, as the egress
    // scrubs do.
    if erased_any && let Some(key) = pin {
        super::window::require_history_free_window(vault, key)?;
    }
    for (root, map_key) in &doomed {
        map_delete(&doc.get_map(*root), map_key)?;
    }
    if !decided.is_empty() {
        write_rows(&doc.get_map(TURN_PROGRAM_WAKES_MAP), &decided)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// Where a row of either map goes in a checkpoint (KS7-3a): an arming or
/// owed wake in its actor's compartment, held while the turn or
/// conversation it names is, so the actor's erase retires it; a decided
/// wake is ids alone under its turn. A row that does not decode is
/// undecodable.
pub(in crate::sync) fn checkpoint_entry(root: &str, value: &[u8]) -> Placement {
    let placement = if root == TURN_PROGRAM_ARMS_MAP {
        replica::arming_row_placement(value)
    } else {
        replica::wake_row_placement(value)
    };
    let entities = |ids: Vec<EntityId>| ids.iter().map(OwnerRef::entity).collect::<Vec<_>>();
    match placement {
        Some(RowPlacement::Owned {
            owner,
            dependencies,
        }) => Placement::owned(OwnerRef::entity(&owner), entities(dependencies)),
        Some(RowPlacement::Structure { dependencies }) => Placement::Structure {
            dependencies: entities(dependencies),
        },
        None => Placement::unclassified(None, SyncUnclassified::Undecodable),
    }
}

/// Whether a wake map key is a turn and a registration in their one
/// spelling, so it may stand plaintext.
pub(in crate::sync) fn wake_key_is_opaque(map_key: &str) -> bool {
    replica::wake_key_ids(map_key).is_some()
}

impl Vault {
    /// Mirrors this vault's turn-program armings and disarms into every live
    /// base window, after a door changed one (FIX 5266). Best effort: a
    /// window opened later writes its month's rows as it opens.
    pub(crate) fn refresh_turn_program_armings_in_live_windows(&self) {
        for window in self.live_windows() {
            if window.key.world().is_some() {
                continue;
            }
            match mirror_turn_program_armings(self, &window.doc, &window.key) {
                Ok(true) => {
                    window
                        .doc
                        .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "turn program armings not mirrored");
                }
            }
        }
    }

    /// Merges, on the elected home, every wake row its live base windows
    /// carry (FIX 5266): a wake that arrived before its arming is taken once
    /// the arming has. Elsewhere it does nothing. Housekeeping runs it on
    /// every pass, before it admits what is owed.
    pub(crate) fn merge_carried_turn_program_wakes(&self) {
        let home = self.store.env.read_txn().ok().and_then(|rtxn| {
            crate::dreamer_runner::turn_program_replica::home_here_in_txn(self, &rtxn).ok()
        });
        if home != Some(Some(true)) {
            return;
        }
        for window in self.live_windows() {
            if window.key.world().is_some() || !holds_map(&window.doc, TURN_PROGRAM_WAKES_MAP) {
                continue;
            }
            let rows = rows_of(&window.doc.get_map(TURN_PROGRAM_WAKES_MAP))
                .into_iter()
                .map(|(map_key, bytes)| (map_key, Some(bytes)))
                .collect();
            merge_wakes(self, window.key.as_str(), rows);
        }
    }

    /// Mirrors TURN `turn`'s riding wakes into the live window that carries
    /// the TURN, and drops the ones this vault admitted (FIX 5266). Best
    /// effort: the window writes them as it opens.
    pub(crate) fn refresh_turn_program_wakes_in_live_windows(&self, turn: &EntityId) {
        let hex = turn.to_hex();
        for window in self.live_windows() {
            if window.key.world().is_some()
                || !map_contains_binary(&window.doc.get_map("entities"), &hex)
            {
                continue;
            }
            match mirror_turn_program_wakes(self, &window.doc, &window.key, turn) {
                Ok(true) => {
                    window
                        .doc
                        .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(window = %window.key, error = %error, "turn program wakes not mirrored");
                }
            }
        }
    }
}
