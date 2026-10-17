//! OF-013: withdrawn-generation cutoffs on the window plane.
//!
//! A withdrawn generation's sweep obligation (`hw:`) and its fence (`wg:`)
//! are this machine's rows. Another machine of the owner's that holds the
//! withdrawn body keeps it in its history and sends it, unless the cutoff
//! reaches it too. So each cutoff rides the windows that carry its artifact,
//! in their `withdrawn_cutoffs` map under the artifact's id.
//!
//! - Egress mirrors this vault's cutoff of each artifact a window carries,
//!   and raises a carried cutoff that is lower. No cutoff is ever lowered.
//! - Own-vault admission refuses every insert into the map that is not a
//!   cutoff filed under its artifact's id, and stages each cutoff the update
//!   carries before the update reaches the live window, so the entity doors
//!   refuse the withdrawn body whichever carrier wins the artifact's key.
//! - Forward rematerialization stages the window's cutoffs before its entity
//!   pass, as a window open does.
//! - Federation copies no such map in or out: erasure across vaults is a
//!   notice only.
//!
//! The same map carries each session's epoch floor (FIX 2867): the place a
//! removed epoch summary held, its epoch and the turn it ended at, no words.
//! It rides the windows that carry the session, under `epoch_floor/` and the
//! session's id, so a machine that never held the removed summary numbers
//! past it too. Egress raises a carried floor that is lower, admission
//! refuses a malformed one, and a carried floor only raises this vault's.
//! Every export, and the erase sweep, drops the floor of a session this
//! vault removed (Engine ruling 10-18).

use std::collections::BTreeMap;

use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::deletion::WithdrawnReplacement;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The window root map that carries withdrawn-generation cutoffs.
pub(crate) const WITHDRAWN_CUTOFFS_MAP: &str = "withdrawn_cutoffs";

/// The key prefix of a session's epoch floor in the cutoff map.
const EPOCH_FLOOR: &str = "epoch_floor/";

/// One row of a window's cutoff map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarriedCutoff {
    /// The newest withdrawn generation of an artifact.
    Withdrawn(EntityId, u64),
    /// A session's epoch floor: the removed epoch and the turn it ended at.
    EpochFloor(EntityId, u64, u64),
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("withdrawn cutoff refused: {reason}"))
}

fn decode_generation(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

/// An epoch floor's bytes: its epoch, then the turn it ended at, each eight
/// bytes big-endian.
fn decode_floor(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() != 16 {
        return None;
    }
    Some((
        decode_generation(&bytes[..8])?,
        decode_generation(&bytes[8..])?,
    ))
}

fn encode_floor((epoch, turn_end): (u64, u64)) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&epoch.to_be_bytes());
    bytes[8..].copy_from_slice(&turn_end.to_be_bytes());
    bytes
}

/// The id a row is filed under, when the key is its canonical hex.
fn filed_under(key: &str, unnamed: &'static str) -> Result<EntityId> {
    let id = EntityId::from_hex(key).map_err(|_| refused(unnamed))?;
    if id.to_hex() != key {
        return Err(refused("filed under another id"));
    }
    Ok(id)
}

/// Admits one insert into a window's cutoff map: the newest withdrawn
/// generation of the artifact it is filed under, eight bytes big-endian, or
/// a session's epoch floor filed under `epoch_floor/` and the session's id,
/// its epoch and the turn it ended at, eight bytes big-endian each.
pub(crate) fn admit_withdrawn_cutoff_carrier(
    map_key: &str,
    value: &LoroValue,
) -> Result<CarriedCutoff> {
    let floor = map_key.strip_prefix(EPOCH_FLOOR);
    let id = match floor {
        Some(session) => filed_under(session, "names no session")?,
        None => filed_under(map_key, "names no artifact")?,
    };
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    if floor.is_some() {
        let (epoch, turn_end) =
            decode_floor(bytes.as_slice()).ok_or_else(|| refused("not an epoch floor"))?;
        return Ok(CarriedCutoff::EpochFloor(id, epoch, turn_end));
    }
    let generation =
        decode_generation(bytes.as_slice()).ok_or_else(|| refused("not a generation"))?;
    Ok(CarriedCutoff::Withdrawn(id, generation))
}

/// [`admit_withdrawn_cutoff_carrier`] over every row `map` holds.
pub(crate) fn admit_withdrawn_cutoff_map(map: &LoroMap) -> Result<Vec<CarriedCutoff>> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    rows.iter()
        .map(|(map_key, value)| admit_withdrawn_cutoff_carrier(map_key, value))
        .collect()
}

/// Writes into `doc` this vault's cutoff of each artifact whose carrier the
/// window's `entities` map holds, where the window carries none or a lower
/// one. Returns whether it wrote; the caller commits.
pub(crate) fn mirror_withdrawn_cutoffs(
    doc: &LoroDoc,
    cutoffs: &BTreeMap<EntityId, u64>,
) -> Result<bool> {
    if cutoffs.is_empty() {
        return Ok(false);
    }
    let entities = doc.get_map("entities");
    let mut wrote = false;
    for (id, generation) in cutoffs {
        let hex = id.to_hex();
        if entities.get(&hex).is_none() {
            continue;
        }
        let map = doc.get_map(WITHDRAWN_CUTOFFS_MAP);
        let carried = map_get_bytes(&map, &hex).and_then(|bytes| decode_generation(&bytes));
        if carried.is_some_and(|carried| carried >= *generation) {
            continue;
        }
        map_insert_bytes(&map, &hex, &generation.to_be_bytes())?;
        wrote = true;
    }
    Ok(wrote)
}

/// Writes into `doc` this vault's epoch floor of each session whose carrier
/// the window's `entities` map holds, where the window carries none or a
/// lower one. Returns whether it wrote; the caller commits.
pub(crate) fn mirror_epoch_floors(doc: &LoroDoc, floors: &[(EntityId, u64, u64)]) -> Result<bool> {
    if floors.is_empty() {
        return Ok(false);
    }
    let entities = doc.get_map("entities");
    let mut wrote = false;
    for (session, epoch, turn_end) in floors {
        let hex = session.to_hex();
        if entities.get(&hex).is_none() {
            continue;
        }
        let map = doc.get_map(WITHDRAWN_CUTOFFS_MAP);
        let key = format!("{EPOCH_FLOOR}{hex}");
        let carried = map_get_bytes(&map, &key).and_then(|bytes| decode_floor(&bytes));
        if carried.is_some_and(|carried| carried >= (*epoch, *turn_end)) {
            continue;
        }
        map_insert_bytes(&map, &key, &encode_floor((*epoch, *turn_end)))?;
        wrote = true;
    }
    Ok(wrote)
}

/// Drops from `doc` the epoch floor of each session this vault removed: an
/// erase takes the session's floor off every window that carried it. A live
/// doc keeps the old entry in its history, so `pin` names the window pinned
/// history-free before any floor goes, as
/// `room_facts::scrub_room_facts` does; the sweep, whose shallow cut drops
/// that history, passes `None`. Returns whether a floor went, committed.
pub(crate) fn scrub_removed_epoch_floors(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_withdrawn_cutoff_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(WITHDRAWN_CUTOFFS_MAP);
    let mut floors = Vec::new();
    map.for_each(|map_key, _| {
        if let Some(session) = map_key
            .strip_prefix(EPOCH_FLOOR)
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            floors.push((map_key.to_owned(), session));
        }
    });
    let gone = {
        let rtxn = vault.store.env.read_txn()?;
        let mut gone = Vec::new();
        for (map_key, session) in floors {
            if crate::ports::removed_in_txn(&vault.store, &rtxn, &session)? {
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

/// Raises this vault's floor of each session a carried floor is above, in
/// one write. A floor only rises, so a repeat writes nothing.
fn raise_epoch_floors(vault: &Vault, carried: &BTreeMap<EntityId, (u64, u64)>) -> Result<()> {
    if carried.is_empty() {
        return Ok(());
    }
    let held: BTreeMap<EntityId, (u64, u64)> = {
        let rtxn = vault.store.env.read_txn()?;
        crate::compaction::epoch_floors_in_txn(&vault.store, &rtxn)?
            .into_iter()
            .map(|(session, epoch, turn_end)| (session, (epoch, turn_end)))
            .collect()
    };
    let raised: Vec<(EntityId, (u64, u64))> = carried
        .iter()
        .filter(|&(session, floor)| held.get(session).is_none_or(|held| held < floor))
        .map(|(session, floor)| (*session, *floor))
        .collect();
    if raised.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (session, (epoch, turn_end)) in &raised {
            crate::compaction::raise_session_epoch_floor_in_txn(
                &vault.store,
                wtxn,
                session,
                *epoch,
                *turn_end,
            )?;
        }
        Ok(())
    })
}

/// Stages the historical sweep's obligation for each carried cutoff above
/// this vault's own, in one write, so ingest refuses the withdrawn body as it
/// does where the withdrawal ran. A cutoff at or below the one held here is
/// owed or done already: a repeat stages nothing, and none is lowered. Each
/// carried epoch floor raises this vault's ([`raise_epoch_floors`]).
pub(crate) fn apply_withdrawn_cutoffs(vault: &Vault, carried: &[CarriedCutoff]) -> Result<()> {
    let mut newest = BTreeMap::new();
    let mut floors = BTreeMap::new();
    for row in carried {
        match *row {
            CarriedCutoff::Withdrawn(id, generation) => {
                let held = newest.entry(id).or_insert(generation);
                *held = (*held).max(generation);
            }
            CarriedCutoff::EpochFloor(session, epoch, turn_end) => {
                let held = floors.entry(session).or_insert((epoch, turn_end));
                *held = (*held).max((epoch, turn_end));
            }
        }
    }
    raise_epoch_floors(vault, &floors)?;
    let pending = {
        let rtxn = vault.store.env.read_txn()?;
        let mut pending = Vec::new();
        for (id, generation) in newest {
            if unseen(vault, &rtxn, &id, generation)? {
                pending.push((id, generation));
            }
        }
        pending
    };
    if pending.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        let at = crate::ports::job_recorded_at_in_txn(&vault.store, wtxn)?;
        for (id, generation) in &pending {
            // Another door may have staged it since the read.
            if !unseen(vault, wtxn, id, *generation)? {
                continue;
            }
            crate::deletion::enqueue_withdrawn_generation_in_txn(
                &vault.store,
                wtxn,
                id,
                *generation,
                WithdrawnReplacement::EpochKeyframe,
                at,
            )?;
            tracing::info!(
                entity = %id.to_hex(),
                "withdrawn generation cutoff from another machine; its sweep is staged"
            );
        }
        Ok(())
    })
}

/// Whether `generation` of `id` is newer than every withdrawn generation this
/// vault owes or has fenced.
fn unseen(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, generation: u64) -> Result<bool> {
    Ok(
        crate::deletion::withdrawn_generation_cutoff_in_txn(&vault.store, txn, id)?
            .is_none_or(|held| held < generation),
    )
}

/// Stages every cutoff window `doc` carries, and raises this vault's floor
/// to each epoch floor it carries, before the forward pass reads its
/// entities. A malformed row is logged and left out.
pub(crate) fn apply_withdrawn_cutoff_map(vault: &Vault, doc: &LoroDoc, window: &str) -> Result<()> {
    if !holds_withdrawn_cutoff_map(doc) {
        return Ok(());
    }
    let mut rows = Vec::new();
    doc.get_map(WITHDRAWN_CUTOFFS_MAP)
        .for_each(|map_key, value| rows.push((map_key.to_owned(), value)));
    let mut carried = Vec::new();
    for (map_key, value) in rows {
        let row = match value {
            ValueOrContainer::Value(value) => admit_withdrawn_cutoff_carrier(&map_key, &value),
            ValueOrContainer::Container(_) => Err(refused("nested container")),
        };
        match row {
            Ok(row) => carried.push(row),
            Err(_) => {
                tracing::warn!(window, key = %map_key, "withdrawn cutoff malformed; left out")
            }
        }
    }
    apply_withdrawn_cutoffs(vault, &carried)
}

/// Whether `doc` holds a cutoff map. Looking a root up by name creates it:
/// look first.
fn holds_withdrawn_cutoff_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(WITHDRAWN_CUTOFFS_MAP))
}
