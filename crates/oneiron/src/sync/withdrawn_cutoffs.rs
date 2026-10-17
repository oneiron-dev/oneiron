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

use std::collections::BTreeMap;

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::loro_support::{map_get_bytes, map_insert_bytes};
use crate::Vault;
use crate::deletion::WithdrawnReplacement;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The window root map that carries withdrawn-generation cutoffs.
pub(crate) const WITHDRAWN_CUTOFFS_MAP: &str = "withdrawn_cutoffs";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("withdrawn cutoff refused: {reason}"))
}

fn decode_generation(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

/// Admits one insert into a window's cutoff map: the newest withdrawn
/// generation of the artifact it is filed under, eight bytes big-endian.
pub(crate) fn admit_withdrawn_cutoff_carrier(
    map_key: &str,
    value: &LoroValue,
) -> Result<(EntityId, u64)> {
    let id = EntityId::from_hex(map_key).map_err(|_| refused("names no artifact"))?;
    if id.to_hex() != map_key {
        return Err(refused("filed under another id"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let generation =
        decode_generation(bytes.as_slice()).ok_or_else(|| refused("not a generation"))?;
    Ok((id, generation))
}

/// [`admit_withdrawn_cutoff_carrier`] over every row `map` holds.
pub(crate) fn admit_withdrawn_cutoff_map(map: &LoroMap) -> Result<Vec<(EntityId, u64)>> {
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

/// Stages the historical sweep's obligation for each carried cutoff above
/// this vault's own, in one write, so ingest refuses the withdrawn body as it
/// does where the withdrawal ran. A cutoff at or below the one held here is
/// owed or done already: a repeat stages nothing, and none is lowered.
pub(crate) fn apply_withdrawn_cutoffs(vault: &Vault, carried: &[(EntityId, u64)]) -> Result<()> {
    let mut newest = BTreeMap::new();
    for (id, generation) in carried {
        let held = newest.entry(*id).or_insert(*generation);
        *held = (*held).max(*generation);
    }
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

/// Stages every cutoff window `doc` carries, before the forward pass reads
/// its entities. A malformed row is logged and left out.
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
