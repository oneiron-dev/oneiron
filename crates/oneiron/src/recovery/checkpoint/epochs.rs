//! What a restore epoch still owes of its world key pads (PAD-2, FIX 10470;
//! CALLS C-L04-MANAGED-RESTORE-LOCKED-WORLDS): kept on the epoch's own
//! RESTORE_EPOCH row, recorded in the transaction that writes it, and
//! reconciled as the pads arrive: a reopen with the kit or an admitted
//! machine, or a machine's hydration (`residence.pad.fetch`).
//!
//! A restore that left a bare reference unrested names its key's exact full
//! id here, beside the notes it reported. A note clears only when every
//! reference it covers resolves here (its row holds its pad, or current
//! custody holds it) or is affirmatively erased (the world's keys destroyed,
//! the row hard-erased, current custody retired it, or the custody the pads
//! came from names it retired), and an erased one says ErasedUnavailable. An
//! unresolved reference stays owed and its note stays: a Locked world is
//! never shown readable and never dropped. A reopen updates its epoch in
//! place; receipts already printed stay as they landed. A pad no epoch owes
//! any longer has its carried compartments pruned from current custody once
//! the transaction that settled it commits ([`prune_carried_pads`], PAD-3).

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{PadRestoreNote, RESTORE_EPOCH, RestoreEpoch};
use crate::store::WorldPadCustody;
use crate::world_keys::{
    PadRowRest, WorldKeyId, pad_row_erased_in_txn, pad_row_rest_in_txn, world_keys_destroyed_in_txn,
};
use crate::{Result, Vault};

/// What one restore epoch still owes of the world key pads its image named
/// (PAD-2, FIX 10470).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePadState {
    /// Each bare reference the restore left unrested, Pending, Withheld or
    /// in a Locked world, by its key's exact full id, until it resolves or
    /// is erased.
    pub required_refs: Vec<WorldKeyId>,
    /// What the restore said of the pads it did not land at rest, as
    /// reconciled since.
    pub remaining: Vec<PadRestoreNote>,
}

impl RestorePadState {
    /// Nothing owed and nothing to say: the row keeps today's form.
    pub(super) fn is_empty(&self) -> bool {
        self.required_refs.is_empty() && self.remaining.is_empty()
    }

    /// `remaining` with no reference owed: an activation's erased pads.
    pub(super) fn settled(remaining: Vec<PadRestoreNote>) -> Self {
        Self {
            required_refs: Vec::new(),
            remaining,
        }
    }

    /// The references owed in the worlds its notes name Locked, by world:
    /// what the kit or an admitted machine opens.
    pub(super) fn locked_refs(&self) -> BTreeMap<crate::EntityId, Vec<WorldKeyId>> {
        let locked: BTreeSet<&str> = self
            .remaining
            .iter()
            .filter_map(|note| match note {
                PadRestoreNote::Locked { world } => Some(world.as_str()),
                _ => None,
            })
            .collect();
        let mut owed: BTreeMap<_, Vec<WorldKeyId>> = BTreeMap::new();
        for key in &self.required_refs {
            if locked.contains(key.world.to_hex().as_str()) {
                owed.entry(key.world).or_default().push(*key);
            }
        }
        owed
    }
}

/// The epoch `sequence` names, when this vault recorded one.
pub(super) fn epoch_at(vault: &Vault, sequence: u64) -> Result<Option<RestoreEpoch>> {
    let txn = vault.store.env.read_txn()?;
    RESTORE_EPOCH.get(&vault.store, &txn, &sequence)
}

/// The latest epoch that landed checkpoint `checkpoint_id`, by its
/// sequence; a later restore, wake or migrate of another checkpoint does not
/// hide it.
pub(super) fn latest_epoch_of(
    vault: &Vault,
    checkpoint_id: &str,
) -> Result<Option<(u64, RestoreEpoch)>> {
    let txn = vault.store.env.read_txn()?;
    for row in RESTORE_EPOCH.iter_rev_from(&vault.store, &txn, &[])? {
        let (sequence, row) = row?;
        if row.checkpoint_id == checkpoint_id {
            return Ok(Some((sequence, row)));
        }
    }
    Ok(None)
}

impl Vault {
    /// The latest restore, wake or migrate epoch this vault recorded, by its
    /// sequence, with what it still owes of its pads; `None` before the
    /// first.
    pub fn latest_restore_epoch(&self) -> Result<Option<(u64, RestoreEpoch)>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = RESTORE_EPOCH.iter_rev_from(&self.store, &txn, &[])?;
        rows.next().transpose()
    }
}

/// Reconciles in `txn` the pads the epoch `epoch` names still owes, or, with
/// `None`, every epoch that still owes one: each owed reference checked
/// against what this vault holds now, and its notes updated on the same row.
/// A bare reference whose pad current custody holds is rested here, in
/// `txn`, so it resolves only with its row at rest. `retired` names the full
/// ids the custody that just gave pads (a head's or a capsule's) holds
/// retired: their erase stands over any pad held here. Returns each epoch it
/// read with its state now. A read fault is a fault, never a resolution.
///
/// # Errors
///
/// Storage and custody faults, and a pad row of another kind or key.
pub(crate) fn reconcile_restore_pad_notes_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    epoch: Option<u64>,
    retired: &BTreeSet<[u8; 40]>,
) -> Result<BTreeMap<u64, RestorePadState>> {
    let rows: Vec<(u64, RestoreEpoch)> = match epoch {
        Some(sequence) => RESTORE_EPOCH
            .get(&vault.store, txn, &sequence)?
            .map(|row| (sequence, row))
            .into_iter()
            .collect(),
        None => {
            let mut owing = Vec::new();
            for row in RESTORE_EPOCH.iter_from(&vault.store, txn, &[])? {
                let (sequence, row) = row?;
                if !row.pad_recovery.required_refs.is_empty() {
                    owing.push((sequence, row));
                }
            }
            owing
        }
    };
    let mut reconciled = BTreeMap::new();
    for (sequence, mut row) in rows {
        let (state, rests) = reconcile_state(vault, txn, &row.pad_recovery, retired)?;
        let puts: Vec<(&[u8], &[u8])> = rests
            .iter()
            .map(|(entity, rested)| (entity.as_bytes().as_slice(), rested.as_slice()))
            .collect();
        super::pad_custody::put_rows_in_txn(vault, txn, &puts)?;
        if state != row.pad_recovery {
            row.pad_recovery = state.clone();
            RESTORE_EPOCH.put(&vault.store, txn, &sequence, &row)?;
        }
        reconciled.insert(sequence, state);
    }
    Ok(reconciled)
}

/// Drops the world pad compartments current custody carries (PAD-3, FIX
/// 11133) for every pad no restore epoch of `vault` still owes: one rested
/// here or erased needs no carried copy, and one no epoch names was never
/// owed. Run after the transaction that reconciled the epochs commits, never
/// inside it, so a write that does not commit strands nothing.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn prune_carried_pads(vault: &Vault) -> Result<()> {
    vault.store.prune_carried_world_pads(|txn| {
        let mut owed = BTreeSet::new();
        for row in RESTORE_EPOCH.iter_from(&vault.store, txn, &[])? {
            let (_, row) = row?;
            owed.extend(
                row.pad_recovery
                    .required_refs
                    .iter()
                    .map(WorldKeyId::envelope_key_id),
            );
        }
        Ok(owed)
    })
}

/// Where one owed reference stands now.
enum RefState {
    /// Its row holds its pad.
    Resolved,
    /// A bare reference whose pad current custody holds: resolved once
    /// `rested` is put under `row` in the same transaction.
    Rest {
        row: crate::EntityId,
        rested: Zeroizing<Vec<u8>>,
    },
    /// Its erase stands.
    Erased,
    /// Still owed.
    Owed,
}

fn ref_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WorldKeyId,
    retired: &BTreeSet<[u8; 40]>,
) -> Result<RefState> {
    let item = key.envelope_key_id();
    if retired.contains(&item)
        || world_keys_destroyed_in_txn(&vault.store, txn, key.world)?
        || pad_row_erased_in_txn(&vault.store, txn, &item)?
        || matches!(
            vault.store.world_pad_custody_entry(&item)?,
            WorldPadCustody::Retired
        )
    {
        return Ok(RefState::Erased);
    }
    Ok(match pad_row_rest_in_txn(&vault.store, txn, key)? {
        PadRowRest::Held => RefState::Resolved,
        PadRowRest::Rest { row, rested } => RefState::Rest { row, rested },
        PadRowRest::Unheld => RefState::Owed,
    })
}

/// `state` checked against what `txn` reads now, with the rows to put at
/// rest for the references it counts resolved by rest. A note whose
/// references were not all checked stays as it is.
fn reconcile_state(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &RestorePadState,
    retired: &BTreeSet<[u8; 40]>,
) -> Result<(RestorePadState, Vec<(crate::EntityId, Zeroizing<Vec<u8>>)>)> {
    let mut owed = Vec::new();
    let mut rests = Vec::new();
    let mut erased = Vec::new();
    let (mut checked_worlds, mut owed_worlds) = (BTreeSet::new(), BTreeSet::new());
    let (mut checked_keys, mut owed_keys) = (BTreeSet::new(), BTreeSet::new());
    for key in &state.required_refs {
        let world = key.world.to_hex();
        checked_worlds.insert(world.clone());
        checked_keys.insert((world.clone(), key.generation));
        match ref_state_in_txn(vault, txn, key, retired)? {
            RefState::Resolved => {}
            RefState::Rest { row, rested } => rests.push((row, rested)),
            RefState::Erased => erased.push(PadRestoreNote::erased(key)),
            RefState::Owed => {
                owed_worlds.insert(world.clone());
                owed_keys.insert((world, key.generation));
                owed.push(*key);
            }
        }
    }
    let mut remaining: Vec<PadRestoreNote> = state
        .remaining
        .iter()
        .filter(|note| match note {
            PadRestoreNote::ErasedUnavailable { .. } => true,
            PadRestoreNote::Locked { world } => {
                owed_worlds.contains(world) || !checked_worlds.contains(world)
            }
            PadRestoreNote::Withheld { world, generation }
            | PadRestoreNote::Pending { world, generation } => {
                let at = (world.clone(), *generation);
                owed_keys.contains(&at) || !checked_keys.contains(&at)
            }
        })
        .cloned()
        .collect();
    for note in erased {
        if !remaining.contains(&note) {
            remaining.push(note);
        }
    }
    Ok((
        RestorePadState {
            required_refs: owed,
            remaining,
        },
        rests,
    ))
}
