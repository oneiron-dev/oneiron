//! Retained copies an entity's erase owns (FIX 7998).
//!
//! Every retained federation batch and every retained maintenance operation
//! names the rows whose bytes it carries in [`CARRIER`]. Both delete doors
//! scrub those items in the erase transaction
//! ([`erase_retained_copies_in_txn`] is one of the derived-row erasers). The
//! hard-erase sweep scrubs them again before it compacts carriers, and its
//! completion writers keep the obligation while any copy is left, so a copy
//! retained again after the erase cannot outlive the erase's completion. A
//! scrubbed item keeps only its content-free receipt.

use std::collections::BTreeSet;

use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, HexId, Raw, SideTable, SideTableDbs};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// One retained item that carries a row's bytes. Empty value.
const CARRIER: SideTable<(HexId, String), (), Raw> =
    SideTable::new(&side_table::SYNC_RETAINED_WORK_CARRIER);

/// The retained item a carrier row names.
pub(crate) enum CarriedBy {
    /// A federation batch, by its `sync_queue` key.
    Burst(Vec<u8>),
    /// A maintenance operation, by its key in its own table.
    Maintenance(String),
}

impl CarriedBy {
    fn reference(&self) -> String {
        match self {
            Self::Burst(key) => format!("b{}", bytes_to_hex_lower(key)),
            Self::Maintenance(key) => format!("m{key}"),
        }
    }

    fn parse(reference: &str) -> Option<Self> {
        match reference.split_at_checked(1)? {
            ("b", key) => hex_bytes(key).map(Self::Burst),
            ("m", key) => Some(Self::Maintenance(key.to_owned())),
            _ => None,
        }
    }
}

/// The bytes `hex` spells in lower-case pairs.
fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Names `by` as a carrier of each of `carried`.
pub(crate) fn register_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    carried: &[EntityId],
    by: &CarriedBy,
) -> Result<()> {
    let reference = by.reference();
    for id in carried {
        CARRIER.put(dbs, txn, &(HexId(*id), reference.clone()), &())?;
    }
    Ok(())
}

/// Forgets `by` as a carrier of each of `carried`, once it is gone.
pub(crate) fn forget_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    carried: &[EntityId],
    by: &CarriedBy,
) -> Result<()> {
    let reference = by.reference();
    for id in carried {
        CARRIER.delete(dbs, txn, &(HexId(*id), reference.clone()))?;
    }
    Ok(())
}

/// Whether a retained item still carries one of `ids`.
pub(crate) fn retained_copies_in(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    ids: impl IntoIterator<Item = impl std::borrow::Borrow<EntityId>>,
) -> Result<bool> {
    for id in ids {
        if !CARRIER
            .scan_keys(
                dbs,
                txn,
                std::borrow::Borrow::<EntityId>::borrow(&id)
                    .to_hex()
                    .as_bytes(),
            )?
            .is_empty()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Scrubs every retained item that carries `id`: its bytes go, and its
/// content-free receipt stays. Runs in the erase transaction at both delete
/// doors, before the record's body and edges go.
pub(crate) fn erase_retained_copies_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (entity, reference) in CARRIER.scan_keys(store, txn, id.to_hex().as_bytes())? {
        match CarriedBy::parse(&reference) {
            Some(CarriedBy::Burst(key)) => super::queue::erase_in_txn(store, txn, &key)?,
            Some(CarriedBy::Maintenance(key)) => {
                crate::sync::quota::erase_retained_in_txn(store, txn, &key)?;
            }
            None => {}
        }
        CARRIER.delete(store, txn, &(entity, reference))?;
    }
    Ok(())
}

/// Scrubs every retained copy of each of `ids`, in one writer: the
/// hard-erase sweep's pass before it compacts the carriers (FIX 7998).
pub(crate) fn scrub_retained_copies(vault: &Vault, ids: &BTreeSet<EntityId>) -> Result<()> {
    let carried = {
        let txn = vault.store.env.read_txn()?;
        let mut carried = Vec::new();
        for id in ids {
            if retained_copies_in(&vault.store, &txn, [id])? {
                carried.push(*id);
            }
        }
        carried
    };
    if carried.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for id in &carried {
            erase_retained_copies_in_txn(&vault.store, txn, id)?;
        }
        Ok(())
    })
}
