//! The instance table of checkpoint payload compartments (KS-7,
//! `checkpoint_payload:instance:v1:`): one row per incarnation of an owner,
//! holding the custody generation its leaf is at and whether it is active,
//! retained or erased. An owner has at most one active incarnation, and an
//! older incarnation keeps its row. A row holds no key and counts no
//! reference: the leaf lives in custody, and shared bytes keep their own
//! holder and refcount rules. Restore class LIVE: the live vault's lifecycle
//! wins over an image's.

use heed::{RoTxn, RwTxn};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

use super::{
    CHECKPOINT_PAYLOADS_ENABLED, INCARNATION_LEN, OWNER_LEN, PayloadItem, Subtype, corrupt,
    ensure_enabled,
};

/// Item -> generation and lifecycle. Key: subtype (1) + owner (32) +
/// incarnation (16).
const INSTANCES: SideTable<PayloadItem, InstanceRow, Named> =
    SideTable::new(&side_table::CHECKPOINT_PAYLOAD_INSTANCE);

/// Where one incarnation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Lifecycle {
    /// The owner's current incarnation: a capture seals the owner under it.
    Active,
    /// Released by an ordinary delete: nothing new is sealed under it, and
    /// its leaf stays for the checkpoints holding it until their retention
    /// ends.
    Retained,
    /// Erased: its leaf is retired, and no capture seals the owner again.
    Erased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceRow {
    generation: u64,
    lifecycle: Lifecycle,
}

/// One incarnation of an owner's compartment: its item, the custody
/// generation its leaf is at, and where it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadInstance {
    pub(crate) item: PayloadItem,
    pub(crate) generation: u64,
    pub(crate) lifecycle: Lifecycle,
}

impl PayloadInstance {
    fn of(item: PayloadItem, row: InstanceRow) -> Self {
        Self {
            item,
            generation: row.generation,
            lifecycle: row.lifecycle,
        }
    }
}

/// The key prefix of every incarnation of `owner` under `subtype`; refused
/// for an owner that is not zero-padded past its subtype's width.
fn owner_prefix(subtype: Subtype, owner: &[u8; OWNER_LEN]) -> Result<Vec<u8>> {
    let item = PayloadItem::new(subtype, *owner, [0; INCARNATION_LEN])?;
    Ok(item.encode()[..1 + OWNER_LEN].to_vec())
}

/// Every incarnation of `owner` under `subtype`, in incarnation order; none
/// while the switch is off.
pub(crate) fn instances_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    subtype: Subtype,
    owner: &[u8; OWNER_LEN],
) -> Result<Vec<PayloadInstance>> {
    if !CHECKPOINT_PAYLOADS_ENABLED {
        return Ok(Vec::new());
    }
    Ok(INSTANCES
        .scan_from(dbs, txn, &owner_prefix(subtype, owner)?)?
        .into_iter()
        .map(|(item, row)| PayloadInstance::of(item, row))
        .collect())
}

/// The one active incarnation among `instances`, if any; two are damage.
fn only_active(instances: Vec<PayloadInstance>) -> Result<Option<PayloadInstance>> {
    let mut active = instances
        .into_iter()
        .filter(|instance| instance.lifecycle == Lifecycle::Active);
    let first = active.next();
    if active.next().is_some() {
        return Err(corrupt());
    }
    Ok(first)
}

/// The owner's active incarnation, if it has one.
pub(crate) fn active_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    subtype: Subtype,
    owner: &[u8; OWNER_LEN],
) -> Result<Option<PayloadInstance>> {
    only_active(instances_in_txn(dbs, txn, subtype, owner)?)
}

/// One incarnation by its item; `None` while the switch is off or when it
/// has no row.
pub(crate) fn instance_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    item: &PayloadItem,
) -> Result<Option<PayloadInstance>> {
    if !CHECKPOINT_PAYLOADS_ENABLED {
        return Ok(None);
    }
    Ok(INSTANCES
        .get(dbs, txn, item)?
        .map(|row| PayloadInstance::of(*item, row)))
}

/// A new incarnation of `owner` under `subtype` (a new attachment
/// occurrence, or an owner's first capture): fresh random bytes, never taken
/// from a digest, active at generation 0. Refused while the owner has an
/// active incarnation or an erased one: an owner has one active incarnation,
/// and an erased owner is never sealed again.
pub(crate) fn mint_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    subtype: Subtype,
    owner: &[u8; OWNER_LEN],
) -> Result<PayloadInstance> {
    ensure_enabled()?;
    if instances_in_txn(dbs, wtxn, subtype, owner)?
        .iter()
        .any(|instance| instance.lifecycle != Lifecycle::Retained)
    {
        return Err(Error::InvariantViolation(
            "checkpoint payload owner is already active or erased",
        ));
    }
    let mut incarnation = [0; INCARNATION_LEN];
    rand::rngs::OsRng.fill_bytes(&mut incarnation);
    let item = PayloadItem::new(subtype, *owner, incarnation)?;
    if INSTANCES.contains(dbs, wtxn, &item)? {
        return Err(corrupt());
    }
    let row = InstanceRow {
        generation: 0,
        lifecycle: Lifecycle::Active,
    };
    INSTANCES.put(dbs, wtxn, &item, &row)?;
    Ok(PayloadInstance::of(item, row))
}

/// The incarnation a capture seals `owner` under: its active one, else a
/// newly minted one; `None` for an erased owner, whose rows a capture omits
/// and never mints a leaf for.
pub(crate) fn active_or_mint_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    subtype: Subtype,
    owner: &[u8; OWNER_LEN],
) -> Result<Option<PayloadInstance>> {
    ensure_enabled()?;
    let instances = instances_in_txn(dbs, wtxn, subtype, owner)?;
    if instances
        .iter()
        .any(|instance| instance.lifecycle == Lifecycle::Erased)
    {
        return Ok(None);
    }
    match only_active(instances)? {
        Some(active) => Ok(Some(active)),
        None => mint_in_txn(dbs, wtxn, subtype, owner).map(Some),
    }
}

/// Marks `item` retained: an ordinary delete released its owner, and keeps
/// backup recovery (ARCH-0038). Its leaf stays for the checkpoints holding
/// it; a retained or erased incarnation is left as it is. Returns the
/// incarnation as it stands now; `None` when it has no row.
pub(crate) fn retain_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    item: &PayloadItem,
) -> Result<Option<PayloadInstance>> {
    ensure_enabled()?;
    let Some(mut row) = INSTANCES.get(dbs, wtxn, item)? else {
        return Ok(None);
    };
    if row.lifecycle == Lifecycle::Active {
        row.lifecycle = Lifecycle::Retained;
        INSTANCES.put(dbs, wtxn, item, &row)?;
    }
    Ok(Some(PayloadInstance::of(*item, row)))
}

/// Marks `item` erased, whatever it was: its owner is erased, and no capture
/// seals it again. Returns the generation its leaf is at, through which the
/// erase stages the leaf's retirement in the same transaction (KS7-4);
/// `None` when it has no row.
pub(crate) fn erase_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    item: &PayloadItem,
) -> Result<Option<u64>> {
    ensure_enabled()?;
    let Some(mut row) = INSTANCES.get(dbs, wtxn, item)? else {
        return Ok(None);
    };
    if row.lifecycle != Lifecycle::Erased {
        row.lifecycle = Lifecycle::Erased;
        INSTANCES.put(dbs, wtxn, item, &row)?;
    }
    Ok(Some(row.generation))
}

/// Rolls an active incarnation's generation for a history purge (call d):
/// the next capture seals the owner's permitted history under a fresh leaf
/// at the next generation, and the purge retires the old one once that
/// reseal is in (KS7-4), so the owner's older checkpoints lose its
/// pre-purge history. Returns the old generation. Refused for an
/// incarnation that has no row or is not active.
pub(crate) fn roll_generation_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    item: &PayloadItem,
) -> Result<u64> {
    ensure_enabled()?;
    let mut row = INSTANCES
        .get(dbs, wtxn, item)?
        .filter(|row| row.lifecycle == Lifecycle::Active)
        .ok_or(Error::InvariantViolation(
            "checkpoint payload instance is not active",
        ))?;
    let old = row.generation;
    row.generation = old
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("checkpoint payload generation"))?;
    INSTANCES.put(dbs, wtxn, item, &row)?;
    Ok(old)
}
