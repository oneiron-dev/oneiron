//! FIX 5661: the free-time families a home move carries, as adapters on
//! L03's carrier C1 (`crate::sync::home_handoff`). On a home move the
//! existing cycle and its remaining allowance move to the new home (Engine
//! 10-20 06:0x): every agent's policy row with its witness, the clock, every
//! cycle with its history, every receipt, and each item whose try never
//! started, which the new home queues again under its own attempt id. The
//! allowance itself is the cycle's spend tree, carried beside these
//! (`agent_dispatch::spend_handoff`), so the original cap stands with what
//! was spent and held.
//!
//! Rows travel as these DTOs, MessagePack by name whatever the table stores,
//! and land through the families' typed writes, never a fenced writer. A
//! carried row lands where this node holds none under its key, or holds one
//! the carried row follows. A row here that is ahead of the carried one or
//! diverged from it is a Conflict: nothing of the move lands and the work
//! here stands, so a late import never combines two allowances. On a node
//! that froze its rows for an earlier move the rows are history: a row the
//! successor no longer holds goes, and one only this node holds is work the
//! successor never saw, a Conflict. An erased agent's rows never land.
//!
//! When no handoff arrives, or one is incomplete, none of this runs, and the
//! new home opens its cycles as before.

mod cycle_rows;
mod item_rows;

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::erase::erased_in_txn;
use super::free_time_item_waits_unstarted;
use super::policy::FreeTimePolicyRecord;
use super::{CLOCK, CYCLE, FreeTimeClock, FreeTimeItemReceipt, POLICY, RECEIPT};
use crate::agent_dispatch::SpendScopeId;
use crate::attempt_queue::AttemptQueue;
use crate::side_table::{self, SideCodec, SideKey, SideTable, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, TableAdopt, froze_home_state_in_txn,
};
use crate::{EntityId, Error, Result, Vault};

pub(crate) use self::cycle_rows::FreeTimeCycleRows;
pub(crate) use self::item_rows::FreeTimeItemRows;

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time home handoff: {reason}"))
}

/// The root spend scope of every cycle here: the free-time trees a home move
/// carries (`agent_dispatch::spend_handoff`).
pub(crate) fn free_time_root_scopes_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<BTreeSet<SpendScopeId>> {
    CYCLE
        .iter_from(&vault.store, txn, &[])?
        .map(|row| row.map(|(_, cycle)| cycle.root_scope))
        .collect()
}

/// Whether no admitted free-time work can still move these rows: every try
/// of every cycle's items, late work of closed cycles included, has ended or
/// never started.
fn settled_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    let queue = AttemptQueue::new(vault);
    for row in CYCLE.iter_from(&vault.store, txn, &[])? {
        let (_, cycle) = row?;
        let run = crate::dreamer_runner::store::free_time_item_run_id(cycle.cycle);
        if queue
            .list_run_in_txn(txn, &run)?
            .iter()
            .any(|record| !record.state.is_terminal() && !free_time_item_waits_unstarted(record))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The full stored key of every row of `table`.
fn all_keys<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<Vec<Vec<u8>>> {
    Ok(table
        .scan_keys(&vault.store, txn, &[])?
        .iter()
        .map(|key| table.key_bytes(key))
        .collect())
}

/// A field set once: unset is behind any value, and two values agree.
fn set_once<T: PartialEq>(local: Option<&T>, carried: Option<&T>) -> bool {
    local.is_none() || local == carried
}

/// Every agent's policy row a home move carries, a cleared policy's witness
/// included.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimePolicyRows {
    rows: Vec<PolicyRow>,
}

#[derive(Serialize, Deserialize)]
struct PolicyRow {
    agent: EntityId,
    record: FreeTimePolicyRecord,
}

impl HomeTable for FreeTimePolicyRows {
    type Rows = Self;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_POLICY;
    const SCHEMA_VERSION: u16 = 1;

    /// An owner's set or clear is one writer of its own: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(vault: &Vault, txn: &RoTxn<'_>, _fence: &HomeFence) -> Result<Self> {
        let rows = POLICY
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(agent, record)| PolicyRow { agent, record }))
            .collect::<Result<_>>()?;
        Ok(Self { rows })
    }

    /// The witnesses decide: a carried row whose acts extend this node's
    /// lands; a row here whose acts extend the carried ones is the owner's
    /// later say-so here and stays; any other difference is a Conflict. Rows
    /// only this node holds stay: each is the owner's own act.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Self,
    ) -> Result<TableAdopt> {
        for PolicyRow { agent, record } in rows.rows {
            if erased_in_txn(vault, txn, &agent)? {
                continue;
            }
            if let Some(local) = POLICY.get(&vault.store, txn, &agent)? {
                if local.acts.starts_with(&record.acts) {
                    continue;
                }
                if !record.acts.starts_with(&local.acts) {
                    return Ok(TableAdopt::Conflict);
                }
            }
            POLICY.put(&vault.store, txn, &agent, &record)?;
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        all_keys(POLICY, vault, txn)
    }
}

/// Every agent's clock a home move carries.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeClockRows {
    rows: Vec<ClockRow>,
}

#[derive(Serialize, Deserialize)]
struct ClockRow {
    agent: EntityId,
    clock: FreeTimeClock,
}

/// Whether the carried clock follows `local`: a later boundary, or the same
/// one with its cycle since ended.
fn clock_follows(local: &FreeTimeClock, carried: &FreeTimeClock) -> bool {
    carried.last_boundary > local.last_boundary
        || (carried.last_boundary == local.last_boundary && carried.open.is_none())
}

impl HomeTable for FreeTimeClockRows {
    type Rows = Self;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_CLOCK;
    const SCHEMA_VERSION: u16 = 1;

    /// A clock moves only where a cycle opens or ends: on the home, at its
    /// boundary, or with its items' receipts (settled with the cycles).
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(vault: &Vault, txn: &RoTxn<'_>, _fence: &HomeFence) -> Result<Self> {
        let rows = CLOCK
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(agent, clock)| ClockRow { agent, clock }))
            .collect::<Result<_>>()?;
        Ok(Self { rows })
    }

    /// A carried clock is the due floor here once it lands, so no boundary
    /// it passed opens again. On a node that froze its rows, a clock the
    /// successor no longer holds went with its policy's clear.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Self,
    ) -> Result<TableAdopt> {
        let mut carried = BTreeSet::new();
        for ClockRow { agent, clock } in rows.rows {
            carried.insert(agent);
            if erased_in_txn(vault, txn, &agent)? {
                continue;
            }
            match CLOCK.get(&vault.store, txn, &agent)? {
                Some(local) if local == clock => {}
                Some(local) if !clock_follows(&local, &clock) => {
                    return Ok(TableAdopt::Conflict);
                }
                _ => CLOCK.put(&vault.store, txn, &agent, &clock)?,
            }
        }
        if froze_home_state_in_txn(vault, txn)? {
            for agent in CLOCK.scan_keys(&vault.store, txn, &[])? {
                if !carried.contains(&agent) {
                    CLOCK.delete(&vault.store, txn, &agent)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        all_keys(CLOCK, vault, txn)
    }
}

/// Every item receipt a home move carries.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeReceiptRows {
    receipts: Vec<FreeTimeItemReceipt>,
}

impl HomeTable for FreeTimeReceiptRows {
    type Rows = Self;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_RECEIPT;
    const SCHEMA_VERSION: u16 = 1;

    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        settled_in_txn(vault, txn)
    }

    fn export(vault: &Vault, txn: &RoTxn<'_>, _fence: &HomeFence) -> Result<Self> {
        let receipts = RECEIPT
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(_, receipt)| receipt))
            .collect::<Result<_>>()?;
        Ok(Self { receipts })
    }

    /// A receipt never changes once recorded: a carried one lands where
    /// there is none, and a different one here is a Conflict. On a node that
    /// froze its rows, a receipt the successor lacks was recorded after.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Self,
    ) -> Result<TableAdopt> {
        let mut carried = BTreeSet::new();
        for receipt in rows.receipts {
            let key = (receipt.agent, receipt.cycle, receipt.item);
            carried.insert(key);
            if erased_in_txn(vault, txn, &receipt.agent)? {
                continue;
            }
            match RECEIPT.get(&vault.store, txn, &key)? {
                None => RECEIPT.put(&vault.store, txn, &key, &receipt)?,
                Some(local) if local == receipt => {}
                Some(_) => return Ok(TableAdopt::Conflict),
            }
        }
        if froze_home_state_in_txn(vault, txn)?
            && RECEIPT
                .scan_keys(&vault.store, txn, &[])?
                .iter()
                .any(|key| !carried.contains(key))
        {
            return Ok(TableAdopt::Conflict);
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        all_keys(RECEIPT, vault, txn)
    }
}
