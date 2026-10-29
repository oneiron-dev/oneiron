//! FIX 5661: every free-time cycle a home move carries, closed history
//! included. A carried cycle lands as its old home kept it, so the new home
//! adopts the cycle rather than opening one: its boundary is taken, and its
//! root keeps the owner's total with what was spent.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::super::CYCLE;
use super::super::cycle::{FreeTimeCycle, FreeTimeCycleState, put_carried_cycle_in_txn};
use super::{all_keys, erased_in_txn, set_once, settled_in_txn};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, TableAdopt, froze_home_state_in_txn,
};
use crate::{EntityId, Result, Vault};

/// Every cycle a home move carries.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeCycleRows {
    cycles: Vec<FreeTimeCycle>,
}

impl HomeTable for FreeTimeCycleRows {
    type Rows = Self;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_CYCLE;
    const SCHEMA_VERSION: u16 = 1;

    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        settled_in_txn(vault, txn)
    }

    fn export(vault: &Vault, txn: &RoTxn<'_>, _fence: &HomeFence) -> Result<Self> {
        let cycles = CYCLE
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(_, cycle)| cycle))
            .collect::<Result<_>>()?;
        Ok(Self { cycles })
    }

    /// A carried cycle lands where none is here at its boundary, or where
    /// the one here is the same cycle not yet as far on; the carried cycle
    /// then takes its boundary, so no fresh cycle opens there. Any other
    /// cycle here at that boundary is a Conflict.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Self,
    ) -> Result<TableAdopt> {
        let mut carried = BTreeSet::new();
        let mut agents = BTreeSet::new();
        for cycle in rows.cycles {
            let key = (cycle.agent, cycle.boundary);
            carried.insert(key);
            agents.insert(cycle.agent);
            if erased_in_txn(vault, txn, &cycle.agent)? {
                continue;
            }
            match CYCLE.get(&vault.store, txn, &key)? {
                Some(local) if local == cycle => {}
                Some(local) if !cycle_follows(&local, &cycle) => {
                    return Ok(TableAdopt::Conflict);
                }
                _ => put_carried_cycle_in_txn(vault, txn, &cycle)?,
            }
        }
        if local_only_conflicts(vault, txn, &carried, &agents)? {
            return Ok(TableAdopt::Conflict);
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        all_keys(CYCLE, vault, txn)
    }
}

/// Whether a cycle only this node holds stops the move. On a node that
/// froze its rows every such cycle does: cycles are never deleted but by an
/// erase, so the successor holds every cycle it was handed, and one it
/// lacks opened here after. On any other node an open cycle beside carried
/// cycles of its agent does: its allowance and the carried one would both
/// stand. A closed cycle of this node's own history stays.
fn local_only_conflicts(
    vault: &Vault,
    txn: &RoTxn<'_>,
    carried: &BTreeSet<(EntityId, u64)>,
    agents: &BTreeSet<EntityId>,
) -> Result<bool> {
    let frozen = froze_home_state_in_txn(vault, txn)?;
    for key in CYCLE.scan_keys(&vault.store, txn, &[])? {
        if carried.contains(&key) {
            continue;
        }
        if frozen {
            return Ok(true);
        }
        if agents.contains(&key.0)
            && CYCLE
                .get(&vault.store, txn, &key)?
                .is_some_and(|cycle| cycle.state == FreeTimeCycleState::Open)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the carried `cycle` follows `local`, the same cycle further on:
/// one opening, ended once, its note and its own-time choice each set once,
/// and its asked-for own-time rounds only ever added to (FIX 7763).
fn cycle_follows(local: &FreeTimeCycle, carried: &FreeTimeCycle) -> bool {
    opening(local) == opening(carried)
        && (local.state == FreeTimeCycleState::Open || carried.state == FreeTimeCycleState::Closed)
        && set_once(local.closed_at.as_ref(), carried.closed_at.as_ref())
        && set_once(local.owner_note.as_ref(), carried.owner_note.as_ref())
        && set_once(
            local.own_time_choice.as_ref(),
            carried.own_time_choice.as_ref(),
        )
        && local.own_time_rounds <= carried.own_time_rounds
        && carried.items.starts_with(&local.items)
}

/// A cycle as it opened: what never changes after. Its items are the ones
/// it opened with, before any asked-for round (FIX 7763).
fn opening(cycle: &FreeTimeCycle) -> FreeTimeCycle {
    let opened_with = cycle
        .items
        .len()
        .saturating_sub(cycle.own_time_rounds as usize);
    FreeTimeCycle {
        state: FreeTimeCycleState::Open,
        closed_at: None,
        owner_note: None,
        own_time_choice: None,
        own_time_rounds: 0,
        items: cycle.items[..opened_with].to_vec(),
        ..cycle.clone()
    }
}
