//! FIX 5661: every free-time cycle a home move carries, closed history
//! included. A carried cycle lands as its old home kept it, so the new home
//! adopts the cycle rather than opening one: its boundary is taken, and its
//! root keeps the owner's total with what was spent.
//!
//! FIX 8875 stage 2: a cycle travels as its facts, its agent and its
//! own-time choice in its agent's partition, and its note in its author's.
//! A cycle whose agent did not open here lands nothing; a note whose author
//! did not open here never lands, and the note this node holds, if any,
//! stands (FIX 10764): never the carried one, never a Conflict.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::super::CYCLE;
use super::super::cycle::{
    FreeTimeCycle, FreeTimeCycleState, FreeTimeItemRef, FreeTimeNote, put_carried_cycle_in_txn,
};
use super::super::policy::FreeTimeSplit;
use super::actor_content::{
    FreeTimeActorPartition, FreeTimeActorPiece, FreeTimeAdoptRow, FreeTimePartitioned,
    FreeTimeSlot, Joined, Pieces,
};
use super::{all_keys, erased_in_txn, set_once, settled_in_txn};
use crate::agent_dispatch::SpendScopeId;
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, TableAdopt, froze_home_state_in_txn,
};
use crate::{EntityId, Result, Vault};

/// Every cycle a home move carries: each cycle's facts, its agent, choice
/// and note apart.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeCycleRows {
    cycles: Vec<CycleFacts>,
}

/// One cycle without its agent, its note or its own-time choice: its ids,
/// budget, boundaries, times, state, root, items and rounds, and when its
/// note was written, if it has one.
#[derive(Serialize, Deserialize)]
struct CycleFacts {
    cycle: EntityId,
    policy_revision: u64,
    total_units: u64,
    pinned_split: Option<FreeTimeSplit>,
    period_start: u64,
    boundary: u64,
    next_boundary: Option<u64>,
    opened_at: u64,
    closed_at: Option<u64>,
    state: FreeTimeCycleState,
    root_scope: SpendScopeId,
    items: Vec<FreeTimeItemRef>,
    own_time_rounds: u32,
    note_at: Option<u64>,
}

/// A carried cycle whose agent opened here, and whether it had a note whose
/// author's content did not.
struct CarriedCycle {
    cycle: FreeTimeCycle,
    note_gone: bool,
}

impl FreeTimeCycleRows {
    /// `cycles`, every cycle here, partitioned.
    fn partition(cycles: Vec<FreeTimeCycle>) -> Result<FreeTimePartitioned<Self>> {
        let mut pieces = Pieces::new(FreeTimeSlot::Cycle);
        let mut facts = Vec::with_capacity(cycles.len());
        for (index, cycle) in cycles.into_iter().enumerate() {
            let row = pieces.row(index)?;
            pieces.push(cycle.agent, FreeTimeActorPiece::Subject { row });
            if let Some(choice) = cycle.own_time_choice {
                pieces.push(cycle.agent, FreeTimeActorPiece::Choice { row, choice });
            }
            let note_at = cycle.owner_note.as_ref().map(|note| note.at);
            if let Some(FreeTimeNote { author, at, text }) = cycle.owner_note {
                pieces.push(author, FreeTimeActorPiece::Note { row, at, text });
            }
            facts.push(CycleFacts {
                cycle: cycle.cycle,
                policy_revision: cycle.policy_revision,
                total_units: cycle.total_units,
                pinned_split: cycle.pinned_split,
                period_start: cycle.period_start,
                boundary: cycle.boundary,
                next_boundary: cycle.next_boundary,
                opened_at: cycle.opened_at,
                closed_at: cycle.closed_at,
                state: cycle.state,
                root_scope: cycle.root_scope,
                items: cycle.items,
                own_time_rounds: cycle.own_time_rounds,
                note_at,
            });
        }
        Ok(pieces.partitioned(Self { cycles: facts }))
    }

    /// Each carried cycle rejoined with its agent, choice and note,
    /// scrubbed-first (FIX 10764).
    fn rejoin_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        rows: FreeTimePartitioned<Self>,
    ) -> Result<Vec<FreeTimeAdoptRow<CarriedCycle, CycleFacts>>> {
        let joined = Joined::in_txn(vault, txn, FreeTimeSlot::Cycle, rows.actors)?;
        Ok((0u32..)
            .zip(rows.facts.cycles)
            .map(|(row, facts)| rejoin(&joined, row, facts))
            .collect())
    }
}

/// Rejoins the cycle row `row` of `facts`: scrubbed with no agent here.
fn rejoin(
    joined: &Joined,
    row: u32,
    facts: CycleFacts,
) -> FreeTimeAdoptRow<CarriedCycle, CycleFacts> {
    let Some(agent) = joined.subject(row) else {
        return FreeTimeAdoptRow::Scrubbed(facts);
    };
    let owner_note = joined
        .find(row, |piece| match piece {
            FreeTimeActorPiece::Note { at, text, .. } => Some((*at, text.clone())),
            _ => None,
        })
        .map(|(author, (at, text))| FreeTimeNote { author, at, text });
    let own_time_choice = joined
        .find(row, |piece| match piece {
            FreeTimeActorPiece::Choice { choice, .. } => Some(*choice),
            _ => None,
        })
        .filter(|(actor, _)| *actor == agent)
        .map(|(_, choice)| choice);
    let note_gone = facts.note_at.is_some() && owner_note.is_none();
    FreeTimeAdoptRow::Live(CarriedCycle {
        cycle: FreeTimeCycle {
            agent,
            cycle: facts.cycle,
            policy_revision: facts.policy_revision,
            total_units: facts.total_units,
            pinned_split: facts.pinned_split,
            period_start: facts.period_start,
            boundary: facts.boundary,
            next_boundary: facts.next_boundary,
            opened_at: facts.opened_at,
            closed_at: facts.closed_at,
            state: facts.state,
            root_scope: facts.root_scope,
            items: facts.items,
            owner_note,
            own_time_choice,
            own_time_rounds: facts.own_time_rounds,
        },
        note_gone,
    })
}

impl HomeTable for FreeTimeCycleRows {
    type Rows = Self;
    type Actor = FreeTimeActorPartition;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_CYCLE;
    const SCHEMA_VERSION: u16 = 2;

    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        settled_in_txn(vault, txn)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<FreeTimePartitioned<Self>> {
        let cycles = CYCLE
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(_, cycle)| cycle))
            .collect::<Result<_>>()?;
        Self::partition(cycles)
    }

    /// A carried cycle lands where none is here at its boundary, or where
    /// the one here is the same cycle not yet as far on; the carried cycle
    /// then takes its boundary, so no fresh cycle opens there. Any other
    /// cycle here at that boundary is a Conflict. A cycle whose agent did
    /// not open here lands nothing and is carried all the same, by its id.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: FreeTimePartitioned<Self>,
    ) -> Result<TableAdopt> {
        let mut carried = BTreeSet::new();
        let mut scrubbed = BTreeSet::new();
        let mut agents = BTreeSet::new();
        for row in Self::rejoin_in_txn(vault, txn, rows)? {
            let CarriedCycle {
                mut cycle,
                note_gone,
            } = match row {
                FreeTimeAdoptRow::Live(live) => live,
                FreeTimeAdoptRow::Scrubbed(facts) => {
                    scrubbed.insert(facts.cycle);
                    continue;
                }
            };
            let key = (cycle.agent, cycle.boundary);
            carried.insert(key);
            agents.insert(cycle.agent);
            if erased_in_txn(vault, txn, &cycle.agent)? {
                continue;
            }
            let local = CYCLE.get(&vault.store, txn, &key)?;
            if note_gone {
                cycle.owner_note = local.as_ref().and_then(|local| local.owner_note.clone());
            }
            match local {
                Some(local) if local == cycle => {}
                Some(local) if !cycle_follows(&local, &cycle) => {
                    return Ok(TableAdopt::Conflict);
                }
                _ => put_carried_cycle_in_txn(vault, txn, &cycle)?,
            }
        }
        if local_only_conflicts(vault, txn, &carried, &scrubbed, &agents)? {
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
/// stand. A closed cycle of this node's own history stays. A cycle here
/// that is one of `scrubbed`, carried cycles whose agent did not open here,
/// is carried all the same (FIX 8875).
fn local_only_conflicts(
    vault: &Vault,
    txn: &RoTxn<'_>,
    carried: &BTreeSet<(EntityId, u64)>,
    scrubbed: &BTreeSet<EntityId>,
    agents: &BTreeSet<EntityId>,
) -> Result<bool> {
    let frozen = froze_home_state_in_txn(vault, txn)?;
    for key in CYCLE.scan_keys(&vault.store, txn, &[])? {
        if carried.contains(&key) {
            continue;
        }
        if !scrubbed.is_empty()
            && CYCLE
                .get(&vault.store, txn, &key)?
                .is_some_and(|cycle| scrubbed.contains(&cycle.cycle))
        {
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
