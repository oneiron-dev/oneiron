//! The campaign's spend on the RSI line: reserve-then-spend, fail-closed.
//!
//! Token work (experiment, judge and held-out runs) reserves on the vault's
//! RSI token line under the campaign's soft or owner-pinned share; bandit
//! exploration reserves on its own exposure line. The campaign's lease caps
//! both and widens neither: the RSI ledger still refuses, stamps overdrafts
//! and holds work while suspended. A settled spend is never refunded.
use serde::{Deserialize, Serialize};

use super::{ResearchBinding, binding, invalid, nodes_in_txn};
use crate::llm::{RsiBudgetError, RsiSettlement, RsiSpendPurpose};
use crate::side_table::{self, Named, SideTable};
use crate::{AttemptId, EntityId, Error, Result, Vault};

/// One reservation the campaign holds on the RSI line, keyed by root attempt
/// then reservation id.
const RESERVATION: SideTable<([u8; 16], EntityId), ResearchReservation, Named> =
    SideTable::new(&side_table::AUTORESEARCH_RESERVATION);
/// The refusal of a reservation the campaign's lease has no room for.
const LEASE_FULL: &str = "the reservation exceeds the campaign's lease";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchReservationLine {
    /// Token-denominated loop work, by purpose.
    Work { purpose: RsiSpendPurpose },
    /// Exposure-denominated exploration.
    Exploration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReservation {
    pub id: EntityId,
    pub line: ResearchReservationLine,
    pub units: u64,
    /// The experiment the work is for, when it is one node's.
    pub attempt: Option<AttemptId>,
    pub settlement: Option<RsiSettlement>,
    pub reserved_at: u64,
}

/// The campaign's lease and what it has committed against it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchBudgetRead {
    pub max_units: u64,
    pub exploration_units: u64,
    pub work_reserved: u64,
    pub work_spent: u64,
    pub exploration_reserved: u64,
    pub exploration_spent: u64,
}

impl ResearchBudgetRead {
    fn work_committed(&self) -> u64 {
        self.work_reserved.saturating_add(self.work_spent)
    }

    fn exploration_committed(&self) -> u64 {
        self.exploration_reserved
            .saturating_add(self.exploration_spent)
    }
}

fn rsi_error(error: RsiBudgetError) -> Error {
    match error {
        RsiBudgetError::Engine(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}

/// Whether a reserve refusal means "no room": a full lease, or an RSI line
/// that is unconfigured, exhausted or suspended. Work waits on those, as a
/// round pauses on budget.
pub(super) fn is_budget_refusal(error: &Error) -> bool {
    let Error::InvalidConfig(reason) = error else {
        return false;
    };
    let no_room = [
        RsiBudgetError::Unconfigured,
        RsiBudgetError::Exhausted,
        RsiBudgetError::Suspended,
    ];
    reason == LEASE_FULL || no_room.iter().any(|refusal| *reason == refusal.to_string())
}

fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &ResearchBinding,
) -> Result<ResearchBudgetRead> {
    let mut read = ResearchBudgetRead {
        max_units: binding.config.budget.max_units,
        exploration_units: binding.config.budget.exploration_units,
        ..ResearchBudgetRead::default()
    };
    for (_, row) in RESERVATION.scan_from(&vault.store, txn, binding.root.as_bytes())? {
        let exploration = row.line == ResearchReservationLine::Exploration;
        let (reserved, spent) = if exploration {
            (&mut read.exploration_reserved, &mut read.exploration_spent)
        } else {
            (&mut read.work_reserved, &mut read.work_spent)
        };
        match row.settlement {
            None => *reserved = reserved.saturating_add(row.units),
            Some(RsiSettlement::Spent(units) | RsiSettlement::Exposure(units)) => {
                *spent = spent.saturating_add(units);
            }
            Some(RsiSettlement::Refunded) => {}
        }
    }
    Ok(read)
}

/// The campaign's lease and its committed work and exploration.
/// # Errors
/// An unbound campaign, or storage errors.
pub fn research_budget(vault: &Vault, root: AttemptId) -> Result<ResearchBudgetRead> {
    let binding = binding(vault, root)?;
    let txn = vault.store.env.read_txn()?;
    read_in_txn(vault, &txn, &binding)
}

/// Every reservation the campaign holds or held, in id order.
/// # Errors
/// Storage errors.
pub fn research_reservations(vault: &Vault, root: AttemptId) -> Result<Vec<ResearchReservation>> {
    let txn = vault.store.env.read_txn()?;
    Ok(RESERVATION
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, row)| row)
        .collect())
}

/// Whether the campaign may take another round: its lease has room and the
/// RSI token line is configured, open and not full. False pauses selection.
pub(super) fn work_available(vault: &Vault, binding: &ResearchBinding) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let read = read_in_txn(vault, &txn, binding)?;
    drop(txn);
    if read.work_committed() >= read.max_units {
        return Ok(false);
    }
    match vault.rsi_budget() {
        Ok(line) => Ok(!line.suspended && line.spent.saturating_add(line.reserved) < line.limit),
        Err(RsiBudgetError::Unconfigured) => Ok(false),
        Err(error) => Err(rsi_error(error)),
    }
}

fn reserve(
    vault: &Vault,
    root: AttemptId,
    line: ResearchReservationLine,
    units: u64,
    attempt: Option<AttemptId>,
    at: u64,
) -> Result<EntityId> {
    let binding = binding(vault, root)?;
    if units == 0 {
        return Err(invalid("a campaign reservation names its units"));
    }
    let txn = vault.store.env.read_txn()?;
    if let Some(attempt) = attempt
        && !nodes_in_txn(vault, &txn, root)?.contains_key(attempt.as_bytes())
    {
        return Err(invalid(
            "the reservation's attempt is not an experiment of this campaign",
        ));
    }
    let fits = |read: &ResearchBudgetRead| match line {
        ResearchReservationLine::Work { .. } => {
            read.work_committed().saturating_add(units) <= read.max_units
        }
        ResearchReservationLine::Exploration => {
            read.exploration_committed().saturating_add(units) <= read.exploration_units
        }
    };
    if !fits(&read_in_txn(vault, &txn, &binding)?) {
        return Err(invalid(LEASE_FULL));
    }
    drop(txn);
    let id = vault.store.clock.entity_id()?;
    let reserved = match line {
        ResearchReservationLine::Work { purpose } => {
            vault.reserve_rsi_budget(id, units, purpose, binding.share.clone())
        }
        ResearchReservationLine::Exploration => vault.reserve_rsi_exploration(id, units),
    };
    reserved.map_err(rsi_error)?;
    let row = ResearchReservation {
        id,
        line,
        units,
        attempt,
        settlement: None,
        reserved_at: at,
    };
    let recorded = vault.with_write_txn_grouped(|txn| {
        // A concurrent reservation may have filled the lease meanwhile.
        if !fits(&read_in_txn(vault, txn, &binding)?) {
            return Err(invalid(LEASE_FULL));
        }
        RESERVATION.put(&vault.store, txn, &(*root.as_bytes(), id), &row)
    });
    if let Err(error) = recorded {
        // Compensate the unrecorded reservation; it was never spent.
        vault.refund_rsi_budget(id).map_err(rsi_error)?;
        return Err(error);
    }
    Ok(id)
}

/// Reserve token work (experiment, judge or held-out) on the RSI line under
/// the campaign's share, within its lease.
/// # Errors
/// An unbound campaign, zero units, an attempt outside the campaign, a full
/// lease, an RSI refusal (unconfigured, exhausted, suspended), or storage
/// errors. A refusal reserves nothing.
pub fn reserve_research_work(
    vault: &Vault,
    root: AttemptId,
    purpose: RsiSpendPurpose,
    units: u64,
    attempt: Option<AttemptId>,
    at: u64,
) -> Result<EntityId> {
    reserve(
        vault,
        root,
        ResearchReservationLine::Work { purpose },
        units,
        attempt,
        at,
    )
}

/// Reserve exploration exposure for a bandit slice, on its own line.
/// # Errors
/// As [`reserve_research_work`], against the exploration share.
pub fn reserve_research_exploration(
    vault: &Vault,
    root: AttemptId,
    exposure: u64,
    attempt: Option<AttemptId>,
    at: u64,
) -> Result<EntityId> {
    reserve(
        vault,
        root,
        ResearchReservationLine::Exploration,
        exposure,
        attempt,
        at,
    )
}

fn finish(
    vault: &Vault,
    root: AttemptId,
    id: EntityId,
    settle: impl FnOnce(&ResearchReservation) -> Result<RsiSettlement>,
) -> Result<ResearchReservation> {
    let txn = vault.store.env.read_txn()?;
    let row = RESERVATION
        .get(&vault.store, &txn, &(*root.as_bytes(), id))?
        .ok_or(invalid("the campaign holds no such reservation"))?;
    drop(txn);
    let settlement = settle(&row)?;
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), id);
        let mut row = RESERVATION
            .get(&vault.store, txn, &key)?
            .ok_or(invalid("the campaign holds no such reservation"))?;
        row.settlement = Some(settlement);
        RESERVATION.put(&vault.store, txn, &key, &row)?;
        Ok(row)
    })
}

/// Settle a reservation with its actual units: tokens on a work line,
/// exposure on the exploration line. The unspent rest is released.
/// # Errors
/// An unknown reservation, more units than reserved, a reservation already
/// settled otherwise, or storage errors.
pub fn settle_research_work(
    vault: &Vault,
    root: AttemptId,
    id: EntityId,
    actual: u64,
) -> Result<ResearchReservation> {
    finish(vault, root, id, |row| {
        Ok(match row.line {
            ResearchReservationLine::Work { .. } => {
                vault.settle_rsi_budget(id, actual).map_err(rsi_error)?;
                RsiSettlement::Spent(actual)
            }
            ResearchReservationLine::Exploration => {
                vault
                    .settle_rsi_exploration(id, actual)
                    .map_err(rsi_error)?;
                RsiSettlement::Exposure(actual)
            }
        })
    })
}

/// Refund a reservation that was never spent. Served exposure and settled
/// work stay spent.
/// # Errors
/// An unknown or settled reservation, or storage errors.
pub fn refund_research_work(
    vault: &Vault,
    root: AttemptId,
    id: EntityId,
) -> Result<ResearchReservation> {
    finish(vault, root, id, |row| {
        if row.settlement.is_some() {
            return Err(invalid("a settled reservation is not refunded"));
        }
        vault.refund_rsi_budget(id).map_err(rsi_error)?;
        Ok(RsiSettlement::Refunded)
    })
}
