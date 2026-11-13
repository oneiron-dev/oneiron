//! The campaign's spend on the RSI line: reserve-then-spend, fail-closed.
//!
//! Token work (experiment, judge and held-out runs) reserves on the vault's
//! RSI token line under the campaign's soft or owner-pinned share; bandit
//! exploration reserves on its own exposure line. The campaign's lease caps
//! both and widens neither: the RSI ledger still refuses, stamps overdrafts
//! and holds work while suspended. A settled spend is never refunded.
//!
//! Each reserve, settle and refund has an `_in_txn` form that runs inside a
//! caller's write, so a continuation pass commits its accounting in the
//! same write as the row that owns it.
use serde::{Deserialize, Serialize};

use super::{ResearchBinding, binding, invalid, nodes_in_txn};
use crate::llm::RsiSigning;
use crate::research_budget::{RsiBudgetError, RsiSettlement, RsiSpendPurpose};
use crate::side_table::{self, Named, SideTable};
use crate::{AttemptId, EntityId, Error, Result, Vault};

/// One reservation the campaign holds on the RSI line, keyed by root attempt
/// then reservation id.
const RESERVATION: SideTable<([u8; 16], EntityId), ResearchReservation, Named> =
    SideTable::new(&side_table::AUTORESEARCH_RESERVATION);
/// The refusal of a reservation the campaign's lease has no room for.
const LEASE_FULL: &str = "the reservation exceeds the campaign's lease";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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
            None | Some(RsiSettlement::Unknown) => {
                *reserved = reserved.saturating_add(row.units);
            }
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

/// One reservation a caller asks for: its line, units, the experiment it is
/// for, and when.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReservationAsk {
    pub(super) line: ResearchReservationLine,
    pub(super) units: u64,
    pub(super) attempt: Option<AttemptId>,
    pub(super) at: u64,
}

/// What a reservation in a caller's write came to.
#[derive(Debug)]
pub(super) enum Reserved {
    Id(EntityId),
    /// No room (`is_budget_refusal`). An exhausted RSI line's suspension is
    /// already written into the caller's write, which commits it.
    Refused(Error),
}

/// The signing keys a reservation on `line` may need, loaded before the
/// write it runs in.
pub(super) fn reservation_signing(
    vault: &Vault,
    binding: &ResearchBinding,
    line: ResearchReservationLine,
) -> RsiSigning {
    match line {
        ResearchReservationLine::Work { .. } => vault.rsi_token_signing(binding.share.as_deref()),
        ResearchReservationLine::Exploration => RsiSigning::none(),
    }
}

/// Reserve `ask` on the RSI line and record it in the campaign, inside the
/// caller's write: the lease check, the RSI reservation and the record are
/// one write. A refusal for no room is answered as `Reserved::Refused`; any
/// other refusal is an error, and the caller's write is discarded.
pub(super) fn reserve_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &ResearchBinding,
    ask: ReservationAsk,
    signing: RsiSigning,
) -> Result<Reserved> {
    let root = binding.root;
    if ask.units == 0 {
        return Err(invalid("a campaign reservation names its units"));
    }
    if let Some(attempt) = ask.attempt
        && !nodes_in_txn(vault, txn, root)?.contains_key(attempt.as_bytes())
    {
        return Err(invalid(
            "the reservation's attempt is not an experiment of this campaign",
        ));
    }
    let read = read_in_txn(vault, txn, binding)?;
    let fits = match ask.line {
        ResearchReservationLine::Work { .. } => {
            read.work_committed().saturating_add(ask.units) <= read.max_units
        }
        ResearchReservationLine::Exploration => {
            read.exploration_committed().saturating_add(ask.units) <= read.exploration_units
        }
    };
    if !fits {
        return Ok(Reserved::Refused(invalid(LEASE_FULL)));
    }
    let id = vault.store.clock.entity_id()?;
    let reserved = match ask.line {
        ResearchReservationLine::Work { purpose } => vault.reserve_rsi_budget_in_txn(
            txn,
            id,
            ask.units,
            purpose,
            binding.share.clone(),
            signing,
        ),
        ResearchReservationLine::Exploration => {
            vault.reserve_rsi_exploration_in_txn(txn, id, ask.units)
        }
    };
    if let Err(error) = reserved {
        let error = rsi_error(error);
        return if is_budget_refusal(&error) {
            Ok(Reserved::Refused(error))
        } else {
            Err(error)
        };
    }
    let row = ResearchReservation {
        id,
        line: ask.line,
        units: ask.units,
        attempt: ask.attempt,
        settlement: None,
        reserved_at: ask.at,
    };
    RESERVATION.put(&vault.store, txn, &(*root.as_bytes(), id), &row)?;
    Ok(Reserved::Id(id))
}

/// One reservation in a write of its own. A refusal for no room still
/// commits what it wrote (an exhausted line's suspension).
fn reserve(
    vault: &Vault,
    root: AttemptId,
    line: ResearchReservationLine,
    units: u64,
    attempt: Option<AttemptId>,
    at: u64,
) -> Result<EntityId> {
    let binding = binding(vault, root)?;
    let signing = reservation_signing(vault, &binding, line);
    let ask = ReservationAsk {
        line,
        units,
        attempt,
        at,
    };
    match vault.with_write_txn_grouped(|txn| reserve_in_txn(vault, txn, &binding, ask, signing))? {
        Reserved::Id(id) => Ok(id),
        Reserved::Refused(error) => Err(error),
    }
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

/// How a reservation ends.
#[derive(Debug, Clone, Copy)]
pub(super) enum Finish {
    /// Its actual units: tokens on a work line, exposure on the exploration
    /// line.
    Settle(u64),
    /// Token work whose meter is missing: the reservation stays committed,
    /// not falsely spent.
    Unknown,
    /// Never spent.
    Refund,
}

/// The campaign's reservation `id`, as `txn` reads it.
pub(super) fn reservation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    id: EntityId,
) -> Result<Option<ResearchReservation>> {
    RESERVATION.get(&vault.store, txn, &(*root.as_bytes(), id))
}

/// End reservation `id` as `how` says, on the RSI line and in the
/// campaign, inside the caller's write. A refusal writes nothing.
pub(super) fn finish_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    id: EntityId,
    how: Finish,
) -> Result<ResearchReservation> {
    let key = (*root.as_bytes(), id);
    let mut row = RESERVATION
        .get(&vault.store, txn, &key)?
        .ok_or(invalid("the campaign holds no such reservation"))?;
    let settlement = match (how, row.line) {
        (Finish::Settle(actual), ResearchReservationLine::Work { .. }) => {
            RsiSettlement::Spent(actual)
        }
        (Finish::Settle(actual), ResearchReservationLine::Exploration) => {
            RsiSettlement::Exposure(actual)
        }
        (Finish::Unknown, ResearchReservationLine::Work { .. }) => RsiSettlement::Unknown,
        (Finish::Unknown, ResearchReservationLine::Exploration) => {
            return Err(invalid(
                "an unknown token measurement requires a work reservation",
            ));
        }
        (Finish::Refund, _) => {
            if row.settlement.is_some() {
                return Err(invalid("a settled reservation is not refunded"));
            }
            RsiSettlement::Refunded
        }
    };
    vault
        .finish_rsi_reservation_in_txn(txn, id, settlement.clone())
        .map_err(rsi_error)?;
    row.settlement = Some(settlement);
    RESERVATION.put(&vault.store, txn, &key, &row)?;
    Ok(row)
}

fn finish(
    vault: &Vault,
    root: AttemptId,
    id: EntityId,
    how: Finish,
) -> Result<ResearchReservation> {
    vault.with_write_txn_grouped(|txn| finish_in_txn(vault, txn, root, id, how))
}

/// Settle a reservation with its actual units: tokens on a work line,
/// exposure on the exploration line. The unspent rest is released.
/// # Errors
/// An unknown reservation, more exploration exposure than reserved, a
/// reservation already settled otherwise, or storage errors. Token spend is
/// recorded whole, including spend past the reservation.
pub fn settle_research_work(
    vault: &Vault,
    root: AttemptId,
    id: EntityId,
    actual: u64,
) -> Result<ResearchReservation> {
    finish(vault, root, id, Finish::Settle(actual))
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
    finish(vault, root, id, Finish::Refund)
}
