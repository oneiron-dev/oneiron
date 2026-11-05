//! Vault-local durable reserve/settle/refund ledger for research-loop spend.
use crate::agent_dispatch::{SpendScope, SpendScopeId, SpendState};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{AttemptId, EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
const RSI_LINE: SideTable<(), Line, LegacyJson> = SideTable::new(&side_table::BUDGET_RSI_LINE);
type RsiResult<T> = std::result::Result<T, RsiBudgetError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    amount: u64,
    line: RsiLine,
    purpose: Option<RsiSpendPurpose>,
    share: Option<String>,
    settlement: Option<RsiSettlement>,
    overdraft: Option<RsiOverdraftReceipt>,
    research: Option<ResearchSpendBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResearchSpendBinding {
    scope: SpendScopeId,
    root: AttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RsiLine {
    Tokens,
    Exposure,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    config: RsiBudgetConfig,
    suspended: bool,
    reservations: BTreeMap<String, Reservation>,
}

impl Line {
    fn usage(
        &self,
        line: RsiLine,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<(u64, u64)> {
        let (mut spent, mut reserved) = (0u64, 0u64);
        for row in self.reservations.values().filter(|row| accepts(row)) {
            let amount = match (row.line, &row.settlement) {
                (RsiLine::Tokens, Some(RsiSettlement::Spent(amount)))
                | (RsiLine::Exposure, Some(RsiSettlement::Exposure(amount))) => Some(*amount),
                (RsiLine::Tokens, Some(RsiSettlement::Unknown))
                | (_, None)
                | (_, Some(RsiSettlement::Refunded)) => None,
                _ => return Err(crate::Error::CorruptedIndex("RSI budget settlement line").into()),
            };
            if row.line != line {
                continue;
            }
            if let Some(amount) = amount {
                spent = spent.checked_add(amount).ok_or(RsiBudgetError::Exhausted)?;
            } else if row.settlement.is_none() || row.settlement == Some(RsiSettlement::Unknown) {
                reserved = reserved
                    .checked_add(row.amount)
                    .ok_or(RsiBudgetError::Exhausted)?;
            }
        }
        Ok((spent, reserved))
    }
    /// Only token reservations draw from shares and their unallocated pool.
    /// Exploration is an independent exposure line, not a token-share debit.
    fn free_pool_usage(&self) -> RsiResult<u64> {
        let mut by_share = BTreeMap::<&str, u64>::new();
        let mut free_used = 0u64;
        for row in self
            .reservations
            .values()
            .filter(|row| row.line == RsiLine::Tokens)
        {
            let units = match row.settlement {
                Some(RsiSettlement::Spent(units)) => units,
                Some(RsiSettlement::Refunded) => 0,
                None | Some(RsiSettlement::Unknown) => row.amount,
                Some(RsiSettlement::Exposure(_)) => {
                    return Err(crate::Error::CorruptedIndex("RSI token settlement line").into());
                }
            };
            if let Some(share) = row.share.as_deref() {
                let total = by_share.entry(share).or_default();
                *total = total.checked_add(units).ok_or(RsiBudgetError::Exhausted)?;
            } else {
                free_used = free_used
                    .checked_add(units)
                    .ok_or(RsiBudgetError::Exhausted)?;
            }
        }
        for (key, used) in by_share {
            let allocation = self.config.shares.get(key).map_or(0, |share| share.units);
            free_used = free_used
                .checked_add(used.saturating_sub(allocation))
                .ok_or(RsiBudgetError::Exhausted)?;
        }
        Ok(free_used)
    }

    fn free_pool_limit(&self) -> RsiResult<u64> {
        let allocated = self.config.shares.values().try_fold(0u64, |total, share| {
            total
                .checked_add(share.units)
                .ok_or(RsiBudgetError::Exhausted)
        })?;
        self.config
            .limit
            .checked_sub(allocated)
            .ok_or(RsiBudgetError::Exhausted)
    }

    fn has_room(
        &self,
        line: RsiLine,
        limit: u64,
        amount: u64,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<()> {
        let (spent, reserved) = self.usage(line, accepts)?;
        if spent
            .checked_add(reserved)
            .and_then(|n| n.checked_add(amount))
            .is_none_or(|total| total > limit)
        {
            return Err(RsiBudgetError::Exhausted);
        }
        Ok(())
    }
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>) -> RsiResult<Line> {
    RSI_LINE
        .get(&vault.store, txn, &())?
        .ok_or(RsiBudgetError::Unconfigured)
}
fn save(vault: &Vault, txn: &mut heed::RwTxn<'_>, line: &Line) -> RsiResult<()> {
    RSI_LINE.put(&vault.store, txn, &(), line)?;
    Ok(())
}

impl Vault {
    /// Creates the line once. Reconfiguration cannot erase receipts or spend.
    pub fn configure_rsi_budget(&self, config: RsiBudgetConfig) -> RsiResult<()> {
        if config
            .shares
            .iter()
            .any(|(key, share)| key.is_empty() || share.units > config.limit)
            || config
                .shares
                .values()
                .try_fold(0u64, |total, share| total.checked_add(share.units))
                .is_none_or(|allocated| allocated > config.limit)
        {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn()?;
        if RSI_LINE.contains(&self.store, &txn, &())? {
            return Err(RsiBudgetError::InvalidConfig);
        }
        save(
            self,
            &mut txn,
            &Line {
                config,
                suspended: false,
                reservations: BTreeMap::new(),
            },
        )?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// The configured lines and shares, exactly as the owner set them.
    pub fn rsi_budget_config(&self) -> RsiResult<RsiBudgetConfig> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        Ok(load(self, &txn)?.config)
    }

    /// Raises one exact limiting line inside the write that stores it.
    /// Receipts, spend and the suspension hold are untouched: resuming held
    /// work is a separate owner act.
    pub fn top_up_rsi_budget(&self, top_up: RsiTopUp) -> RsiResult<RsiBudgetConfig> {
        let units = match &top_up {
            RsiTopUp::Tokens { units }
            | RsiTopUp::Exploration { units }
            | RsiTopUp::Share { units, .. } => *units,
        };
        if units == 0 {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn()?;
        let mut line = load(self, &txn)?;
        match &top_up {
            RsiTopUp::Tokens { units } => {
                line.config.limit = line
                    .config
                    .limit
                    .checked_add(*units)
                    .ok_or(RsiBudgetError::InvalidConfig)?;
            }
            RsiTopUp::Exploration { units } => {
                line.config.exploration_exposure_limit = line
                    .config
                    .exploration_exposure_limit
                    .checked_add(*units)
                    .ok_or(RsiBudgetError::InvalidConfig)?;
            }
            RsiTopUp::Share { share, units } => {
                let row = line
                    .config
                    .shares
                    .get_mut(share)
                    .ok_or(RsiBudgetError::InvalidConfig)?;
                row.units = row
                    .units
                    .checked_add(*units)
                    .ok_or(RsiBudgetError::InvalidConfig)?;
                let allocated = line
                    .config
                    .shares
                    .values()
                    .try_fold(0u64, |total, share| total.checked_add(share.units));
                if allocated.is_none_or(|allocated| allocated > line.config.limit) {
                    return Err(RsiBudgetError::InvalidConfig);
                }
            }
        }
        let config = line.config.clone();
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(config)
    }

    /// Reserve token-denominated loop spend; this cannot debit exploration exposure.
    pub fn reserve_rsi_budget(
        &self,
        id: EntityId,
        units: u64,
        purpose: RsiSpendPurpose,
        share: Option<String>,
    ) -> RsiResult<()> {
        self.reserve_rsi_line(id, units, RsiLine::Tokens, Some(purpose), share)
    }

    /// Reserve exposure for a bandit slice, independently of token spend.
    pub fn reserve_rsi_exploration(&self, id: EntityId, exposure: u64) -> RsiResult<()> {
        self.reserve_rsi_line(id, exposure, RsiLine::Exposure, None, None)
    }

    fn reserve_rsi_line(
        &self,
        id: EntityId,
        amount: u64,
        kind: RsiLine,
        purpose: Option<RsiSpendPurpose>,
        share: Option<String>,
    ) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut line = load(self, &txn)?;
        if line.suspended {
            return Err(RsiBudgetError::Suspended);
        }
        if line.reservations.contains_key(&id.to_hex()) {
            return Err(RsiBudgetError::DuplicateReservation);
        }
        let pool_before = if kind == RsiLine::Tokens {
            Some(line.free_pool_usage()?)
        } else {
            None
        };
        let key = id.to_hex();
        line.reservations.insert(
            key.clone(),
            Reservation {
                amount,
                line: kind,
                purpose,
                share: share.clone(),
                settlement: None,
                overdraft: None,
                research: None,
            },
        );
        let admission = (|| {
            let limit = match kind {
                RsiLine::Tokens => line.config.limit,
                RsiLine::Exposure => line.config.exploration_exposure_limit,
            };
            line.has_room(kind, limit, 0, |_| true)?;
            if kind == RsiLine::Tokens {
                if let Some(share) = &share
                    && let Some(policy) = line.config.shares.get(share)
                    && policy.pinned
                {
                    line.has_room(kind, policy.units, 0, |row| {
                        row.share.as_ref() == Some(share)
                    })?;
                }
                let pool_after = line.free_pool_usage()?;
                if pool_after > line.free_pool_limit()? {
                    return Err(RsiBudgetError::Exhausted);
                }
                if let Some(share) = &share
                    && !line
                        .config
                        .shares
                        .get(share)
                        .is_some_and(|policy| policy.pinned)
                {
                    let overdrawn = pool_after
                        - pool_before.ok_or(crate::Error::InvariantViolation(
                            "RSI token pool missing before admission",
                        ))?;
                    if overdrawn > 0 {
                        return Ok(Some(RsiOverdraftReceipt {
                            share: share.clone(),
                            units: overdrawn,
                        }));
                    }
                }
            }
            Ok(None)
        })();
        match admission {
            Ok(overdraft) => {
                let row =
                    line.reservations
                        .get_mut(&key)
                        .ok_or(crate::Error::InvariantViolation(
                            "RSI reservation missing after admission",
                        ))?;
                row.overdraft = overdraft;
            }
            Err(RsiBudgetError::Exhausted) => {
                line.reservations.remove(&key);
                line.suspended = true;
                save(self, &mut txn, &line)?;
                txn.commit().map_err(crate::Error::from)?;
                return Err(RsiBudgetError::Exhausted);
            }
            Err(other) => return Err(other),
        }
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Settle token spend once, releasing unused reserved tokens.
    pub fn settle_rsi_budget(&self, id: EntityId, spent: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Spent(spent))
    }

    /// Settle exploration exposure once, releasing unused reserved exposure.
    pub fn settle_rsi_exploration(&self, id: EntityId, exposure: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Exposure(exposure))
    }

    /// Refunds an unspent reservation. Settled spend cannot be erased.
    pub fn refund_rsi_budget(&self, id: EntityId) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Refunded)
    }

    fn finish_rsi_reservation(&self, id: EntityId, settlement: RsiSettlement) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        self.finish_rsi_reservation_in_txn(&mut txn, id, settlement)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    pub(crate) fn finish_rsi_reservation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        settlement: RsiSettlement,
    ) -> RsiResult<()> {
        let mut line = load(self, txn)?;
        let row = line
            .reservations
            .get_mut(&id.to_hex())
            .ok_or(RsiBudgetError::ReservationRequired)?;
        if !matches!(
            (row.line, &settlement),
            (
                RsiLine::Tokens,
                RsiSettlement::Spent(_) | RsiSettlement::Unknown
            ) | (RsiLine::Exposure, RsiSettlement::Exposure(_))
                | (_, RsiSettlement::Refunded)
        ) {
            return Err(RsiBudgetError::WrongLine);
        }
        if let Some(current) = &row.settlement {
            return if *current == settlement {
                Ok(())
            } else {
                Err(RsiBudgetError::ReservationRequired)
            };
        }
        // Token spend already happened: record it whole even past the
        // reservation. Future admission still applies the configured caps.
        if let RsiSettlement::Exposure(amount) = settlement
            && amount > row.amount
        {
            return Err(RsiBudgetError::Exhausted);
        }
        row.settlement = Some(settlement);
        save(self, txn, &line)
    }

    /// Binds a host-observed run's native total to its existing reservation.
    /// The caller read both the persisted running pair and this scope in `txn`.
    pub(crate) fn settle_research_spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        root: AttemptId,
        scope: Option<&SpendScope>,
    ) -> RsiResult<RsiSettlement> {
        let settlement = scope.map_or(RsiSettlement::Unknown, |scope| {
            RsiSettlement::Spent(scope.spent_units)
        });
        self.finish_rsi_reservation_in_txn(txn, id, settlement.clone())?;
        if let Some(scope) = scope {
            let mut line = load(self, txn)?;
            let row = line
                .reservations
                .get_mut(&id.to_hex())
                .ok_or(RsiBudgetError::ReservationRequired)?;
            row.research = Some(ResearchSpendBinding {
                scope: scope.scope.clone(),
                root,
            });
            save(self, txn, &line)?;
        }
        Ok(settlement)
    }

    /// Revises only already-bound native totals. This records incurred spend;
    /// it changes no cap, hold, suspension, or future admission.
    pub(crate) fn revise_research_spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScope,
    ) -> crate::Result<()> {
        if scope.state != SpendState::Closed || scope.unit != crate::run_budget::LeaseUnit::tokens()
        {
            return Ok(());
        }
        let Some(mut line) = RSI_LINE.get(&self.store, txn, &())? else {
            return Ok(());
        };
        let mut updates = Vec::new();
        for (id, row) in &mut line.reservations {
            let Some(binding) = &row.research else {
                continue;
            };
            if binding.scope != scope.scope || row.line != RsiLine::Tokens {
                continue;
            }
            if let Some(RsiSettlement::Spent(previous)) = row.settlement
                && scope.spent_units > previous
            {
                row.settlement = Some(RsiSettlement::Spent(scope.spent_units));
                updates.push((binding.root, EntityId::from_hex(id)?));
            }
        }
        if updates.is_empty() {
            return Ok(());
        }
        for (root, id) in updates {
            crate::autoreason_campaign::research::revise_research_work_in_txn(
                self,
                txn,
                root,
                id,
                scope.spent_units,
            )?;
        }
        RSI_LINE.put(&self.store, txn, &(), &line)
    }

    /// A suspension holds new work; admitted work can still settle honestly.
    pub fn suspend_rsi_budget(&self, suspended: bool) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut line = load(self, &txn)?;
        line.suspended = suspended;
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Releases the hold on new loop work; admitted work may already settle while held.
    pub fn resume_rsi_budget(&self) -> RsiResult<()> {
        self.suspend_rsi_budget(false)
    }

    pub fn rsi_budget(&self) -> RsiResult<RsiBudgetRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent, reserved) = line.usage(RsiLine::Tokens, |_| true)?;
        Ok(RsiBudgetRead {
            limit: line.config.limit,
            spent,
            reserved,
            suspended: line.suspended,
        })
    }

    /// Reads the exposure line without adding token spend to it.
    pub fn rsi_exploration(&self) -> RsiResult<RsiExplorationRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent_exposure, reserved_exposure) = line.usage(RsiLine::Exposure, |_| true)?;
        Ok(RsiExplorationRead {
            exposure_limit: line.config.exploration_exposure_limit,
            spent_exposure,
            reserved_exposure,
            suspended: line.suspended,
        })
    }

    /// Reads the token-share overdraft stamped at reservation, including after settlement.
    pub fn rsi_overdraft(&self, id: EntityId) -> RsiResult<Option<RsiOverdraftReceipt>> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        Ok(line
            .reservations
            .get(&id.to_hex())
            .and_then(|row| row.overdraft.clone()))
    }

    /// Reads the terminal receipt without exposing another vault's key material.
    pub fn rsi_settlement(&self, id: EntityId) -> RsiResult<Option<RsiSettlement>> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        Ok(line
            .reservations
            .get(&id.to_hex())
            .and_then(|row| row.settlement.clone()))
    }
}

pub use crate::research_budget::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};
