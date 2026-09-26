//! Vault-local durable reserve/settle/refund ledger for research-loop spend.
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
const RSI_LINE: SideTable<(), Line, LegacyJson> = SideTable::new(&side_table::BUDGET_RSI_LINE);

/// Loop purpose, kept separate from ordinary interactive LLM budget rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiSpendPurpose {
    Experiment,
    Judge,
    HeldOut,
}

/// A share is advisory unless the owner pins its cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiBudgetShare {
    pub units: u64,
    pub pinned: bool,
}

/// Independent vault lines: loop spend is token-denominated, exploration is exposure-denominated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiBudgetConfig {
    pub limit: u64,
    pub exploration_exposure_limit: u64,
    pub shares: BTreeMap<String, RsiBudgetShare>,
}

/// Token-denominated loop accounting, including reservations that survive reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsiBudgetRead {
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
    pub suspended: bool,
}

/// Exposure-denominated exploration accounting, independent of token spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsiExplorationRead {
    pub exposure_limit: u64,
    pub spent_exposure: u64,
    pub reserved_exposure: u64,
    pub suspended: bool,
}

/// The durable receipt of one reservation's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiSettlement {
    Spent(u64),
    Exposure(u64),
    Refunded,
}

/// Fail-closed ledger refusals. Nothing is spent or reserved on a refusal.
#[derive(Debug, thiserror::Error)]
pub enum RsiBudgetError {
    #[error("RSI budget is not configured")]
    Unconfigured,
    #[error("RSI budget configuration is invalid or already set")]
    InvalidConfig,
    #[error("RSI reservation already exists")]
    DuplicateReservation,
    #[error("RSI spend requires an open reservation")]
    ReservationRequired,
    #[error("RSI settlement uses the wrong budget line")]
    WrongLine,
    #[error("RSI budget capacity exceeded")]
    Exhausted,
    #[error("RSI work is suspended")]
    Suspended,
    #[error(transparent)]
    Engine(#[from] crate::Error),
}
type RsiResult<T> = std::result::Result<T, RsiBudgetError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    amount: u64,
    line: RsiLine,
    purpose: Option<RsiSpendPurpose>,
    share: Option<String>,
    settlement: Option<RsiSettlement>,
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
                (_, None) | (_, Some(RsiSettlement::Refunded)) => None,
                _ => return Err(crate::Error::CorruptedIndex("RSI budget settlement line").into()),
            };
            if row.line != line {
                continue;
            }
            if let Some(amount) = amount {
                spent = spent.checked_add(amount).ok_or(RsiBudgetError::Exhausted)?;
            } else if row.settlement.is_none() {
                reserved = reserved
                    .checked_add(row.amount)
                    .ok_or(RsiBudgetError::Exhausted)?;
            }
        }
        Ok((spent, reserved))
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
        {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
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
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        if line.suspended {
            return Err(RsiBudgetError::Suspended);
        }
        if line.reservations.contains_key(&id.to_hex()) {
            return Err(RsiBudgetError::DuplicateReservation);
        }
        let limit = match kind {
            RsiLine::Tokens => line.config.limit,
            RsiLine::Exposure => line.config.exploration_exposure_limit,
        };
        line.has_room(kind, limit, amount, |_| true)?;
        if let Some(key) = &share
            && let Some(policy) = line.config.shares.get(key)
            && policy.pinned
        {
            line.has_room(kind, policy.units, amount, |row| {
                row.share.as_ref() == Some(key)
            })?;
        }
        line.reservations.insert(
            id.to_hex(),
            Reservation {
                amount,
                line: kind,
                purpose,
                share,
                settlement: None,
            },
        );
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
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        let row = line
            .reservations
            .get_mut(&id.to_hex())
            .ok_or(RsiBudgetError::ReservationRequired)?;
        if !matches!(
            (row.line, &settlement),
            (RsiLine::Tokens, RsiSettlement::Spent(_))
                | (RsiLine::Exposure, RsiSettlement::Exposure(_))
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
        if let RsiSettlement::Spent(amount) | RsiSettlement::Exposure(amount) = settlement
            && amount > row.amount
        {
            return Err(RsiBudgetError::Exhausted);
        }
        row.settlement = Some(settlement);
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// A suspension holds new work; admitted work can still settle honestly.
    pub fn suspend_rsi_budget(&self, suspended: bool) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        line.suspended = suspended;
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rsi_line_reserves_settles_refunds_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::VaultConfig::device();
        let vault = Vault::open(dir.path(), config.clone()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 100,
                exploration_exposure_limit: 20,
                shares: BTreeMap::new(),
            })
            .unwrap();
        let missing = EntityId::now();
        assert!(matches!(
            vault.settle_rsi_budget(missing, 1),
            Err(RsiBudgetError::ReservationRequired)
        ));
        let first = EntityId::now();
        let second = EntityId::now();
        vault
            .reserve_rsi_budget(first, 70, RsiSpendPurpose::Experiment, None)
            .unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(second, 31, RsiSpendPurpose::Judge, None),
            Err(RsiBudgetError::Exhausted)
        ));
        vault.reserve_rsi_exploration(second, 20).unwrap();
        drop(vault);
        let vault = Vault::open(dir.path(), config).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().reserved, 70);
        assert_eq!(vault.rsi_exploration().unwrap().reserved_exposure, 20);
        vault.suspend_rsi_budget(true).unwrap();
        assert!(matches!(
            vault.reserve_rsi_exploration(EntityId::now(), 1),
            Err(RsiBudgetError::Suspended)
        ));
        vault.settle_rsi_budget(first, 40).unwrap();
        vault.settle_rsi_budget(first, 40).unwrap();
        assert!(vault.settle_rsi_budget(first, 41).is_err());
        vault.refund_rsi_budget(second).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().spent, 40);
        assert_eq!(vault.rsi_budget().unwrap().reserved, 0);
        assert_eq!(
            vault.rsi_settlement(second).unwrap(),
            Some(RsiSettlement::Refunded)
        );
    }

    #[test]
    fn exploration_exposure_is_independent_of_token_spend() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 10,
                exploration_exposure_limit: 2,
                shares: BTreeMap::new(),
            })
            .unwrap();
        let tokens = EntityId::now();
        let bandit = EntityId::now();
        vault
            .reserve_rsi_budget(tokens, 10, RsiSpendPurpose::Experiment, None)
            .unwrap();
        assert_eq!(vault.rsi_exploration().unwrap().reserved_exposure, 0);
        vault.reserve_rsi_exploration(bandit, 2).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().reserved, 10);
        assert_eq!(vault.rsi_exploration().unwrap().reserved_exposure, 2);
        assert!(matches!(
            vault.reserve_rsi_budget(EntityId::now(), 1, RsiSpendPurpose::Judge, None),
            Err(RsiBudgetError::Exhausted)
        ));
        assert!(matches!(
            vault.reserve_rsi_exploration(EntityId::now(), 1),
            Err(RsiBudgetError::Exhausted)
        ));
        assert!(matches!(
            vault.settle_rsi_budget(bandit, 1),
            Err(RsiBudgetError::WrongLine)
        ));
        assert!(matches!(
            vault.settle_rsi_exploration(tokens, 1),
            Err(RsiBudgetError::WrongLine)
        ));
        assert!(matches!(
            vault.settle_rsi_exploration(bandit, 3),
            Err(RsiBudgetError::Exhausted)
        ));
        vault.settle_rsi_budget(tokens, 10).unwrap();
        vault.settle_rsi_exploration(bandit, 1).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().spent, 10);
        assert_eq!(vault.rsi_exploration().unwrap().spent_exposure, 1);
        assert_eq!(
            vault.rsi_settlement(bandit).unwrap(),
            Some(RsiSettlement::Exposure(1))
        );
        vault.reserve_rsi_exploration(EntityId::now(), 1).unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(EntityId::now(), 1, RsiSpendPurpose::HeldOut, None),
            Err(RsiBudgetError::Exhausted)
        ));
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        assert_eq!(reopened.rsi_budget().unwrap().spent, 10);
        assert_eq!(reopened.rsi_exploration().unwrap().spent_exposure, 1);
        assert_eq!(reopened.rsi_exploration().unwrap().reserved_exposure, 1);
    }
}
