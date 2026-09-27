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

/// The stamped token-share overflow admitted from the unallocated token pool.
/// Units record reservation-time overdraft, even if it settles for less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiOverdraftReceipt {
    pub share: String,
    pub units: u64,
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
    overdraft: Option<RsiOverdraftReceipt>,
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
                None => row.amount,
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
        vault.resume_rsi_budget().unwrap();
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
        vault.resume_rsi_budget().unwrap();
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
        vault.resume_rsi_budget().unwrap();
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
    #[test]
    fn exploration_exposure_and_pinned_tokens_are_independent_in_both_orders() {
        for exposure_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
            vault
                .configure_rsi_budget(RsiBudgetConfig {
                    limit: 100,
                    exploration_exposure_limit: 20,
                    shares: BTreeMap::from([(
                        "pin".into(),
                        RsiBudgetShare {
                            units: 30,
                            pinned: true,
                        },
                    )]),
                })
                .unwrap();
            let exposure = EntityId::now();
            let pinned = EntityId::now();
            if exposure_first {
                vault.reserve_rsi_exploration(exposure, 20).unwrap();
            }
            vault
                .reserve_rsi_budget(pinned, 30, RsiSpendPurpose::Judge, Some("pin".into()))
                .unwrap();
            if !exposure_first {
                vault.reserve_rsi_exploration(exposure, 20).unwrap();
            }
            let free = EntityId::now();
            vault
                .reserve_rsi_budget(free, 70, RsiSpendPurpose::Experiment, None)
                .unwrap();
            assert!(!vault.rsi_budget().unwrap().suspended);
            assert_eq!(vault.rsi_budget().unwrap().reserved, 100);
            assert_eq!(vault.rsi_exploration().unwrap().reserved_exposure, 20);
            assert_eq!(vault.rsi_overdraft(pinned).unwrap(), None);
            assert_eq!(vault.rsi_overdraft(exposure).unwrap(), None);
            vault.settle_rsi_budget(pinned, 30).unwrap();
            vault.settle_rsi_exploration(exposure, 20).unwrap();
        }
    }

    #[test]
    fn token_soft_share_receipts_pool_overdraft_and_holds_until_resume() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::VaultConfig::device();
        let vault = Vault::open(dir.path(), config.clone()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 100,
                exploration_exposure_limit: 20,
                shares: BTreeMap::from([
                    (
                        "pin".into(),
                        RsiBudgetShare {
                            units: 30,
                            pinned: true,
                        },
                    ),
                    (
                        "soft".into(),
                        RsiBudgetShare {
                            units: 20,
                            pinned: false,
                        },
                    ),
                ]),
            })
            .unwrap();
        let pinned = EntityId::now();
        let soft = EntityId::now();
        let free = EntityId::now();
        vault
            .reserve_rsi_budget(pinned, 30, RsiSpendPurpose::Judge, Some("pin".into()))
            .unwrap();
        vault
            .reserve_rsi_budget(soft, 65, RsiSpendPurpose::Experiment, Some("soft".into()))
            .unwrap();
        assert_eq!(
            vault.rsi_overdraft(soft).unwrap(),
            Some(RsiOverdraftReceipt {
                share: "soft".into(),
                units: 45
            })
        );
        drop(vault);
        let vault = Vault::open(dir.path(), config).unwrap();
        assert_eq!(vault.rsi_overdraft(soft).unwrap().unwrap().units, 45);
        assert!(matches!(
            vault.reserve_rsi_budget(free, 6, RsiSpendPurpose::Judge, None),
            Err(RsiBudgetError::Exhausted)
        ));
        assert!(vault.rsi_budget().unwrap().suspended);
        assert!(matches!(
            vault.reserve_rsi_exploration(EntityId::now(), 1),
            Err(RsiBudgetError::Suspended)
        ));
        vault.settle_rsi_budget(soft, 55).unwrap();
        assert!(vault.rsi_budget().unwrap().suspended);
        vault.resume_rsi_budget().unwrap();
        vault
            .reserve_rsi_budget(free, 6, RsiSpendPurpose::Judge, None)
            .unwrap();
        vault.settle_rsi_budget(free, 6).unwrap();
        assert_eq!(vault.rsi_overdraft(soft).unwrap().unwrap().units, 45);
        assert_eq!(vault.rsi_budget().unwrap().spent, 61);
    }

    #[test]
    fn token_share_allocations_cannot_exceed_token_limit() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        assert!(matches!(
            vault.configure_rsi_budget(RsiBudgetConfig {
                limit: 10,
                exploration_exposure_limit: 100,
                shares: BTreeMap::from([
                    (
                        "a".into(),
                        RsiBudgetShare {
                            units: 7,
                            pinned: false
                        }
                    ),
                    (
                        "b".into(),
                        RsiBudgetShare {
                            units: 7,
                            pinned: true
                        }
                    ),
                ]),
            }),
            Err(RsiBudgetError::InvalidConfig)
        ));
    }
}
