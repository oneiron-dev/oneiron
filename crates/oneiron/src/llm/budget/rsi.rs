//! Vault-local durable reserve/settle/refund ledger for research-loop spend.
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const LINE_KEY: &[u8] = b"budget.rsi.line.v1";

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

/// One vault line with a protected exploration slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiBudgetConfig {
    pub limit: u64,
    pub exploration_units: u64,
    pub shares: BTreeMap<String, RsiBudgetShare>,
}

/// Observable accounting, including reservations that survive reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsiBudgetRead {
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
    pub suspended: bool,
}

/// The stamped share overflow admitted from the unallocated pool.
/// Units record the reservation-time overdraft, even if it later settles for less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiOverdraftReceipt {
    pub share: String,
    pub units: u64,
}

/// The durable receipt of one reservation's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiSettlement {
    Spent(u64),
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
    units: u64,
    purpose: RsiSpendPurpose,
    share: Option<String>,
    exploration: bool,
    settlement: Option<RsiSettlement>,
    overdraft: Option<RsiOverdraftReceipt>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    config: RsiBudgetConfig,
    suspended: bool,
    reservations: BTreeMap<String, Reservation>,
}

impl Line {
    fn usage(&self, accepts: impl Fn(&Reservation) -> bool) -> RsiResult<(u64, u64)> {
        let (mut spent, mut reserved) = (0u64, 0u64);
        for row in self.reservations.values().filter(|row| accepts(row)) {
            match row.settlement {
                Some(RsiSettlement::Spent(units)) => {
                    spent = spent.checked_add(units).ok_or(RsiBudgetError::Exhausted)?;
                }
                None => {
                    reserved = reserved
                        .checked_add(row.units)
                        .ok_or(RsiBudgetError::Exhausted)?;
                }
                Some(RsiSettlement::Refunded) => {}
            }
        }
        Ok((spent, reserved))
    }
    /// Normal-spend shares are carved out before the unallocated pool is used.
    /// Exploration has its own protected slice, outside these share allocations.
    fn free_pool_usage(&self) -> RsiResult<u64> {
        let mut by_share = BTreeMap::<&str, u64>::new();
        let mut free_used = 0u64;
        for row in self.reservations.values().filter(|row| !row.exploration) {
            let units = match row.settlement {
                Some(RsiSettlement::Spent(units)) => units,
                Some(RsiSettlement::Refunded) => 0,
                None => row.units,
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
            .checked_sub(self.config.exploration_units)
            .and_then(|normal| normal.checked_sub(allocated))
            .ok_or(RsiBudgetError::Exhausted)
    }

    fn has_room(
        &self,
        limit: u64,
        units: u64,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<()> {
        let (spent, reserved) = self.usage(accepts)?;
        if spent
            .checked_add(reserved)
            .and_then(|n| n.checked_add(units))
            .is_none_or(|total| total > limit)
        {
            return Err(RsiBudgetError::Exhausted);
        }
        Ok(())
    }
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>) -> RsiResult<Line> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, LINE_KEY)?
        .ok_or(RsiBudgetError::Unconfigured)?;
    serde_json::from_slice(&raw)
        .map_err(|_| crate::Error::CorruptedIndex("RSI budget ledger").into())
}
fn save(vault: &Vault, txn: &mut heed::RwTxn<'_>, line: &Line) -> RsiResult<()> {
    let raw = serde_json::to_vec(line)
        .map_err(|_| crate::Error::InvariantViolation("RSI ledger encoding"))?;
    vault.store.vault_meta.put(txn, LINE_KEY, &raw)?;
    Ok(())
}

impl Vault {
    /// Creates the line once. Reconfiguration cannot erase receipts or spend.
    pub fn configure_rsi_budget(&self, config: RsiBudgetConfig) -> RsiResult<()> {
        if config.exploration_units > config.limit
            || config
                .shares
                .iter()
                .any(|(key, share)| key.is_empty() || share.units > config.limit)
            || config
                .shares
                .values()
                .try_fold(0u64, |total, share| total.checked_add(share.units))
                .is_none_or(|allocated| allocated > config.limit - config.exploration_units)
        {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        if self.store.vault_meta.get(&txn, LINE_KEY)?.is_some() {
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

    /// Admission reserves first. No reservation means no lawful loop spend.
    pub fn reserve_rsi_budget(
        &self,
        id: EntityId,
        units: u64,
        purpose: RsiSpendPurpose,
        share: Option<String>,
        exploration: bool,
    ) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        if line.suspended {
            return Err(RsiBudgetError::Suspended);
        }
        if line.reservations.contains_key(&id.to_hex()) {
            return Err(RsiBudgetError::DuplicateReservation);
        }
        let pool_before = line.free_pool_usage()?;
        let key = id.to_hex();
        line.reservations.insert(
            key.clone(),
            Reservation {
                units,
                purpose,
                share: share.clone(),
                exploration,
                settlement: None,
                overdraft: None,
            },
        );
        let admission = (|| {
            line.has_room(line.config.limit, 0, |_| true)?;
            let slice = if exploration {
                line.config.exploration_units
            } else {
                line.config.limit - line.config.exploration_units
            };
            line.has_room(slice, 0, |row| row.exploration == exploration)?;
            if let Some(share) = &share
                && let Some(policy) = line.config.shares.get(share)
                && policy.pinned
            {
                line.has_room(policy.units, 0, |row| row.share.as_ref() == Some(share))?;
            }
            if !exploration {
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
                    let overdrawn = pool_after - pool_before;
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

    /// Settles absolute usage once and releases unused reserved capacity.
    /// Repeating the exact terminal response is idempotent; changing it fails.
    pub fn settle_rsi_budget(&self, id: EntityId, spent: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Spent(spent))
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
        if let Some(current) = &row.settlement {
            return if *current == settlement {
                Ok(())
            } else {
                Err(RsiBudgetError::ReservationRequired)
            };
        }
        if let RsiSettlement::Spent(units) = settlement
            && units > row.units
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

    /// Releases a held loop after the caller has restored spend capacity.
    /// A failed reservation takes the loop back to hold; it never kills existing work.
    pub fn resume_rsi_budget(&self) -> RsiResult<()> {
        self.suspend_rsi_budget(false)
    }

    pub fn rsi_budget(&self) -> RsiResult<RsiBudgetRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent, reserved) = line.usage(|_| true)?;
        Ok(RsiBudgetRead {
            limit: line.config.limit,
            spent,
            reserved,
            suspended: line.suspended,
        })
    }

    /// Reads a reservation's stamped overdraft, including after settlement or refund.
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
                exploration_units: 20,
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
            .reserve_rsi_budget(first, 70, RsiSpendPurpose::Experiment, None, false)
            .unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(second, 11, RsiSpendPurpose::Judge, None, false),
            Err(RsiBudgetError::Exhausted)
        ));
        vault.resume_rsi_budget().unwrap();
        vault
            .reserve_rsi_budget(second, 20, RsiSpendPurpose::HeldOut, None, true)
            .unwrap();
        drop(vault);
        let vault = Vault::open(dir.path(), config).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().reserved, 90);
        vault.suspend_rsi_budget(true).unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(EntityId::now(), 1, RsiSpendPurpose::Judge, None, true),
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
    fn shares_overdraw_only_free_pool_and_hold_until_resume() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::VaultConfig::device();
        let vault = Vault::open(dir.path(), config.clone()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 100,
                exploration_units: 10,
                shares: BTreeMap::from([
                    (
                        "owner".into(),
                        RsiBudgetShare {
                            units: 30,
                            pinned: true,
                        },
                    ),
                    (
                        "skill".into(),
                        RsiBudgetShare {
                            units: 20,
                            pinned: false,
                        },
                    ),
                ]),
            })
            .unwrap();
        let owner = EntityId::now();
        let soft = EntityId::now();
        let extra = EntityId::now();
        vault
            .reserve_rsi_budget(
                owner,
                30,
                RsiSpendPurpose::Judge,
                Some("owner".into()),
                false,
            )
            .unwrap();
        vault
            .reserve_rsi_budget(
                soft,
                35,
                RsiSpendPurpose::Experiment,
                Some("skill".into()),
                false,
            )
            .unwrap();
        assert_eq!(
            vault.rsi_overdraft(soft).unwrap(),
            Some(RsiOverdraftReceipt {
                share: "skill".into(),
                units: 15
            })
        );
        assert_eq!(vault.rsi_overdraft(owner).unwrap(), None);
        drop(vault);
        let vault = Vault::open(dir.path(), config).unwrap();
        assert_eq!(vault.rsi_overdraft(soft).unwrap().unwrap().units, 15);
        // The unallocated free pool is 40; 15 is overdrawn, so only 25 remains.
        assert!(matches!(
            vault.reserve_rsi_budget(extra, 26, RsiSpendPurpose::Judge, None, false),
            Err(RsiBudgetError::Exhausted)
        ));
        assert!(vault.rsi_budget().unwrap().suspended);
        assert!(matches!(
            vault.reserve_rsi_budget(extra, 1, RsiSpendPurpose::Judge, None, false),
            Err(RsiBudgetError::Suspended)
        ));
        vault.settle_rsi_budget(soft, 25).unwrap();
        assert!(vault.rsi_budget().unwrap().suspended);
        vault.resume_rsi_budget().unwrap();
        vault
            .reserve_rsi_budget(extra, 26, RsiSpendPurpose::Judge, None, false)
            .unwrap();
        vault.settle_rsi_budget(extra, 26).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().spent, 51);
        assert_eq!(vault.rsi_overdraft(soft).unwrap().unwrap().units, 15);
    }

    #[test]
    fn pinned_share_and_unallocated_spend_cannot_borrow_other_shares() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 70,
                exploration_units: 10,
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
        let first = EntityId::now();
        let second = EntityId::now();
        vault
            .reserve_rsi_budget(first, 10, RsiSpendPurpose::Judge, None, false)
            .unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(second, 1, RsiSpendPurpose::Judge, None, false),
            Err(RsiBudgetError::Exhausted)
        ));
        vault.resume_rsi_budget().unwrap();
        vault
            .reserve_rsi_budget(
                second,
                30,
                RsiSpendPurpose::Judge,
                Some("pin".into()),
                false,
            )
            .unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(
                EntityId::now(),
                1,
                RsiSpendPurpose::Judge,
                Some("pin".into()),
                false
            ),
            Err(RsiBudgetError::Exhausted)
        ));
        assert!(vault.rsi_overdraft(second).unwrap().is_none());
    }
    #[test]
    fn shares_must_fit_outside_exploration_and_refunds_free_the_pool() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        assert!(matches!(
            vault.configure_rsi_budget(RsiBudgetConfig {
                limit: 20,
                exploration_units: 10,
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
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 20,
                exploration_units: 10,
                shares: BTreeMap::from([(
                    "a".into(),
                    RsiBudgetShare {
                        units: 7,
                        pinned: false,
                    },
                )]),
            })
            .unwrap();
        let first = EntityId::now();
        let second = EntityId::now();
        vault
            .reserve_rsi_budget(
                first,
                9,
                RsiSpendPurpose::Experiment,
                Some("a".into()),
                false,
            )
            .unwrap();
        assert_eq!(vault.rsi_overdraft(first).unwrap().unwrap().units, 2);
        assert!(matches!(
            vault.reserve_rsi_budget(second, 2, RsiSpendPurpose::Judge, Some("a".into()), false),
            Err(RsiBudgetError::Exhausted)
        ));
        vault.refund_rsi_budget(first).unwrap();
        vault.resume_rsi_budget().unwrap();
        vault
            .reserve_rsi_budget(second, 2, RsiSpendPurpose::Judge, Some("a".into()), false)
            .unwrap();
        assert_eq!(vault.rsi_overdraft(second).unwrap(), None);
        assert_eq!(vault.rsi_overdraft(first).unwrap().unwrap().units, 2);
    }
}
